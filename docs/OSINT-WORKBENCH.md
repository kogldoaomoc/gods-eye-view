# OSINT workbench design

Status: design, not implemented. Scope: personal research use on one machine.

This document describes how God's Eye View (GEV) becomes the map and case
surface for a set of external OSINT tools, without removing any existing
layer, slowing startup, or making the current interface harder to use.

Tools covered: SpiderFoot, Recon-ng, theHarvester, Sherlock, GHunt,
PhoneInfoga, DataSploit, Shodan, Skiptracer, sn0int, ReconDog, LittleBrother,
Maigret and h8mail.

## Goals and constraints

- **Nothing is removed.** Every existing layer, panel, voice action and MCP
  tool keeps working exactly as today. The workbench is additive.
- **Zero cost when unused.** With no case open, GEV makes no extra requests,
  constructs no extra Cesium resources and starts no extra processes. The
  startup numbers in [PERFORMANCE.md](PERFORMANCE.md) must not move.
- **Most results are not geographic.** Usernames, emails, breaches and
  accounts have no coordinates. The design treats the map as one view of a
  case, not the only one, and never invents a location to make something
  plottable.
- **Investigation data never leaves the machine by accident.** It stays out
  of share links, stored layer state, scene exports and model prompts unless
  the user explicitly includes it.
- **The existing ownership rules still apply.** Portable sources stay free of
  Cesium and Node ([CODE-BOUNDARIES.md](CODE-BOUNDARIES.md)), panels follow
  [panel-surfaces.md](panel-surfaces.md), world text uses the overlay host,
  and `npm run check:boundaries` stays green.

## The model: cases, entities, observations

Everything a tool returns is normalized into one schema before GEV sees it.

- A **case** is a named investigation with its own store.
- An **entity** is one distinct thing: `person`, `username`, `account`,
  `email`, `phone`, `domain`, `host`, `ip`, `organization`, `address`,
  `place`, `breach` or `image`. Its ID is a hash of its type and normalized
  value, so the same email found by theHarvester, h8mail and SpiderFoot is
  one entity.
- An **observation** records that a tool reported an entity or a link, with
  the tool, its version, the query, the time, a confidence and a pointer to
  the raw output. Entities accumulate observations; they are never
  overwritten.
- A **link** joins two entities with a relation such as `registered_with`,
  `resolves_to`, `located_at`, `same_as` or `breached_in`. Links also carry
  observations.

Normalization rules: emails are lowercased; phones become E.164
(libphonenumber); domains are lowercased and punycode-encoded; usernames are
kept case-sensitive but matched case-insensitively per platform; IPs use
their canonical text form.

```json
{
  "id": "ent_3f9c…",
  "type": "ip",
  "value": "203.0.113.7",
  "label": "203.0.113.7 (AS64500 Example Hosting)",
  "geo": {
    "lat": 52.37,
    "lon": 4.89,
    "precision": "city",
    "radiusM": 25000,
    "method": "shodan-host"
  },
  "observations": [
    {
      "tool": "shodan",
      "toolVersion": "1.31.0",
      "query": "host 203.0.113.7",
      "at": "2026-10-19T20:31:04Z",
      "confidence": 0.8,
      "raw": "runs/2026-10-19/shodan-7c1e.json#/data/0"
    }
  ]
}
```

### Geographic precision is explicit

`geo` is optional and always carries a `precision`: `exact`, `address`,
`street`, `city`, `region` or `country`, plus a radius or a boundary
reference. The layer draws a pin only for `exact` and `address`; it draws an
uncertainty circle for `street` and `city`, and an outline for `region` and
`country` using the bundled Natural Earth and admin-boundary data
(`src/data/naturalEarthRegions.js`, `src/data/adminBoundaries.js`). A phone
number's country is never drawn as a pin in the capital.

Resolution order, first match wins:

1. Coordinates in the tool output (Shodan `location`, GHunt Maps reviews,
   SpiderFoot `PHYSICAL_COORDINATES`).
2. An address string, geocoded through GEV's existing `/api/geocode`
   (Nominatim). It is already serialized and cached, which respects the
   one-request-per-second policy.
3. An IP: Shodan host data when a key is set, otherwise a local GeoLite2
   database if the user supplies one. Precision is never better than `city`.
4. A phone: country and, where libphonenumber knows it, region.
5. Nothing. The entity stays off the map and appears only in the case panel.

## Architecture

```
┌──────────────────────────── browser ────────────────────────────┐
│ existing layers / panels / voice     │  Case panel (right rail) │
│                                      │  OSINT layer (catalog)   │
│            src/sources/osint.js  (portable, no Cesium)          │
└───────────────────────────────┬─────────────────────────────────┘
                                │ /api/osint/*  (same origin, SSE)
┌───────────────────────────────┴─────────────────────────────────┐
│ GEV server: server/providers/osint/  (proxy, auth, caps, cache) │
│ MCP server: server/mcp  (adds osint tools via src/tools)        │
└───────────────────────────────┬─────────────────────────────────┘
                                │ loopback HTTP + shared token
┌───────────────────────────────┴─────────────────────────────────┐
│ osint-bridge sidecar (Python): job queue, adapters, normalizer, │
│ SQLite case store, raw-output archive                           │
│   adapters → spiderfoot · recon-ng · theHarvester · sherlock ·  │
│   maigret · ghunt · phoneinfoga · shodan · h8mail · sn0int ·    │
│   datasploit · skiptracer · recondog · littlebrother            │
└─────────────────────────────────────────────────────────────────┘
```

### 1. `osint-bridge` sidecar

A separate process, ideally a second service in `compose.yaml`, published on
`127.0.0.1` only, like the existing GEV service.

Why it runs outside GEV:

- **Runtimes.** The tools are Python, Go (PhoneInfoga) and Rust (sn0int).
  GEV's Node server should not manage virtualenvs.
- **Licences.** Recon-ng, theHarvester, PhoneInfoga, sn0int and DataSploit
  are GPL. Running them as separate programs and exchanging JSON keeps GEV's
  MIT code separate from theirs.
- **Isolation.** A hung scraper or a crashed tool must not block the Vite
  server's event loop or take the globe down.

Responsibilities:

- **Adapters.** One module per tool, with one interface:
  `accepts: [entity types]`, `run(selector, options) → native output`, and
  `normalize(native) → entities + links + observations`. Adapters call each
  tool's machine-readable output (`sf.py -o json` or SpiderFoot's REST API,
  `recon-cli` plus the JSON reporting module, `theHarvester -f`,
  `sherlock --json`, `maigret --json`, `ghunt … --json`,
  `phoneinfoga scan -o json` or its REST server, `shodan` via the Python
  library, `h8mail -j`, `sn0int` exports, and so on) rather than scraping
  terminal text.
- **Health checks.** Each adapter reports `ready`, `missing-binary`,
  `missing-key` or `broken`, with the reason. Unmaintained tools (DataSploit,
  Skiptracer, ReconDog, LittleBrother) are kept as **legacy** adapters: off
  by default, shown with their state, never silently failing.
- **Jobs.** A queue with a global concurrency limit and a per-tool limit and
  rate. Each job has a state (`queued`, `running`, `done`, `failed`,
  `cancelled`), progress events and a hard timeout. Cancelling kills the
  process group.
- **Caching.** Results are cached by `(tool, tool version, normalized
  selector, options)` with a per-tool TTL, so re-running a pivot is instant
  and does not re-hit the upstream service.
- **Storage.** One SQLite file per case under `.gev-cache/osint/` (already
  git-ignored with the rest of `.gev-cache`), with an R-tree index on
  `geo` for bounding-box queries. Raw outputs are kept as files beside it,
  referenced from observations.
- **Secrets.** API keys and session material (Shodan, HIBP for h8mail,
  GHunt's Google session) live in the bridge's environment, never in the
  browser and never in case files.

### 2. GEV server provider: `server/providers/osint/`

A new plugin added to `localProviderPlugins` in `server/providers/local.js`,
following the shape of `local-receivers.js`:

- The bridge URL comes only from `OSINT_BRIDGE_URL` and must pass the same
  loopback/RFC1918 rule (`src/data/tapAddress.js`). The browser never
  supplies an address.
- The provider adds the shared bridge token, enforces body-size and
  bounding-box caps, and relays:
  - `GET  /api/osint/cases`, `POST /api/osint/cases`
  - `GET  /api/osint/cases/:id/entities?bbox=…&types=…&limit=…`
  - `GET  /api/osint/cases/:id/entities/:entityId` (detail, observations,
    links)
  - `POST /api/osint/cases/:id/jobs` (selector, tools, options)
  - `DELETE /api/osint/jobs/:jobId`
  - `GET  /api/osint/cases/:id/events` (one Server-Sent Events stream for job
    progress and new entities)
  - `GET  /api/osint/tools` (adapter health)
- When `OSINT_BRIDGE_URL` is unset, every route answers `unavailable` and the
  layer row shows a setup hint. GEV behaves exactly as it does today.

A `osint-bridge` entry in the key registry (`src/keySetupCore.mjs`) gives it
the same Provider Settings guidance as other optional services, naming
`OSINT_BRIDGE_URL` and `OSINT_BRIDGE_TOKEN`.

### 3. Portable source: `src/sources/osint.js`

The browser and MCP clients share one source factory,
`createOsintSource({ fetchImpl })`, with `listCases`, `queryEntities(bbox,
filter)`, `getEntity`, `startJob`, `cancelJob` and `subscribe(caseId)`.
It reaches no Cesium, Node or browser globals, so it can be a package export
listed in `scripts/package-boundaries.json`, like the other sources.

### 4. The OSINT layer: `src/layers/osint/`

Constructed in `src/app/constructCatalog.js` like every other layer, with a
new reserved state token (`npm run layer-token:next`).

- **Local-only.** It is registered in `LOCAL_ONLY_LAYER_METADATA`, the same
  disposition `local-adsb` uses, so it never enters share links or restored
  layer state. Scene export needs an explicit "include case data" choice,
  and the export carries only the entities selected.
- **Rendering.** Point primitives and billboards in collections, with
  screen-space clustering, plus one entity per uncertainty circle or outline.
  Labels go through the overlay host (Cesium labels are forbidden). Icons
  and colours are per entity type; opacity scales with confidence.
- **Loading.** Entities are fetched by the current view's bounding box with a
  row cap, the same pattern CCTV and Places use, and refreshed only on camera
  settle or SSE updates.
- **Panel group.** A new `Investigation` group at the top of `PANEL_GROUPS`
  in `src/ui/layerPanel.js`. When no bridge is configured, the group is not
  shown at all.

### 5. Case panel

A right-rail panel (new template under `src/ui/templates/`, following the
panel surface contract) that holds everything the map cannot:

1. **Case bar.** Case picker, new case, and an export button.
2. **Selector box.** Paste anything; the type is auto-detected (email,
   E.164 or national phone, domain, IP, URL, `@handle`, name). The tool
   checklist below it is pre-filled for that type (see the routing table)
   and shows each tool's health. Run, then watch per-tool progress chips.
3. **Entity list.** Grouped by type, with counts, search and a confidence
   filter. Entities without geography show a small "not on map" marker
   instead of being hidden.
4. **Entity card.** Value, sources (with links to raw output), linked
   entities and a timeline of observations. Actions: **Fly to** (when it
   has geography), **Pivot** (run tools on this entity), **Mark verified**,
   **Hide**.
5. **Timeline strip.** Observations over time; scrubbing filters the map.

Clicking a map feature opens its entity card; clicking a non-geographic
entity highlights its linked geographic entities on the map.

### 6. Reusing what GEV already does well

The workbench gets most of its value from existing features, so it calls
them instead of re-implementing them:

| Need | Existing feature it uses |
| --- | --- |
| Check what is at an address | Street Level (Mapillary, KartaView, Panoramax, Google) opened at the entity |
| See recent conditions at a site | Recent Imagery box drawn around the entity |
| Area of interest | The draw and region tools in `src/annotations/` define an area, which becomes a Shodan `geo:` filter or a map filter |
| Address to coordinates | `/api/geocode` and the composed place search |
| Context around a location | A one-click "context" action enables chosen existing layers (CCTV, ALPR, installations, flights, vessels) with the camera fixed on the area |
| Save and present a view | Director scenes, with case data included only on request |
| Ask questions in natural language | MCP and voice tools (below) |

The "context" action is what keeps heavy layers fast: CCTV's cold activation
is about 20 seconds in the baseline, so the workbench never turns it on
globally; it only turns it on while the camera is already close to an area.

### 7. MCP and voice tools

New tools in `src/tools/queries/osint.js`, composed through `composeCatalog`
and gated by `requires: ['osint']`, so they disappear when no bridge is set:

- `osint_cases` (query): list cases.
- `osint_entities` (query): entities in a case, filtered by type, area,
  confidence or text.
- `osint_entity` (query): one entity with its links and observations.
- `osint_run` (action): start a job. Off on the voice surface by default in
  `src/tools/surfaces.js`, and on MCP it should require the client's
  confirmation, because it sends a selector to third-party services.

Case data reaches a model only through these tools, when the user asks.

## Tool routing

Which tools run by default for each selector type. Users can tick others.

| Selector | Default tools | Optional | Map output |
| --- | --- | --- | --- |
| Username | Maigret, Sherlock | SpiderFoot, sn0int | Only when a profile states a location (geocoded, `city` at best) |
| Email | h8mail, GHunt (Gmail), theHarvester (its domain) | SpiderFoot, DataSploit (legacy) | GHunt Maps reviews give `exact` places |
| Phone | PhoneInfoga | SpiderFoot | `country` or `region` outline |
| Domain | theHarvester, SpiderFoot | Recon-ng, sn0int, ReconDog (legacy), DataSploit (legacy) | Hosts and IPs, via IP geolocation |
| IP or netblock | Shodan | SpiderFoot, Recon-ng | Shodan coordinates, `city` precision |
| Area on the map | Shodan `geo:` search | Recon-ng location modules | Hosts and pushpins in the area |
| Person name or address | SpiderFoot | Skiptracer (legacy), LittleBrother (legacy) | Geocoded addresses |

SpiderFoot overlaps most of the others. It is used for broad scans; the
dedicated tools run directly when the user wants one fast answer. The
entity hash removes duplicates between them.

## Performance budget

- **Startup:** no change. The layer module is constructed with the catalog
  but makes no requests and creates no primitives until it is enabled; the
  Case panel template is hidden until opened.
- **Network:** one SSE connection per open case; bounding-box queries only on
  camera settle; nothing while the layer is off.
- **Rendering:** primitive collections and clustering keep a few thousand
  entities at the display's frame rate, in line with the datacenters
  baseline (4,362 features). Above the row cap the panel says how many are
  hidden rather than drawing them.
- **Server:** the GEV provider only relays and caches; all tool work runs in
  the sidecar. Bridge concurrency defaults to two jobs, so a scan cannot
  saturate the machine while the globe is in use.
- **Heavy existing layers:** enabled only through the scoped "context"
  action, never by a case automatically.

## Keeping the interface clean

- **Progressive disclosure.** With no bridge configured, the app is unchanged.
  With a bridge but no case open, the only additions are the Investigation
  group heading and a Case panel button.
- **One place for each job.** The map shows where; the Case panel shows what
  and who; existing panels keep their current roles.
- **A workspace preset.** "Investigate" collapses the Movement, Weather and
  Events groups and opens the Case panel; "Explore" restores today's layout.
  It is a saved panel arrangement, not a separate mode with its own rules.
- **Honest states.** Every tool chip shows ready, missing key, missing
  binary, broken or rate-limited, with the fix, matching how layers already
  report `keyRequired`.

## Privacy and safety for personal use

- The bridge and GEV both bind to loopback. The compose file must not
  publish the bridge port beyond `127.0.0.1`.
- Case stores are plain local files; deleting a case deletes its directory.
- Case data is excluded from share links, layer-state persistence and logs.
- Tools that scrape people-search sites (Skiptracer, LittleBrother) and
  breach lookups (h8mail) touch data with legal limits on use in many
  places; they stay off by default.

## Implementation phases

Each phase leaves the app shippable and passes `npm test`,
`npm run check:boundaries`, `npm run layer-token:check` and `npm run build`.

1. **Schema and bridge.** The entity schema, normalizer, SQLite store, job
   queue and adapters for SpiderFoot, Shodan and theHarvester. A
   `bridge export --geojson` command makes results usable immediately
   through the existing GeoJSON import, before any GEV change.
2. **GEV plumbing.** `server/providers/osint/`, `src/sources/osint.js`, the
   key-registry entry and contract tests against recorded bridge responses.
3. **Layer and Case panel.** The local-only layer, precision rendering,
   clustering, the Investigation group and the Case panel.
4. **Remaining adapters.** Maigret, Sherlock, GHunt, PhoneInfoga, h8mail,
   Recon-ng and sn0int, then the legacy adapters behind their health checks.
5. **Integration.** Pivots, the "context" action, area-of-interest searches,
   scene export with explicit case data, and the MCP and voice tools.

# Casefile workbench design

Status: phase 1 (the bridge) implemented in [`casefile-bridge/`](../casefile-bridge/);
later phases are design. Scope: personal research use on one machine.

This document describes how God's Eye View (GEV) becomes the map and case
surface for a set of external research tools, without removing any existing
layer, slowing startup, or making the current interface harder to use.

Tools with adapters: SpiderFoot, theHarvester, Sherlock, Maigret and
PhoneInfoga. Recon-ng and sn0int are candidates for later adapters.

### Out of scope

The workbench does not include people-search scrapers that resolve a private
person's home address (Skiptracer, LittleBrother), breached-credential lookups
(h8mail, the people-search parts of DataSploit), Google-account profiling
(GHunt), or any action that switches on CCTV or ALPR cameras around a located
person. Combined with automatic geocoding onto the globe, those turn a research
tool into one for finding and watching a specific individual. ReconDog is
covered by theHarvester and SpiderFoot.

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
  value, so the same email found by theHarvester and SpiderFoot is
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
    "method": "geolite2"
  },
  "observations": [
    {
      "tool": "spiderfoot",
      "toolVersion": "4.0",
      "query": "203.0.113.7",
      "at": "2026-10-19T20:31:04Z",
      "confidence": 0.8,
      "raw": "runs/2026-10-19/spiderfoot-7c1e.json"
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

1. Coordinates in the tool output (SpiderFoot `PHYSICAL_COORDINATES`,
   theHarvester host rows that carry a latitude and longitude).
2. An address string, geocoded through GEV's existing `/api/geocode`
   (Nominatim). It is already serialized and cached, which respects the
   one-request-per-second policy.
3. An IP: a local GeoLite2 database if the user supplies one. Precision is never better than `city`.
4. A phone: country and, where libphonenumber knows it, region.
5. Nothing. The entity stays off the map and appears only in the case panel.

## Architecture

```
┌──────────────────────────── browser ────────────────────────────┐
│ existing layers / panels / voice     │  Case panel (right rail) │
│                                      │  research layer (catalog)   │
│            src/sources/casefile.js  (portable, no Cesium)          │
└───────────────────────────────┬─────────────────────────────────┘
                                │ /api/casefile/*  (same origin, SSE)
┌───────────────────────────────┴─────────────────────────────────┐
│ GEV server: server/providers/casefile/  (proxy, auth, caps, cache) │
│ MCP server: server/mcp  (adds casefile tools via src/tools)        │
└───────────────────────────────┬─────────────────────────────────┘
                                │ loopback HTTP + shared token
┌───────────────────────────────┴─────────────────────────────────┐
│ casefile-bridge sidecar (Python): job queue, adapters, normalizer, │
│ SQLite case store, raw-output archive                           │
│   adapters → spiderfoot · recon-ng · theHarvester · sherlock ·  │
│   maigret · phoneinfoga · sn0int                                │
└─────────────────────────────────────────────────────────────────┘
```

### 1. `casefile-bridge` sidecar

A separate process, ideally a second service in `compose.yaml`, published on
`127.0.0.1` only, like the existing GEV service.

Why it runs outside GEV:

- **Runtimes.** The tools are Python, Go (PhoneInfoga) and Rust (sn0int).
  GEV's Node server should not manage virtualenvs.
- **Licences.** Recon-ng, theHarvester, PhoneInfoga and sn0int
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
  `sherlock --print-found`, `maigret -J simple`,
  `phoneinfoga scan`, `sn0int` exports, and so on) rather than scraping
  terminal text.
- **Health checks.** Each adapter reports `ready`, `missing-binary`,
  `missing-key` or `broken`, with the reason. A tool that is not installed is
  shown with its state, never silently failing.
- **Jobs.** A queue with a global concurrency limit and a per-tool limit and
  rate. Each job has a state (`queued`, `running`, `done`, `failed`,
  `cancelled`), progress events and a hard timeout. Cancelling kills the
  process group.
- **Caching.** Results are cached by `(tool, tool version, normalized
  selector, options)` with a per-tool TTL, so re-running a pivot is instant
  and does not re-hit the upstream service.
- **Storage.** One SQLite file per case under `.gev-cache/casefile/` (already
  git-ignored with the rest of `.gev-cache`), with an R-tree index on
  `geo` for bounding-box queries. Raw outputs are kept as files beside it,
  referenced from observations.
- **Secrets.** Any API keys a tool needs live in the bridge's environment, never in the
  browser and never in case files. SMTP, SMS and OAuth secrets used for
  verified consent are the same: environment only, never in a response or a log.
- **Verified consent.** Sherlock, Maigret and PhoneInfoga do not run on an
  email, phone or username until that identifier has a verified consent
  record. The check is in the job queue and the HTTP API, and the adapter
  modules are unchanged. The flow and the record layout are in
  [Verified consent](#verified-consent).

### 2. GEV server provider: `server/providers/casefile/`

A new plugin added to `localProviderPlugins` in `server/providers/local.js`,
following the shape of `local-receivers.js`:

- The bridge URL comes only from `CASEFILE_BRIDGE_URL` and must pass the same
  loopback/RFC1918 rule (`src/data/tapAddress.js`). The browser never
  supplies an address.
- The provider adds the shared bridge token, enforces body-size and
  bounding-box caps, and relays:
  - `GET  /api/casefile/cases`, `POST /api/casefile/cases`
  - `GET  /api/casefile/cases/:id/entities?bbox=…&types=…&limit=…`
  - `GET  /api/casefile/cases/:id/entities/:entityId` (detail, observations,
    links)
  - `POST /api/casefile/cases/:id/jobs` (selector, tools, options)
  - `DELETE /api/casefile/jobs/:jobId`
  - `GET  /api/casefile/cases/:id/events` (one Server-Sent Events stream for job
    progress and new entities)
  - `GET  /api/casefile/tools` (adapter health)
- When `CASEFILE_BRIDGE_URL` is unset, every route answers `unavailable` and the
  layer row shows a setup hint. GEV behaves exactly as it does today.

A `casefile-bridge` entry in the key registry (`src/keySetupCore.mjs`) gives it
the same Provider Settings guidance as other optional services, naming
`CASEFILE_BRIDGE_URL` and `CASEFILE_BRIDGE_TOKEN`.

### 3. Portable source: `src/sources/casefile.js`

The browser and MCP clients share one source factory,
`createCasefileSource({ fetchImpl })`, with `listCases`, `queryEntities(bbox,
filter)`, `getEntity`, `startJob`, `cancelJob` and `subscribe(caseId)`.
It reaches no Cesium, Node or browser globals, so it can be a package export
listed in `scripts/package-boundaries.json`, like the other sources.

### 4. The research layer: `src/layers/casefile/`

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
| Area of interest | The draw and region tools in `src/annotations/` define an area, which becomes a map filter |
| Address to coordinates | `/api/geocode` and the composed place search |
| Context around a location | A one-click "context" action enables chosen existing layers (CCTV, ALPR, installations, flights, vessels) with the camera fixed on the area |
| Save and present a view | Director scenes, with case data included only on request |
| Ask questions in natural language | MCP and voice tools (below) |

The "context" action is what keeps heavy layers fast: CCTV's cold activation
is about 20 seconds in the baseline, so the workbench never turns it on
globally; it only turns it on while the camera is already close to an area.

### 7. MCP and voice tools

New tools in `src/tools/queries/casefile.js`, composed through `composeCatalog`
and gated by `requires: ['casefile']`, so they disappear when no bridge is set:

- `casefile_cases` (query): list cases.
- `casefile_entities` (query): entities in a case, filtered by type, area,
  confidence or text.
- `casefile_entity` (query): one entity with its links and observations.
- `casefile_run` (action): start a job. Off on the voice surface by default in
  `src/tools/surfaces.js`, and on MCP it should require the client's
  confirmation, because it sends a selector to third-party services.

Case data reaches a model only through these tools, when the user asks.

## Tool routing

Which tools run by default for each selector type. Users can tick others.

| Selector | Default tools | Optional | Map output |
| --- | --- | --- | --- |
| Username | Maigret, Sherlock | SpiderFoot, sn0int | Only when a profile states a location (geocoded, `city` at best) |
| Email | theHarvester (its domain) | SpiderFoot | Only through linked hosts or addresses |
| Phone | PhoneInfoga | SpiderFoot | `country` or `region` outline |
| Domain | theHarvester, SpiderFoot | Recon-ng, sn0int | Hosts and IPs, via IP geolocation |
| IP or netblock | SpiderFoot | Recon-ng | GeoLite2, `city` precision |
| Organization or address | SpiderFoot | | Geocoded addresses |

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
- People-search, breach-lookup and account-profiling tools are out of
  scope (see above).

## Verified consent

Sherlock, Maigret and PhoneInfoga may run on an email address, a phone number
or a username only after the person who controls that identifier has proved
it. SpiderFoot, and theHarvester on a domain, host or IP, are unchanged and
do not ask for consent. A client can stay anonymous: the record has no name
and no contact field.

The office flow is one data package. The client hands over a batch of their
own identifiers. The case opens one verification per identifier and sends
every code at the same time. The client confirms each code on their own
phone, and staff type the codes in. Confirming one identifier does not
verify any other. The method is chosen per identifier.

### Proof of control

The challenge goes to the identifier itself. The bridge will not deliver it
to any other address or number, and it will not accept a staff attestation
or one alternate contact as proof for several identifiers.

| Identifier | Method | Proof |
| --- | --- | --- |
| Email | `email_code` | A one-time code sent to that address over SMTP |
| Phone | `sms_code` | An SMS code sent to that number |
| Username | `profile_code` | The client posts a generated code on that public profile. The bridge fetches the profile and checks that the code is there. This method is always available |
| Username | `oauth` | The client signs in with an OAuth provider configured on the server, where that is practical |

OAuth is a pluggable `OAuthProvider`. No provider is enabled until the server
environment names one. Profile-code does not depend on it. SMS is a pluggable
sender with a console implementation for local development and tests. Codes
are single-use, expire after 15 minutes, are rate-limited (five sends per
identifier per hour, five confirm attempts), and are compared in constant time.

`POST /api/cases/:id/verifications` with `{identifiers: [{type, value, method, tools?, platform?}]}`
creates the batch and returns a checklist. Each entry is `pending`,
`verified`, `expired` or `locked`. Email and SMS codes are not in that
response; the profile code and the OAuth URL are, because the client needs
them. `POST /api/cases/:id/verifications/:id/confirm` completes one row.
`GET /api/cases/:id/consents` lists consent records.
`POST /api/cases/:id/consents/:id/revoke` sets `revoked_at`.

### Consent record

One row per verified identifier, in the bridge's `consent.sqlite`. The raw
identifier is not stored. The pending verification row keeps the identifier
the client just handed over so the checklist can be matched to the package
and a profile fetch knows which username to read. That value is not copied
onto the consent record.

| Field | Meaning |
| --- | --- |
| `id` | `cns_` and 12 hex characters |
| `case_id` | Case the consent belongs to |
| `identifier_hash` | HMAC-SHA256 of the type and the normalized identifier, keyed with `CASEFILE_CONSENT_SALT`. Usernames are folded before hashing |
| `identifier_type` | `email`, `phone` or `username` |
| `method` | `email_code`, `sms_code`, `profile_code` or `oauth` |
| `verified_at` | When the challenge was accepted |
| `tools` | Subset of `sherlock`, `maigret`, `phoneinfoga` that this consent allows |
| `expires_at` | Consent lifetime, 24 hours from verification |
| `revoked_at` | Null while the consent is live |

A lookup is allowed only when a row for that case and identifier hash is
verified, `expires_at` is still in the future, `revoked_at` is null, and the
tool is in `tools`. Normalization matches the entity schema, so
`Owner@Example.com` and `owner@example.com` are one identifier.

### Audit log

Every gated lookup writes one append-only row, allowed or refused. The job
is checked when it is accepted and again when it starts, so a consent
revoked while the job is queued still fails and is audited. Updates and
deletes on this table are rejected.

| Field | Meaning |
| --- | --- |
| `consent_id` | Consent row used for the decision, or null when none applies |
| `tool` | `sherlock`, `maigret` or `phoneinfoga` |
| `at` | Time of the attempt |
| `result` | `allowed` or `refused` |

The case id is stored beside those fields so the shared log can be filtered.
The selector is not stored.

### Enforcement

The HTTP server and the job runner both refuse a Sherlock, Maigret or
PhoneInfoga job that lacks a valid consent. The response is HTTP 403 and
names the tool and the reason (`no verified consent`, `consent has expired`,
`consent has been revoked`, `consent does not cover <tool>`). No job from
that request is queued, and the tool is not started. A request that only
names SpiderFoot or theHarvester is accepted as before.

## Implementation phases

Each phase leaves the app shippable and passes `npm test`,
`npm run check:boundaries`, `npm run layer-token:check` and `npm run build`.

1. **Schema and bridge.** The entity schema, normalizer, SQLite store, job
   queue and adapters for SpiderFoot, theHarvester, Sherlock, Maigret and PhoneInfoga. A
   `bridge export --geojson` command makes results usable immediately
   through the existing GeoJSON import, before any GEV change.
2. **GEV plumbing.** `server/providers/casefile/`, `src/sources/casefile.js`, the
   key-registry entry and contract tests against recorded bridge responses.
3. **Layer and Case panel.** The local-only layer, precision rendering,
   clustering, the Investigation group and the Case panel.
4. **Remaining adapters.** Recon-ng and sn0int.
5. **Integration.** Pivots, the "context" action, area-of-interest searches,
   scene export with explicit case data, and the MCP and voice tools.

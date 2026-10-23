# Casefile bridge

A local sidecar for God's Eye View. It runs research tools, normalizes their
output into one schema (entities, observations and links), stores it per case,
and serves it to the globe. It never talks to the browser directly — the GEV
server relays to it — and it binds `127.0.0.1` only.

This is the engine behind the Casefile layer and panel described in
[`../docs/CASEFILE.md`](../docs/CASEFILE.md).

## What it does

- **One schema.** Every tool's output becomes entities (`email`, `ip`, `domain`,
  `username`, `account`, `phone`, `person`, `address`, …) with observations
  (which tool, when, confidence, raw output) and links between them. The same
  email found by three tools is one entity, because the entity ID is a hash of
  its type and normalized value.
- **Geography is explicit.** Each located entity states its precision
  (`exact`, `address`, `street`, `city`, `region`, `country`). Coarse
  precisions are drawn as circles or outlines, not fake pins. Entities with no
  location stay off the map and live in the Case panel.
- **Nothing runs until asked.** Tools run as jobs in a bounded worker pool with
  per-tool rate limits and result caching. Cancelling a job kills the tool and
  its children.

## Install

The core needs only Python 3.10+ (standard library). Optional extras improve
geographic precision:

```sh
cd casefile-bridge
python -m venv .venv && . .venv/bin/activate
pip install -e '.[geo,dev]'     # geo = phonenumbers + geoip2; dev = pytest
```

Install the research tools you want on your PATH (each is a separate project
under its own licence): SpiderFoot, theHarvester, Sherlock, Maigret,
PhoneInfoga. The bridge reports which ones it can find.

theHarvester 5.x needs Python 3.14 and is not the `theHarvester` package on
PyPI (that is a 0.0.1 placeholder). Install it from source into its own
environment and point the bridge at it:

```sh
git clone --depth 1 https://github.com/laramies/theHarvester
uv venv -p 3.14 ~/.venvs/theharvester
VIRTUAL_ENV=~/.venvs/theharvester uv pip install ./theHarvester
export CASEFILE_THEHARVESTER_BIN=~/.venvs/theharvester/bin/theHarvester
```

Verified against theHarvester 5.0.0: a keyless run on `example.com` returns
about 500 hosts and 500 IPs in under ten seconds.

## Run

```sh
# Serve the API (loopback only). The token is shared with the GEV server.
export CASEFILE_BRIDGE_TOKEN=$(openssl rand -hex 16)
python -m casefile serve --port 7733
```

Then point God's Eye View at it:

```sh
# in the GEV .env
CASEFILE_BRIDGE_URL=http://127.0.0.1:7733
CASEFILE_BRIDGE_TOKEN=<same token>
```

### Without the app

You can use a case before touching GEV. Export its geographic findings as
GeoJSON and drop the file into GEV's existing import (it accepts `.geojson`):

```sh
python -m casefile cases
python -m casefile export case_xxxxxxxxxxxx -o case.geojson --pretty
```

## HTTP API

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/health` | Liveness (no token) |
| GET | `/api/tools` | Adapter health and default routing |
| GET/POST | `/api/cases` | List or create a case |
| GET/DELETE | `/api/cases/:id` | Describe or delete a case |
| GET | `/api/cases/:id/entities` | Entities, filtered by `bbox`, `types`, `minConfidence`, `text`, `limit` |
| GET | `/api/cases/:id/entities/:entityId` | One entity with observations and links |
| POST | `/api/cases/:id/entities/:entityId/flags` | `{hidden, verified}` |
| GET/POST | `/api/cases/:id/jobs` | List or start jobs `{selector, tools?, selectorType?}`. Sherlock, Maigret and PhoneInfoga return 403 without verified consent |
| POST | `/api/cases/:id/verifications` | Data package: one pending verification per identifier |
| GET | `/api/cases/:id/verifications` | Checklist of those verifications |
| POST | `/api/cases/:id/verifications/:id/confirm` | `{code}` or `{oauthCode, state}` |
| GET | `/api/cases/:id/consents` | Anonymous consent records for the case |
| POST | `/api/cases/:id/consents/:id/revoke` | Revoke one consent |
| DELETE | `/api/jobs/:jobId` | Cancel a job |
| GET | `/api/cases/:id/events` | Server-Sent Events: job progress and new entities |
| GET | `/api/cases/:id/export.geojson` | Case as GeoJSON |

## Environment

| Variable | Meaning |
| --- | --- |
| `CASEFILE_STORE` | Case store directory (default `./.gev-cache/casefile`) |
| `CASEFILE_BRIDGE_TOKEN` | Shared token required in `X-Casefile-Token` |
| `GEV_URL` | God's Eye View base URL for address geocoding (default `http://127.0.0.1:4173`) |
| `CASEFILE_GEOLITE2_DB` | Path to a local GeoLite2-City database for IP geolocation |
| `CASEFILE_<TOOL>_BIN` | Override a tool's executable path |
| `CASEFILE_THEHARVESTER_SOURCES` | theHarvester sources (default: keyless set) |
| `CASEFILE_CONSENT_SALT` | HMAC key for identifier hashes. Required before a gated lookup or a verification |
| `CASEFILE_SMTP_HOST` | SMTP host for email codes |
| `CASEFILE_SMTP_PORT` | SMTP port (default `587`; `465` uses implicit TLS) |
| `CASEFILE_SMTP_USER` | SMTP username |
| `CASEFILE_SMTP_PASSWORD` | SMTP password. Never logged or returned |
| `CASEFILE_SMTP_FROM` | From address for email codes |
| `CASEFILE_SMS_PROVIDER` | SMS provider id. `console` (the default) is the dev and test implementation |
| `CASEFILE_OAUTH_PROVIDERS` | Comma-separated OAuth provider ids, for example `github` |
| `CASEFILE_OAUTH_REDIRECT_URI` | Redirect URI sent to those providers |
| `CASEFILE_OAUTH_<NAME>_CLIENT_ID` | OAuth client id (`<NAME>` is the provider id in upper case) |
| `CASEFILE_OAUTH_<NAME>_CLIENT_SECRET` | OAuth client secret. Never logged or placed on the authorization URL |
| `CASEFILE_OAUTH_<NAME>_AUTHORIZE_URL` | Authorization endpoint |
| `CASEFILE_OAUTH_<NAME>_TOKEN_URL` | Token endpoint |
| `CASEFILE_OAUTH_<NAME>_USERINFO_URL` | Userinfo endpoint |
| `CASEFILE_OAUTH_<NAME>_USER_FIELD` | JSON field holding the username (default `login`) |

Sherlock, Maigret and PhoneInfoga run on an email, phone or username only
after a verified consent for that identifier. The flow and the consent and
audit records are described in [`../docs/CASEFILE.md`](../docs/CASEFILE.md).

## Tests

```sh
python -m pytest
```

Adapter tests feed recorded tool output through `normalize()`, so they do not
require the tools to be installed.

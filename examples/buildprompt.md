# AI Build Prompt

## Persona
You are an expert in Docker, Python, PostgreSQL, and MikroTik RouterOS scripting.

## Task
Build a full Dockerized application called **Mikrotik Whitelist Service**.

**Languages used:**
- Python (`.py`)
- PostgreSQL SQL (`.sql`)
- Bash/Shell (`.sh`)
- MikroTik RouterOS 7 scripting (`.rsc`)

Also create:
- `readme.md` — describes what the application does and references `install.md`
- `install.md` — step-by-step Docker install instructions for someone new to Docker

---

### Scope Notes
This is an **internal-only service**, not exposed to the internet. No web authentication or role-based access control is required.

Allow/deny overlap handling (when a CIDR appears in both a whitelist and a blacklist) is delegated entirely to the MikroTik router's own firewall policy. The application does not detect, flag, or resolve overlaps.

IP list source content is trusted. No geographic verification or content validation is required at MVP.

---

## Requirements

### Docker

Provide a `.env` file and a sanitized `.env.example` in the `examples/` folder. The `.env` file must be listed in `.gitignore`.

`.env` variables required:
- `POSTGRES_USER`
- `POSTGRES_PASSWORD`
- `POSTGRES_HOST`
- `POSTGRES_PORT`
- `POSTGRES_DATABASE`
- `ENCRYPTION_KEY` — AES-256 key used to encrypt/decrypt firewall secrets at the application layer; generate with `openssl rand -hex 32`
- `FETCH_TIMEOUT_SECONDS` (default: `30`)
- `FETCH_RETRIES` (default: `3`)
- `APPLY_TIMEOUT_SECONDS` (default: `60`)
- `LOG_LEVEL` (default: `INFO`)

Use **PostgreSQL 18**. PostgreSQL data must be stored in a named Docker volume to persist between restarts.

Docker Compose must define services in the following startup order using health checks:
1. `postgres` — health check: `pg_isready`
2. `api` — depends on `postgres` being healthy; runs `alembic upgrade head` before starting the web server
3. `fetcher` — depends on `postgres` being healthy
4. `applicator` — depends on `postgres` being healthy

All services must write **structured JSON logs** using `python-json-logger` or equivalent. Log level is configurable via `LOG_LEVEL`.

Named Docker volumes:
- `postgres_data` — PostgreSQL data directory
- `rawiplists` — stores raw downloaded IP list files

---

### Postgres Database

- **Database name:** `mikrotik`
- **Schema name:** `iplist`
- Managed with **Alembic** (SQLAlchemy models). All migrations must be timestamped.
- `alembic upgrade head` runs automatically at `api` startup before the server accepts requests.

#### Naming Convention
Use **camelCase** for all table and column names in ORM models, migrations, and the API layer. Database column names match exactly (e.g. `flagInactive`, `lastSync`, `iplistsId`).

#### Standard Fields (every table must include all four)
- `id` — BigInteger, primary key, sequential auto-increment (not random), not null
- `createDate` — Timestamp with timezone, default `now()` on insert, not null
- `updateDate` — Timestamp with timezone, automatically updated on every row update via a PostgreSQL trigger, not null
- `flagInactive` — SmallInt, not null, default `0` — `0` = active, `1` = inactive

Every table must have an index on `flagInactive ASC`.

---

#### Table: `iplists`
Standard fields plus:
- `url` — Text, not null
- `flagBlacklist` — SmallInt, not null, default `0` — `0` = allow/whitelist, `1` = deny/blacklist
- `description` — Text, nullable
- `comment` — Text, nullable
- `lastSync` — Timestamp with timezone, nullable — updated to `now()` only after a fully successful fetch and DB load; never updated on failure
- `fetchFrequencyHours` — Integer, not null, default `0` — scheduling interval in hours; `0` = do not auto-schedule

---

#### Table: `ipAddresses`
Standard fields plus:
- `ipAddress` — Text, not null — one IPv4 address or CIDR per row (e.g. `1.2.3.4` or `1.2.3.0/24`)
- `iplistsId` — BigInteger, not null, foreign key → `iplists.id`

Composite index on `(iplistsId, flagInactive)`.

Database cascade: when an `iplists` row is deleted, all `ipAddresses` rows with matching `iplistsId` must be deleted automatically (CASCADE or trigger).

---

#### Table: `firewallTypes`
Standard fields plus:
- `firewallTypeDescription` — Text, not null

---

#### Table: `firewalls`
Standard fields plus:
- `firewallAddress` — Text, not null — hostname or IP of the firewall
- `firewallPort` — Integer, not null
- `firewallUser` — Text, not null
- `firewallSecret` — Text, not null — stored AES-256 encrypted using `ENCRYPTION_KEY`; only the Applicator Service decrypts this at runtime, in memory only, never persisted or logged in plaintext
- `firewallTypeId` — BigInteger, not null, foreign key → `firewallTypes.id`
- `applyFrequencyHours` — Integer, not null, default `0` — how often to push to this firewall in hours; `0` = do not auto-schedule

---

#### Table: `configuration`
Standard fields plus:
- `configurationItem` — Text, not null — short key name
- `configurationHelp` — Text, nullable — human-readable description
- `configurationItemValue` — Text, nullable — the value

Seed the following rows in an Alembic data migration on first run:

| configurationItem | configurationHelp | configurationItemValue |
|---|---|---|
| `fetcherEnabled` | Whether the scheduled fetcher is running | `0` |
| `applicatorEnabled` | Whether the scheduled applicator is running | `0` |
| `applicatorTTLDays` | Days MikroTik dynamic address-list entries stay active | `7` |

---

#### Table: `fetchJobs`
Standard fields plus:
- `iplistsId` — BigInteger, not null, foreign key → `iplists.id`
- `status` — Text, not null — one of: `pending`, `fetching`, `parsing`, `loading`, `complete`, `failed`
- `startedAt` — Timestamp with timezone, nullable
- `completedAt` — Timestamp with timezone, nullable
- `errorMessage` — Text, nullable
- `entriesParsed` — Integer, nullable — count of valid entries parsed from the raw file
- `entriesLoaded` — Integer, nullable — count of rows inserted into `ipAddresses`

Index on `(iplistsId, status)`.

---

#### Table: `fetchErrors`
Standard fields plus:
- `iplistsId` — BigInteger, not null, foreign key → `iplists.id`
- `attempt` — Integer, not null — which retry attempt (1-based)
- `errorMessage` — Text, not null
- `occurredAt` — Timestamp with timezone, not null, default `now()`

Index on `(iplistsId, occurredAt DESC)`.

---

#### Table: `applyHistory`
Standard fields plus:
- `firewallsId` — BigInteger, not null, foreign key → `firewalls.id`
- `status` — Text, not null — one of: `pending`, `generating`, `pushing`, `complete`, `failed`
- `startedAt` — Timestamp with timezone, nullable
- `completedAt` — Timestamp with timezone, nullable
- `whitelistHash` — Text, nullable — SHA-256 of the sorted consolidated whitelist CIDR set
- `blacklistHash` — Text, nullable — SHA-256 of the sorted consolidated blacklist CIDR set
- `whitelistCount` — Integer, nullable — number of consolidated whitelist CIDRs
- `blacklistCount` — Integer, nullable — number of consolidated blacklist CIDRs
- `errorMessage` — Text, nullable

Index on `(firewallsId, startedAt DESC)`.

---

### HTTP/HTTPS Fetcher Service

Fetches IP lists from URLs in the `iplists` table and loads them into `ipAddresses`.

#### Scheduling
- On startup, read all `iplists` where `flagInactive = 0` and `fetchFrequencyHours > 0`.
- Schedule each list independently at its own interval.
- Re-read `iplists` on every scheduling cycle to detect newly activated or deactivated lists; do not cache the schedule indefinitely in memory.
- Lists with `flagInactive = 1` are never fetched.
- Lists with `fetchFrequencyHours = 0` are never auto-scheduled (manual trigger only).

#### Fetch Lifecycle (per list)
1. Insert a `fetchJobs` row: `status = 'fetching'`, `startedAt = now()`.
2. Download the URL to `rawiplists/<iplists.id>.iplist`, replacing any existing file.
3. On download failure: insert a `fetchErrors` row with the error and attempt number. Retry up to `FETCH_RETRIES` times with exponential backoff. After all retries are exhausted, set `fetchJobs.status = 'failed'`, `errorMessage`, `completedAt`. Do **not** update `iplists.lastSync`. Stop.
4. Set `fetchJobs.status = 'parsing'`.
5. Parse the file line by line:
   - Strip whitespace. Skip blank lines and comment lines (`#` or `;` prefixed).
   - Accept plain IPv4 (`1.2.3.4` → treat as `/32`) and CIDR notation (`1.2.3.0/24`).
   - Skip and log any non-IPv4 or malformed lines.
   - Record `entriesParsed` count.
6. Set `fetchJobs.status = 'loading'`.
7. In a single database transaction:
   - Delete all existing `ipAddresses` rows for this `iplistsId`.
   - Bulk-insert the newly parsed entries.
   - Set `iplists.lastSync = now()`.
   - Set `fetchJobs.status = 'complete'`, `completedAt = now()`, `entriesLoaded = <count>`.
   - On transaction failure: roll back entirely; set `fetchJobs.status = 'failed'`, `errorMessage`. Do **not** update `lastSync`.
8. Log a structured entry: list id, URL, `entriesParsed`, `entriesLoaded`, duration, status.

#### Manual Trigger API
Expose internal HTTP endpoints callable by the UI:
- `POST /internal/fetch/all` — immediate fetch of all active lists
- `POST /internal/fetch/{iplistsId}` — immediate fetch of one specific list

---

### Firewall Policy Applicator Service

Generates MikroTik RouterOS address-list scripts and pushes them to each configured firewall.

#### Scheduling
- On startup, read all `firewalls` where `flagInactive = 0` and `applyFrequencyHours > 0`.
- Schedule each firewall independently at its own interval.
- Re-read `firewalls` on every scheduling cycle.
- Firewalls with `flagInactive = 1` or `applyFrequencyHours = 0` are never auto-scheduled.

#### CIDR Consolidation (pre-apply, runs before every apply)
1. Query all `ipAddresses.ipAddress` values where `ipAddresses.flagInactive = 0` and the joined `iplists.flagInactive = 0`, split into two sets:
   - **Whitelist set**: joined `iplists.flagBlacklist = 0`
   - **Blacklist set**: joined `iplists.flagBlacklist = 1`
2. For each set, run CIDR consolidation using Python's `ipaddress.collapse_addresses()`. This merges overlapping and adjacent ranges into the minimum covering set — for example, `10.0.0.0/8` absorbs any more-specific prefix within it.
3. Compute SHA-256 of the sorted consolidated whitelist and blacklist CIDR strings.
4. Hold results in memory (not in a permanent table).

#### Idempotency
Before pushing to a firewall, compare the new `whitelistHash` and `blacklistHash` against the `whitelistHash` and `blacklistHash` on the most recent `applyHistory` row for that firewall with `status = 'complete'`. If both hashes are identical, skip the push and log that nothing changed. The "Apply Now" manual trigger bypasses this check.

#### Apply Lifecycle (per firewall)
1. Insert an `applyHistory` row: `status = 'pending'`, `startedAt = now()`, hashes and counts populated.
2. Set `applyHistory.status = 'generating'`.
3. Generate two RouterOS scripts in memory:
   - `ip-whitelist-dynamic.rsc` — removes the existing `ip-whitelist-dynamic` address list from the device, then adds each consolidated whitelist CIDR as `/ip firewall address-list add list=ip-whitelist-dynamic address=<cidr> timeout=<N>d`
   - `ip-blacklist-dynamic.rsc` — same pattern for `ip-blacklist-dynamic`
   - TTL timeout is read from `configuration` where `configurationItem = 'applicatorTTLDays'`.
   - Entries are added with a `timeout` value so they are dynamic (memory-only on MikroTik, not written to disk). This is intentional.
   - If a list exceeds 500 entries, split into multiple script chunks of 500 each to avoid SSH/execution timeouts.
4. Set `applyHistory.status = 'pushing'`.
5. Connect to the firewall via SSH (use `paramiko`). Decrypt `firewallSecret` in memory using `ENCRYPTION_KEY`. Never log or write the decrypted value anywhere.
6. Push and execute the whitelist script, then the blacklist script.
7. On success: set `applyHistory.status = 'complete'`, `completedAt = now()`.
8. On failure: set `applyHistory.status = 'failed'`, `errorMessage`. Retry up to `FETCH_RETRIES` times with backoff. Log failure without including the decrypted secret.
9. Log a structured entry: firewall id, address, whitelist count, blacklist count, duration, status.

#### Manual Trigger API
Expose internal HTTP endpoints callable by the UI:
- `POST /internal/apply/all` — immediate apply to all active firewalls (skip idempotency check)
- `POST /internal/apply/{firewallsId}` — immediate apply to one specific firewall (skip idempotency check)

---

### Control UI (Web/HTTP)

A web UI served by the `api` service. Internal-only; no authentication required.

Use FastAPI with Jinja2 templates, or Flask. Front-end should be clean and functional — Bootstrap or equivalent is acceptable.

---

#### Page: Configuration

**Fetcher Service Control section:**
- Toggle switch: Fetcher On/Off — reads/writes `configurationItemValue` for `configurationItem = 'fetcherEnabled'`. Default off.
- Button: "Fetch Now" — calls `POST /internal/fetch/all`.

**Firewall Applicator Service Control section:**
- Toggle switch: Applicator On/Off — reads/writes `configurationItem = 'applicatorEnabled'`. Default off.
- Number input: TTL Days — reads/writes `configurationItem = 'applicatorTTLDays'`.
- Button: "Apply Now" — calls `POST /internal/apply/all` (bypasses idempotency check).

All values are read from `configuration` on page load; saved back to `configuration` on form submit.

---

#### Page: IP Lists

All rows from `iplists`, sorted by `id`.

**Read-only (display only):** `id`, `createDate`, `updateDate`, `lastSync`

**Editable inline (one Save button per row):**
- `flagInactive` — checkbox (checked = inactive)
- `url` — text input
- `flagBlacklist` — dropdown: `0 = Whitelist / Allow`, `1 = Blacklist / Deny`
- `description` — text input
- `comment` — text input
- `fetchFrequencyHours` — number input

**Per-row actions:**
- **Save** — commits that row's changes to the database
- **Fetch Now** — calls `POST /internal/fetch/{id}` for this row
- **Delete** — deletes the row after a confirmation prompt; cascades to `ipAddresses`

**Page-level actions:**
- **Add New** — inline form to create a new `iplists` row; on save, calls `POST /internal/fetch/{new_id}` automatically
- **Fetch All** — calls `POST /internal/fetch/all`

**Status indicator per row:** Show the `status` and `errorMessage` from the most recent `fetchJobs` row for this `iplistsId`.

---

#### Page: Firewalls

All rows from `firewalls`, sorted by `id`.

**Read-only (display only):** `id`, `createDate`, `updateDate`

**Editable inline (one Save button per row):**
- `flagInactive` — checkbox
- `firewallAddress` — text input
- `firewallPort` — number input
- `firewallUser` — text input
- `firewallSecret` — password input (write-only; never display the stored value; on save, re-encrypt with `ENCRYPTION_KEY` before storing)
- `applyFrequencyHours` — number input
- `firewallTypeId` — dropdown populated from all active `firewallTypes` rows

**Per-row actions:**
- **Save** — commits changes to the database
- **Apply Now** — calls `POST /internal/apply/{id}` for this row (bypasses idempotency check)
- **Delete** — removes the row after a confirmation prompt

**Page-level actions:**
- **Add New** — inline form to create a new `firewalls` row
- **Apply All** — calls `POST /internal/apply/all`

**Status indicator per row:** Show `status` and `startedAt` from the most recent `applyHistory` row for this `firewallsId`.

---

#### Page: Status & Logs

**Fetch Jobs section:**
- Table of the 100 most recent `fetchJobs` rows, sorted by `startedAt DESC`.
- Columns: `id`, `iplistsId`, `status`, `startedAt`, `completedAt`, `entriesParsed`, `entriesLoaded`, `errorMessage`
- Filter by `iplistsId` and/or `status`.

**Apply History section:**
- Table of the 100 most recent `applyHistory` rows, sorted by `startedAt DESC`.
- Columns: `id`, `firewallsId`, `status`, `startedAt`, `completedAt`, `whitelistCount`, `blacklistCount`, `errorMessage`
- Filter by `firewallsId` and/or `status`.

---

## Optional Feature: GeoIP Source Support

> **Not required for MVP.** Implement this as a separate, clearly isolated feature after the core pipeline works end-to-end.

This feature allows IP lists to be built from well-known geolocation IP databases (ipdeny.com or MaxMind GeoLite2) by country code, then fed into the standard `iplists`/`ipAddresses` pipeline.

### Database Additions

**New column on `iplists`:**
- `sourceGeoRegion` — Text, nullable — optional ISO 3166-1 alpha-2 country code (e.g. `US`) tagging this list's intended geographic scope. Informational only.

**New table: `geoipSources`** (standard fields plus):
- `provider` — Text, not null — e.g. `ipdeny` or `maxmind`
- `countryCode` — Text, not null — ISO 3166-1 alpha-2
- `url` — Text, not null — URL for the country file
- `format` — Text, not null — `zone` (one CIDR per line) or `csv` (MaxMind GeoLite2 CSV)
- `lastFetched` — Timestamp with timezone, nullable

### GeoIP Fetch Behavior
- For `ipdeny` / `format = zone`: parse one CIDR per line; strip `#` comment lines.
- For `maxmind` / `format = csv`: parse `GeoLite2-Country-Blocks-IPv4.csv`; filter rows by target country's `geoname_id`. Requires `MAXMIND_LICENSE_KEY` in `.env`.
- In both cases: create or reuse a linked `iplists` record, then populate `ipAddresses` using the standard fetch pipeline. GeoIP sources simply act as an automated source for `iplists` entries.

### New `.env` Variable (GeoIP only)
- `MAXMIND_LICENSE_KEY` — required only if MaxMind sources are configured

### UI Additions (GeoIP feature)
- New page: **GeoIP Sources** — list/manage `geoipSources` rows (inline edit, save, delete, "Fetch Now" per row).
- On the IP Lists page: display `sourceGeoRegion` badge next to each list row if the value is set.

---

## Delivery

### MVP (implement first, in this order)
1. PostgreSQL schema — all tables, Alembic migrations, seed data, triggers, indexes
2. Fetcher Service — schedule, manual trigger, fetch lifecycle, error tracking
3. CIDR consolidation logic — whitelist and blacklist separately, using `ipaddress.collapse_addresses()`
4. Applicator Service — script generation, atomic apply, idempotency check, apply history
5. Control UI — all four pages (Configuration, IP Lists, Firewalls, Status & Logs)
6. Docker Compose — all four services, health checks, volumes, startup order
7. `.env.example` in `examples/`, `.gitignore` entries, `readme.md`, `install.md`

### Phase 2 (after MVP is working end-to-end)
- GeoIP source support (see Optional Feature section)
- Per-firewall SSH connectivity test button in the Firewalls UI
- Retention of generated `.rsc` script artifacts (store with hash reference for rollback/audit)
- Prometheus `/metrics` endpoint for external monitoring
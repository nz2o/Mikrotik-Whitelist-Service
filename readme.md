# Mikrotik Whitelist Service

A self-hosted Dockerized service that maintains dynamic IP address lists on MikroTik RouterOS 7 firewalls.

Instead of filtering at DNS level (like Pi-hole), this service operates at the **firewall/WAN address-list level**. It:

- **Fetches** IP block lists from configurable URLs (e.g. [ipdeny.com](https://www.ipdeny.com/ipblocks/) country zone files)
- **Consolidates** overlapping and adjacent CIDR ranges into the minimum covering set
- **Generates** RouterOS-compatible `.rsc` address-list scripts
- **Pushes** those scripts atomically to one or more MikroTik firewalls via SSH

A typical use case is allowing only traffic from a specific country (e.g. US-only WAN ingress) by maintaining a `ip-whitelist-dynamic` address list, or blocking known-bad IP ranges via `ip-blacklist-dynamic`. The router's own firewall rules decide how to use the lists — this service only manages the lists themselves.

---

## Features

| Feature | Detail |
|---|---|
| Multi-source IP lists | Separate allow / deny lists from any HTTP/HTTPS URL |
| CIDR consolidation | Uses Python `ipaddress.collapse_addresses()` — supernets absorb subnets |
| Atomic apply | Old address list is removed before new one is added in one RouterOS operation |
| Hash-based idempotency | Skips push if list content hasn't changed since last successful apply |
| Per-list fetch frequency | Each list has its own schedule (in hours); 0 = manual only |
| Per-firewall apply frequency | Each firewall has its own push schedule; 0 = manual only |
| Job tracking | Every fetch and apply is logged to the database with status and error details |
| Web UI | Bootstrap-based UI for configuration, IP list management, firewall management, and logs |
| Encrypted secrets | Firewall passwords are AES-256-GCM encrypted at rest; decrypted only in memory at apply time |

---

## Architecture

```
┌──────────────┐     ┌────────────────┐     ┌──────────────────┐
│   Fetcher    │────▶│   PostgreSQL   │◀────│    Applicator    │
│  (scheduler) │     │  (iplist schema│     │    (scheduler)   │
└──────────────┘     │   + volumes)   │     └──────────────────┘
                     └───────┬────────┘
                             │
                     ┌───────▼────────┐
                     │   FastAPI UI   │
                     │  (port 8000)   │
                     └────────────────┘
```

Four Docker services:
- **postgres** — PostgreSQL 18 with persistent volume
- **api** — FastAPI web UI + internal trigger endpoints; runs `alembic upgrade head` before starting
- **fetcher** — Scheduled download and DB load of IP lists
- **applicator** — Scheduled generation and SSH push of RouterOS scripts

---

## Quick Start

See [install.md](install.md) for full step-by-step instructions.

```bash
cp examples/.env.example .env
# Edit .env with your database password and encryption key
docker compose up -d
```

Open [http://localhost:8000](http://localhost:8000) in your browser.

---

## Configuration (`.env`)

| Variable | Description |
|---|---|
| `POSTGRES_USER` | PostgreSQL username |
| `POSTGRES_PASSWORD` | PostgreSQL password |
| `POSTGRES_HOST` | PostgreSQL host (use `postgres` inside Docker) |
| `POSTGRES_PORT` | PostgreSQL port (default `5432`) |
| `POSTGRES_DATABASE` | Database name (default schema is `iplist`) |
| `ENCRYPTION_KEY` | 64-character hex AES-256 key — generate with `openssl rand -hex 32` |
| `FETCH_TIMEOUT_SECONDS` | HTTP download timeout per request (default `30`) |
| `FETCH_RETRIES` | Download retry attempts before failing (default `3`) |
| `APPLY_TIMEOUT_SECONDS` | SSH command timeout per push (default `60`) |
| `LOG_LEVEL` | `DEBUG`, `INFO`, `WARNING`, or `ERROR` (default `INFO`) |

---

## How IP Lists Work

1. Add a list entry on the **IP Lists** page with a URL pointing to a plain-text file of IPv4 addresses or CIDR blocks (one per line).
2. Set `Type` to **Allow** (goes into `ip-whitelist-dynamic`) or **Deny** (`ip-blacklist-dynamic`).
3. Set a `Fetch Frequency` in hours, or leave at `0` for manual-only.
4. Click **Add & Fetch** — the fetcher downloads the list immediately and loads it into the database.

### Supported source formats

- One CIDR per line: `1.2.3.0/24`
- Plain IPv4 address (treated as `/32`): `1.2.3.4`
- Lines starting with `#` or `;` are treated as comments and skipped
- Inline `#` and `;` comments are stripped

[ipdeny.com](https://www.ipdeny.com/ipblocks/) `.zone` files and MaxMind GeoLite2 aggregated CIDR lists both work out of the box.

---

## RouterOS Address Lists

The applicator pushes two separate named address lists:

| List name | Source |
|---|---|
| `ip-whitelist-dynamic` | All active IPs from Allow lists, collapsed |
| `ip-blacklist-dynamic` | All active IPs from Deny lists, collapsed |

Entries are added with a `timeout` (TTL) so they are **dynamic** — stored in router RAM, not flash. The TTL resets on each apply. If the service stops applying, entries expire automatically after the configured TTL.

Allow/deny overlap handling is left to your MikroTik firewall rules — the service does not enforce precedence between the two lists.

---

## License

See [LICENSE](LICENSE).

---

## Disclaimer

- This project is provided **as-is**, with **no warranty** of any kind.
- You are responsible for implementing and maintaining appropriate security controls, including authentication, authorization, network segmentation, and access restrictions.
- This software was intended for **internal use in a home lab** environment.
- I am not responsible for any damage that occurs resulting from your use of this software.

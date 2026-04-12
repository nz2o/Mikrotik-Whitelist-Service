# Installation Guide

This guide walks you through setting up the Mikrotik Whitelist Service on any machine running Docker. No prior Docker experience required.

---

## Prerequisites

### 1. Install Docker Desktop (or Docker Engine + Compose)

**Linux (Ubuntu/Debian):**
```bash
sudo apt update
sudo apt install -y docker.io docker-compose-plugin
sudo systemctl enable --now docker
sudo usermod -aG docker $USER   # log out and back in after this
```

**macOS / Windows:**
Download and install [Docker Desktop](https://www.docker.com/products/docker-desktop/).

Verify Docker is working:
```bash
docker --version
docker compose version
```

### 2. Generate an Encryption Key

The service encrypts your firewall passwords at rest. You need a 64-character hex key:

**Linux / macOS:**
```bash
openssl rand -hex 32
```

**Windows (PowerShell):**
```powershell
[System.BitConverter]::ToString([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).Replace("-","").ToLower()
```

Copy the output — you'll paste it into `.env` in the next step.

---

## Installation

### Step 1 — Clone the repository

```bash
git clone https://github.com/nz2o/Mikrotik-Whitelist-Service.git
cd Mikrotik-Whitelist-Service
```

### Step 2 — Create your `.env` file

```bash
cp examples/.env.example .env
```

Open `.env` in a text editor and fill in your values:

```env
POSTGRES_USER=mikrotik
POSTGRES_PASSWORD=a-strong-password-here
POSTGRES_HOST=postgres
POSTGRES_PORT=5432
POSTGRES_DATABASE=mikrotik

ENCRYPTION_KEY=paste-your-64-char-hex-key-here

FETCH_TIMEOUT_SECONDS=30
FETCH_RETRIES=3
APPLY_TIMEOUT_SECONDS=60
LOG_LEVEL=INFO
```

> **Security note:** `.env` is listed in `.gitignore` and will never be committed to git. Do not share it.

### Step 3 — Start the services

```bash
docker compose up -d
```

Docker will:
1. Pull the PostgreSQL 18 image
2. Build the application image
3. Start all four services (postgres, api, fetcher, applicator)
4. Run database migrations automatically before the UI starts

### Step 4 — Open the web UI

Navigate to [http://localhost:8000](http://localhost:8000) in your browser.

The first time you open it you'll see the Configuration page. Leave everything at default (Off) until you've added your IP lists and firewalls.

---

## Adding Your First IP List

1. Click **IP Lists** in the left sidebar.
2. Click **Add New**.
3. Paste a URL — for example a US CIDR block list from ipdeny:
   ```
   https://www.ipdeny.com/ipblocks/data/countries/us.zone
   ```
4. Set **Type** to `Allow / Whitelist`.
5. Set **Fetch Frequency** to `24` (hours) for daily refresh.
6. Click **Add & Fetch** — it will begin downloading immediately.

You can watch progress on the **Status & Logs** page.

---

## Adding a Firewall

1. Click **Firewalls** in the left sidebar.
2. Click **Add New**.
3. Fill in your MikroTik router's LAN address, SSH port (default 22), SSH username, and password.
4. Set **Apply Frequency** to `0` for now (manual only) until you've verified things work.
5. Click **Add Firewall**.

---

## Pushing a Test Apply

1. Go to **Firewalls**.
2. Click the **Send** (apply) icon next to your firewall.
3. Go to **Status & Logs** to see the result.

If it succeeds, you'll see `complete` status. Log into your MikroTik and verify:

```routeros
/ip firewall address-list print where list=ip-whitelist-dynamic
```

---

## Enabling Automatic Scheduling

Once you're happy with manual operation:

1. Go to **Configuration**.
2. Enable **Auto-fetch** to start pulling IP lists on their configured schedules.
3. Enable **Auto-apply** to start pushing to firewalls on their configured schedules.
4. Click **Save**.

---

## Viewing Logs

```bash
# All services
docker compose logs -f

# Single service
docker compose logs -f fetcher
docker compose logs -f applicator
docker compose logs -f api
```

Logs are structured JSON. Use `| jq` to pretty-print if installed.

---

## Updating

```bash
git pull
docker compose build
docker compose up -d
```

Alembic migrations run automatically on `api` startup — no manual schema changes needed.

---

## Stopping the Service

```bash
docker compose down
```

Data is preserved in the `postgres_data` Docker volume. To also remove the data:

```bash
docker compose down -v   # WARNING: deletes all database data
```

---

## Troubleshooting

| Problem | What to check |
|---|---|
| UI not loading | `docker compose logs api` — look for migration errors |
| Fetch always fails | Check the URL is reachable from inside Docker: `docker compose exec fetcher curl -I <url>` |
| Apply fails | Verify SSH access: `docker compose exec applicator ssh user@router-ip` |
| DB connection refused | Check `POSTGRES_HOST=postgres` (not `localhost`) in `.env` |
| Encryption key error | Ensure `ENCRYPTION_KEY` is exactly 64 hex characters |

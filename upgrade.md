# Upgrade Guide

This guide covers the normal upgrade flow for a running Docker-based deployment of Mikrotik Whitelist Service.

---

## Standard Upgrade

On your Docker server:

```bash
cd /path/to/Mikrotik-Whitelist-Service
git pull
docker compose up -d --build
```

What this does:

1. Pulls the latest application code from git
2. Rebuilds the application images from the updated source
3. Restarts the containers with the new code
4. Runs Alembic migrations automatically when the `api` service starts

For most upgrades, this is the only command sequence you need.

---

## Cautious Upgrade Flow

If you want to build first and then watch startup logs:

```bash
cd /path/to/Mikrotik-Whitelist-Service
git pull
docker compose build
docker compose up -d
docker compose logs -f api
```

Use this when you want to confirm migrations and application startup before walking away.

---

## Data Safety

Your PostgreSQL data is stored in a Docker volume, so normal upgrades do not remove your database.

Safe commands:

```bash
docker compose up -d --build
docker compose down
```

Destructive command:

```bash
docker compose down -v
```

`docker compose down -v` removes the database volume and deletes all stored data.

---

## Check For New Environment Variables

Before restarting after an upgrade, compare your local `.env` with the example file in the repository:

```bash
diff -u .env examples/.env.example
```

If a newer release adds required environment variables, update your `.env` before running:

```bash
docker compose up -d --build
```

---

## If Something Fails

Check service status and logs:

```bash
docker compose ps
docker compose logs -f api
docker compose logs -f fetcher
docker compose logs -f applicator
```

If the problem started immediately after `git pull`, review what changed and fix forward if possible. Because the database is preserved in the Docker volume, most failed upgrades can be recovered by correcting configuration or code and restarting the stack.

---

## Recommended Routine

For day-to-day maintenance, use this as the standard upgrade command:

```bash
cd /path/to/Mikrotik-Whitelist-Service
git pull
docker compose up -d --build
```
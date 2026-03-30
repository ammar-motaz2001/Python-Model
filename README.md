# SOC Detector + Automation Service

## Architecture

`Detector API (main.py)` -> `Redis Stream (security-alerts)` -> `Automation Service (automation_service.py)` -> `Firewall`

## 1) Run Detector API

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

The detector publishes each event to:
- Redis pub/sub channel: `attack-events` (realtime UI)
- Redis stream queue: `security-alerts` (durable automation)

## 2) Run Automation Service

```bash
bash scripts/run_automation_service.sh
```

It consumes `security-alerts` and applies policy:
- DDoS attack -> isolate `client_ip`
- Brute-force attack -> block `foreign_ip` when `password_count >= BF_AUTO_BLOCK_THRESHOLD` (default 6)

## 3) Enable Real Enforcement

By default, actions are dry/state unless you provide real commands.

```bash
export ENFORCEMENT_ENABLED=1
export ENFORCE_BLOCK_CMD='sudo /usr/local/bin/soc-block-ip {ip}'
export ENFORCE_ISOLATE_CMD='sudo /usr/local/bin/soc-isolate-ip {ip}'
```

Command templates must contain `{ip}`.

## Useful Env Vars

- `REDIS_URL` (default `redis://localhost:6379/0`)
- `ALERT_QUEUE_STREAM` (default `security-alerts`)
- `ACTION_SERVICE_GROUP` (default `action-service`)
- `ACTION_SERVICE_CONSUMER` (default `consumer-1`)
- `BF_AUTO_BLOCK_THRESHOLD` (default `6`)
- `ENFORCEMENT_ENABLED` (`1` to execute real commands)
- `ENFORCE_BLOCK_CMD`, `ENFORCE_ISOLATE_CMD`, `ENFORCE_TIMEOUT_SECONDS`

## Deploy To Vercel

This repository is configured for Vercel Python runtime using:
- `vercel.json`
- `api/index.py` (exports FastAPI `app` from `main.py`)

### 1) Install and login

```bash
npm i -g vercel
vercel login
```

### 2) Link and deploy

```bash
vercel
vercel --prod
```

### 3) Set environment variables in Vercel

Set from dashboard or CLI:

```bash
vercel env add MONGO_URL
vercel env add MONGO_DB
vercel env add REDIS_URL
vercel env add BF_AUTO_BLOCK_THRESHOLD
vercel env add WIFI_LOG_INGEST_KEY
```

### Important notes for serverless deployment

- Vercel filesystem is read-only except `/tmp`. This app writes logs under `/tmp/logs` automatically on Vercel.
- `automation_service.py` is a long-running worker and should run on a VM/container, not Vercel serverless.
- Model files (`model.pkl`, `model_bruteforce.pkl`, encoder `.pkl`) are gitignored by default.
  Make sure they exist in deployment artifacts, otherwise detection endpoints can return `503`.

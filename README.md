# ARGUS — Open-Source Security Operations Dashboard

![Python 3.12](https://img.shields.io/badge/Python-3.12-blue?style=flat-square)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?style=flat-square)
![Next.js 16](https://img.shields.io/badge/Next.js-16-black?style=flat-square)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791?style=flat-square)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)

> Lightweight SOC dashboard — threat intel, IOC enrichment, alerts, incidents. Zero paid APIs required. `docker compose up` and go.

**Live demo:** https://web-five-liard-75.vercel.app  
**API docs:** https://argus-api-production.up.railway.app/docs

---

## What is ARGUS?

ARGUS (named after Argus Panoptes, the all-seeing giant of Greek mythology) is a self-hosted Security Operations Center dashboard built for security analysts, bug bounty hunters, and small security teams who need a lightweight, powerful alternative to heavyweight platforms like Wazuh, TheHive, or MISP — without weeks of setup or expensive licenses.

It aggregates real-time threat intelligence from free community sources, lets you look up any indicator of compromise (IOC) across multiple feeds in one click, and provides a clean interface for managing the full lifecycle of security alerts and incidents.

---

## Features

- **Threat Intel Hub** — Live feed aggregating malicious IPs, domains, URLs, and file hashes from Abuse.ch (URLhaus, ThreatFox, Feodo, MalwareBazaar) and AlienVault OTX. Auto-syncs every 15 minutes. No API key required for the core feeds.

- **IOC Lookup** — Type any IP, domain, SHA-256 hash, or URL and get enriched results from OTX, GreyNoise, and VirusTotal simultaneously. Returns a composite risk score, tags, and per-source breakdown in under 3 seconds.

- **Alert Queue** — Create and triage security alerts with severity (Critical/High/Medium/Low), status workflow (New → Investigating → Contained → Resolved → False Positive), analyst notes, and linked IOCs.

- **Incident Tracker** — Full PICERL incident lifecycle (Identification → Containment → Eradication → Recovery → Lessons Learned) with timestamped timeline, evidence collection, and auto-generated Markdown incident reports.

- **Sigma Rule Manager** — Write and validate Sigma detection rules (the open standard used by Splunk, Elastic, QRadar). Browse 12,000+ community rules from SigmaHQ. Export to multiple SIEM formats *(pySigma backend coming soon)*.

- **Threat Hunting Workbench** — Paste a list of 100 IOCs, enrich all of them in bulk against every configured source, and export results as CSV for further analysis.

---

## Quick Start

Requires [Docker Desktop](https://www.docker.com/products/docker-desktop/).

```bash
git clone https://github.com/ankitmishra01/argus
cd argus
cp .env.example .env        # optionally add free API keys (see below)
docker compose up           # starts Postgres + Redis + API + Web
```

Open **http://localhost:3000** — threat feeds start pulling in data within 2 minutes.

---

## Configuration

Copy `.env.example` to `.env` and fill in values. All API keys are **optional** — the core feeds (URLhaus, Feodo Tracker) work without any keys.

| Variable | Required | Default | Description |
|---|---|---|---|
| `SECRET_KEY` | Production | — | Random string for signing. Generate: `openssl rand -hex 32` |
| `NEXT_PUBLIC_API_URL` | Production | `http://localhost:8000` | Backend URL for the frontend |
| `DATABASE_URL` | Production | localhost default | PostgreSQL connection string |
| `REDIS_URL` | Production | localhost default | Redis connection string |
| `OTX_API_KEY` | No | — | [AlienVault OTX](https://otx.alienvault.com/settings) — free account |
| `VT_API_KEY` | No | — | [VirusTotal](https://www.virustotal.com/gui/my-apikey) — free, 1k req/day |
| `GREYNOISE_API_KEY` | No | — | [GreyNoise](https://viz.greynoise.io/account/) — free community tier |
| `ABUSECH_API_KEY` | No | — | [Abuse.ch](https://abuse.ch/api/) — free, unlocks ThreatFox & MalwareBazaar |

---

## Threat Intelligence Sources

All sources are free. No credit card required for any of them.

| Source | Data | Key Required | Sync Interval |
|---|---|---|---|
| [URLhaus](https://urlhaus.abuse.ch) | Malicious URLs | No | 15 min |
| [Feodo Tracker](https://feodotracker.abuse.ch) | Botnet C2 IPs | No | 15 min |
| [ThreatFox](https://threatfox.abuse.ch) | IPs, domains, hashes | Free account | 15 min |
| [MalwareBazaar](https://bazaar.abuse.ch) | Malware file hashes | Free account | 15 min |
| [AlienVault OTX](https://otx.alienvault.com) | Threat pulses, IOC enrichment | Free account | 1 hour |
| [GreyNoise](https://greynoise.io) | IP noise classification | Optional (free tier) | On lookup |
| [VirusTotal](https://www.virustotal.com) | File/URL/IP/domain reputation | Optional (free tier) | On lookup |

---

## Architecture

```
┌──────────────────────────────────────────────────────┐
│  Next.js 16 Dashboard (Vercel / localhost:3000)       │
│  6 pages · Dark UI · TypeScript · React 19            │
└─────────────────────┬────────────────────────────────┘
                      │ HTTPS / REST
┌─────────────────────▼────────────────────────────────┐
│  FastAPI Backend (Railway / localhost:8000)            │
│  Python 3.12 · Async SQLAlchemy · APScheduler         │
├──────────────────────┬───────────────────────────────┤
│  PostgreSQL          │  External Sources               │
│  Alerts, Incidents,  │  Abuse.ch · OTX · GreyNoise    │
│  IOCs, Sigma Rules   │  VirusTotal · Feodo Tracker     │
└──────────────────────┴───────────────────────────────┘
```

**Stack:**

| Layer | Technology |
|---|---|
| Frontend | Next.js 16, Tailwind CSS v4, TypeScript |
| Backend | Python 3.12, FastAPI, SQLAlchemy 2.0 (async) |
| Database | PostgreSQL 16 |
| Cache | Redis 7 *(provisioned, caching layer coming soon)* |
| Background Jobs | APScheduler |
| HTTP Client | httpx (async) |
| Container | Docker / Docker Compose |

---

## Deployment (Production)

### Frontend → Vercel

```bash
cd web
vercel --prod
```

Set `NEXT_PUBLIC_API_URL` in your Vercel project environment variables pointing to your Railway API URL.

### Backend → Railway

```bash
# Install Railway CLI
brew install railway

# Login and initialise
railway login
cd api
railway init

# Add databases
railway add --database postgres
railway add --database redis

# Deploy
railway up

# Set env vars
railway variables set SECRET_KEY=your-secret OTX_API_KEY=optional

# Generate public URL
railway domain
```

---

## API Reference

Interactive docs available at `https://your-api-url/docs` (Swagger UI, auto-generated by FastAPI).

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/intel/feed` | Live IOC feed (filterable by source, type) |
| `GET` | `/intel/feed/stats` | Feed statistics (24h counts, totals) |
| `GET` | `/intel/sources` | Feed source health status |
| `GET` | `/intel/lookup/{ioc}` | Enrich a single IOC across all sources |
| `GET` | `/alerts/` | List all alerts |
| `POST` | `/alerts/` | Create a new alert |
| `PATCH` | `/alerts/{id}/status` | Update alert status |
| `POST` | `/alerts/{id}/notes` | Add analyst note |
| `GET` | `/incidents/` | List all incidents |
| `POST` | `/incidents/` | Open a new incident |
| `PATCH` | `/incidents/{id}` | Update incident fields |
| `POST` | `/incidents/{id}/timeline` | Add timeline entry |
| `GET` | `/incidents/{id}/report` | Generate Markdown report |
| `GET` | `/health` | Health check |

---

## Known Limitations

- **No authentication** — all API endpoints are public. ARGUS is designed for self-hosting behind your own network or a reverse proxy with authentication (e.g., Cloudflare Access, nginx basic auth). Do not expose the API directly to the internet.
- **Sigma rule export** — the rule editor and validator work in-browser. Conversion to SIEM formats (Splunk SPL, Elastic ESQL) requires a pySigma backend that is not yet implemented.
- **Redis caching** — Redis is provisioned and connected but not yet used for caching API responses. High-volume IOC lookups may be slow.
- **No test coverage** — the project has no automated tests yet.

---

## Roadmap

- [ ] JWT authentication + role-based access control (admin, analyst, read-only)
- [ ] Redis caching for IOC lookups (1h TTL)
- [ ] pySigma backend for rule conversion (Splunk, Elastic, QRadar, Suricata)
- [ ] Abuse.ch API key support (ThreatFox, MalwareBazaar full access)
- [ ] Alert correlation and automatic deduplication
- [ ] Webhook ingestion (receive alerts from external tools via HTTP)
- [ ] Test suite (pytest for backend, Playwright for frontend)
- [ ] Kubernetes / Helm chart for production deployment
- [ ] MISP integration for threat intel sharing
- [ ] Notification channels (Slack, email, PagerDuty)

---

## Contributing

Contributions are welcome. Please open an issue to discuss what you'd like to change before submitting a pull request.

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit your changes: `git commit -m "Add your feature"`
4. Push and open a PR

---

## License

[MIT License](LICENSE) — free to use, modify, and distribute.

---

*Built with [Claude Code](https://claude.ai/code).*

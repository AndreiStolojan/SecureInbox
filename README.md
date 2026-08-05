# SecureInbox

[![Quality](https://github.com/AndreiStolojan/SecureInbox/actions/workflows/quality.yml/badge.svg)](https://github.com/AndreiStolojan/SecureInbox/actions/workflows/quality.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

SecureInbox is an explainable phishing triage application for Gmail. It scores
every message from real evidence — verified sender identity, link and
attachment reputation, deterministic rules, and a bounded local AI signal —
and shows the reasoning behind each verdict instead of a black-box score.

<p align="center">
  <img src="assets/screenshots/dashboard.png" alt="SecureInbox dashboard" width="900" />
</p>

## What it does

- Synchronizes Gmail incrementally via the history API, with optional
  real-time ingestion through Gmail push notifications (Cloud Pub/Sub).
- Authenticates the sender: SPF (via Gmail's own `Authentication-Results`),
  DKIM (re-verified independently from the raw MIME), DMARC (evaluated live
  against DNS), and ARC for forwarded and mailing-list mail. Brand
  verification is gated on this result, so a spoofed sender can no longer
  outscore an unverified one.
- Checks links against Google Web Risk and URLhaus, resolves redirects with
  SSRF-hardened, resolved-IP validation on every hop, and factors in domain
  age via RDAP.
- Inspects attachments by content, not filename: magic-byte type detection,
  in-memory ZIP/OOXML/PDF structural analysis for encrypted archives, macros,
  and auto-executing PDF actions, and SHA-256 lookups against MalwareBazaar.
  Bytes are never written to disk or persisted.
- Combines all of the above with deterministic rules and a bounded local
  Ollama AI signal — AI alone can never declare a message phishing — through
  an auditable, independently-failable signal-provider engine.
- Explains why a message was marked safe, suspicious, or likely phishing.
- Supports trusted and blocked sender rules plus manual review decisions.
- Runs locally with Docker, MongoDB, Ollama, Prometheus, and Grafana.

## Architecture

```text
Browser -> nginx / React -> Express -> MongoDB
                              |
                              +-> optional Gmail OAuth, history sync, push (Pub/Sub)
                              +-> local Ollama
                              +-> DNS (DMARC), Web Risk, URLhaus, RDAP, MalwareBazaar

Prometheus -> Express /metrics -> Grafana
```

The backend owns authentication, synchronization, scoring, reports, and data.
The frontend talks to it through the nginx reverse proxy. Detection itself is
a registry of independent signal providers — each new signal (authentication,
threat intel, attachments) is its own module with its own weights, isolated
so that one provider's failure or external dependency never blocks a scan.
See [architecture.md](docs/architecture.md) and
[detection-engine.md](docs/detection-engine.md) for the deeper design.

## Quick start

Requirements:

- Docker Engine or Docker Desktop with the Docker Compose plugin, running and
  accessible without `sudo`.
- OpenSSL, used to generate the local secrets.

```bash
git clone https://github.com/AndreiStolojan/SecureInbox.git
cd SecureInbox
./provision
```

`./provision` creates `.env`, generates the local secrets, builds and starts all
containers, downloads the Ollama model, and creates a demo account with six
scanned emails. Leave the script running until it prints `SecureInbox is
ready`.

| Service | Address |
| --- | --- |
| SecureInbox | `http://localhost:8080` |
| Prometheus | `http://localhost:9090` |
| Grafana | `http://localhost:3000` |

Demo email: `demo@secureinbox.test`

The generated demo and Grafana passwords are printed at the end and stored in
`.env`.

Verify the installation:

```bash
docker compose ps
curl --fail http://127.0.0.1:8080/api/v1/ready
curl --fail http://127.0.0.1:9090/-/ready
curl --fail http://127.0.0.1:3000/api/health
```

All six services should be healthy. You can safely run `./provision` again:
existing configuration, database contents, monitoring data, and the Ollama
model are preserved.

For the Raspberry Pi / public Cloudflare deployment, use the separate
[`prod` branch and production Compose guide](docs/raspberry-pi-deployment.md).
Never run the local Compose file or `./provision` on that deployment.

## Optional Gmail connection

The local application starts without Google, email, or Arcjet credentials.
Features that need a missing integration return a clear message only when used.

To connect Gmail, add these values to `.env`:

```dotenv
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
GOOGLE_REDIRECT_URI=http://localhost:8080/api/v1/mail-accounts/google/callback
```

Add the same redirect URI to the OAuth client in Google Cloud, then run
`./provision` again:

```bash
nano .env
./provision
```

SMTP and Arcjet variables are documented in `.env.example` and are optional.

## Optional detection integrations

Every integration below is off or degraded by default and fails open: a
missing key or an unreachable service never blocks a scan, it just means that
signal is unavailable for that message. All variables are documented with
their defaults in `.env.example`.

| Feature | Env vars | Without it |
| --- | --- | --- |
| Gmail push notifications | `GMAIL_PUSH_ENABLED`, `GOOGLE_CLOUD_PROJECT_ID`, `GMAIL_PUBSUB_TOPIC`, `GMAIL_PUSH_AUDIENCE` | Falls back to incremental history polling |
| Threat intelligence (Web Risk, URLhaus, domain age) | `THREAT_INTEL_ENABLED`, `WEB_RISK_API_KEY`, `URLHAUS_AUTH_KEY` | Link scoring stays lexical (patterns, shorteners) |
| Attachment verification | `ATTACHMENT_ANALYSIS_ENABLED` | Attachments are scored by extension only |

Gmail push notifications additionally need a public HTTPS endpoint (the
Cloudflare Tunnel used in the production deployment) and are not meant to be
exercised on a bare local install; incremental history sync is what runs
out of the box.

## Local operations

Show status and logs:

```bash
docker compose ps
docker compose logs --tail=100
docker compose logs --follow backend
```

Restart the application:

```bash
docker compose restart
```

Update the local installation:

```bash
git pull --ff-only origin main
./provision
```

Create a validated MongoDB backup:

```bash
./scripts/backup
ls -lh backups
```

Restore the latest backup:

```bash
LATEST_BACKUP="$(find backups -name '*.archive.gz' -type f | sort | tail -1)"
./scripts/restore "$LATEST_BACKUP" --confirm-replace
```

Keep an encrypted backup of `.env` with every MongoDB backup. In particular,
`MAIL_TOKEN_ENCRYPTION_KEY` is required to decrypt restored Gmail tokens.

Stop the application while preserving all data:

```bash
docker compose down
```

To erase MongoDB, Grafana, Prometheus, and the downloaded Ollama model:

```bash
docker compose down --volumes
```

That command is destructive and cannot be undone without a backup.

## Development checks

```bash
npm --prefix backend install
npm --prefix frontend install
npm --prefix backend run lint
npm --prefix backend test
npm --prefix frontend test
npm --prefix frontend run build
```

## Limitations

- Gmail OAuth requires a Google Cloud client and configured test users.
- Real-time push ingestion needs a public HTTPS endpoint and a Cloud Pub/Sub
  topic; a bare local install synchronizes via incremental history polling.
- Threat intelligence and attachment hash reputation depend on third-party
  services (Google Web Risk, URLhaus, MalwareBazaar) and degrade to the
  underlying deterministic rules if those are unreachable or unconfigured.
- Local AI is a secondary signal and cannot declare phishing on its own.
- SecureInbox does not claim precision or recall without a labeled evaluation dataset.

## Author and license

Andrei Stolojan — [GitHub](https://github.com/AndreiStolojan) ·
[LinkedIn](https://www.linkedin.com/in/andrei-stolojan/)

Released under the [MIT License](LICENSE).

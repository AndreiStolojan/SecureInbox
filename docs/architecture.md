# Architecture

SecureInbox is a modular monolith: one React single-page application, one
Express API, and one MongoDB database. Detection stays in the backend so the
browser receives a persisted, auditable result instead of owning security
logic.

The architecture optimizes for traceability and a small operating footprint.
Splitting the Gmail workflow, detection engine, and review state into separate
services would add deployment and consistency work without solving a current
scale problem.

## Components

| Component | Responsibility | Main entry point |
| --- | --- | --- |
| React and Vite frontend | Inbox, evidence display, sender rules, manual review | `frontend/src/App.jsx` |
| nginx | Serves the frontend and proxies `/api` to Express | `frontend/nginx.conf`, `frontend/nginx.prod.conf` |
| Express backend | Authentication, validation, Gmail sync, scanning, reports, metrics | `backend/src/server.js`, `backend/src/app.js` |
| Detection engine | Independent evidence providers, centralized weights and verdicts | `backend/src/detection/` |
| MongoDB | Users, encrypted OAuth tokens, normalized emails, scan results, caches | `backend/src/models/` |
| Ollama | Optional local semantic signal and natural-language explanation | `backend/src/services/ollama-*.service.js` |
| Scheduler and Gmail push | Incremental polling, watch renewal, and queued push-triggered sync | `backend/src/services/scheduler.service.js`, `backend/src/services/gmail-push-runtime.service.js` |
| Prometheus and Grafana | Local metrics, alerts, and dashboard | `monitoring/`, `docker-compose.monitoring.yml` |

## Data flow

```text
1. User browser
      |
      | login, OAuth initiation, inbox and review actions
      v
2. nginx -> Express API
      |
      +-> Google OAuth and Gmail API
      |     fetch message metadata/content and, briefly, raw MIME for DKIM/ARC
      |
      +-> parse and authenticate sender
      |     SPF from trusted Gmail headers; DKIM/ARC locally; DMARC through DNS
      |
      +-> MongoDB
      |     normalized email, encrypted OAuth tokens, auth result and sync cursor
      |
      +-> detection providers, run in a bounded order
      |     sender list, email auth, reply-to, links, threat intelligence,
      |     attachment analysis, extension rules, semantic AI
      |
      +-> centralized scorer -> optional explanation -> MongoDB Scan
      |
      v
3. React renders the verdict and evidence
      HTML is sanitized and remote images are blocked by default
```

Polling and Gmail push converge on the same incremental synchronization state
machine. A push notification is a prompt to synchronize, not an authoritative
copy of the message. The Gmail history cursor in MongoDB remains authoritative.

Attachment bytes are fetched only when opt-in analysis is enabled. Analysis is
bounded by count, individual size, total size, concurrency, and timeout. Bytes
remain in memory and are discarded. The database retains attachment metadata
and normalized findings, not the file content. When MalwareBazaar lookup is
configured, a separate TTL cache retains the attachment SHA-256 and the bounded
`malicious` or `unknown` verdict. The email and public scan records do not
contain that hash.

## Trust boundaries

A trust boundary is a place where data moves between parties with different
security assumptions. Every value crossing one must be authenticated,
validated, bounded, or treated as unavailable.

| Boundary | Untrusted or sensitive input | Control and failure behavior |
| --- | --- | --- |
| Browser to nginx and Express | Credentials, IDs, filters, email actions | JWT authentication, ownership checks, Joi validation, rate limits, security headers |
| Gmail and Google OAuth to backend | OAuth tokens, messages, push claims, Gmail headers | Exact redirect configuration, encrypted token storage, OIDC validation for push, bounded sync, trusted-header selection |
| Email content to parser and UI | HTML, links, filenames, MIME structures | Parsing limits, HTML sanitization, remote-image blocking, no attachment execution |
| Backend to DNS for DMARC | Sender-controlled domain and TXT response | Domain normalization, bounded DNS deadlines, conservative cache, unavailable result on failure |
| Backend to reputation providers | Attacker-controlled domains, URLs, and attachment hashes | Opt-in feature flags, strict timeouts and input limits, SSRF-resistant redirect/IP checks, fail-open provider isolation |
| Backend to Ollama | Bounded excerpts of message content | Local-only Compose network, input/output caps, optional signal, deterministic fallback |
| Backend to MongoDB | Email content, scan evidence, encrypted OAuth tokens | Application ownership filters, unique indexes, encryption key kept outside the database |
| Public internet to production | HTTP requests and claimed client IPs | Cloudflare Tunnel is the only ingress; nginx trusts only the `cloudflared` peer and replaces the forwarded chain |
| Operator to runtime | `.env`, tunnel token, Atlas and OAuth credentials | Files excluded from Git, restrictive permissions, separate encrypted backups; never record values in documentation |

External reputation data is evidence, not authority. A missing or failed
provider contributes no signal and cannot prevent the remaining local scan.
Conversely, "fail open" means reduced visibility, not proof that a message is
safe. Provider status is persisted with the scan so that distinction remains
auditable.

## Why hybrid phishing detection

Deterministic rules are stable, testable, and explainable, but they are weak at
intent and social-engineering language. A language model can recognize that
context, but it is probabilistic and can fail or overreact. SecureInbox combines
them with explicit limits:

- Providers emit point-free evidence; only the scorer assigns weights.
- Rule and AI scores are stored separately with the triggered evidence.
- AI contributes at most 50 points, below the 60-point phishing threshold, so
  AI alone cannot declare a message likely phishing. It can cross the
  30-point suspicious threshold, which is why its evidence and score remain
  visible separately.
- Each provider can fail independently. The scan continues and records the
  provider outcome.
- The engine version and relevant configuration fingerprints make stale scans
  detectable.

This is a triage architecture, not a claim of classifier accuracy. Accuracy,
precision, recall, and uplift require the independent corpus work tracked in
[issue #82](https://github.com/AndreiStolojan/SecureInbox/issues/82).

## Deployment topologies

### Local and CI

```text
127.0.0.1:8080 -> nginx -> Express -> MongoDB
                               |
                               +-> Ollama

127.0.0.1:9090 -> Prometheus -> Express /metrics
127.0.0.1:3000 -> Grafana -> Prometheus
```

`docker-compose.yml` runs six services: MongoDB, backend, frontend, Ollama,
Prometheus, and Grafana. Published ports bind to loopback. Named volumes retain
database, model, and monitoring data. `docker-compose.monitoring.yml` repeats
the two monitoring services as a standalone overlay entry point; the default
local Compose file already includes them.

### Raspberry Pi production

```text
Browser -> Cloudflare edge -> cloudflared -> nginx -> Express -> MongoDB Atlas
                                                   |
                                                   +-> Ollama on the Pi
```

`docker-compose.prod.yml` runs four services: backend, frontend, Ollama, and
`cloudflared`. It publishes no host ports. MongoDB Atlas is external, and the
production Compose file does not include Prometheus or Grafana. Production
rollout is manual from the reviewed `prod` branch; CI validates the Compose
configuration but does not deploy to the Pi.

## Data retained

- MongoDB stores application users, normalized email content and metadata,
  sender authentication outcomes, encrypted Gmail OAuth tokens, sync state,
  sender lists, scan evidence, review actions, and bounded reputation caches.
  The attachment reputation cache stores SHA-256 values and verdicts until its
  TTL expires; it does not store attachment bytes.
- The encryption key for OAuth tokens is configuration, not database data. A
  database restore without the matching `MAIL_TOKEN_ENCRYPTION_KEY` cannot
  recover Gmail access.
- Local Docker volumes store MongoDB data, the Ollama model, and monitoring
  history. Production application data lives in Atlas; Ollama model data stays
  on the Pi.
- Raw RFC 822 messages used for DKIM/ARC verification and attachment bytes used
  for analysis are transient and are not persisted by the application.

Retention, deletion, production backup, and secret-rotation policy remain
operational decisions tracked in
[issue #79](https://github.com/AndreiStolojan/SecureInbox/issues/79) and
[issue #77](https://github.com/AndreiStolojan/SecureInbox/issues/77).

## Architectural constraints

- Gmail is the only mail provider.
- One connected Gmail account is supported per application user.
- Detection providers currently execute serially to preserve observable
  evidence order. Bounded concurrency may occur inside a provider, such as
  attachment analysis. The explanation can add a second Ollama call.
- Third-party signals depend on configuration, network availability, quotas,
  and provider behavior.
- The production deployment is single-node at the application layer and has no
  automated rollout or rollback controller.
- The repository has no production Atlas restore command. Local backup scripts
  target the MongoDB service in `docker-compose.yml` only.
- No large, independently sourced held-out corpus has established real-world
  detection accuracy.

See [detection-engine.md](detection-engine.md) for provider and scoring
contracts, [raspberry-pi-deployment.md](raspberry-pi-deployment.md) for the
production path, and [project-handoff.md](project-handoff.md) for operational
entry points and evidence status.

# Project retrospective and handoff

Snapshot date: 2026-08-13

Maintenance status: active feature development paused on 2026-08-13

SecureInbox remains public as a portfolio and learning reference. There is no
support or security-response SLA, and repository documentation does not prove
that a production deployment is currently online, healthy, or configured as
described. Verify live state before operating it.

## What was implemented

- Gmail OAuth with encrypted token storage, bounded synchronization, history
  cursors, polling, and optional Pub/Sub push-triggered sync.
- An explainable 0 to 100 phishing score with separate deterministic and AI
  contributions, persisted evidence, provider outcome metadata, and manual
  review actions.
- Sender authentication using trusted Gmail SPF results, local DKIM and ARC
  verification, and live DMARC evaluation.
- Link analysis with lexical rules plus optional Google Web Risk, URLhaus,
  redirect validation, RDAP domain age, and bounded caching.
- Opt-in attachment analysis with magic-byte detection, in-memory archive,
  OOXML and PDF inspection, and optional MalwareBazaar hash reputation.
- A local React interface for inbox triage, evidence inspection, sender rules,
  settings, dashboard reporting, and sanitized email rendering.
- Reproducible local provisioning, health checks, metrics, dashboards, validated
  MongoDB backup/restore, production Compose configuration, and protected
  repository workflows.

The detailed component, trust-boundary, data-flow, and topology descriptions
are in [architecture.md](architecture.md). Detection contracts and scoring
invariants are in [detection-engine.md](detection-engine.md).

## Evidence status

"Covered by tests" means the repository checks that behavior in a controlled
environment. It does not mean the same behavior was observed on the current Pi
or against live third-party services.

| Claim | Evidence in the repository | Status at handoff |
| --- | --- | --- |
| Rule scoring, thresholds, provider contracts, fallbacks, authentication parsing, URL safety, attachment bounds | Focused backend unit tests and immutable detection fixtures | 380 tests passed on 2026-08-13 |
| Frontend risk mapping, authentication state, evidence rendering, and HTML sanitization | Frontend Vitest suites | 76 tests passed on 2026-08-13 |
| Six-service local stack, demo data, readiness, metrics target, Grafana dashboard, backup and restore | `Quality / integration` workflow | Covered in disposable CI |
| Shell syntax, provisioning behavior, Compose parsing, production environment validation, nginx config, pinned ARM64 image manifests | `Quality / infra` workflow | Covered in CI |
| Static JavaScript and workflow vulnerability analysis | GitHub CodeQL required check | Covered by repository automation |
| Current Cloudflare, Atlas, Google OAuth, Gmail push, DNS, threat-intelligence, MalwareBazaar, Pi firewall, temperature, storage, and backup state | Requires live account and device inspection | Not verified by this handoff |
| Production deployment and rollback | CI validates inputs; deployment remains manual | Not exercised by CI |
| Real-world phishing accuracy or improvement over a baseline | Existing fixtures are regression and small semantic-evaluation inputs | Not established; tracked in #82 |
| Restore of Atlas plus matching production secrets into an isolated target | No committed completed drill | Not established; tracked in #77 |
| Unattended privacy, retention, rotation, patching, and alert-response policy | Open operational checklist | Not finalized; tracked in #79 |

The safe public claim is that SecureInbox has tested security mechanisms and an
auditable architecture. Do not claim a detection rate, false-positive rate,
production uptime, or autonomous protection level until a dated report proves
it.

## Known limitations and deferred risks

- Gmail is the only supported provider, and each application user can connect
  only one Gmail account.
- Google OAuth needs an explicitly configured client and test/published users.
  Gmail push additionally needs public HTTPS and Pub/Sub. Polling is the local
  fallback.
- Threat intelligence and attachment hash reputation depend on external
  services. Missing keys, timeouts, quotas, or outages reduce available
  evidence while allowing the scan to finish.
- AI is local and optional. It is bounded below the phishing threshold, but it
  still adds CPU and latency and can return inconsistent semantic judgments.
- Detection providers are serial, and explanation generation can make a second
  model call. Profile those paths before considering a language or service
  rewrite.
- Attachment inspection is static and bounded. It does not execute files and
  does not include ClamAV or a sandbox.
- Attachment bytes are not persisted, but configured MalwareBazaar lookups use
  a MongoDB TTL cache containing SHA-256 values and bounded verdicts. Treat the
  database and its backups as sensitive even though the public email and scan
  contracts omit those hashes.
- The backend supports `MALWAREBAZAAR_AUTH_KEY`, but the handoff revision does
  not expose it in the example environment files or pass it through the local
  Compose service. Hash reputation therefore needs explicit runtime wiring
  before it is available through the standard Compose path.
- The UI sanitizes HTML and blocks remote images by default, but SecureInbox is
  a triage tool, not an email security gateway or malware-analysis platform.
- Production is a manually operated, single-Pi application deployment using
  external Atlas and Cloudflare services. The production Compose path has no
  Prometheus or Grafana stack.
- Local `scripts/backup` and `scripts/restore` operate on the local Compose
  MongoDB service. They are not production Atlas backup or restore tools.
- A database backup is insufficient by itself because encrypted OAuth tokens
  require the matching `MAIL_TOKEN_ENCRYPTION_KEY`.
- Live retention, secret rotation, security monitoring, restore evidence,
  thermal behavior, and public exposure must be resolved in #77, #78, and #79.
- No defensible large-corpus precision, recall, false-positive rate, or uplift
  exists yet. The small fixture sets must not be described as production
  accuracy.
- The 2026-08-13 backend `npm audit` reported one moderate direct finding in
  `mailauth` through `undici` and one high transitive `undici` finding. A fix
  was reported available, with the affected `undici` range ending before
  `7.29.0`. This dependency state is time-sensitive; re-run the audit, select a
  compatible fixed release, and triage it under #79 before operating the
  service unattended.

## Operational entry points

Commands below contain placeholders only. Never paste secret values into an
issue, commit, screenshot, or terminal transcript intended for publication.

### Local install and health

```bash
./provision
docker compose ps
curl --fail http://127.0.0.1:8080/api/v1/ready
curl --fail http://127.0.0.1:9090/-/ready
curl --fail http://127.0.0.1:3000/api/health
docker compose logs --tail=100
```

`./provision` creates or completes `.env`, builds the six local services, pulls
the configured Ollama model, and seeds a synthetic account. It preserves
existing configuration and volumes.

### Development and CI

```bash
npm ci --prefix backend
npm ci --prefix frontend
npm run lint --prefix backend
npm test --prefix backend
npm test --prefix frontend
npm run build --prefix frontend
bash tests/provisioning.test.sh
```

`.github/workflows/quality.yml` is the canonical CI entry point. It runs
backend, frontend, infrastructure, and disposable-stack integration jobs on
every pull request and pushes to `main` or `prod`. CodeQL is configured in
GitHub and required by branch protection. Inspect current controls before a
release with the commands in [repository-controls.md](repository-controls.md).

### Local backup and restore

```bash
./scripts/backup
ls -lh backups

LATEST_BACKUP="$(find backups -name '*.archive.gz' -type f | sort | tail -1)"
test -n "$LATEST_BACKUP" || { echo "No backup archive found" >&2; exit 1; }
./scripts/restore "$LATEST_BACKUP" --confirm-replace
curl --fail http://127.0.0.1:8080/api/v1/ready
```

The backup command stops the local backend briefly, creates a compressed
archive and manifest, dry-runs restoration, records a checksum and document
counts, then restarts the backend. Restore verifies those values before
dropping and replacing the configured local database. `--confirm-replace` is a
destructive confirmation.

Backup filenames contain a zero-padded UTC timestamp, so lexical sorting
selects the latest archive.

Keep an encrypted copy of `.env` separately. These commands do not operate on
MongoDB Atlas. A production backup and isolated restore drill remains part of
[issue #77](https://github.com/AndreiStolojan/SecureInbox/issues/77).

The MongoDB archive contains email content and encrypted OAuth tokens. Keep the
local `backups/` directory access-restricted and encrypt any archive copied to
another device or storage provider.

### Raspberry Pi production

Production uses only the `prod` branch and `docker-compose.prod.yml`. Stop if
`git status --short` is not clean.

```bash
cd /opt/secureinbox
test -z "$(git status --porcelain)" || { echo "Dirty worktree" >&2; exit 1; }
git fetch origin
git switch prod
git pull --ff-only origin prod
docker compose -f docker-compose.prod.yml config --quiet
docker compose -f docker-compose.prod.yml build --pull
docker compose -f docker-compose.prod.yml up -d
docker compose -f docker-compose.prod.yml ps
docker compose -f docker-compose.prod.yml exec frontend \
  wget -qO- http://backend:5500/api/v1/ready
curl -i https://YOUR_HOSTNAME/api/v1/ready
git rev-parse HEAD
```

For diagnosis:

```bash
docker compose -f docker-compose.prod.yml ps
docker compose -f docker-compose.prod.yml logs --tail=100
docker compose -f docker-compose.prod.yml logs --follow backend
```

The full deployment and promotion procedure is in
[raspberry-pi-deployment.md](raspberry-pi-deployment.md). Before using it,
complete the inventory, backup, recovery, and live-state checks in #77 and #79.

## Lessons learned

### Phishing detection

Explainability works best as a data contract, not as prose added after a score.
Providers emit evidence, the scorer owns weights, and the database keeps the
split and provenance. Golden fixtures catch silent scoring drift, while a real
held-out corpus is still necessary to establish effectiveness.

### OAuth and email authentication

OAuth tokens are durable production credentials. Encrypting them is useful
only if the key is backed up and rotated separately. Email authentication also
cannot be reduced to one header: SPF relies on the receiving MTA's observation,
while DKIM and ARC can be reverified over raw MIME and DMARC adds alignment and
policy.

### Secure networking

Attacker-controlled URLs turn a reputation lookup into an SSRF risk. Every
redirect hop needs scheme, host, DNS, resolved-IP, size, and timeout checks.
At the public edge, client IP is trustworthy only when the proxy chain and its
sole trusted hop are explicit.

### Containers and deployment

Local and production Compose files serve different threat models. Local binds
services to loopback and includes development observability; production
publishes no ports and uses Cloudflare plus Atlas. Digest pinning and ARM64
manifest checks reduce surprise, but do not replace a tested rollout.

### Storage and backup

A backup is a hypothesis until restoration succeeds. Checksums, manifests, dry
runs, document counts, and an isolated restore drill give progressively
stronger evidence. Database data and the keys needed to decrypt it belong in
separate, access-controlled backups.

### Observability

Metrics labels must remain bounded, and provider failure must be distinguishable
from a safe result. Readiness, logs, metrics, and alert rules cover different
failure modes. Local dashboards do not prove production monitoring exists.

### CI/CD

CI should test the deployable shape, not just source files. SecureInbox checks
Compose parsing, nginx, environment validation, image architecture, a complete
disposable stack, seed data, monitoring, backup, and restore. Production rollout
is still manual, so CI proves inputs rather than the live outcome.

### Incident risk

Fail-open integrations preserve availability but create degraded security
visibility. Unattended operation therefore needs explicit alert ownership,
secret rotation, retention, patch cadence, backups, and a recovery procedure.
A green health endpoint alone is not a security posture.

## Portfolio and interview summary

### Short portfolio summary

SecureInbox is an explainable Gmail phishing-triage system built as a React and
Express modular monolith. I designed a provider-based detection engine that
combines deterministic sender, link, authentication, threat-intelligence, and
attachment evidence with a bounded local Ollama signal. The system persists why
each verdict occurred, isolates optional-provider failures, encrypts Gmail OAuth
tokens, sanitizes email HTML, and ships reproducible local and Raspberry Pi
Compose paths with CI, backup/restore, and observability. I deliberately avoid
accuracy claims until the held-out corpus benchmark in #82 is complete.

### Defensible technical highlights

- Eight independent detection providers feed one centralized scorer: sender
  list, email authentication, reply-to, link analysis, threat intelligence,
  attachment content, attachment extension, and semantic AI. The AI
  contribution is capped at 50 points, below the 60-point phishing threshold.
- Gmail authentication combines trusted SPF evidence with local DKIM/ARC
  verification and live DMARC alignment instead of trusting all forwarded
  headers equally.
- URL fetching revalidates resolved IPs across redirects to reduce SSRF risk;
  attachment analysis is in-memory and bounded.
- The handoff gate passed 380 backend and 76 frontend tests. CI additionally
  covers four required Quality jobs plus a required CodeQL check and exercises
  a disposable six-service local stack, including a validated database backup
  and restore.
- Production uses a four-service, no-published-port Compose topology behind
  Cloudflare Tunnel, with MongoDB Atlas outside the Pi.

These are architecture and test-coverage facts, not production performance or
detection-effectiveness claims.

### Resume checklist

- [ ] State personal ownership precisely: architecture, implementation,
  security decisions, operations, or testing that can be explained in depth.
- [ ] Name the scope: Gmail triage, not a universal mail gateway or antivirus.
- [ ] Prefer concrete design constraints already evidenced above, such as eight
  providers, the AI cap, or the six-service CI stack.
- [ ] Link every accuracy, latency, resource, temperature, or uptime number to a
  dated report and exact Git commit.
- [ ] Do not turn the small regression fixtures into precision, recall, or
  false-positive claims.
- [ ] After #82, include corpus size, untouched test split, baseline, metric,
  percentage-point change, confidence interval, and performance tradeoff.
- [ ] After #78, distinguish measured Pi results from laptop or estimated
  results.
- [ ] Be ready to explain one tradeoff and one failure mode for OAuth, SSRF,
  local AI, backups, and manual deployment.
- [ ] Keep screenshots synthetic and re-run the privacy check before publishing
  new examples.

## Development restart order

The first three tasks when active development resumes are:

1. Complete [#79, unattended security and privacy](https://github.com/AndreiStolojan/SecureInbox/issues/79): re-run and triage the dependency audit, then settle retention, secret rotation, exposure, patching, monitoring, and alert ownership before reconnecting real Gmail data.
2. Complete [#77, hibernation and recovery](https://github.com/AndreiStolojan/SecureInbox/issues/77): verify the selected operating mode, deployed revision, external-service inventory, backups, and an isolated restore before trusting production state.
3. Complete [#82, reproducible phishing benchmark](https://github.com/AndreiStolojan/SecureInbox/issues/82): use an isolated corpus workflow to establish defensible accuracy and uplift before changing thresholds or publishing CV metrics.

If the Pi will remain online, execute
[#78, Pi resource and temperature measurement](https://github.com/AndreiStolojan/SecureInbox/issues/78)
alongside the first two operational tasks, before selecting an always-on AI
profile.

## Public-data and secret audit

The repository was reviewed on 2026-08-13 for email-like strings,
secret-like assignments, screenshot content, and PNG metadata:

- Screenshots show the synthetic `Demo` account and fabricated phishing
  messages. They show no personal mailbox address, token, or credential.
- Email-authentication `.eml` fixtures are documented standards-derived test
  vectors. Other examples and fixtures use reserved test domains, public brand
  sender patterns, or synthetic names and addresses.
- Configuration files contain empty values, generated-value markers, or CI/test
  sentinels. No live token or credential was identified.
- PNG metadata contains no author, email, comment, or description fields.

This is a repository-content review, not proof about untracked files, GitHub
secrets, previous Git history, external services, or production databases. Run
the same review again before adding screenshots, fixtures, benchmark corpora, or
operational evidence. Never commit raw Gmail exports or real phishing samples.

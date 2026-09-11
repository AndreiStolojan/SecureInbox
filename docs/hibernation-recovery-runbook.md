# Hibernation and recovery runbook

This runbook captures sanitized production evidence. It never contains secret
values. The encrypted recovery artifacts are stored outside the repository.

## Operating state, refreshed 2026-09-11

Development continues. Keep production online; hibernation is an optional future
operation, not a prerequisite for recovery readiness. Owner: Andrei Stolojan.
Review recovery readiness by 2026-11-18 and before any production rollout.

On 2026-09-11 the production checkout remained clean at `dd7b89f`. Backend,
frontend, Prometheus and Grafana reported healthy; cloudflared was running.
This is container status, not a fresh restore drill or public-access check.
The August backup evidence below has not been reverified in this session.

The current source uses a root production environment file and
`docker-compose.yml` plus `docker-compose.prod.yml`. The deployed August revision
uses a standalone production file plus `docker-compose.monitoring.yml` and two
environment files. Match the commands and secret backup to the revision being
recovered. Never apply the new overlay alone or assume an old environment backup
is sufficient for a new release. See [environments.md](environments.md).

## Production inventory

Historical evidence captured on 2026-08-18; identifiers and risks below may have changed.

| Item | Sanitized value |
| --- | --- |
| Pi path | `/opt/secureinbox` |
| Branch and revision | `prod` at `dd7b89fd2abf731c479439d07cc14d310ba49388` |
| Worktree | Clean after the encrypted backup was verified |
| OS | Debian GNU/Linux 13, ARM64, kernel `6.18.39+rpt-rpi-2712` |
| Runtime | Docker `29.7.2`, Compose `5.4.0` |
| Secret files | `.env` and `backend/.env.production.local`, mode `600` |
| SecureInbox ingress | Cloudflare Tunnel only; production Compose publishes no host ports |
| Other Pi listeners | Pi-hole owns host ports 53, 80, and 443; SSH owns port 22 |
| Monitoring | Prometheus and Grafana bind only to `127.0.0.1` |
| AI | `AI_SEMANTIC_ENABLED=false`; Ollama is not running |

Runtime image identities:

| Service | Runtime image identity |
| --- | --- |
| Backend | `sha256:0d9d8091880d2512c89bd8b6fcf074ca3a09e8342d66453aa0ead2eb385b62a4` |
| Frontend | `sha256:ab4b13e44ac48ba475b2ac60b166b1d9ad1021cba0e31348e0022d53a93f8aa7` |
| cloudflared | `sha256:4f6655284ab3d252b7f28fedb19fe6c8fc82ee5b1295c20ac74d475e5398a52d` |
| Prometheus | `sha256:69f5241418838263316593f7274a304b095c40bcf22e57272865da91bd60a8ac` |
| Grafana | `sha256:121a7a9ece6dc10b969f1f96eed64b4f07dfac0d0b8abc070f7cb83bbde86f63` |

The backend and frontend are locally built images, so their image IDs are the
deployable identities. The other images are pinned by registry digest.

### External services

| Service | Identifier and observed state |
| --- | --- |
| Public DNS | `secure-inbox.app`, Cloudflare nameservers `aaden.ns.cloudflare.com` and `ryleigh.ns.cloudflare.com` |
| Cloudflare | Tunnel `c02839b0-4ff7-43a0-bc33-91596c5f415b`; `/api/v1/ready` returned HTTP 200 without an Access challenge |
| MongoDB Atlas | Host `licenta.krmdknm.mongodb.net`, database `test` |
| Google Cloud | Project `licenta-492320` |
| Gmail Pub/Sub | Topic `projects/licenta-492320/topics/secureinbox-gmail-notifications` |
| Push identity | `gmail-push-invoker@licenta-492320.iam.gserviceaccount.com` |
| Push audience | `https://secure-inbox.app/api/v1/webhooks/gmail` |
| Google OAuth callback | `https://secure-inbox.app/api/v1/mail-accounts/google/callback` |
| GitHub | Public repository, default branch `main`, deployment branch `prod` |

Observed risks that must be reviewed before resuming:

- Cloudflare Access did not protect the public readiness path. Confirm whether
  that is intentional before restoring public ingress.
- An Atlas notice dated 2026-08-05 reported `0.0.0.0/0` network access for the
  production project. Replace it with the narrowest workable allow-list.
- The Gmail token is expired or revoked. Push and 30-minute polling jobs are
  currently failing and require OAuth reconnection after resume.
- UFW is not installed on the Pi. SecureInbox exposes no host ports, but Pi-hole
  and SSH are separate host-level exposure decisions.

## Backups and restore evidence

Recovery artifacts exist in both locations:

- `~/SecureInbox-Recovery/2026-08-18`
- `~/Library/Mobile Documents/com~apple~CloudDocs/SecureInbox-Recovery/2026-08-18`

Both directories contain identical, mode-`600` encrypted copies:

- `pi-root.env.enc`
- `pi-backend.env.production.local.enc`
- `pi-backend.env.production.local.bak-20260811-144542.enc`
- `test-2026-08-18T120856Z.archive.gz.enc`

The old plaintext `.bak` was removed from the Pi only after its encrypted copy
was decrypted and hash-verified. Current `.env` files were also independently
encrypted and verified.

The database archive is 4,829,184 bytes with SHA-256:

```text
af2ade5c3970a10d4c9908be4b6f9cdd57581dc49e7885318e9b0bfb14dc4090
```

Its 8 collections and 1,182 documents were restored into the isolated Atlas
database `secureinbox_restore_drill_20260818`. Per-collection counts matched the
source exactly, after which the drill database was deleted.

Wrapping keys are separate from the artifacts in macOS Keychain:

- `secureinbox-hibernation-env-2026-08-18`
- `secureinbox-hibernation-db-2026-08-18`

The restored backend environment contains `MAIL_TOKEN_ENCRYPTION_KEY`, which is
required to decrypt Gmail OAuth tokens stored in MongoDB. Never store a Keychain
export beside the encrypted artifacts.

Verify an artifact without writing plaintext to disk:

```bash
export SECUREINBOX_DB_WRAP_KEY="$(
  security find-generic-password \
    -a polo -s secureinbox-hibernation-db-2026-08-18 -w
)"

openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 \
  -pass env:SECUREINBOX_DB_WRAP_KEY \
  -in "$HOME/SecureInbox-Recovery/2026-08-18/test-2026-08-18T120856Z.archive.gz.enc" \
  | gzip -t

unset SECUREINBOX_DB_WRAP_KEY
```

## What remains active during the pause

| Item | Current behavior | Hibernated behavior |
| --- | --- | --- |
| Public application | HTTP 200 through Cloudflare | DNS and tunnel configuration remain, but the stopped connector makes the origin unavailable |
| Cloudflare | Domain is on the Free plan | DNS and account remain active; verify renewals and account access monthly |
| Atlas | Production database is active | Database remains until deliberately paused or removed; active tier and billing must be verified in Atlas |
| Google Cloud | Project has Gmail API and Pub/Sub configuration | Resources remain configured; the last billing notice found was past-due on 2026-05-01, with no later resolution notice |
| Gmail jobs | Push enabled; polling every 30 minutes; both currently fail due to revoked OAuth | No application jobs run while backend is stopped |
| GitHub | Actions enabled; Dependabot monthly; 5 open alerts at capture | Event-driven Actions and monthly Dependabot remain active |
| Pi OS | `apt-daily` and `apt-daily-upgrade` timers active | Timers run only while the Pi is powered on |
| Container updates | No Watchtower or DIUN | No automatic container image updates |

Cloudflare Free is confirmed from the provider's 2026-07-22 activation notice.
Atlas tier and the current Google billing-account status cannot be derived from
the runtime. Verify both dashboards before the actual shutdown and record the
result privately. Do not put account numbers or payment data in this repository.

## Current release startup, readiness and optional shutdown

These commands apply after the shared-environment release in PR #95 is promoted.
Before deployment, preserve the previous revision, images and matching encrypted
environment files. Verify recovery access and a recent backup under #77.

Use the root production `.env` with mode `600`, `NODE_ENV=production`,
`COMPOSE_PROJECT_NAME=secureinbox`,
`COMPOSE_FILE=docker-compose.yml:docker-compose.prod.yml`,
`COMPOSE_PROFILES=monitoring` and `SEED_DEMO=false`. Preserve the database URI,
mail-token encryption key, JWT secret and integration credentials during migration.

```bash
cd /opt/secureinbox
test "$(git branch --show-current)" = prod
test -z "$(git status --porcelain)"
test "$(stat -c %a .env)" = 600
git rev-parse HEAD
docker compose --env-file .env config --quiet
docker compose --env-file .env ps
```

Start the reviewed release only after its configuration and recovery checks pass:

```bash
./provision
docker compose --env-file .env exec -T frontend \
  wget -qO- http://backend:5500/api/v1/ready </dev/null
curl --fail --max-time 20 http://127.0.0.1:9090/-/ready
curl --fail --max-time 20 http://127.0.0.1:3000/api/health
curl --fail --max-time 20 https://secure-inbox.app/api/v1/ready
docker compose --env-file .env ps
docker inspect secureinbox-backend-1 secureinbox-frontend-1 \
  --format '{{.Name}} {{.Image}}'
```

Privately inspect backend and tunnel logs for startup, database and scheduler
errors. Do not paste raw logs into public evidence. Verify login and inbox reads;
Gmail reconnection, synchronization and scans are separate controlled actions.

Only if a shutdown is requested, stop ingress first, then the application:

```bash
cd /opt/secureinbox
docker compose --env-file .env stop cloudflared
docker compose --env-file .env stop backend frontend prometheus grafana
docker compose --env-file .env --profile ai stop ollama
docker compose --env-file .env ps --all
```

Do not remove volumes, prune Docker, delete the checkout, or power off the Pi.
Pi-hole and the management network are separate services.

## Rollback across the environment migration

The pre-promotion rollback target is `dd7b89fd2abf731c479439d07cc14d310ba49388`.
It requires its original root `.env` AND `backend/.env.production.local`.
Keep their encrypted backups and the existing images until rollout verification
passes. Rollback does not restore MongoDB or revoke credentials.

After confirming the production worktree is clean, switch to the exact target
without rewriting `prod`:

```bash
cd /opt/secureinbox
test -z "$(git status --porcelain)"
git switch --detach dd7b89fd2abf731c479439d07cc14d310ba49388
```

Restore the two matching environment files from the owner's encrypted backup,
with mode `600`, before executing the legacy commands. Keep the new root config
separately for a future retry. Do not print or commit either configuration.

```bash
docker compose -p secureinbox -f docker-compose.prod.yml \
  -f docker-compose.monitoring.yml config --quiet
docker compose -p secureinbox -f docker-compose.prod.yml \
  -f docker-compose.monitoring.yml up -d --build backend frontend cloudflared prometheus grafana
docker compose -p secureinbox -f docker-compose.prod.yml exec -T frontend \
  wget -qO- http://backend:5500/api/v1/ready </dev/null
curl --fail --max-time 20 https://secure-inbox.app/api/v1/ready
```

The same legacy file selection is required for `ps` and `stop` while that
revision is deployed. To retry promotion, switch back to `prod`, update it using
`git pull --ff-only origin prod`, restore the consolidated root configuration,
and follow the current release procedure. Do not mix old secrets layout with
new Compose files.

## Recovery on a replacement Pi

1. Install Docker and Compose, restore trusted management access, and clone the
   exact reviewed `prod` revision into `/opt/secureinbox`.
2. Andrei retrieves the encrypted environment artifacts and separate wrapping
   keys. Decrypt through the trusted management connection into mode-`600` files.
   Use the environment layout matching the selected revision. Never place
   wrapping keys alongside the database archive.
3. Verify artifact hashes and archive integrity before using them. A successful
   decryption alone does not prove data completeness or encryption-key compatibility.
4. If Atlas is intact, do not overwrite it. If data recovery is needed, restore
   first into a new isolated database using a database-scoped credential. Leave
   the application stopped during the drill; do not connect production schedulers,
   Gmail credentials or mail delivery to the restore target.
5. Compare collection counts, ownership links and latest-scan relationships.
   Check token decryption locally with the matching `MAIL_TOKEN_ENCRYPTION_KEY`
   without displaying plaintext or calling Google. Record only success/failure.
6. Verify application reads through an isolated, side-effect-controlled workflow.
   A normal backend startup is not read-only. #105 owns that supported mode.
7. Record restore duration and backup age. A production data replacement needs
   a separately selected target, a new backup of existing data and an explicit
   recovery decision. This runbook intentionally supplies no automatic
   production `--drop` command.
8. Start the recovered release and verify the readiness and read-only requests
   above. Public ingress must follow the intended Cloudflare policy.

## Outstanding recovery evidence

The August drill proved archive restoration and count parity, not a complete
fresh-session application recovery. #77 remains open for:

- Reverification of the off-device artifacts and key access by the owner.
- A current backup and isolated restore with application reads, relationship
  checks and token-key compatibility, with no live Gmail or mail side effects.
- Measured restore duration and agreed acceptable data-loss/recovery windows.
- A fresh-session run through the revision-specific instructions.
- One agreed retention schedule, verification cadence and failure notification.
  Historical policies conflict; do not delete recovery copies based on either.

## Maintenance cadence

Monthly while the service remains active:

- Review domain expiry, Cloudflare account access, Atlas tier/billing and
  network allow-list, and Google Cloud billing status.
- Review GitHub Dependabot and security alerts. Do not merge directly into
  `prod`; use the normal `main` review and promotion flow.
- Confirm both encrypted artifact locations still exist and their SHA-256
  values match. Confirm both Keychain entries are readable.

At the 2026-11-18 review, and quarterly afterward:

- Boot and patch the Pi through the trusted management path.
- Start SecureInbox, run every health check, and inspect logs.
- Create a fresh encrypted database and environment backup.
- Repeat an isolated restore drill and update the evidence in this document.
- Keep the service online unless a separate shutdown is requested.

## Resume checklist

- [ ] Decide that resume is intentional and name the reviewed `prod` SHA.
- [ ] Confirm the Pi worktree is clean and environment files are mode `600`.
- [ ] Verify Cloudflare, Atlas, Google Cloud, DNS, GitHub, and domain ownership.
- [ ] Remove Atlas `0.0.0.0/0` access or document the justified alternative.
- [ ] Resolve Google Cloud billing status.
- [ ] Apply the reviewed Prometheus 7-day retention change through normal Git
      promotion before recreating monitoring containers.
- [ ] Start services and pass private, monitoring, and public health checks.
- [ ] Reconnect Gmail OAuth and verify polling and push without errors.
- [ ] Keep semantic AI disabled unless Ollama is deliberately restored and tested.
- [ ] Run login, sync, scan, and rollback-readiness checks.
- [ ] Record the deployed SHA, runtime image identities, and new review date.

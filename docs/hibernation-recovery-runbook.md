# Hibernation and recovery runbook

This runbook captures sanitized production evidence. It never contains secret
values. The encrypted recovery artifacts are stored outside the repository.

## Decision

| Field | Value |
| --- | --- |
| Mode | `offline-recoverable` |
| Owner | Andrei Stolojan |
| Decided | 2026-08-18 |
| Review | 2026-11-18 |
| Current state | Online. Preparation is complete, but shutdown still requires explicit authorization. |

`offline-recoverable` was selected because SecureInbox is being deliberately
paused, semantic AI is already disabled, Ollama is stopped, and the configured
Gmail account can no longer sync because its OAuth token was revoked. Leaving
the full application online would retain attack surface and failing scheduled
work without providing the intended service.

Do not archive the repository, delete cloud resources, remove Docker volumes,
or shut down production merely because this decision is recorded.

## Production inventory

Captured on 2026-08-18.

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

## Stop procedure

This procedure stops SecureInbox containers. It does not power off the Pi and
does not modify Pi-hole.

1. Confirm a recent verified backup and a clean production tree:

   ```bash
   cd /opt/secureinbox
   git switch prod
   test -z "$(git status --porcelain)"
   git rev-parse HEAD
   docker compose \
     -f docker-compose.prod.yml \
     -f docker-compose.monitoring.yml config --quiet
   ```

2. Record the current container identities:

   ```bash
   docker compose \
     -f docker-compose.prod.yml \
     -f docker-compose.monitoring.yml ps
   docker inspect secureinbox-backend-1 secureinbox-frontend-1 \
     --format '{{.Name}} {{.Image}}'
   ```

3. Stop ingress first, followed by the application and monitoring:

   ```bash
   docker compose \
     -f docker-compose.prod.yml \
     -f docker-compose.monitoring.yml \
     stop cloudflared backend frontend prometheus grafana ollama

   docker compose \
     -f docker-compose.prod.yml \
     -f docker-compose.monitoring.yml ps --all
   ```

4. From another machine, confirm the public health endpoint no longer returns
   HTTP 200:

   ```bash
   curl --max-time 20 -i https://secure-inbox.app/api/v1/ready
   ```

Never use `docker compose down -v`, `docker volume rm`, `docker system prune`,
or delete `/opt/secureinbox`. Powering off the Pi is a separate operation that
requires explicit authorization.

## Start and health-check procedure

1. Connect through the trusted management path and validate the deployment:

   ```bash
   cd /opt/secureinbox
   git switch prod
   test -z "$(git status --porcelain)"
   git rev-parse HEAD
   docker compose \
     -f docker-compose.prod.yml \
     -f docker-compose.monitoring.yml config --quiet
   ```

2. Start only the services used by the current non-AI configuration:

   ```bash
   docker compose \
     -f docker-compose.prod.yml \
     -f docker-compose.monitoring.yml \
     up -d backend frontend cloudflared prometheus grafana

   docker compose \
     -f docker-compose.prod.yml \
     -f docker-compose.monitoring.yml ps
   ```

3. Check private, monitoring, and public health:

   ```bash
   docker compose -f docker-compose.prod.yml exec -T frontend \
     wget -qO- http://backend:5500/api/v1/ready </dev/null
   curl --fail http://127.0.0.1:9090/-/ready
   curl --fail http://127.0.0.1:3000/api/health
   curl --fail https://secure-inbox.app/api/v1/ready
   ```

4. Inspect failures without printing environment values:

   ```bash
   docker compose -f docker-compose.prod.yml logs --tail=200 backend frontend cloudflared
   ```

Reconnect the Gmail account through the UI before expecting sync or push to
work. If semantic AI is deliberately re-enabled, start Ollama and verify its
model separately.

## Application rollback

Do not rewrite the `prod` branch on the Pi. Deploy a known reviewed revision in
detached mode, keeping the branch recoverable:

```bash
cd /opt/secureinbox
test -z "$(git status --porcelain)"
git fetch origin

ROLLBACK_SHA=REVIEWED_PROD_SHA
git cat-file -e "${ROLLBACK_SHA}^{commit}"
git switch --detach "$ROLLBACK_SHA"

docker compose -f docker-compose.prod.yml config --quiet
docker compose -f docker-compose.prod.yml build
docker compose \
  -f docker-compose.prod.yml \
  -f docker-compose.monitoring.yml up -d
docker compose \
  -f docker-compose.prod.yml \
  -f docker-compose.monitoring.yml ps
```

Run every health check above. To return to the deployment branch:

```bash
git switch prod
git pull --ff-only origin prod
```

An application rollback does not roll back MongoDB. Restore the database only
when a verified data or schema problem requires it.

## Recovery on a replacement Pi

On the replacement Pi:

```bash
sudo mkdir -p /opt/secureinbox
sudo chown "$USER":"$USER" /opt/secureinbox
git clone --branch prod \
  https://github.com/AndreiStolojan/SecureInbox.git \
  /opt/secureinbox
```

From the Mac that owns the Keychain entries:

```bash
PI_HOST=TRUSTED_SSH_HOST
RECOVERY_DIR="$HOME/SecureInbox-Recovery/2026-08-18"

export SECUREINBOX_ENV_WRAP_KEY="$(
  security find-generic-password \
    -a polo -s secureinbox-hibernation-env-2026-08-18 -w
)"

openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 \
  -pass env:SECUREINBOX_ENV_WRAP_KEY \
  -in "$RECOVERY_DIR/pi-root.env.enc" \
  | ssh "$PI_HOST" 'install -m 600 /dev/stdin /opt/secureinbox/.env'

openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 \
  -pass env:SECUREINBOX_ENV_WRAP_KEY \
  -in "$RECOVERY_DIR/pi-backend.env.production.local.enc" \
  | ssh "$PI_HOST" \
      'install -m 600 /dev/stdin /opt/secureinbox/backend/.env.production.local'

unset SECUREINBOX_ENV_WRAP_KEY
```

Restore MongoDB only after confirming the archive date and stopping the backend:

```bash
RECOVERY_DIR="$HOME/SecureInbox-Recovery/2026-08-18"
CONFIRM_REPLACE=restore-production-2026-08-18
test "$CONFIRM_REPLACE" = restore-production-2026-08-18

export SECUREINBOX_ENV_WRAP_KEY="$(
  security find-generic-password \
    -a polo -s secureinbox-hibernation-env-2026-08-18 -w
)"
export SECUREINBOX_DB_WRAP_KEY="$(
  security find-generic-password \
    -a polo -s secureinbox-hibernation-db-2026-08-18 -w
)"

DB_URI="$(
  openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 \
    -pass env:SECUREINBOX_ENV_WRAP_KEY \
    -in "$RECOVERY_DIR/pi-backend.env.production.local.enc" \
    | sed -n 's/^DB_URI="\{0,1\}\([^"[:space:]]*\)"\{0,1\}$/\1/p'
)"
test -n "$DB_URI"

openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 \
  -pass env:SECUREINBOX_DB_WRAP_KEY \
  -in "$RECOVERY_DIR/test-2026-08-18T120856Z.archive.gz.enc" \
  | mongorestore "$DB_URI" --archive --gzip --drop --nsInclude 'test.*'

unset DB_URI SECUREINBOX_ENV_WRAP_KEY SECUREINBOX_DB_WRAP_KEY
```

Then follow the start and health-check procedure. Confirm login, Gmail OAuth
reconnection, one inbox sync, and one representative scan.

## Maintenance cadence

Monthly while paused:

- Review domain expiry, Cloudflare account access, Atlas tier/billing and
  network allow-list, and Google Cloud billing status.
- Review GitHub Dependabot and security alerts. Do not merge directly into
  `prod`; use the normal `main` review and promotion flow.
- Confirm both encrypted artifact locations still exist and their SHA-256
  values match. Confirm both Keychain entries are readable.

At the 2026-11-18 review, and every quarter if the pause continues:

- Boot and patch the Pi through the trusted management path.
- Start SecureInbox, run every health check, and inspect logs.
- Create a fresh encrypted database and environment backup.
- Repeat an isolated restore drill and update the evidence in this document.
- Stop the stack again only after the new evidence passes.

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

# Raspberry Pi production deployment

Production and development use the same source and Compose base. The root `.env`
selects the production overlay, Atlas database, and separate runtime name.
See [environment configuration](environments.md) for the complete variable list.

```text
Browser -> Cloudflare -> cloudflared -> nginx -> Express -> MongoDB Atlas
                                                |
                                                +-> Ollama
```

The production Compose file publishes no host ports. Cloudflare Tunnel is the
only ingress; do not configure router port forwarding.

## Prerequisites

- Raspberry Pi OS Lite 64-bit on a cooled Pi with reliable storage and power
- Docker Engine plus the Compose plugin (`docker compose version`)
- MongoDB Atlas database, least-privileged database user, and a `/32` Atlas IP allow-list entry for the Pi
- Cloudflare-managed domain and a remotely managed tunnel
- Google OAuth web client with Gmail API enabled, if Gmail is used

Verify `dpkg --print-architecture` prints `arm64` and `docker run --rm hello-world`
works without `sudo`.

## Install the reviewed production revision

```bash
sudo mkdir -p /opt/secureinbox
sudo chown "$USER":"$USER" /opt/secureinbox
git clone --branch prod https://github.com/AndreiStolojan/SecureInbox.git /opt/secureinbox
cd /opt/secureinbox
git status --short --branch
git rev-parse HEAD
```

`prod` is the deployment branch. It must point to a reviewed, tested revision;
the Pi must never pull `main` as part of a routine update.

## Configure secrets

Use one root configuration:

```bash
cp .env.example .env
chmod 600 .env
```

Apply the production values from [environments.md](environments.md). Keep the
existing Atlas URI, JWT secret, Gmail encryption key, OAuth credentials, and
tunnel token when migrating. The tunnel service remains `http://frontend:80`.
For a new installation, generate unique secrets with `openssl rand -hex 32`.

## Proxy and rate-limit identity

Production mounts `frontend/nginx.prod.conf`. The production-only `edge`
network has cloudflared as nginx's only peer; nginx resolves and trusts that
service name for `CF-Connecting-IP`, then replaces rather than appends the
forwarded client-IP chain. It forwards that client IP and `https` to the
backend, so Express's single trusted nginx hop keeps distinct public visitors
in distinct rate-limit buckets. Only optional monitoring publishes loopback ports, so the
backend and nginx are reachable only through the private Compose network and
cloudflared.

## Validate and start

```bash
docker compose config --quiet
./provision
docker compose ps
```

Ollama is optional. Enable the `ai` profile before running provisioning if the
Pi should host the model. Monitoring uses the separate `monitoring` profile.

### Choosing the model

`qwen2.5:7b-instruct` is 4.7 GB on disk and needs roughly 6 GB resident, so it
suits an 8 GB or 16 GB Pi 5 and not a 4 GB one. The size matters more than it
looks. Measured with `npm run eval:semantic` over the 40-message labelled corpus
in `backend/tests/fixtures/semantic-eval.fixtures.js`, on identical code and the
same prompt:

| | `qwen2.5:1.5b-instruct-q4_K_M` | `qwen2.5:7b-instruct` |
| --- | --- | --- |
| false positives on legitimate mail | 0% | 0% |
| signal accuracy | 15% | 85% |
| useful signal on malicious mail | 10% | 90% |

At 1.5B the semantic layer is effectively inert: it is quiet on benign mail only
because it has stopped discriminating at all, and it contributes nothing on real
phishing. It is harmless but not worth its latency. Prefer 7B wherever the RAM
allows, and re-run the evaluation after any prompt change:

```bash
cd backend && OLLAMA_MODEL=qwen2.5:7b-instruct npm run eval:semantic
```

`OLLAMA_TIMEOUT_MS` defaults to 300000 (5 minutes) because a 7B model on Pi 5
CPU is far slower than on a laptop. Scanning runs in the background, so latency
costs throughput rather than interactivity.

Check private health endpoints and then the public hostname:

```bash
docker compose exec frontend wget -qO- http://backend:5500/api/v1/ready
curl -i https://YOUR_HOSTNAME/api/v1/ready
```

## Promote and update safely

Test changes on a branch and merge them to `main`. After the CI production
Compose validation gate passes, open a separate PR from the selected `main` revision
into `prod`; require the Quality check and human review before merging that PR.
Then update the Pi only from `prod`:

```bash
cd /opt/secureinbox
git fetch origin
git switch prod
git pull --ff-only origin prod
docker compose build --pull
docker compose up -d
docker compose ps
```

Record `git rev-parse HEAD` after each deployment. Stop if the working tree is
not clean; do not resolve local changes by pulling `main`.

CI verifies the promotion inputs only. Rollout remains a manual Pi operation
until dedicated deployment infrastructure is introduced.

## Backups and maintenance

Atlas backups protect the database, but Gmail OAuth tokens stored there cannot
be recovered without the matching `MAIL_TOKEN_ENCRYPTION_KEY`. Keep encrypted,
access-controlled backups of `.env` separately from the database backup. Test a
restore before relying on it.

Regularly check `docker compose ps`, disk space,
Pi temperature, tunnel status, Atlas access rules, and container logs. Keep
the OS and Docker patched.

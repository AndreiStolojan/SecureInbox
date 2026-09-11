# Development and deployment

One source tree and one environment schema serve both modes. Production runs
built images, so editing development source does not change the running release.
Use a separate `.env` per running environment. Never commit credentials.

## Development on Pi or Mac

Run `./provision`. The generated root `.env` selects `secureinbox-dev`, local
MongoDB, and a six-message demo inbox. The app listens on loopback port 8080;
MongoDB listens on loopback port 27018. Production has its own containers and data.
Re-running provisioning updates images and the demo account; other messages remain.

For hot reload, update the root `.env` URLs to the Vite origin first:

```dotenv
FRONTEND_APP_URL=http://localhost:5173
GOOGLE_REDIRECT_URI=http://localhost:5173/api/v1/mail-accounts/google/callback
```

Register that callback separately with Google if testing Gmail OAuth. Keep only
MongoDB in Docker and run the app with Node and Vite:

```bash
docker compose stop frontend backend
docker compose up -d mongodb
npm ci --prefix backend
npm ci --prefix frontend
npm run dev --prefix backend
# Another terminal:
npm run dev --prefix frontend
```

Use Node 24.20 or newer in the Node 24 line. The backend reads the root `.env`,
derives the local MongoDB URI, and watches source changes with Node's built-in
watcher. Vite uses the root `PORT` to reach the backend. Open localhost:5173.
Restart development processes after changing `.env`. When returning to the
container app, change both URLs back to port 8080 before running `./provision`.

From a laptop, `ssh -L 8080:127.0.0.1:8080 polo@<pi-address>` gives access to the
container app; forward 5173 instead for Vite. Neither endpoint is public.

## Atlas for development

Create a separate Atlas database and a database user restricted to that database.
Do not reuse the production database or production OAuth tokens. Set:

```dotenv
NODE_ENV=development
COMPOSE_PROJECT_NAME=secureinbox-dev
COMPOSE_FILE=docker-compose.yml
COMPOSE_PROFILES=
DB_URI=mongodb+srv://DEV_USER:URL_ENCODED_PASSWORD@YOUR_CLUSTER/secureinbox_test
SEED_DEMO=true
```

Run `./provision`, or the native commands above without starting MongoDB.
Development requires a database name ending in `_dev`, `-dev`, `_test`, or `-test`.
The name check catches mistakes; Atlas user permissions enforce access isolation.
Seeding additionally requires `SEED_DEMO=true` and refuses production.

## Optional services

Add `ai` to `COMPOSE_PROFILES` and set `AI_SEMANTIC_ENABLED=true` for local Ollama.
Provisioning pulls `OLLAMA_MODEL` only when the `ai` profile is active. For an
existing Ollama host, set `OLLAMA_BASE_URL` without enabling the profile.

Add `monitoring` to start Prometheus and Grafana. Development defaults to ports
9091 and 3001 so production can keep 9090 and 3000. For example:
`COMPOSE_PROFILES=local-db,ai,monitoring`.

When removing a profile, stop its services first, for example
`docker compose --profile ai stop ollama`. Changing profiles does not remove
previously started containers or their volumes.

## Production

Copy `.env.example` to the production configuration and set:

```dotenv
NODE_ENV=production
COMPOSE_PROJECT_NAME=secureinbox
COMPOSE_FILE=docker-compose.yml:docker-compose.prod.yml
COMPOSE_PROFILES=monitoring
DB_URI=mongodb+srv://PROD_USER:URL_ENCODED_PASSWORD@YOUR_CLUSTER/secureinbox
FRONTEND_APP_URL=https://YOUR_HOSTNAME
GOOGLE_REDIRECT_URI=https://YOUR_HOSTNAME/api/v1/mail-accounts/google/callback
SEED_DEMO=false
PROMETHEUS_PORT=9090
GRAFANA_PORT=3000
```

Fill the tunnel token, existing encryption/JWT secrets, Google credentials and
email delivery credentials. Preserve `MAIL_TOKEN_ENCRYPTION_KEY` exactly when
migrating an installation, because it decrypts stored Gmail tokens. Production
provisioning validates existing values and never generates replacement secrets.
The application is accessible through Cloudflare Tunnel, with no published app
or MongoDB port. Monitoring is loopback-only.

`./provision` works in both modes. To keep development `.env` active and use a
separate production config, use the same file for every Compose command:

```bash
PROVISION_ENV_FILE=/path/to/production.env ./provision
docker compose --env-file /path/to/production.env ps
```

Compose 2.24.4 or newer is required for the production overlay. The `prod`
branch remains an approval gate, not a different implementation. Promote tested
`main` through the protected PR before replacing the deployed images.
See [the deployment guide](raspberry-pi-deployment.md).

## Backups

`scripts/backup` and `scripts/restore` operate on the local MongoDB service and
honor `PROVISION_ENV_FILE`. Atlas backup/restore uses Atlas tooling. Store the
matching encryption key separately from database backups. Never restore
production data into development automatically.

## Native development without Docker

Use Node 24.20 or newer in the Node 24 line and npm with the committed lockfiles.
There is no Bun or pnpm migration. Supply either a native MongoDB server or an
Atlas database restricted to development, with a name ending in `_dev` or `_test`.
No Docker service is required when that database already exists.

From a clean checkout, create a private root configuration without overwriting
an existing environment:

```bash
umask 077
cp -n .env.example .env.native.local
node --input-type=module <<'JS'
import { readFileSync, writeFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
const path = '.env.native.local';
const text = readFileSync(path, 'utf8').replaceAll('replace-with-a-generated-value',
  () => randomBytes(32).toString('hex'));
writeFileSync(path, text, { mode: 0o600 });
JS
```

Edit that private file: set `DB_URI` to the isolated database, `SEED_DEMO=false`,
`COMPOSE_PROFILES=`, `PORT=5501`, `FRONTEND_APP_URL=http://localhost:5173` and
`GOOGLE_REDIRECT_URI=http://localhost:5173/api/v1/mail-accounts/google/callback`.
Leave OAuth, SMTP, Arcjet and reputation keys blank unless testing that integration.
Set `AI_SEMANTIC_ENABLED=false` when Ollama is unavailable; local rules still work.
For Gmail testing, register the local redirect in a separate OAuth client and use
a test mailbox. An ordinary development server runs the synchronization/digest/watch
schedulers; it must never point at a shared production database.

Run from the repository root in separate terminals:

```bash
npm ci --prefix backend
npm ci --prefix frontend
ENV_FILE="$PWD/.env.native.local" npm run dev --prefix backend
```

```bash
PORT=5501 npm run dev --prefix frontend
```

Open `http://localhost:5173`, register a development user and log in normally.
If synthetic demo data is desired, set `SEED_DEMO=true` and run
`ENV_FILE="$PWD/.env.native.local" npm run seed:local --prefix backend` once.
Configure a generated `DEMO_USER_PASSWORD` in the private file before seeding.

```bash
curl --fail --max-time 5 http://127.0.0.1:5501/api/v1/ready
curl --fail --max-time 5 http://127.0.0.1:5173/api/v1/ready
```

Both servers bind loopback. Press Ctrl-C in both terminals to stop them. The
backend stops its schedulers, drains queued Gmail work and disconnects MongoDB;
its shutdown deadline is ten seconds. The external MongoDB server remains running.

## Inspect shared data without writes

Use the same native server with `APP_READ_ONLY=true` in `.env.native.local` and
a separate Atlas credential granted only the `read` role on the inspected database.
Use a fresh local `JWT_SECRET` generated above, never the production signing key.
Keep the local generated `MAIL_TOKEN_ENCRYPTION_KEY`; reading stored messages does
not require decrypting Gmail tokens. Do not copy production OAuth, tunnel, SMTP,
Arcjet or provider credentials. Do not seed shared data.

The development database-name check permits shared names only in this mode.
Database permissions are a second boundary: the inspection credential must have
no write or administrative roles. This mode is rejected under `NODE_ENV=production`
and forces the native backend to bind `127.0.0.1`, regardless of `APP_HOST`.
It is deliberately not passed into production Compose containers.

Log in using the existing SecureInbox account password. Login checks the stored
password hash and issues a token signed by the local key; it does not write data
or call Arcjet. This local token is not valid in production. If the password is
unavailable, recover access separately; do not add a bypass or paste a production
token into a script.

The server disables scheduled synchronization, digests, watch renewal, Gmail push
handling, and Mongoose automatic index/collection creation. An explicit route list
allows login, readiness, the current user's profile, inbox/details/raw stored data,
scan results, mail-account summaries, reports, sender counts and metadata reads.
All other routes, including OAuth GET callbacks, return `403 READ_ONLY_MODE` before
handlers run. New routes must be reviewed before being allowed. UI mutation buttons
remain visible and receive that error; no new UI was introduced.

Read-only is a server/data boundary, not browser network isolation. Existing HTML
sanitization and remote-image blocking still apply; clicking an external link is
an explicit browser action. Log out of the inspection session afterward to remove its local token. Keep any exported private data out of commits and public reports.

### Verification, 2026-09-11

On Linux ARM64 with Node 24.20.0, the native server was exercised against MongoDB
8.0.28 using a database-scoped `read` credential and synthetic user/email records.
Login and eight authenticated read routes succeeded; mutation and OAuth callbacks
returned 403. Collection contents, collection inventory and indexes matched before
and after. The backend forced loopback despite `APP_HOST=0.0.0.0`, started no
schedulers, and exited with code zero on SIGTERM.

The documented `npm run dev` commands served Vite and proxied backend readiness;
both process groups stopped on Ctrl-C. The test database ran in a disposable
container solely for validation and was removed afterward. The application
processes were native, and neither Atlas nor live Gmail was accessed. Backend
and frontend clean installs, tests, lint/build and provisioning checks passed.

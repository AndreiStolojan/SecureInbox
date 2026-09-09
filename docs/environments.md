# Development and deployment

One source tree and one environment schema serve both modes. Production runs
built images, so editing development source does not change the running release.
Use a separate `.env` per running environment. Never commit credentials.

## Development on Pi or Mac

Run `./provision`. The generated root `.env` selects `secureinbox-dev`, local
MongoDB, and a six-message demo inbox. The app listens on loopback port 8080;
MongoDB listens on loopback port 27018. Production has its own containers and data.
Re-running provisioning updates images and the demo account; other messages remain.

For hot reload, keep only MongoDB in Docker and run the app with Node and Vite:

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
Restart development processes after changing `.env`.

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

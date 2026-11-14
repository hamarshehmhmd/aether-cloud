# Aether Cloud

Central service for Aether self-hosted deployments. Provides:

- **License validation** — `GET /licenses/validate`
- **Token proxy** — `GET /github/token?installation_id=X` (GitHub App private key lives here only)
- **Webhook relay** — `POST /webhooks/github` → forwards to self-hosted instances
- **Installation registration** — `POST /installations/register`
- **Admin** — `POST /admin/licenses` (create license keys)

## Setup

```bash
cp .env.example .env
# Fill in GITHUB_APP_ID, GITHUB_PRIVATE_KEY, GITHUB_WEBHOOK_SECRET, ADMIN_API_KEY
poetry install
make upgrade   # run DB migrations
make dev       # start on :8001
```

## Self-Hoster Onboarding

1. Look up the customer's numeric GitHub account ID: `curl https://api.github.com/orgs/{org}` (or `/users/{user}`) → `id`
   Generate license: `POST /admin/licenses` with `customer_email` + `github_account_id` → returns `license_key` (shown once, store it)
2. Send `license_key` to customer
3. Customer installs official Aether GitHub App on their org → GitHub creates `installation_id`
4. Customer sets `AETHER_LICENSE_KEY={license_key}` in their `bangalore/.env`
5. Customer calls `POST /installations/register` with `installation_id` + `relay_url`
   (rejected with 403 unless GitHub reports the installation belongs to the license's `github_account_id`)
6. Set returned `relay_secret` as `AETHER_RELAY_SECRET` in `bangalore/.env`
7. On GitHub App settings → set Webhook URL to `https://api.tryaether.io/webhooks/github`
8. Done — events flow: GitHub → aether-cloud → self-hosted instance

## Environment Variables

See `.env.example`. Required at startup: `GITHUB_APP_ID`, `GITHUB_PRIVATE_KEY`, `GITHUB_WEBHOOK_SECRET`, `ADMIN_API_KEY` (min 32 chars).

## Admin Endpoints

All `/admin/*` routes require `Authorization: Bearer {ADMIN_API_KEY}`.

```bash
# Create a license
curl -X POST https://api.tryaether.io/admin/licenses \
  -H "Authorization: Bearer $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"customer_email": "customer@example.com", "github_account_id": 123456}'

# List all licenses
curl https://api.tryaether.io/admin/licenses \
  -H "Authorization: Bearer $ADMIN_API_KEY"

# Revoke a license
curl -X DELETE https://api.tryaether.io/admin/licenses/{id} \
  -H "Authorization: Bearer $ADMIN_API_KEY"
```

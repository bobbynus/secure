# secure.abramov.vip

Multilingual (RU / DE / EN) radar of IT security events and problematic updates for system and network administrators.
Project plan: [`secure-abramov-project-plan.md`](secure-abramov-project-plan.md).

## Layout

| Path | What |
|---|---|
| `site/` | Astro static site (feed, articles, products, archive, RSS, sitemap) |
| `data/events/*.json` | Published events, one file per event (written by the pipeline; currently demo content) |
| `data/products.json`, `data/sources.json` | Product catalog and source coverage catalog |
| `.github/ISSUE_TEMPLATE/source-suggestion.yml` | "+ Source" form (MVP) |
| `.github/workflows/deploy.yml` | Build + deploy to Cloudflare Workers static assets |
| `worker/` | Cloudflare Worker for `/api/*`: stats, source suggestions → GitHub issues, Web Push (D1 `secure-db`) |
| `worker/migrations/` | D1 schema migrations |
| `wrangler.jsonc` | Cloudflare config: assets, Worker, D1, rate limits, cron, `secure.abramov.vip` |

## Develop

```sh
cd site
npm ci
npx astro dev          # http://localhost:4321/ru/
npx astro check        # types + content schema
npx astro build        # → site/dist (incl. _redirects, _headers)
```

Content is validated against the schema in `site/src/content.config.ts` at build time; an invalid event fails the build.
Only translations with `"status": "ready"` are published.

`SITE.demo` in `site/src/config.ts` keeps the site in demo mode (banner, `noindex`, `Disallow: /`).

## Worker / API (variant B)

```sh
npm ci                      # root: wrangler, typescript, workers types
npm run db:migrate:local
npx wrangler dev            # site + /api on http://localhost:8787 (needs site/dist)
node --test worker/test/    # Web Push crypto round-trip etc.
```

Local secrets go to `.dev.vars` (gitignored). Production secrets (`wrangler secret put <NAME>`):

| Secret | Purpose |
|---|---|
| `VAPID_PRIVATE_JWK` | VAPID private key (JWK). Public key is `VAPID_PUBLIC_KEY` in `wrangler.jsonc` |
| `DISPATCH_TOKEN` | Bearer token for `/api/push/dispatch` and `/api/push/pause`; same value as GitHub secret `DISPATCH_TOKEN` |
| `GITHUB_TOKEN` | Fine-grained PAT, *Issues: read & write* on `bobbynus/secure` only — on-site suggestion form |
| `TURNSTILE_SECRET` | Optional Cloudflare Turnstile secret (+ `turnstileSiteKey` in `site/src/config.ts`) |

Stop all push delivery: `curl -X POST -H "Authorization: Bearer $DISPATCH_TOKEN" -H "Content-Type: application/json" -d '{"paused":true}' https://secure.abramov.vip/api/push/pause`.

## Deploy

`npm run deploy` from the repo root, or push to `main` with `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` repository secrets set.
CI: checks → build → D1 migrations → deploy → verify published URLs → push dispatch.

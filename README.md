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
| `wrangler.jsonc` | Cloudflare config (`secure.abramov.vip` custom domain) |

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

## Deploy

`npx wrangler deploy` from the repo root, or push to `main` with `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` repository secrets set.

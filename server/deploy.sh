#!/usr/bin/env bash
# Сборка сайта и деплой на Cloudflare прямо с сервера (раньше — workflow deploy.yml на каждый коммит событий).
. "$(dirname "$0")/common.sh"
exec 8>/tmp/secure-deploy.lock
flock 8
LOG="$LOGS/deploy.log"
SITE=https://secure.abramov.vip
{
  set -e
  echo "=== $(date '+%F %T') деплой $(git rev-parse --short HEAD)"
  [ -n "${CLOUDFLARE_API_TOKEN:-}" ] || { echo "нет CLOUDFLARE_API_TOKEN — деплой пропущен"; exit 1; }
  # зависимости — только если поменялись lock-файлы
  sum=$(cat package-lock.json site/package-lock.json | sha256sum | cut -c1-16)
  if [ "$(cat "$BASE/.npm-sum" 2>/dev/null)" != "$sum" ] || [ ! -d node_modules ] || [ ! -d site/node_modules ]; then
    npm ci --silent && npm ci --silent --prefix site && echo "$sum" > "$BASE/.npm-sum"
  fi
  npx tsc -p worker
  (cd site && npx astro build)
  npx wrangler d1 migrations apply secure-db --remote
  npx wrangler deploy
  sleep 10
  for p in / /ru/ /de/ /en/ /en/rss.xml /api/health; do
    curl -fsS -o /dev/null --retry 5 --retry-delay 5 --retry-all-errors "$SITE$p"
  done
  if [ -n "${DISPATCH_TOKEN:-}" ]; then
    curl -fsS -o /dev/null -X POST -H "Authorization: Bearer $DISPATCH_TOKEN" "$SITE/api/push/dispatch" || echo "push-рассылка не прошла"
  fi
  echo "=== готово"
} >>"$LOG" 2>&1

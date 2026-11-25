#!/usr/bin/env bash
# Установка сборщика secure.abramov.vip на сервер worker. Запускать от root:
#   bash /srv/secure/app/server/install.sh
# Повторный запуск ничего не ломает.
set -euo pipefail
APP="$(cd "$(dirname "$0")/.." && pwd)"
BASE="$(dirname "$APP")"
U=secure
say() { printf '\n\033[1;32m==> %s\033[0m\n' "$*"; }
[ "$(id -u)" = 0 ] || { echo "запустите от root"; exit 1; }

say "Пользователь $U и папки"
id $U >/dev/null 2>&1 || useradd -m -s /bin/bash $U
mkdir -p "$BASE/logs"
chown -R $U:$U "$BASE"

as() { sudo -u $U -H bash -lc "$*"; }

say "Python: окружение сборщика"
as "python3 -m venv '$BASE/venv' && '$BASE/venv/bin/pip' install -q -r '$APP/pipeline/requirements.txt'"

say "Состояние сборщика (последнее с ветки pipeline-state на GitHub — один раз)"
if [ ! -d "$BASE/state/.git" ]; then
  as "git clone -q --depth 1 -b pipeline-state https://github.com/bobbynus/secure '$BASE/state' && git -C '$BASE/state' remote remove origin"
fi

say "Node: зависимости сайта"
as "cd '$APP' && npm ci --silent && npm ci --silent --prefix site"

say "Секреты"
if [ ! -f "$BASE/.env" ]; then cp "$APP/server/env.example" "$BASE/.env"; echo "Создан $BASE/.env — впишите секреты"; fi
chown $U:$U "$BASE/.env"; chmod 600 "$BASE/.env"

say "Расписание (cron пользователя $U): сбор в :07 и :37"
( crontab -u $U -l 2>/dev/null | { grep -v 'server/collect.sh' || true; } ; echo "7,37 * * * * $APP/server/collect.sh" ) | crontab -u $U -
crontab -u $U -l

cat <<MSG

Готово. Дальше:
  1. nano $BASE/.env            — секреты (см. $APP/server/README.md)
  2. su - $U -c '$APP/server/collect.sh' ; tail -40 $BASE/logs/collect.log   — первый прогон вручную
  3. один раз отключить старый «запасной запуск» GitHub в Worker'е сайта:
     su - $U -c 'cd $APP && set -a && . $BASE/.env && set +a && echo y | npx wrangler secret delete COLLECT_TOKEN'
MSG

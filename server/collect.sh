#!/usr/bin/env bash
# Сбор источников → тексты нейросети → публикация событий → деплой сайта (если что-то изменилось).
# cron каждые 30 минут. Раньше это делал workflow collect.yml на GitHub Actions — он удалён (риск блокировки GitHub).
. "$(dirname "$0")/common.sh"
exec 9>/tmp/secure-collect.lock
flock -n 9 || exit 0
LOG="$LOGS/collect.log"
{
  echo "=== $(date '+%F %T')"
  # 1. свежий код с GitHub (только чтение; события в data/events живут здесь и на GitHub не коммитятся)
  before=$(git rev-parse HEAD)
  git pull -q --ff-only --autostash origin main || echo "::git pull не удался — работаю на текущем коде"
  after=$(git rev-parse HEAD)
  [ "$before" != "$after" ] && { echo "код обновлён: $before → $after"; touch "$BASE/.need-deploy"; \
    "$BASE/venv/bin/pip" install -q -r pipeline/requirements.txt; }

  # 2. сбор
  (cd pipeline && timeout 35m python -m secure_pipeline --state "$STATE" collect)
  rc=$?
  save_state

  # 3. тексты и переводы (сбой не теряет собранное)
  args=(); [ "${PUBLISH_ENABLED:-}" = "true" ] && args+=(--publish)
  (cd pipeline && timeout 25m python -m secure_pipeline --state "$STATE" ai "${args[@]}") || echo "::AI-шаг не удался"
  save_state

  # 4. публикация событий в data/events → деплой, если файлы изменились
  if [ "${PUBLISH_ENABLED:-}" = "true" ]; then
    (cd pipeline && python -m secure_pipeline --state "$STATE" publish --out ../data/events)
    # события не коммитим (иначе локальная ветка разойдётся с GitHub и код перестанет обновляться):
    # изменения ловим по отпечатку папки; история событий — в состоянии $STATE
    sum=$(cd data/events && find . -type f -name '*.json' -print0 | sort -z | xargs -0 sha1sum | sha1sum | cut -c1-16)
    if [ "$(cat "$BASE/.events-sum" 2>/dev/null)" != "$sum" ]; then
      echo "события изменились"
      echo "$sum" > "$BASE/.events-sum"
      touch "$BASE/.need-deploy"
    fi
  fi
  if [ -f "$BASE/.need-deploy" ]; then
    if "$APP/server/deploy.sh"; then rm -f "$BASE/.need-deploy"; resolved deploy
    else notify deploy "⚠️ secure.abramov.vip: деплой сайта не прошёл. Лог: $LOGS/deploy.log"; fi
  fi

  # 5. статус сборщика для сайта и проверка свежести (раньше — freshness.yml)
  (cd pipeline && python -m secure_pipeline --state "$STATE" push-status) || echo "::push-status не прошёл"
  if (cd pipeline && python -m secure_pipeline --state "$STATE" health --max-age 3h); then resolved stale
  else notify stale "⚠️ secure.abramov.vip: последний успешный сбор старше 3 часов. Лог: $LOG"; fi
  [ $rc = 0 ] && resolved collect || notify collect "⚠️ secure.abramov.vip: сбор упал (код $rc). Лог: $LOG"
  echo "=== код $rc"
} >>"$LOG" 2>&1
[ "$(stat -c %s "$LOG" 2>/dev/null || echo 0)" -gt 5000000 ] && tail -c 2000000 "$LOG" > "$LOG.tmp" && mv "$LOG.tmp" "$LOG"
exit 0

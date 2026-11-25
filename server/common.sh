# Общее для скриптов сборщика: пути, секреты, журнал, оповещения.
set -uo pipefail
APP="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE="${SECURE_BASE:-$(dirname "$APP")}"
STATE="$BASE/state"
LOGS="$BASE/logs"
mkdir -p "$LOGS"
export PATH="$BASE/venv/bin:$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin"
export PYTHONUNBUFFERED=1 TZ=Europe/Berlin
if [ -f "$BASE/.env" ]; then set -a; . "$BASE/.env"; set +a; fi
cd "$APP" || exit 1

notify() {  # сообщение владельцу; одна и та же тема — не чаще раза в 6 часов
  local key="$1" text="$2" mark="$BASE/.notified-$1"
  [ -n "${TG_BOT_TOKEN:-}" ] && [ -n "${TG_CHAT_ID:-}" ] || { echo "notify: нет TG_BOT_TOKEN/TG_CHAT_ID"; return 0; }
  if [ -f "$mark" ] && [ $(( $(date +%s) - $(stat -c %Y "$mark") )) -lt 21600 ]; then return 0; fi
  curl -fsS -o /dev/null --max-time 20 "https://api.telegram.org/bot${TG_BOT_TOKEN}/sendMessage" \
    --data-urlencode "chat_id=${TG_CHAT_ID}" --data-urlencode "text=${text}" && touch "$mark"
}
resolved() { rm -f "$BASE/.notified-$1"; }

save_state() {  # история состояния — локально в $STATE (это git); наружу ничего не уходит
  git -C "$STATE" add -A >/dev/null 2>&1
  git -C "$STATE" -c user.name="secure-collector" -c user.email="collector@worker.local" \
    commit -qm "state: $(date -u +%Y-%m-%dT%H:%MZ)" >/dev/null 2>&1 || true
}

# Сборщик secure.abramov.vip на сервере worker

С 25.11.2026 сбор источников, тексты нейросети, публикация событий и деплой сайта работают **не на GitHub Actions**,
а на сервере владельца `worker` (LXC на Proxmox, общий для автоматизаций). Причина: соседний репозиторий
bobbynus/tut.dus GitHub заблокировал 20.11.2026 за похожую автоматику (сбор по расписанию + поток автоматических
коммитов). На GitHub остались только разрешённые вещи: код, тесты при изменениях (`pipeline-ci.yml`), ручная
оценка ИИ (`ai-eval.yml`) и ручной деплой (`deploy.yml`, только по кнопке).

## Как устроено

| Что | Где |
|---|---|
| Код | `/srv/secure/app` — клон этого репозитория; каждые 30 мин `git pull` (только чтение) |
| Состояние сборщика | `/srv/secure/state` — локальный git (начато с ветки `pipeline-state`, дальше на GitHub не пушится) |
| События сайта | `/srv/secure/app/data/events` — пишет `publish`; **на GitHub не коммитятся** |
| Секреты | `/srv/secure/.env` (шаблон `server/env.example`) |
| Расписание | cron пользователя `secure`: `server/collect.sh` в :07 и :37 |
| Деплой | `server/deploy.sh` — когда изменились события или код: сборка Astro, D1-миграции, `wrangler deploy`, проверка URL, push-рассылка |
| Журналы | `/srv/secure/logs/collect.log`, `deploy.log` |
| Оповещения | Telegram (`TG_BOT_TOKEN`, `TG_CHAT_ID`): сбор упал, сбор старше 3 ч, деплой не прошёл — не чаще раза в 6 ч на тему |

Важно: события на сервере новее, чем в git. Поэтому **деплой с GitHub (`deploy.yml`) запускать только в крайнем
случае** — он выложит сайт с устаревшими событиями (до следующего деплоя с сервера). Обычный путь: запушили код →
сервер в ближайшие 30 минут подтянет его и сам задеплоит.

## Установка (от root на worker)

```bash
git clone https://github.com/bobbynus/secure /srv/secure/app      # репозиторий публичный — токен не нужен
bash /srv/secure/app/server/install.sh
nano /srv/secure/.env
su - secure -c '/srv/secure/app/server/collect.sh'; tail -40 /srv/secure/logs/collect.log
```
Перед первым запуском на сервере на GitHub уже не должно быть `collect.yml` (иначе два сборщика будут публиковать
одновременно) — он удалён в этом же коммите.

### Секреты — где взять
Значения секретов GitHub прочитать нельзя, поэтому:
- `CLOUDFLARE_API_TOKEN` — Cloudflare → My Profile → API Tokens → Create Token → шаблон **Edit Cloudflare Workers**
  + добавить **Account · D1 · Edit**; `CLOUDFLARE_ACCOUNT_ID` — справа на главной странице аккаунта.
- `DISPATCH_TOKEN` — придумать новый (`openssl rand -hex 32`) и записать и в `.env`, и в Worker:
  `npx wrangler secret put DISPATCH_TOKEN` (из `/srv/secure/app` под `secure`, с загруженным `.env`).
- `GEMINI_API_KEY` — aistudio.google.com; лучше отдельный проект, не общий с ТУТ.DUS (лимиты общие на проект).
- `NVD_API_KEY` — nvd.nist.gov/developers/request-an-api-key (можно без него).
- `TG_BOT_TOKEN` / `TG_CHAT_ID` — бот для оповещений (можно бот ТУТ.DUS) и ваш chat id.

После первого успешного деплоя с сервера удалить из Worker'а старый «запасной запуск» GitHub:
`echo y | npx wrangler secret delete COLLECT_TOKEN` (без него `worker/src/scheduler.ts` ничего не делает).

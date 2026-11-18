import type { Env } from './env';
import { assertOrigin, HttpError, isBot, json, now, rateLimit, readJson, utcDay } from './http';

/**
 * Public, approximate statistics (methodology on /<lang>/privacy/):
 *  - views today / total: registered page opens (UTC days);
 *  - event views: sum over the three language versions of an Event ID;
 *  - active sessions: random per-tab IDs with a heartbeat in the last 2 minutes.
 * No cookies, no fingerprinting, no IP storage.
 */

const ACTIVE_WINDOW = 120;
const PATH_RE = /^\/(ru|de|en)\/[a-z0-9\-/]*$/;
const EVENT_RE = /^sr-\d{2}-\d{4}$/;
const SID_RE = /^[a-f0-9]{32}$/;

export async function hit(req: Request, env: Env): Promise<Response> {
  assertOrigin(req, env);
  if (isBot(req)) return json({ ok: true, counted: false });
  await rateLimit(env.RL_HIT, req, 'hit');
  const body = await readJson<{ path?: string; event?: string }>(req, 1024);
  if (!body.path || !PATH_RE.test(body.path) || body.path.length > 200) throw new HttpError(400, 'bad_path');
  const day = utcDay();
  const upsert = `INSERT INTO views_daily (day, event_id, count) VALUES (?1, ?2, 1)
                  ON CONFLICT (day, event_id) DO UPDATE SET count = count + 1`;
  const stmts = [env.DB.prepare(upsert).bind(day, '')];
  if (body.event && EVENT_RE.test(body.event)) stmts.push(env.DB.prepare(upsert).bind(day, body.event));
  await env.DB.batch(stmts);
  return json({ ok: true, counted: true });
}

export async function heartbeat(req: Request, env: Env): Promise<Response> {
  assertOrigin(req, env);
  if (isBot(req)) return json({ ok: true });
  await rateLimit(env.RL_HIT, req, 'hb');
  const body = await readJson<{ sid?: string }>(req, 256);
  if (!body.sid || !SID_RE.test(body.sid)) throw new HttpError(400, 'bad_sid');
  await env.DB.prepare(
    `INSERT INTO active_sessions (sid, last_seen) VALUES (?1, ?2) ON CONFLICT (sid) DO UPDATE SET last_seen = ?2`,
  )
    .bind(body.sid, now())
    .run();
  return json({ ok: true });
}

export async function stats(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const url = new URL(req.url);
  const event = url.searchParams.get('event');
  if (event && !EVENT_RE.test(event)) throw new HttpError(400, 'bad_event');

  // Short shared cache: the panel is approximate anyway and this keeps D1 reads flat.
  const cacheKey = new Request(`${url.origin}/api/stats?event=${event ?? ''}`, { method: 'GET' });
  const cache = (caches as unknown as { default: Cache }).default;
  const cached = await cache.match(cacheKey);
  if (cached) return cached;

  const t = now();
  const [today, total, active, ev] = await env.DB.batch<{ n: number | null }>([
    env.DB.prepare(`SELECT count AS n FROM views_daily WHERE day = ?1 AND event_id = ''`).bind(utcDay()),
    env.DB.prepare(`SELECT SUM(count) AS n FROM views_daily WHERE event_id = ''`),
    env.DB.prepare(`SELECT COUNT(*) AS n FROM active_sessions WHERE last_seen > ?1`).bind(t - ACTIVE_WINDOW),
    env.DB.prepare(`SELECT SUM(count) AS n FROM views_daily WHERE event_id = ?1`).bind(event ?? '-'),
  ]);
  const since = await env.DB.prepare(`SELECT MIN(day) AS d FROM views_daily`).first<{ d: string | null }>();
  const res = json(
    {
      ok: true,
      today: today?.results[0]?.n ?? 0,
      total: total?.results[0]?.n ?? 0,
      active: active?.results[0]?.n ?? 0,
      event: event ? (ev?.results[0]?.n ?? 0) : null,
      since: since?.d ?? null,
    },
    200,
    { 'Cache-Control': 'public, max-age=20' },
  );
  ctx.waitUntil(cache.put(cacheKey, res.clone()));
  return res;
}

/** Cron: drop expired sessions. */
export async function cleanupSessions(env: Env) {
  await env.DB.prepare(`DELETE FROM active_sessions WHERE last_seen < ?1`).bind(now() - ACTIVE_WINDOW * 5).run();
}

import type { Env } from '../env';
import { assertBearer, assertOrigin, HttpError, json, now, rateLimit, readJson, sha256Hex } from '../http';
import { b64urlDecode, isAllowedEndpoint, sendPush, type Vapid } from './webpush';

const LANGS = ['ru', 'de', 'en'] as const;
const PRIORITIES = ['info', 'low', 'medium', 'high', 'critical'] as const; // ascending
const CATEGORIES = ['vulnerability', 'attack', 'update-issue'] as const;
/** Only significant changes trigger a (re-)notification. */
const SIGNIFICANT = new Set(['created', 'exploitation', 'fix', 'versions']);
const MAX_ATTEMPTS = 5;
/** Free plan allows 50 subrequests per invocation; keep a margin. */
const BATCH = 40;

type Lang = (typeof LANGS)[number];

interface Prefs {
  lang: Lang;
  minPriority: (typeof PRIORITIES)[number];
  categories: string[];
  products: string[];
}

interface SubscribeBody {
  subscription?: { endpoint?: string; keys?: { p256dh?: string; auth?: string } };
  prefs?: Partial<Prefs>;
}

interface IndexItem {
  id: string;
  url: string;
  title: string;
  summary: string;
  category: string;
  priority: string;
  exploitation: string;
  products: { id: string }[];
  rev?: { date: string; kind: string };
}

const WELCOME: Record<Lang, { title: string; body: string }> = {
  ru: { title: 'Уведомления включены', body: 'Вы будете получать сообщения о событиях по выбранным условиям.' },
  de: { title: 'Benachrichtigungen aktiviert', body: 'Sie erhalten Meldungen zu Ereignissen gemäß Ihren Filtern.' },
  en: { title: 'Notifications enabled', body: 'You will receive alerts for events matching your filters.' },
};

// ---------- public endpoints ----------

export function vapidPublic(env: Env): Response {
  return json({ ok: true, key: env.VAPID_PUBLIC_KEY }, 200, { 'Cache-Control': 'public, max-age=3600' });
}

export async function subscribe(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  assertOrigin(req, env);
  await rateLimit(env.RL_PUSH, req, 'push');
  const b = await readJson<SubscribeBody>(req, 4096);
  const endpoint = b.subscription?.endpoint ?? '';
  const p256dh = b.subscription?.keys?.p256dh ?? '';
  const auth = b.subscription?.keys?.auth ?? '';
  if (endpoint.length > 1000 || !isAllowedEndpoint(endpoint)) throw new HttpError(400, 'bad_endpoint');
  if (!validKey(p256dh, 65) || !validKey(auth, 16)) throw new HttpError(400, 'bad_keys');
  const prefs = parsePrefs(b.prefs);

  const id = await sha256Hex(endpoint);
  const t = now();
  const existed = await env.DB.prepare(`SELECT 1 FROM push_subscriptions WHERE id = ?1`).bind(id).first();
  await env.DB.prepare(
    `INSERT INTO push_subscriptions (id, endpoint, p256dh, auth, lang, min_priority, categories, products, failures, created_at, updated_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, ?9, ?9)
     ON CONFLICT (id) DO UPDATE SET p256dh = ?3, auth = ?4, lang = ?5, min_priority = ?6, categories = ?7, products = ?8, failures = 0, updated_at = ?9`,
  )
    .bind(id, endpoint, p256dh, auth, prefs.lang, prefs.minPriority, JSON.stringify(prefs.categories), JSON.stringify(prefs.products), t)
    .run();

  const vapid = getVapid(env);
  if (!existed && vapid) {
    const w = WELCOME[prefs.lang];
    ctx.waitUntil(
      sendPush({ endpoint, p256dh, auth }, JSON.stringify({ ...w, url: `/${prefs.lang}/`, tag: 'welcome' }), vapid, { ttl: 3600 })
        .then((r) => !r.ok && console.warn('welcome push', r.status, r.text))
        .catch((e) => console.warn('welcome push', e)),
    );
  }
  return json({ ok: true, created: !existed, prefs });
}

export async function unsubscribe(req: Request, env: Env): Promise<Response> {
  assertOrigin(req, env);
  await rateLimit(env.RL_PUSH, req, 'push');
  const b = await readJson<{ endpoint?: string }>(req, 2048);
  if (!b.endpoint) throw new HttpError(400, 'bad_endpoint');
  const id = await sha256Hex(b.endpoint);
  await env.DB.batch([
    env.DB.prepare(`DELETE FROM push_outbox WHERE sub_id = ?1`).bind(id),
    env.DB.prepare(`DELETE FROM push_subscriptions WHERE id = ?1`).bind(id),
  ]);
  return json({ ok: true });
}

/** Read stored preferences. The endpoint itself acts as the capability. */
export async function getPrefs(req: Request, env: Env): Promise<Response> {
  assertOrigin(req, env);
  await rateLimit(env.RL_PUSH, req, 'push');
  const b = await readJson<{ endpoint?: string }>(req, 2048);
  if (!b.endpoint) throw new HttpError(400, 'bad_endpoint');
  const row = await env.DB.prepare(`SELECT lang, min_priority, categories, products FROM push_subscriptions WHERE id = ?1`)
    .bind(await sha256Hex(b.endpoint))
    .first<{ lang: Lang; min_priority: Prefs['minPriority']; categories: string; products: string }>();
  if (!row) return json({ ok: true, subscribed: false });
  return json({
    ok: true,
    subscribed: true,
    prefs: { lang: row.lang, minPriority: row.min_priority, categories: JSON.parse(row.categories), products: JSON.parse(row.products) },
  });
}

// ---------- CI endpoints ----------

/**
 * Called by CI after a deploy has been verified. Finds events whose latest significant revision is newer
 * than the stored watermark, queues one outbox row per matching subscription, then starts sending.
 * Idempotent: re-running enqueues nothing new (watermark + outbox primary key).
 */
export async function dispatch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  assertBearer(req, env.DISPATCH_TOKEN);
  if (await isPaused(env)) return json({ ok: true, paused: true });

  const indexes = await Promise.all(LANGS.map((l) => loadIndex(env, req, l)));
  const all = indexes.flatMap((x) => x.items);
  const maxRev = all.map((i) => i.rev?.date ?? '').sort().at(-1) ?? '';
  const watermark = await getMeta(env, 'push_watermark');
  if (!watermark) {
    // First run: start from now, do not notify about the existing archive.
    await setMeta(env, 'push_watermark', maxRev);
    return json({ ok: true, initialized: true, watermark: maxRev });
  }

  let queued = 0;
  const t = now();
  for (const [i, lang] of LANGS.entries()) {
    const { items, labels } = indexes[i]!;
    const fresh = items.filter((it) => it.rev && it.rev.date > watermark && SIGNIFICANT.has(it.rev.kind));
    if (!fresh.length) continue;
    const subs = await env.DB.prepare(`SELECT id, min_priority, categories, products FROM push_subscriptions WHERE lang = ?1`)
      .bind(lang)
      .all<{ id: string; min_priority: string; categories: string; products: string }>();
    const stmts: D1PreparedStatement[] = [];
    for (const s of subs.results) {
      const cats: string[] = JSON.parse(s.categories);
      const prods: string[] = JSON.parse(s.products);
      for (const it of fresh) {
        if (rank(it.priority) < rank(s.min_priority)) continue;
        if (cats.length && !cats.includes(it.category)) continue;
        if (prods.length && !it.products.some((p) => prods.includes(p.id))) continue;
        stmts.push(
          env.DB.prepare(
            `INSERT OR IGNORE INTO push_outbox (sub_id, event_id, rev, payload, status, attempts, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, 'pending', 0, ?5, ?5)`,
          ).bind(s.id, it.id, it.rev!.date, JSON.stringify(payloadFor(it, labels, it.rev!.kind)), t),
        );
      }
    }
    for (let k = 0; k < stmts.length; k += 50) {
      const res = await env.DB.batch(stmts.slice(k, k + 50));
      queued += res.reduce((n, r) => n + (r.meta.changes ?? 0), 0);
    }
  }
  await setMeta(env, 'push_watermark', maxRev > watermark ? maxRev : watermark);
  ctx.waitUntil(processOutbox(env));
  return json({ ok: true, queued, watermark: maxRev });
}

/** Emergency stop / resume for all push delivery. */
export async function pause(req: Request, env: Env): Promise<Response> {
  assertBearer(req, env.DISPATCH_TOKEN);
  const b = await readJson<{ paused?: boolean }>(req, 256);
  await setMeta(env, 'push_paused', b.paused ? '1' : '0');
  return json({ ok: true, paused: !!b.paused });
}

// ---------- outbox worker ----------

export async function processOutbox(env: Env): Promise<{ sent: number; failed: number; gone: number }> {
  const stats = { sent: 0, failed: 0, gone: 0 };
  if (await isPaused(env)) return stats;
  const vapid = getVapid(env);
  if (!vapid) return stats;

  // Release rows stuck in "sending" (invocation died mid-way) after 10 minutes.
  await env.DB.prepare(`UPDATE push_outbox SET status = 'pending' WHERE status = 'sending' AND updated_at < ?1`).bind(now() - 600).run();

  // Claim a batch atomically so concurrent runs never send the same row twice.
  const claimed = await env.DB.prepare(
    `UPDATE push_outbox SET status = 'sending', updated_at = ?1
     WHERE rowid IN (SELECT rowid FROM push_outbox WHERE status = 'pending' AND attempts < ?2 ORDER BY created_at LIMIT ?3)
     RETURNING sub_id, event_id, rev, payload, attempts`,
  )
    .bind(now(), MAX_ATTEMPTS, BATCH)
    .all<{ sub_id: string; event_id: string; rev: string; payload: string; attempts: number }>();

  for (const row of claimed.results) {
    const sub = await env.DB.prepare(`SELECT endpoint, p256dh, auth FROM push_subscriptions WHERE id = ?1`)
      .bind(row.sub_id)
      .first<{ endpoint: string; p256dh: string; auth: string }>();
    const key = [row.sub_id, row.event_id, row.rev];
    if (!sub) {
      await env.DB.prepare(`UPDATE push_outbox SET status = 'gone', updated_at = ?4 WHERE sub_id = ?1 AND event_id = ?2 AND rev = ?3`).bind(...key, now()).run();
      continue;
    }
    let r;
    try {
      const p = JSON.parse(row.payload) as { urgent?: boolean };
      r = await sendPush(sub, row.payload, vapid, { urgency: p.urgent ? 'high' : 'normal', topic: row.event_id.replace(/-/g, '') });
    } catch (e) {
      r = { ok: false, gone: false, status: 0, text: String(e) };
    }
    if (r.ok) {
      stats.sent++;
      await env.DB.prepare(`UPDATE push_outbox SET status = 'sent', attempts = attempts + 1, updated_at = ?4 WHERE sub_id = ?1 AND event_id = ?2 AND rev = ?3`).bind(...key, now()).run();
    } else if (r.gone) {
      stats.gone++;
      await env.DB.batch([
        env.DB.prepare(`UPDATE push_outbox SET status = 'gone', updated_at = ?2 WHERE sub_id = ?1`).bind(row.sub_id, now()),
        env.DB.prepare(`DELETE FROM push_subscriptions WHERE id = ?1`).bind(row.sub_id),
      ]);
    } else {
      stats.failed++;
      const attempts = row.attempts + 1;
      await env.DB.batch([
        env.DB.prepare(
          `UPDATE push_outbox SET status = ?4, attempts = ?5, last_error = ?6, updated_at = ?7 WHERE sub_id = ?1 AND event_id = ?2 AND rev = ?3`,
        ).bind(...key, attempts >= MAX_ATTEMPTS ? 'failed' : 'pending', attempts, `${r.status} ${r.text ?? ''}`.slice(0, 300), now()),
        env.DB.prepare(`UPDATE push_subscriptions SET failures = failures + 1 WHERE id = ?1`).bind(row.sub_id),
      ]);
    }
  }
  return stats;
}

// ---------- helpers ----------

function validKey(s: string, len: number): boolean {
  if (!/^[A-Za-z0-9_-]+={0,2}$/.test(s)) return false;
  try {
    return b64urlDecode(s).length === len;
  } catch {
    return false;
  }
}

function parsePrefs(p: Partial<Prefs> | undefined): Prefs {
  const lang = LANGS.includes(p?.lang as Lang) ? (p!.lang as Lang) : null;
  if (!lang) throw new HttpError(400, 'bad_prefs', { field: 'lang' });
  const minPriority = PRIORITIES.includes(p?.minPriority as Prefs['minPriority']) ? p!.minPriority! : 'high';
  const categories = Array.isArray(p?.categories) ? p!.categories.filter((c) => (CATEGORIES as readonly string[]).includes(c)) : [];
  const products = Array.isArray(p?.products) ? p!.products.filter((x) => typeof x === 'string' && /^[a-z0-9-]{1,40}$/.test(x)).slice(0, 50) : [];
  return { lang, minPriority, categories: [...new Set(categories)], products: [...new Set(products)] };
}

const rank = (p: string) => PRIORITIES.indexOf(p as Prefs['minPriority']);

function payloadFor(it: IndexItem, labels: Record<string, string>, kind: string) {
  const prio = labels[`prio.${it.priority}`] ?? it.priority;
  const exploited = it.exploitation === 'confirmed' ? ` · ${labels['exp.confirmed'] ?? 'exploited'}` : '';
  const summary = it.summary.length > 180 ? `${it.summary.slice(0, 177)}…` : it.summary;
  return {
    title: `[${prio}${exploited}] ${it.title}`.slice(0, 160),
    body: summary,
    url: it.url,
    tag: it.id,
    kind,
    urgent: it.priority === 'critical' || it.exploitation === 'confirmed',
  };
}

async function loadIndex(env: Env, req: Request, lang: Lang): Promise<{ items: IndexItem[]; labels: Record<string, string> }> {
  const r = await env.ASSETS.fetch(new Request(new URL(`/${lang}/index.json`, req.url)));
  if (!r.ok) throw new HttpError(502, 'index_unavailable', { lang });
  return (await r.json()) as { items: IndexItem[]; labels: Record<string, string> };
}

function getVapid(env: Env): Vapid | null {
  if (!env.VAPID_PRIVATE_JWK || !env.VAPID_PUBLIC_KEY) return null;
  return { publicKey: env.VAPID_PUBLIC_KEY, privateJwk: JSON.parse(env.VAPID_PRIVATE_JWK), subject: env.VAPID_SUBJECT };
}

async function isPaused(env: Env) {
  return (await getMeta(env, 'push_paused')) === '1';
}

async function getMeta(env: Env, key: string): Promise<string | null> {
  return (await env.DB.prepare(`SELECT value FROM meta WHERE key = ?1`).bind(key).first<{ value: string }>())?.value ?? null;
}

async function setMeta(env: Env, key: string, value: string) {
  await env.DB.prepare(`INSERT INTO meta (key, value) VALUES (?1, ?2) ON CONFLICT (key) DO UPDATE SET value = ?2`).bind(key, value).run();
}

import type { Env } from './env';
import { assertBearer, HttpError, json, readJson } from './http';

/**
 * Collector status: pushed by CI after every collection run, read by the site (status bar, sources page).
 * Static builds would show stale collection times; this keeps "last successful collection" live.
 */

const STATES = new Set(['ok', 'error', 'planned', 'paused']);
const ID_RE = /^[a-z0-9-]{1,64}$/;
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;

interface SourceStatus {
  id: string;
  state: string;
  lastSuccess?: string | null;
  lastError?: string | null;
  failures?: number;
}

interface CollectorStatus {
  generatedAt: string;
  lastSuccess: string | null;
  run: { ok: number; error: number };
  sources: SourceStatus[];
}

export async function putCollector(req: Request, env: Env): Promise<Response> {
  assertBearer(req, env.DISPATCH_TOKEN);
  const b = await readJson<Partial<CollectorStatus>>(req, 65_536);
  if (typeof b.generatedAt !== 'string' || !ISO_RE.test(b.generatedAt)) throw new HttpError(400, 'bad_status');
  if (!Array.isArray(b.sources) || b.sources.length > 200) throw new HttpError(400, 'bad_status');
  const sources: SourceStatus[] = b.sources
    .filter((s) => s && ID_RE.test(String(s.id)) && STATES.has(String(s.state)))
    .map((s) => ({
      id: s.id,
      state: s.state,
      lastSuccess: typeof s.lastSuccess === 'string' && ISO_RE.test(s.lastSuccess) ? s.lastSuccess : null,
      // Error texts are shown publicly: plain, short, no control characters.
      lastError: typeof s.lastError === 'string' ? s.lastError.replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, 200) : null,
      failures: Number.isInteger(s.failures) ? s.failures : 0,
    }));
  const status: CollectorStatus = {
    generatedAt: b.generatedAt,
    lastSuccess: typeof b.lastSuccess === 'string' && ISO_RE.test(b.lastSuccess) ? b.lastSuccess : null,
    run: { ok: Number(b.run?.ok) || 0, error: Number(b.run?.error) || 0 },
    sources,
  };
  await env.DB.prepare(`INSERT INTO meta (key, value) VALUES ('collector_status', ?1) ON CONFLICT (key) DO UPDATE SET value = ?1`)
    .bind(JSON.stringify(status))
    .run();
  return json({ ok: true, sources: sources.length });
}

export async function getCollector(env: Env): Promise<Response> {
  const row = await env.DB.prepare(`SELECT value FROM meta WHERE key = 'collector_status'`).first<{ value: string }>();
  if (!row) return json({ ok: true, status: null }, 200, { 'Cache-Control': 'public, max-age=60' });
  return json({ ok: true, status: JSON.parse(row.value) }, 200, { 'Cache-Control': 'public, max-age=60' });
}

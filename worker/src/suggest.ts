import type { Env } from './env';
import { assertOrigin, HttpError, json, now, rateLimit, readJson } from './http';

/**
 * On-site "suggest a source" form → exactly one GitHub issue.
 *
 * Form → validation → anti-spam (honeypot, optional Turnstile) / rate limit → duplicate check
 * (catalog, previous suggestions, open issues) → issue in the fixed repository → number + URL.
 *
 * The suggested URL is never fetched here (no SSRF surface). Repository, labels and token are server-side.
 */

const KINDS = ['vendor', 'cert', 'database', 'research', 'media', 'community'] as const;
const FORMATS = ['rss', 'api', 'file', 'html', 'unknown'] as const;
const LABELS = ['source-suggestion', 'needs-review'];

interface SuggestBody {
  requestId?: string;
  name?: string;
  url?: string;
  kind?: string;
  format?: string;
  language?: string;
  products?: string;
  rationale?: string;
  docs?: string;
  /** Honeypot: real users never fill it. */
  website?: string;
  turnstile?: string;
}

export async function suggest(req: Request, env: Env): Promise<Response> {
  assertOrigin(req, env);
  await rateLimit(env.RL_SUGGEST, req, 'suggest');
  const b = await readJson<SuggestBody>(req, 16_384);

  // Honeypot: pretend success, create nothing.
  if (b.website) return json({ ok: true, number: 0, url: '' });

  const requestId = str(b.requestId, 'requestId', 8, 64, true);
  if (!/^[a-zA-Z0-9-]+$/.test(requestId)) throw new HttpError(400, 'invalid', { field: 'requestId' });
  const name = str(b.name, 'name', 2, 120, true);
  const url = parseUrl(str(b.url, 'url', 8, 500, true), 'url');
  const kind = oneOf(b.kind, KINDS, 'kind');
  const format = oneOf(b.format, FORMATS, 'format');
  const language = str(b.language, 'language', 2, 40, true);
  const products = str(b.products, 'products', 0, 300, false);
  const rationale = str(b.rationale, 'rationale', 0, 2000, false);
  const docs = b.docs ? parseUrl(str(b.docs, 'docs', 8, 500, true), 'docs') : null;

  // Idempotency: a repeated submit (double click, retry) returns the same issue.
  const prev = await env.DB.prepare(`SELECT issue_number, issue_url, status FROM suggestions WHERE request_id = ?1`)
    .bind(requestId)
    .first<{ issue_number: number | null; issue_url: string | null; status: string }>();
  if (prev) {
    if (prev.status === 'created') return json({ ok: true, number: prev.issue_number, url: prev.issue_url, repeated: true });
    throw new HttpError(409, 'in_progress');
  }

  if (env.TURNSTILE_SECRET) await verifyTurnstile(env.TURNSTILE_SECRET, b.turnstile, req);

  const norm = normalizeUrl(url);

  // Duplicates: already in the catalog?
  const catalog = await loadCatalog(env, req);
  const inCatalog = catalog.find((c) => sameSource(normalizeUrl(new URL(c.url)), norm));
  if (inCatalog) throw new HttpError(409, 'duplicate_catalog', { name: inCatalog.name });

  // …suggested before through this form?
  const dup = await env.DB.prepare(`SELECT issue_number, issue_url FROM suggestions WHERE url_norm = ?1 AND status = 'created'`)
    .bind(norm)
    .first<{ issue_number: number; issue_url: string }>();
  if (dup) throw new HttpError(409, 'duplicate_issue', { number: dup.issue_number, url: dup.issue_url });

  // Everything below needs GitHub; local duplicate checks above work without it.
  if (!env.GITHUB_TOKEN) throw new HttpError(503, 'not_configured');

  // …or as an issue on GitHub (e.g. through the Issue Form)?
  const gh = await findIssue(env, norm);
  if (gh) throw new HttpError(409, 'duplicate_issue', { number: gh.number, url: gh.html_url });

  // Reserve the URL first: UNIQUE(url_norm) stops parallel submissions from creating two issues.
  try {
    await env.DB.prepare(`INSERT INTO suggestions (request_id, url_norm, status, created_at) VALUES (?1, ?2, 'pending', ?3)`)
      .bind(requestId, norm, now())
      .run();
  } catch {
    throw new HttpError(409, 'in_progress');
  }

  try {
    const issue = await createIssue(env, {
      // Titles render as plain text; only neutralise @mentions.
      title: `[Source suggestion] ${oneLine(name).replace(/@/g, '@​')}`.slice(0, 200),
      body: issueBody({ name, url: url.href, kind, format, language, products, rationale, docs: docs?.href ?? '' }),
    });
    await env.DB.prepare(`UPDATE suggestions SET status = 'created', issue_number = ?1, issue_url = ?2 WHERE request_id = ?3`)
      .bind(issue.number, issue.html_url, requestId)
      .run();
    return json({ ok: true, number: issue.number, url: issue.html_url });
  } catch (e) {
    await env.DB.prepare(`DELETE FROM suggestions WHERE request_id = ?1`).bind(requestId).run();
    throw e instanceof HttpError ? e : new HttpError(502, 'github_failed');
  }
}

// ---------- validation ----------

function str(v: unknown, field: string, min: number, max: number, required: boolean): string {
  if (v === undefined || v === null || v === '') {
    if (required) throw new HttpError(400, 'required', { field });
    return '';
  }
  if (typeof v !== 'string') throw new HttpError(400, 'invalid', { field });
  // Drop control characters except newlines/tabs; collapse excessive blank lines.
  const s = v.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f‪-‮⁦-⁩]/g, '').replace(/\n{3,}/g, '\n\n').trim();
  if (s.length < min || s.length > max) throw new HttpError(400, 'length', { field, min, max });
  return s;
}

function oneOf<T extends string>(v: unknown, allowed: readonly T[], field: string): T {
  if (typeof v !== 'string' || !allowed.includes(v as T)) throw new HttpError(400, 'invalid', { field });
  return v as T;
}

function parseUrl(s: string, field: string): URL {
  let u: URL;
  try {
    u = new URL(s);
  } catch {
    throw new HttpError(400, 'invalid_url', { field });
  }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new HttpError(400, 'invalid_url', { field });
  if (u.username || u.password) throw new HttpError(400, 'invalid_url', { field });
  // Internal/private targets make no sense as public sources (and must never be fetched by later tooling).
  if (isPrivateHost(u.hostname)) throw new HttpError(400, 'private_url', { field });
  return u;
}

function isPrivateHost(h: string): boolean {
  const host = h.replace(/^\[|\]$/g, '').toLowerCase();
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal') || host.endsWith('.lan')) return true;
  if (!host.includes('.') && !host.includes(':')) return true;
  const m = host.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (m) {
    const [a, b] = [Number(m[1]), Number(m[2])];
    return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || a >= 224;
  }
  if (host.includes(':')) return host === '::1' || host.startsWith('fc') || host.startsWith('fd') || host.startsWith('fe80');
  return false;
}

/** host + path, lowercase host, no www, no query/fragment, no trailing slash. */
export function normalizeUrl(u: URL): string {
  const host = u.hostname.toLowerCase().replace(/^www\./, '');
  const path = u.pathname.replace(/\/+$/, '');
  return `${host}${path}`;
}

/** Same source if one normalized URL is a path prefix of the other on the same host. */
function sameSource(a: string, b: string): boolean {
  return a === b || a.startsWith(`${b}/`) || b.startsWith(`${a}/`);
}

// ---------- anti-spam ----------

async function verifyTurnstile(secret: string, token: unknown, req: Request) {
  if (typeof token !== 'string' || !token) throw new HttpError(400, 'captcha_required');
  const form = new FormData();
  form.append('secret', secret);
  form.append('response', token);
  const ip = req.headers.get('CF-Connecting-IP');
  if (ip) form.append('remoteip', ip);
  const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', body: form });
  const data = (await r.json()) as { success?: boolean };
  if (!data.success) throw new HttpError(400, 'captcha_failed');
}

// ---------- catalog & GitHub ----------

async function loadCatalog(env: Env, req: Request): Promise<{ name: string; url: string }[]> {
  try {
    const r = await env.ASSETS.fetch(new Request(new URL('/catalog.json', req.url)));
    if (!r.ok) return [];
    return ((await r.json()) as { sources: { name: string; url: string }[] }).sources;
  } catch {
    return [];
  }
}

function ghHeaders(env: Env): HeadersInit {
  return {
    Authorization: `Bearer ${env.GITHUB_TOKEN}`,
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'secure.abramov.vip',
  };
}

async function findIssue(env: Env, norm: string): Promise<{ number: number; html_url: string } | null> {
  const q = `repo:${env.GITHUB_REPO} is:issue label:source-suggestion "${norm.replace(/"/g, '')}"`;
  const r = await fetch(`https://api.github.com/search/issues?per_page=1&q=${encodeURIComponent(q)}`, { headers: ghHeaders(env) });
  if (!r.ok) return null; // search is best-effort; D1 still guards our own submissions
  const data = (await r.json()) as { items?: { number: number; html_url: string; state: string }[] };
  return data.items?.[0] ?? null;
}

async function createIssue(env: Env, issue: { title: string; body: string }): Promise<{ number: number; html_url: string }> {
  const r = await fetch(`https://api.github.com/repos/${env.GITHUB_REPO}/issues`, {
    method: 'POST',
    headers: { ...ghHeaders(env), 'Content-Type': 'application/json' },
    body: JSON.stringify({ ...issue, labels: LABELS }),
  });
  if (!r.ok) {
    console.error('github create issue', r.status, (await r.text()).slice(0, 300));
    throw new HttpError(502, 'github_failed');
  }
  return (await r.json()) as { number: number; html_url: string };
}

// ---------- issue body ----------

/** Neutralize Markdown/HTML and GitHub mentions/references in visitor text. */
function md(s: string): string {
  return s
    .replace(/[\\`*_{}[\]()<>#+!|~]/g, (c) => `\\${c}`)
    .replace(/@/g, '@​')
    .replace(/\n/g, '  \n');
}

function oneLine(s: string): string {
  return s.replace(/\s+/g, ' ');
}

/** URLs go into code spans: rendered literally, never auto-linked as Markdown. */
function code(s: string): string {
  return `\`${s.replace(/`/g, '%60')}\``;
}

const KIND_LABEL: Record<string, string> = {
  vendor: 'Vendor advisory / release notes / status page',
  cert: 'CERT / government',
  database: 'Vulnerability database',
  research: 'Security research',
  media: 'Media',
  community: 'Community',
};
const FORMAT_LABEL: Record<string, string> = { rss: 'RSS / Atom', api: 'API (JSON)', file: 'JSON / CSV file', html: 'HTML page only', unknown: 'Not sure' };

function issueBody(f: { name: string; url: string; kind: string; format: string; language: string; products: string; rationale: string; docs: string }): string {
  const rows = [
    `**Name:** ${md(oneLine(f.name))}`,
    `**URL:** ${code(f.url)}`,
    `**Type:** ${KIND_LABEL[f.kind]}`,
    `**Format:** ${FORMAT_LABEL[f.format]}`,
    `**Language:** ${md(oneLine(f.language))}`,
  ];
  if (f.products) rows.push(`**Products / topics:** ${md(oneLine(f.products))}`);
  if (f.docs) rows.push(`**Documentation:** ${code(f.docs)}`);
  const parts = ['### Suggested source', rows.join('\n')];
  if (f.rationale) parts.push('### Rationale', md(f.rationale));
  parts.push(
    '---',
    '_Submitted anonymously via the form on secure.abramov.vip. Unverified: check origin, terms of use, format and a test collection before accepting._',
  );
  return parts.join('\n\n');
}

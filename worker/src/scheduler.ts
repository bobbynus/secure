import type { Env } from './env';

/**
 * Fallback scheduler for the collection workflow.
 *
 * GitHub's own cron may be delayed for hours or skipped. The Worker cron runs every 10 minutes: when the
 * last collector status (pushed by every collection run) is older than STALE and no dispatch was made in
 * the same window, it starts collect.yml through the GitHub API. If GitHub's schedule works, the status
 * stays fresh and this does nothing. Needs COLLECT_TOKEN: a fine-grained PAT with Actions read/write on
 * the repository only (kept separate from the Issues token of the public form).
 */

const STALE_MS = 28 * 60_000;

export async function kickCollector(env: Env, now = Date.now()): Promise<'disabled' | 'fresh' | 'recent' | 'dispatched' | 'failed'> {
  if (!env.COLLECT_TOKEN) return 'disabled';
  const rows = await env.DB.prepare(`SELECT key, value FROM meta WHERE key IN ('collector_status', 'collector_kick')`).all<{
    key: string;
    value: string;
  }>();
  const meta = new Map(rows.results.map((r) => [r.key, r.value]));
  const status = meta.get('collector_status');
  const generated = status ? Date.parse(JSON.parse(status).generatedAt ?? '') : NaN;
  if (Number.isFinite(generated) && now - generated < STALE_MS) return 'fresh';
  const kicked = Number(meta.get('collector_kick') ?? 0);
  if (now - kicked < STALE_MS) return 'recent';

  // Record first: a slow or failing API call must not cause a dispatch on every cron tick.
  await env.DB.prepare(`INSERT INTO meta (key, value) VALUES ('collector_kick', ?1) ON CONFLICT (key) DO UPDATE SET value = ?1`)
    .bind(String(now))
    .run();
  const r = await fetch(`https://api.github.com/repos/${env.GITHUB_REPO}/actions/workflows/collect.yml/dispatches`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${env.COLLECT_TOKEN}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'secure.abramov.vip',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ ref: 'main' }),
  });
  if (r.status !== 204) {
    console.error('collect dispatch', r.status, (await r.text()).slice(0, 200));
    return 'failed';
  }
  return 'dispatched';
}

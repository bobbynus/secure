/**
 * Public approximate statistics (methodology: /<lang>/privacy/).
 * - one "hit" per page open (path + Event ID on articles);
 * - heartbeat every ~50 s while the tab is visible, with a random per-tab ID kept in sessionStorage;
 * - status bar: active sessions (≈, last 2 min) and views today; article: views over all languages.
 * No cookies, no fingerprinting. Any failure is silent: the site works without this script.
 */

document.documentElement.classList.add('js');

const HEARTBEAT_MS = 50_000;
const STATS_MS = 60_000;

const eventId = document.body.dataset.eventId || undefined;
const automated = (navigator as Navigator & { webdriver?: boolean }).webdriver === true;

function sessionId(): string {
  try {
    let sid = sessionStorage.getItem('sid');
    if (!sid || !/^[a-f0-9]{32}$/.test(sid)) {
      sid = [...crypto.getRandomValues(new Uint8Array(16))].map((b) => b.toString(16).padStart(2, '0')).join('');
      sessionStorage.setItem('sid', sid);
    }
    return sid;
  } catch {
    return '';
  }
}

function post(path: string, body: unknown) {
  return fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), keepalive: true }).catch(() => undefined);
}

const fmt = new Intl.NumberFormat(document.documentElement.lang || 'en');

async function refreshStats() {
  if (document.visibilityState !== 'visible') return;
  const live = document.getElementById('live-stats');
  const views = document.getElementById('event-views');
  if (!live && !views) return;
  try {
    const r = await fetch(`/api/stats${eventId ? `?event=${eventId}` : ''}`);
    if (!r.ok) return;
    const s = (await r.json()) as { active: number; today: number; event: number | null };
    if (live) {
      const a = live.querySelector<HTMLElement>('[data-tpl="active"]');
      const t = live.querySelector<HTMLElement>('[data-tpl="today"]');
      if (a) a.textContent = (a.dataset.text ?? '{n}').replace('{n}', fmt.format(s.active));
      if (t) t.textContent = (t.dataset.text ?? '{n}').replace('{n}', fmt.format(s.today));
      live.hidden = false;
    }
    if (views && s.event !== null) {
      views.querySelector('dd')!.textContent = fmt.format(s.event);
      views.hidden = false;
    }
  } catch {
    /* keep hidden */
  }
}

if (!automated) {
  const sid = sessionId();
  void post('/api/hit', { path: location.pathname, event: eventId });
  const beat = () => document.visibilityState === 'visible' && sid && post('/api/heartbeat', { sid });
  void beat();
  setInterval(beat, HEARTBEAT_MS);
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') {
      void beat();
      void refreshStats();
    }
  });
}
void refreshStats();
setInterval(refreshStats, STATS_MS);

/** Live collection status (pushed by the collector after every run). */
interface CollectorStatus {
  lastSuccess: string | null;
  run: { ok: number; error: number };
  sources: { id: string; state: string; lastSuccess?: string | null; lastError?: string | null }[];
}

const pad = (n: number) => String(n).padStart(2, '0');
const utc = (iso: string) => {
  const d = new Date(iso);
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())} UTC`;
};

async function refreshCollector() {
  try {
    const r = await fetch('/api/collector');
    if (!r.ok) return;
    const { status } = (await r.json()) as { status: CollectorStatus | null };
    if (!status) return;
    const at = document.getElementById('collected-at');
    if (at && status.lastSuccess) {
      at.textContent = utc(status.lastSuccess);
      at.setAttribute('datetime', status.lastSuccess);
    }
    const ok = document.getElementById('src-ok');
    const err = document.getElementById('src-err');
    if (ok) ok.textContent = String(status.run.ok);
    if (err) {
      err.textContent = String(status.run.error);
      document.getElementById('src-err-wrap')!.hidden = status.run.error === 0;
    }
    const table = document.getElementById('sources-table');
    if (table) {
      for (const s of status.sources) {
        const cell = table.querySelector<HTMLElement>(`[data-src-state="${CSS.escape(s.id)}"]`);
        const last = table.querySelector<HTMLElement>(`[data-src-last="${CSS.escape(s.id)}"]`);
        if (cell && (s.state === 'ok' || s.state === 'error')) {
          const span = document.createElement('span');
          span.className = `state state-${s.state}`;
          span.textContent = `${s.state === 'ok' ? '●' : '✕'} ${table.dataset[s.state === 'ok' ? 'labelOk' : 'labelError'] ?? s.state}`;
          if (s.lastError) span.title = s.lastError;
          cell.replaceChildren(span);
        }
        if (last && s.lastSuccess) last.textContent = utc(s.lastSuccess);
      }
    }
  } catch {
    /* keep the static values */
  }
}
void refreshCollector();

export {};

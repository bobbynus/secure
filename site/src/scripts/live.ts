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

export {};

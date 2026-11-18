/**
 * Progressive enhancement for the main feed. The page is fully usable without
 * it (server-rendered cards + pagination links). With JS:
 *  - filters (product / priority / period / search), mirrored in the URL query;
 *  - "Load more" instead of pagination;
 *  - "New events: N" button: the list never jumps on its own.
 */
import { renderCard, type CardLabels, type FeedItem } from '../lib/card';
import { esc } from '../lib/format';

interface FeedIndex {
  now: string;
  labels: CardLabels;
  items: FeedItem[];
}

const POLL_MS = 120_000;
const PERIOD_MS: Record<string, number> = { '1d': 864e5, '7d': 7 * 864e5, '30d': 30 * 864e5, '365d': 365 * 864e5 };

const cfg = document.getElementById('feed-config');
if (cfg) void init(cfg);

async function init(cfg: HTMLElement) {
  const lang = document.documentElement.lang;
  const base = `/${lang}`;
  const pageSize = Number(cfg.dataset.pageSize) || 10;
  const offset = Number(cfg.dataset.offset) || 0;

  const list = document.getElementById('feed-list')!;
  const form = document.getElementById('filters') as HTMLFormElement;
  const more = document.getElementById('load-more') as HTMLButtonElement;
  const newBtn = document.getElementById('new-events') as HTMLButtonElement;
  const count = document.getElementById('feed-count')!;
  const pagination = document.getElementById('pagination');

  let index: FeedIndex;
  try {
    index = await fetchIndex(base);
  } catch {
    return; // keep the static page as is
  }

  let known = new Set(index.items.map((i) => i.id));
  let pending: FeedIndex | null = null;
  // Without filters, the server already rendered items [offset, offset + pageSize).
  let shown = Math.min(offset + pageSize, index.items.length);
  let start = offset;

  const box = document.getElementById('filters-box') as HTMLDetailsElement;
  box.hidden = false;
  pagination?.setAttribute('hidden', '');
  readQuery(form);
  // Open on wide screens or when the URL already carries filters; collapsed on phones.
  box.open = matchMedia('(min-width: 761px)').matches || location.search.length > 1;

  const filtered = (): FeedItem[] => {
    const f = new FormData(form);
    const product = String(f.get('product') ?? '');
    const priority = String(f.get('priority') ?? '');
    const period = String(f.get('period') ?? '');
    const q = String(f.get('q') ?? '').trim().toLowerCase();
    const since = period && PERIOD_MS[period] ? new Date(index.now).getTime() - PERIOD_MS[period]! : 0;
    return index.items.filter(
      (i) =>
        (!product || i.products.some((p) => p.id === product)) &&
        (!priority || i.priority === priority) &&
        (!since || new Date(i.published).getTime() >= since) &&
        (!q || haystack(i).includes(q)),
    );
  };

  const hasFilters = () => [...new FormData(form).values()].some((v) => String(v).trim() !== '');

  const render = (append = false) => {
    const items = filtered();
    const slice = items.slice(start, shown);
    if (!append) {
      list.innerHTML = slice.length
        ? slice.map((i) => renderCard(i, index.labels, base)).join('\n')
        : `<p class="empty">${esc(index.labels['feed.empty'] ?? '')}</p>`;
    }
    more.hidden = shown >= items.length;
    count.textContent = (index.labels['feed.count'] ?? '')
      .replace('{shown}', String(Math.max(0, Math.min(shown, items.length) - start)))
      .replace('{total}', String(items.length - start));
  };

  render(true);

  more.addEventListener('click', () => {
    const items = filtered();
    const from = shown;
    shown = Math.min(shown + pageSize, items.length);
    list.insertAdjacentHTML('beforeend', items.slice(from, shown).map((i) => renderCard(i, index.labels, base)).join('\n'));
    // Move focus to the first newly added card for keyboard users.
    list.querySelectorAll<HTMLAnchorElement>('.card-title a')[from - start]?.focus();
    render(true);
  });

  const onFilter = () => {
    start = hasFilters() ? 0 : offset;
    shown = start + pageSize;
    writeQuery(form);
    render();
  };
  form.addEventListener('input', debounce(onFilter, 150));
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    onFilter();
  });
  form.addEventListener('reset', () => setTimeout(onFilter));
  if (hasFilters()) onFilter();

  // "New events: N" — polled only while the tab is visible.
  const poll = async () => {
    if (document.visibilityState !== 'visible') return;
    try {
      const next = await fetchIndex(base);
      const fresh = next.items.filter((i) => !known.has(i.id)).length;
      if (fresh > 0) {
        pending = next;
        newBtn.textContent = (next.labels['feed.new'] ?? '{n}').replace('{n}', String(fresh));
        newBtn.hidden = false;
      }
    } catch {
      /* offline or deploy in progress: try again later */
    }
  };
  setInterval(poll, POLL_MS);
  newBtn.addEventListener('click', () => {
    if (!pending) return;
    const added = pending.items.filter((i) => !known.has(i.id)).length;
    index = pending;
    pending = null;
    known = new Set(index.items.map((i) => i.id));
    start = hasFilters() ? 0 : offset;
    shown += added;
    newBtn.hidden = true;
    render();
    list.querySelector<HTMLAnchorElement>('.card-title a')?.focus();
  });
}

async function fetchIndex(base: string): Promise<FeedIndex> {
  const res = await fetch(`${base}/index.json`, { cache: 'no-cache' });
  if (!res.ok) throw new Error(String(res.status));
  return res.json();
}

function haystack(i: FeedItem): string {
  return [i.title, i.summary, ...i.ids, ...i.products.map((p) => p.name)].join(' ').toLowerCase();
}

function readQuery(form: HTMLFormElement) {
  const q = new URLSearchParams(location.search);
  for (const el of Array.from(form.elements) as (HTMLInputElement | HTMLSelectElement)[]) {
    if (el.name && q.has(el.name)) el.value = q.get(el.name)!;
  }
}

function writeQuery(form: HTMLFormElement) {
  const q = new URLSearchParams();
  for (const [k, v] of new FormData(form)) if (String(v).trim()) q.set(k, String(v).trim());
  const s = q.toString();
  history.replaceState(null, '', s ? `?${s}` : location.pathname);
}

function debounce<T extends () => void>(fn: T, ms: number) {
  let h: ReturnType<typeof setTimeout> | undefined;
  return () => {
    clearTimeout(h);
    h = setTimeout(fn, ms);
  };
}

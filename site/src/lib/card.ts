import { esc, fmtDate, fmtTime } from './format';

/**
 * Compact feed entry. Built at build time (lib/events.ts), embedded into
 * /<lang>/index.json and rendered by the same function on server and client.
 */
export interface FeedItem {
  id: string;
  url: string;
  title: string;
  summary: string;
  category: 'vulnerability' | 'attack' | 'update-issue';
  priority: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confirmation: 'vendor' | 'official' | 'preliminary';
  fix: 'available' | 'partial' | 'none' | 'n/a' | 'unknown';
  exploitation: 'confirmed' | 'reported' | 'none-known';
  kev: boolean;
  products: { id: string; name: string }[];
  ids: string[];
  sources: number;
  published: string;
  updated: string;
  /** Latest revision (push notifications react to significant kinds only). */
  rev?: { date: string; kind: string };
}

/** Label strings the card needs; shipped with index.json for the client. */
export type CardLabels = Record<string, string>;

const PRIO_ICON: Record<FeedItem['priority'], string> = {
  critical: '◆',
  high: '▲',
  medium: '■',
  low: '●',
  info: 'i',
};

export function renderCard(it: FeedItem, L: CardLabels, base = ''): string {
  const tags: string[] = [];
  for (const p of it.products) {
    tags.push(`<li><a class="chip" href="${base}/products/${esc(p.id)}/">${esc(p.name)}</a></li>`);
  }
  tags.push(`<li><span class="chip chip-fix-${fixClass(it.fix)}">${esc(L[`fix.${it.fix}`] ?? '')}</span></li>`);
  tags.push(`<li><span class="chip chip-conf-${it.confirmation}">${esc(L[`conf.${it.confirmation}`] ?? '')}</span></li>`);
  tags.push(`<li><span class="chip chip-muted">${esc((L['sources.n'] ?? '{n}').replace('{n}', String(it.sources)))}</span></li>`);

  const ids = it.ids.slice(0, 3).map((x) => `<span class="id">${esc(x)}</span>`).join(' ');
  const more = it.ids.length > 3 ? ` <span class="id id-more">+${it.ids.length - 3}</span>` : '';

  return `<article class="card card-${it.priority}" data-id="${esc(it.id)}">
  <div class="card-meta">
    <time datetime="${esc(it.published)}"><span class="card-date">${fmtDate(it.published)}</span> <span class="card-time">${fmtTime(it.published)}</span></time>
    <span class="flag flag-${it.priority}"><span aria-hidden="true">${PRIO_ICON[it.priority]}</span> ${esc(L[`prio.${it.priority}`] ?? it.priority)}</span>
    <span class="flag flag-cat">${esc(L[`cat.${it.category}`] ?? it.category)}</span>
    ${it.exploitation === 'confirmed' ? `<span class="flag flag-exp"><span aria-hidden="true">⚠</span> ${esc(L['exp.confirmed'] ?? '')}</span>` : ''}
    ${it.exploitation === 'reported' ? `<span class="flag flag-exp-rep">${esc(L['exp.reported'] ?? '')}</span>` : ''}
    ${it.kev ? `<span class="flag flag-kev">KEV</span>` : ''}
  </div>
  <h3 class="card-title"><a href="${esc(it.url)}">${esc(it.title)}</a></h3>
  ${ids ? `<p class="card-ids">${ids}${more}</p>` : ''}
  <p class="card-summary">${esc(it.summary)}</p>
  <ul class="card-tags">${tags.join('')}</ul>
  <button type="button" class="quick-btn" data-quick="${esc(it.url)}" aria-haspopup="dialog">${esc(L['quick.open'] ?? 'Quick view')}</button>
</article>`;
}

function fixClass(f: FeedItem['fix']): string {
  return f === 'n/a' ? 'na' : f;
}

/** Keys of the UI dictionary the card uses (subset sent to the client). */
export const CARD_LABEL_KEYS = [
  'prio.critical', 'prio.high', 'prio.medium', 'prio.low', 'prio.info',
  'cat.vulnerability', 'cat.attack', 'cat.update-issue',
  'fix.available', 'fix.partial', 'fix.none', 'fix.n/a', 'fix.unknown',
  'conf.vendor', 'conf.official', 'conf.preliminary',
  'exp.confirmed', 'exp.reported', 'sources.n',
  'feed.empty', 'feed.new', 'feed.count', 'quick.open',
] as const;

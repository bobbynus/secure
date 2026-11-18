import { getCollection, type CollectionEntry } from 'astro:content';
import type { Lang } from '../i18n/ui';
import { LANGS, UI } from '../i18n/ui';
import { CARD_LABEL_KEYS, type CardLabels, type FeedItem } from './card';

export type SecEvent = CollectionEntry<'events'>['data'];
export type Product = CollectionEntry<'products'>['data'];
export type Source = CollectionEntry<'sources'>['data'];

let cache: Promise<{ events: SecEvent[]; products: Map<string, Product>; sources: Source[] }> | undefined;

/** Loads and validates everything once per build. */
export function loadAll() {
  cache ??= (async () => {
    const [ev, pr, sr] = await Promise.all([getCollection('events'), getCollection('products'), getCollection('sources')]);
    const products = new Map(pr.map((p) => [p.data.id, p.data]));
    const events = ev.map((e) => e.data).sort((a, b) => b.dates.published.localeCompare(a.dates.published));
    for (const e of events) {
      for (const p of e.products) if (!products.has(p)) throw new Error(`${e.id}: unknown product "${p}"`);
      if (e.affected.some((a) => !products.has(a.product))) throw new Error(`${e.id}: unknown product in affected`);
    }
    return { events, products, sources: sr.map((s) => s.data) };
  })();
  return cache;
}

export const isReady = (e: SecEvent, lang: Lang) => e.translations[lang].status === 'ready';

/** Events that have a published (ready) translation in `lang`. */
export async function eventsIn(lang: Lang) {
  const { events } = await loadAll();
  return events.filter((e) => isReady(e, lang));
}

export function articlePath(e: SecEvent, lang: Lang): string {
  return `/${lang}/news/${e.id}-${e.translations[lang].slug}/`;
}

/** Language → URL of the equivalent article, only for ready translations. */
export function alternates(e: SecEvent): Partial<Record<Lang, string>> {
  const out: Partial<Record<Lang, string>> = {};
  for (const l of LANGS) if (isReady(e, l)) out[l] = articlePath(e, l);
  return out;
}

/**
 * Reference "now" for relative views (last 24 h, period filter): time of the
 * last successful collection, so a static build stays self-consistent.
 */
export async function collectedAt(): Promise<string> {
  const { sources, events } = await loadAll();
  const times = sources.map((s) => s.lastSuccess).filter((x): x is string => !!x);
  if (times.length) return times.sort().at(-1)!;
  return events[0]?.dates.updated ?? new Date().toISOString();
}

export const TOPICS = ['vulnerabilities', 'attacks', 'update-issues', 'exploited', 'fix-available', 'last-24h'] as const;
export type Topic = (typeof TOPICS)[number];

export function topicFilter(topic: Topic, now: string): (e: SecEvent) => boolean {
  const dayAgo = new Date(new Date(now).getTime() - 86_400_000).toISOString();
  switch (topic) {
    case 'vulnerabilities': return (e) => e.category === 'vulnerability';
    case 'attacks': return (e) => e.category === 'attack';
    case 'update-issues': return (e) => e.category === 'update-issue';
    case 'exploited': return (e) => e.exploitation.status === 'confirmed';
    case 'fix-available': return (e) => e.fix === 'available' || e.fix === 'partial';
    case 'last-24h': return (e) => e.dates.updated >= dayAgo;
  }
}

export function toFeedItem(e: SecEvent, lang: Lang, products: Map<string, Product>): FeedItem {
  const tr = e.translations[lang];
  return {
    id: e.id,
    url: articlePath(e, lang),
    title: tr.title,
    summary: tr.summary,
    category: e.category,
    priority: e.priority,
    confirmation: e.confirmation,
    fix: e.fix,
    exploitation: e.exploitation.status,
    kev: e.exploitation.kev,
    products: e.products.map((id) => ({ id, name: products.get(id)!.name })),
    ids: [...e.identifiers.cve, ...e.identifiers.kb, ...e.identifiers.advisory],
    sources: e.sources.length,
    published: e.dates.published,
    updated: e.dates.updated,
  };
}

export function cardLabels(lang: Lang): CardLabels {
  return Object.fromEntries(CARD_LABEL_KEYS.map((k) => [k, UI[lang][k]]));
}

/** Products that have at least one ready event in `lang`, sorted by name. */
export async function productsWithEvents(lang: Lang) {
  const { products } = await loadAll();
  const evs = await eventsIn(lang);
  return [...products.values()]
    .map((p) => ({ ...p, count: evs.filter((e) => e.products.includes(p.id)).length }))
    .filter((p) => p.count > 0)
    .sort((a, b) => a.name.localeCompare(b.name));
}

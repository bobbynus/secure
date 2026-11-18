import type { APIRoute, GetStaticPaths } from 'astro';
import { cardLabels, collectedAt, eventsIn, loadAll, toFeedItem } from '../../lib/events';
import { LANGS, type Lang } from '../../i18n/ui';

export const getStaticPaths: GetStaticPaths = () => LANGS.map((lang) => ({ params: { lang } }));

/** Compact feed index for client-side filters, "load more" and "new events". */
export const GET: APIRoute = async ({ params }) => {
  const lang = params.lang as Lang;
  const { products } = await loadAll();
  const items = (await eventsIn(lang)).map((e) => toFeedItem(e, lang, products));
  const body = { now: await collectedAt(), labels: cardLabels(lang), items };
  return new Response(JSON.stringify(body), { headers: { 'Content-Type': 'application/json; charset=utf-8' } });
};

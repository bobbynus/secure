import rss from '@astrojs/rss';
import type { APIRoute, GetStaticPaths } from 'astro';
import { SITE } from '../../config';
import { articlePath, eventsIn } from '../../lib/events';
import { LANGS, t, type Lang } from '../../i18n/ui';

export const getStaticPaths: GetStaticPaths = () => LANGS.map((lang) => ({ params: { lang } }));

/** One feed per language. GUID = event ID + language: stable across edits and slug changes. */
export const GET: APIRoute = async ({ params, site }) => {
  const lang = params.lang as Lang;
  const events = (await eventsIn(lang)).slice(0, 50);
  return rss({
    title: `${SITE.name} (${lang.toUpperCase()})`,
    description: t(lang, 'description'),
    site: site!,
    customData: `<language>${lang}</language>`,
    items: events.map((e) => ({
      title: `[${t(lang, `prio.${e.priority}`)}] ${e.translations[lang].title}`,
      link: articlePath(e, lang),
      description: e.translations[lang].summary,
      pubDate: new Date(e.dates.published),
      categories: [t(lang, `cat.${e.category}`), ...e.identifiers.cve],
      customData: `<guid isPermaLink="false">${e.id}:${lang}</guid>`,
    })),
  });
};

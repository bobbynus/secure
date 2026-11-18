import { readdir, readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

/**
 * Writes dist/_redirects (Cloudflare Workers static assets format):
 *  - old slugs (slugHistory) → current URL, 301;
 *  - bare stable ID `/<lang>/news/<id>/` → current URL, 301.
 * Only for translations with status "ready".
 */
export default function redirects({ dataDir }) {
  return {
    name: 'secure-redirects',
    hooks: {
      'astro:build:done': async ({ dir, logger }) => {
        const root = path.resolve(fileURLToPath(new URL('..', import.meta.url)), dataDir);
        const lines = [];
        for (const f of (await readdir(root)).filter((f) => f.endsWith('.json')).sort()) {
          const e = JSON.parse(await readFile(path.join(root, f), 'utf8'));
          for (const [lang, tr] of Object.entries(e.translations)) {
            if (tr.status !== 'ready') continue;
            const to = `/${lang}/news/${e.id}-${tr.slug}/`;
            lines.push(`/${lang}/news/${e.id}/ ${to} 301`);
            for (const old of tr.slugHistory ?? []) lines.push(`/${lang}/news/${e.id}-${old}/ ${to} 301`);
          }
        }
        await writeFile(new URL('_redirects', dir), lines.join('\n') + '\n');
        logger.info(`_redirects: ${lines.length} rules`);
      },
    },
  };
}

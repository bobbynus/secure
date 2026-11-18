import { defineConfig } from 'astro/config';
import sitemap from '@astrojs/sitemap';
import redirects from './integrations/redirects.mjs';

export default defineConfig({
  site: 'https://secure.abramov.vip',
  trailingSlash: 'always',
  build: { format: 'directory', inlineStylesheets: 'never' },
  vite: { build: { assetsInlineLimit: 0 } },
  integrations: [
    sitemap({ filter: (page) => !page.endsWith('/404/') && page !== 'https://secure.abramov.vip/' }),
    redirects({ dataDir: '../data/events' }),
  ],
});

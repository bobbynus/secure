import { defineCollection } from 'astro:content';
import { glob, file } from 'astro/loaders';
import { z } from 'astro/zod';

/**
 * Published content model (MVP): one JSON file per Event in ../data/events.
 * The collector/AI pipeline (stage 3–4) writes these files; the site only reads them.
 */

const LANGS = ['ru', 'de', 'en'] as const;

const localized = z.object({ ru: z.string(), de: z.string(), en: z.string() });

const regression = z.object({
  update: z.string(),
  symptoms: z.array(z.string()).min(1),
  conditions: z.string(),
  vendorStatus: z.string(),
  fixedBy: z.string().optional(),
  rollback: z.string().optional(),
});

const translation = z.object({
  /** Only `ready` translations get a public page, RSS item and sitemap entry. */
  status: z.enum(['ready', 'draft', 'failed']),
  slug: z.string().regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/),
  /** Previous slugs; each gets a 301 to the current URL. */
  slugHistory: z.array(z.string()).default([]),
  title: z.string(),
  summary: z.string(),
  impact: z.string(),
  exploitation: z.string(),
  fix: z.string(),
  workaround: z.string().optional(),
  checks: z.array(z.string()).min(1),
  regression: regression.optional(),
});

const sourceRef = z.object({
  id: z.string(),
  title: z.string(),
  url: z.url(),
  publisher: z.string(),
  kind: z.enum(['vendor', 'kev', 'nvd', 'cert', 'research', 'media', 'community']),
  date: z.iso.date().optional(),
});

const events = defineCollection({
  loader: glob({ pattern: '*.json', base: '../data/events' }),
  schema: z.object({
    id: z.string().regex(/^sr-\d{2}-\d{4}$/),
    category: z.enum(['vulnerability', 'attack', 'update-issue']),
    /** Editorial priority, independent of CVSS. */
    priority: z.enum(['critical', 'high', 'medium', 'low', 'info']),
    confirmation: z.enum(['vendor', 'official', 'preliminary']),
    lifecycle: z.enum(['detected', 'confirmed', 'fix-available', 'resolved']),
    fix: z.enum(['available', 'partial', 'none', 'n/a', 'unknown']),
    workaround: z.boolean(),
    exploitation: z.object({
      status: z.enum(['confirmed', 'reported', 'none-known']),
      kev: z.boolean(),
      kevAdded: z.iso.date().optional(),
      evidence: z.array(z.string()).default([]),
    }),
    vendor: z.string(),
    /** Catalog product ids (may be empty: not every vendor product is in the catalog). */
    products: z.array(z.string()).default([]),
    identifiers: z.object({
      cve: z.array(z.string().regex(/^CVE-\d{4}-\d{4,}$/)).default([]),
      advisory: z.array(z.string()).default([]),
      kb: z.array(z.string()).default([]),
    }),
    affected: z.array(
      /** `product`: catalog id, or the vendor's product name when it is not in the catalog. */
      z.object({ product: z.string(), versions: z.string(), fixed: z.string().optional() }),
    ),
    cvss: z
      .object({
        score: z.number().min(0).max(10),
        version: z.enum(['3.0', '3.1', '3.x', '4.0']),
        source: z.string(),
      })
      .optional(),
    dates: z.object({
      event: z.iso.datetime(),
      published: z.iso.datetime(),
      updated: z.iso.datetime(),
    }),
    sources: z.array(sourceRef).min(1),
    revisions: z.array(
      z.object({
        date: z.iso.datetime(),
        kind: z.enum(['created', 'exploitation', 'fix', 'versions', 'workaround', 'status', 'edit']),
        note: localized,
      }),
    ),
    /** Set when texts were written by the AI step (stage 4); shown on the article. */
    generated: z.object({ model: z.string(), prompt: z.string(), at: z.iso.datetime() }).optional(),
    translations: z.object(Object.fromEntries(LANGS.map((l) => [l, translation])) as Record<(typeof LANGS)[number], typeof translation>),
  }),
});

const products = defineCollection({
  loader: file('../data/products.json'),
  schema: z.object({
    id: z.string(),
    name: z.string(),
    vendor: z.string(),
  }),
});

const sources = defineCollection({
  loader: file('../data/sources.json'),
  schema: z.object({
    id: z.string(),
    name: z.string(),
    url: z.url(),
    kind: z.enum(['vendor', 'kev', 'nvd', 'cert', 'research', 'media', 'community']),
    format: z.enum(['api', 'rss', 'json', 'csv', 'html']),
    vendors: z.array(z.string()).default([]),
    interval: z.string(),
    state: z.enum(['ok', 'error', 'planned', 'paused']),
    lastSuccess: z.iso.datetime().optional(),
    terms: z.string().optional(),
  }),
});

export const collections = { events, products, sources };

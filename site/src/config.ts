/** Site-wide configuration. Empty links are hidden in the UI. */
export const SITE = {
  name: 'secure.abramov.vip',
  url: 'https://secure.abramov.vip',
  /**
   * Demo mode: test content. Adds a visible banner, `noindex` on every page
   * and `Disallow: /` in robots.txt. Switch off once the real pipeline publishes.
   */
  demo: false,
  pageSize: 10,
  repoUrl: 'https://github.com/bobbynus/secure',
  /** GitHub Issue Form used by "+ Source" until the on-site form (stage 6). */
  suggestUrl: 'https://github.com/bobbynus/secure/issues/new?template=source-suggestion.yml',
  /** Ko-fi page; empty = Ko-fi links hidden. */
  kofiUrl: 'https://ko-fi.com/borisabramov',
  telegram: { ru: '', de: '', en: '' } as Record<string, string>,
  contactEmail: '',
  /** Cloudflare Turnstile site key for the suggestion form; empty = disabled (honeypot + rate limit only). */
  turnstileSiteKey: '',
} as const;

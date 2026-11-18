export interface Env {
  ASSETS: Fetcher;
  DB: D1Database;
  RL_HIT: RateLimit;
  RL_SUGGEST: RateLimit;
  RL_PUSH: RateLimit;

  SITE_ORIGIN: string;
  GITHUB_REPO: string;
  VAPID_PUBLIC_KEY: string;
  VAPID_SUBJECT: string;

  /** Fine-grained PAT: Issues read/write on GITHUB_REPO only. Optional: without it the form reports "not configured". */
  GITHUB_TOKEN?: string;
  /** Cloudflare Turnstile secret. Optional: without it only honeypot + rate limit protect the form. */
  TURNSTILE_SECRET?: string;
  /** JSON Web Key (ECDSA P-256 private) for VAPID. */
  VAPID_PRIVATE_JWK?: string;
  /** Bearer token for /api/push/dispatch and /api/push/pause (used by CI after deploy). */
  DISPATCH_TOKEN?: string;
}

/** Workers Rate Limiting binding (in-memory per key, nothing persisted). */
export interface RateLimit {
  limit(opts: { key: string }): Promise<{ success: boolean }>;
}

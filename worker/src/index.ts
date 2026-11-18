import type { Env } from './env';
import { errorResponse, HttpError, json } from './http';
import { cleanupSessions, heartbeat, hit, stats } from './stats';
import { suggest } from './suggest';
import { getCollector, putCollector } from './collector';
import { dispatch, getPrefs, pause, processOutbox, subscribe, unsubscribe, vapidPublic } from './push/routes';

/**
 * secure.abramov.vip Worker. Static assets are served by Cloudflare directly;
 * this script only runs for /api/* (assets.run_worker_first) and the cron trigger.
 * A failure here never affects the static site.
 */

type Handler = (req: Request, env: Env, ctx: ExecutionContext) => Promise<Response> | Response;

const routes: Record<string, Partial<Record<'GET' | 'POST', Handler>>> = {
  '/api/hit': { POST: hit },
  '/api/heartbeat': { POST: heartbeat },
  '/api/stats': { GET: stats },
  '/api/suggest': { POST: suggest },
  '/api/push/key': { GET: (_r, env) => vapidPublic(env) },
  '/api/push/subscribe': { POST: subscribe },
  '/api/push/unsubscribe': { POST: unsubscribe },
  '/api/push/prefs': { POST: getPrefs },
  '/api/push/dispatch': { POST: dispatch },
  '/api/push/pause': { POST: pause },
  '/api/collector': { GET: (_r, env) => getCollector(env), POST: putCollector },
  '/api/health': { GET: () => json({ ok: true }) },
};

export default {
  async fetch(req, env, ctx): Promise<Response> {
    const { pathname } = new URL(req.url);
    if (!pathname.startsWith('/api/')) return env.ASSETS.fetch(req);
    try {
      const route = routes[pathname];
      if (!route) throw new HttpError(404, 'not_found');
      const handler = route[req.method as 'GET' | 'POST'];
      if (!handler) throw new HttpError(405, 'method_not_allowed');
      return await handler(req, env, ctx);
    } catch (e) {
      return errorResponse(e);
    }
  },

  async scheduled(_event, env, ctx): Promise<void> {
    ctx.waitUntil(
      Promise.allSettled([cleanupSessions(env), processOutbox(env)]).then((r) =>
        r.forEach((x) => x.status === 'rejected' && console.error('cron', x.reason)),
      ),
    );
  },
} satisfies ExportedHandler<Env>;

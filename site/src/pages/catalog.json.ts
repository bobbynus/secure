import type { APIRoute } from 'astro';
import { loadAll } from '../lib/events';

/** Source catalog (names + URLs) for the suggestion form's duplicate check in the Worker. */
export const GET: APIRoute = async () => {
  const { sources } = await loadAll();
  const body = { sources: sources.map((s) => ({ id: s.id, name: s.name, url: s.url, state: s.state })) };
  return new Response(JSON.stringify(body), { headers: { 'Content-Type': 'application/json; charset=utf-8' } });
};

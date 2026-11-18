/** Pure helpers shared by server templates and the client feed script. */

const ESC: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

export function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ESC[c]!);
}

/**
 * Minimal inline markup for pipeline text: `code` only. Everything is escaped
 * first, so untrusted source text can never inject HTML.
 */
export function inline(s: string): string {
  return esc(s).replace(/`([^`]+)`/g, '<code>$1</code>');
}

/** `2024-04-12 14:32` in UTC, locale-independent (terminal style). */
export function fmtDateTime(iso: string): string {
  const d = new Date(iso);
  return `${fmtDate(iso)} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`;
}

export function fmtDate(iso: string): string {
  const d = new Date(iso);
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
}

export function fmtTime(iso: string): string {
  const d = new Date(iso);
  return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`;
}

function pad(n: number): string {
  return String(n).padStart(2, '0');
}

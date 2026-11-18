/** On-site source suggestion form → POST /api/suggest → exactly one GitHub issue. */

const form = document.getElementById('suggest-form') as HTMLFormElement | null;

if (form) {
  const M: Record<string, string> = JSON.parse(form.dataset.messages ?? '{}');
  const status = document.getElementById('suggest-status')!;
  const submit = form.querySelector<HTMLButtonElement>('button[type=submit]')!;
  const submitText = submit.textContent ?? '';
  // One request ID per filled form: retries and double clicks map to the same issue.
  let requestId = crypto.randomUUID();
  form.addEventListener('input', () => {
    if (form.dataset.done) {
      requestId = crypto.randomUUID();
      delete form.dataset.done;
    }
  });

  const show = (kind: 'ok' | 'error', html: string) => {
    status.className = `sform-status sform-${kind}`;
    status.innerHTML = html;
    status.focus();
  };
  const esc = (s: string) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
  const issueLink = (n: number, url: string, tpl: string) =>
    esc(tpl).replace(`#{n}`, url.startsWith('https://github.com/') ? `<a href="${esc(url)}" rel="noopener">#${n}</a>` : `#${n}`);

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!form.checkValidity()) {
      form.reportValidity();
      return;
    }
    const f = new FormData(form);
    const body: Record<string, string> = { requestId };
    for (const k of ['name', 'url', 'kind', 'format', 'language', 'products', 'rationale', 'docs', 'website']) body[k] = String(f.get(k) ?? '').trim();
    const ts = f.get('cf-turnstile-response');
    if (ts) body.turnstile = String(ts);

    submit.disabled = true;
    submit.textContent = M['sf.sending'] ?? '…';
    try {
      const r = await fetch('/api/suggest', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      const data = (await r.json().catch(() => ({}))) as { ok?: boolean; error?: string; number?: number; url?: string; name?: string; repeated?: boolean };
      if (r.ok && data.ok) {
        form.dataset.done = '1';
        show('ok', issueLink(data.number ?? 0, data.url ?? '', M[data.repeated ? 'sf.repeated' : 'sf.ok'] ?? '#{n}'));
        if (!data.repeated) form.reset();
        return;
      }
      const code = data.error ?? 'generic';
      if (code === 'duplicate_issue') show('error', issueLink(data.number ?? 0, data.url ?? '', M['sf.err.duplicate_issue'] ?? ''));
      else if (code === 'duplicate_catalog') show('error', esc((M['sf.err.duplicate_catalog'] ?? '').replace('{name}', data.name ?? '')));
      else {
        const key = code.startsWith('captcha') ? 'sf.err.captcha' : `sf.err.${code}`;
        show('error', esc(M[key] ?? M['sf.err.generic'] ?? 'Error'));
      }
    } catch {
      show('error', esc(M['sf.err.generic'] ?? 'Error'));
    } finally {
      submit.disabled = false;
      submit.textContent = submitText;
      (window as unknown as { turnstile?: { reset(): void } }).turnstile?.reset();
    }
  });
}

export {};

/**
 * Quick view: on wide screens a side panel with the article; the article always has its own page.
 * The button is only visible with JS on wide screens (CSS), so narrow screens use the normal link.
 */

const dialog = document.getElementById('quick') as HTMLDialogElement | null;

if (dialog) {
  const body = dialog.querySelector<HTMLElement>('.quick-body')!;
  const full = dialog.querySelector<HTMLAnchorElement>('.quick-full')!;
  const errorText = dialog.dataset.error ?? 'Error';
  let controller: AbortController | undefined;

  document.addEventListener('click', async (e) => {
    const btn = (e.target as Element).closest<HTMLButtonElement>('[data-quick]');
    if (!btn) return;
    const url = btn.dataset.quick!;
    if (!url.startsWith('/')) return;
    full.href = url;
    body.replaceChildren();
    body.setAttribute('aria-busy', 'true');
    dialog.showModal();
    controller?.abort();
    controller = new AbortController();
    try {
      const r = await fetch(url, { signal: controller.signal });
      if (!r.ok) throw new Error(String(r.status));
      const doc = new DOMParser().parseFromString(await r.text(), 'text/html');
      const article = doc.querySelector('.article');
      if (!article) throw new Error('no article');
      article.querySelectorAll('.crumbs, .support, .other-langs, script').forEach((n) => n.remove());
      const h1 = article.querySelector('h1');
      if (h1) h1.id = 'quick-title';
      body.replaceChildren(...Array.from(article.childNodes).map((n) => document.importNode(n, true)));
      body.scrollTop = 0;
    } catch (err) {
      if ((err as Error).name === 'AbortError') return;
      const p = document.createElement('p');
      p.className = 'empty';
      p.textContent = errorText;
      body.replaceChildren(p);
    } finally {
      body.removeAttribute('aria-busy');
    }
  });

  dialog.querySelector('.quick-close')!.addEventListener('click', () => dialog.close());
  // Click on the backdrop closes the panel.
  dialog.addEventListener('click', (e) => {
    if (e.target === dialog) dialog.close();
  });
}

export {};

/**
 * Copy link buttons on feed cards: copies the absolute article URL, shows a check mark for a moment
 * and announces it to screen readers. Delegated, so cards added later by the feed script work too.
 */

const status = document.getElementById('copy-status');
const timers = new WeakMap<HTMLButtonElement, number>();

async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // Older browsers / non-secure contexts: a temporary textarea and the legacy command.
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.append(ta);
    ta.select();
    const ok = document.execCommand('copy');
    ta.remove();
    return ok;
  }
}

document.addEventListener('click', async (e) => {
  const btn = (e.target as Element).closest<HTMLButtonElement>('[data-copy]');
  if (!btn) return;
  const path = btn.dataset.copy!;
  if (!path.startsWith('/')) return;
  if (!(await copyText(new URL(path, location.origin).href))) return;
  const label = btn.getAttribute('aria-label') ?? '';
  const done = btn.dataset.done ?? '';
  btn.classList.add('copied');
  btn.title = done;
  if (status) status.textContent = done;
  clearTimeout(timers.get(btn));
  timers.set(
    btn,
    window.setTimeout(() => {
      btn.classList.remove('copied');
      btn.title = label;
      if (status) status.textContent = '';
    }, 1600),
  );
});

export {};

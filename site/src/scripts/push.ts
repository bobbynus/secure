/**
 * Web Push subscription UI. Permission is requested only after an explicit click.
 * Preferences: language (page language), minimum priority, categories, products.
 */

const form = document.getElementById('push-form') as HTMLFormElement | null;

if (form) void init(form);

async function init(form: HTMLFormElement) {
  const M: Record<string, string> = JSON.parse(form.dataset.messages ?? '{}');
  const lang = form.dataset.lang!;
  const env = document.getElementById('push-env')!;
  const status = document.getElementById('push-status')!;
  const enable = document.getElementById('push-enable') as HTMLButtonElement;
  const disable = document.getElementById('push-disable') as HTMLButtonElement;

  const say = (kind: 'ok' | 'error', key: string) => {
    status.className = `sform-status sform-${kind}`;
    status.textContent = M[key] ?? key;
  };
  const note = (key: string) => {
    env.textContent = M[key] ?? key;
    env.hidden = false;
  };

  if (!('serviceWorker' in navigator) || !('PushManager' in window) || !('Notification' in window)) {
    note(/iPhone|iPad/.test(navigator.userAgent) ? 'push.ios' : 'push.unsupported');
    form.querySelectorAll('button, input').forEach((el) => ((el as HTMLButtonElement).disabled = true));
    return;
  }
  if (Notification.permission === 'denied') note('push.denied');

  const reg = await navigator.serviceWorker.register('/sw.js', { scope: '/' });
  let sub = await reg.pushManager.getSubscription();

  const setMode = (subscribed: boolean) => {
    enable.textContent = M[subscribed ? 'push.save' : 'push.enable'] ?? '';
    disable.hidden = !subscribed;
  };

  // Restore saved preferences for an existing subscription.
  if (sub) {
    try {
      const r = await api('/api/push/prefs', { endpoint: sub.endpoint });
      if (r.subscribed && r.prefs) {
        applyPrefs(form, r.prefs);
        setMode(true);
        say('ok', 'push.on');
      } else setMode(false);
    } catch {
      setMode(false);
    }
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    enable.disabled = true;
    try {
      if (Notification.permission !== 'granted') {
        const p = await Notification.requestPermission();
        if (p !== 'granted') {
          note('push.denied');
          return;
        }
      }
      if (!sub) {
        const { key } = await (await fetch('/api/push/key')).json();
        sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: b64urlToBytes(key) });
      }
      const r = await api('/api/push/subscribe', { subscription: sub.toJSON(), prefs: readPrefs(form, lang) });
      setMode(true);
      say('ok', r.created ? 'push.on' : 'push.saved');
    } catch {
      say('error', 'push.error');
    } finally {
      enable.disabled = false;
    }
  });

  disable.addEventListener('click', async () => {
    disable.disabled = true;
    try {
      if (sub) {
        await api('/api/push/unsubscribe', { endpoint: sub.endpoint }).catch(() => undefined);
        await sub.unsubscribe();
        sub = null;
      }
      setMode(false);
      say('ok', 'push.off');
    } catch {
      say('error', 'push.error');
    } finally {
      disable.disabled = false;
    }
  });
}

interface Prefs {
  lang: string;
  minPriority: string;
  categories: string[];
  products: string[];
}

function readPrefs(form: HTMLFormElement, lang: string): Prefs {
  const f = new FormData(form);
  return {
    lang,
    minPriority: String(f.get('minPriority') ?? 'high'),
    categories: f.getAll('categories').map(String),
    products: f.getAll('products').map(String),
  };
}

function applyPrefs(form: HTMLFormElement, p: Prefs) {
  form.querySelectorAll<HTMLInputElement>('input[name=minPriority]').forEach((i) => (i.checked = i.value === p.minPriority));
  form.querySelectorAll<HTMLInputElement>('input[name=categories]').forEach((i) => (i.checked = !p.categories.length || p.categories.includes(i.value)));
  form.querySelectorAll<HTMLInputElement>('input[name=products]').forEach((i) => (i.checked = p.products.includes(i.value)));
}

async function api(path: string, body: unknown) {
  const r = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  const data = await r.json();
  if (!r.ok || !data.ok) throw new Error(data.error ?? String(r.status));
  return data;
}

function b64urlToBytes(s: string): Uint8Array<ArrayBuffer> {
  const b = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4));
  return Uint8Array.from(b, (c) => c.charCodeAt(0));
}

export {};

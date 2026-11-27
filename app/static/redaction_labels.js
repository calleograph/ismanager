'use strict';
(() => {
  // A login or logout rotates CSRF. Its non-secret suffix scopes this tab's
  // labels without retaining the complete credential or sending a label to the server.
  const csrf = document.querySelector('meta[name="csrf-token"]')?.content;
  if (!csrf) return;
  const root = 'ismanager.batch.labels.';
  const scope = csrf.slice(-16);
  const prefix = root + scope + '.';
  const marker = root + 'scope';
  function clearMatching(match) {
    for (let i = sessionStorage.length - 1; i >= 0; i--) {
      const key = sessionStorage.key(i);
      if (key && match(key)) sessionStorage.removeItem(key);
    }
  }
  try {
    if (sessionStorage.getItem(marker) !== scope) {
      clearMatching(key => key.startsWith(root));
      sessionStorage.setItem(marker,scope);
    }
  } catch { /* Some browsers disable tab storage. Uploads still work. */ }

  function read(key) {
    const raw = JSON.parse(sessionStorage.getItem(key) || '[]');
    return Array.isArray(raw) ? raw.filter(value => typeof value === 'string') : [];
  }
  window.batchFileLabels = {
    remember(batch,ordinal,name) {
      try {
        const key = prefix + batch + '.' + ordinal;
        const names = read(key);
        if (!names.includes(name)) {
          names.push(name);
          sessionStorage.setItem(key,JSON.stringify(names));
        }
      } catch { /* Quota, disabled storage, or malformed existing entry. */ }
    },
    display(batch,node) {
      for (const label of node.querySelectorAll('[data-local-name]')) {
        try {
          const names = read(prefix + batch + '.' + label.dataset.localName);
          label.textContent = names.length ? ' · ' + names.join(' / ') : '';
        } catch { label.textContent = ''; }
      }
    },
    forget(batch) {
      try { clearMatching(key => key.startsWith(prefix + batch + '.')); } catch { /* optional storage */ }
    }
  };
  if (!location.pathname.startsWith('/redaction/')) return;
  const shell = document.querySelector('.shell');
  const notice = document.createElement('p');
  notice.className = 'notice workspace-check';
  notice.setAttribute('role', 'status');
  const retry = document.createElement('button');
  retry.type = 'button';
  retry.textContent = 'Проверить доступ';
  retry.addEventListener('click', verify);
  let focused;
  let check;
  window.addEventListener('pagehide', event => {
    check?.abort();
    if (!event.persisted) return;
    focused = document.activeElement;
    shell.classList.add('checking-workspace');
    shell.inert = true;
    document.querySelectorAll('[data-local-name]').forEach(label => { label.textContent = ''; });
  });
  async function verify() {
    check?.abort();
    check = new AbortController();
    const {signal} = check;
    shell.classList.add('checking-workspace');
    shell.inert = true;
    notice.replaceChildren('Проверяем доступ к материалу…');
    shell.before(notice);
    const url = document.querySelector('[data-check-url]')?.dataset.checkUrl || location.href;
    try {
      const response = await fetch(url, {method:'HEAD', cache:'no-store', signal});
      if (response.status >= 500 || response.status === 429) throw new Error();
      if (!response.ok || response.redirected || response.headers.get('X-Workspace-Scope') !== scope) {
        const target = new URL(url, location.origin);
        window.removeEventListener('beforeunload', warnOnLeave);
        location.replace(target.pathname + target.search);
        return;
      }
      const batch = document.querySelector('[data-batch-id]')?.dataset.batchId;
      if (batch) window.batchFileLabels.display(batch, shell);
      shell.classList.remove('checking-workspace');
      shell.inert = false;
      notice.remove();
      if (focused?.isConnected) focused.focus({preventScroll:true});
    } catch {
      if (!signal.aborted) notice.replaceChildren('Не удалось проверить доступ к материалу. ', retry);
    }
  }
  window.addEventListener('pageshow', event => { if (event.persisted) verify(); });
})();

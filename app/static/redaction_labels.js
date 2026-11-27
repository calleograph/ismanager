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
  // A restored page must recheck the session before rendering an earlier user's labels.
  if (location.pathname.startsWith('/redaction/')) {
    window.addEventListener('pagehide', () => {
      document.querySelectorAll('[data-local-name]').forEach(label => { label.textContent = ''; });
    });
    window.addEventListener('pageshow', event => { if (event.persisted) location.reload(); });
  }
})();

'use strict';
(() => {
  const form = document.getElementById('batch-upload');
  if (!form) return;
  const field = form.querySelector('[type=file]');
  const csrf = form.elements.csrf_token.value;
  const prefix = form.elements.nonce.value.slice(0, 16);
  const ready = new WeakSet();
  const keys = new WeakMap();
  const label = form.querySelector('.batch-js');
  if (label) label.hidden = false;
  field.multiple = true;
  const starting = form.hasAttribute('data-create');
  const status = document.getElementById('batch-upload-status');
  const link = document.getElementById('batch-upload-link');
  const formats = new Set(form.dataset.formats.split(','));
  let counter = 0;
  let busy = false;
  let refreshTimer;
  let uploadVersion = 0;
  let address = starting ? null : {id: form.dataset.batchId, url: location.pathname, upload: form.action};
  const labels = window.batchFileLabels;
  if (address) labels?.display(address.id,document);


  async function post(url, options) {
    const response = await fetch(url, {method: 'POST', credentials: 'same-origin', cache: 'no-store', ...options});
    if (!response.ok || !response.headers.get('content-type')?.includes('application/json')) {
      throw new Error('Передача не подтверждена. Проверьте соединение и вход в IS Manager, затем повторите загрузку.');
    }
    return response.json();
  }

  // Only rejected files need a metadata hint: accepted files are identified by
  // their verified bytes on the server. No filename is sent in this request.
  function invalidHint(file) {
    let a = 2166136261, b = 5381;
    for (const char of file.name) {
      const value = char.codePointAt(0);
      a = Math.imul(a ^ value,16777619);
      b = Math.imul(b,33) ^ value;
    }
    return [a,b].map(number => (number >>> 0).toString(16).padStart(8,'0')).join('');
  }

  document.addEventListener('submit',async event => {
    const deletion = event.target.closest('form[data-delete-batch]');
    if (!deletion) return;
    event.preventDefault();
    const message = deletion.querySelector('[role=alert]');
    if (busy) { message.textContent = 'Дождитесь завершения загрузки.'; return; }
    const button = deletion.querySelector('button');
    button.disabled = true;
    try {
      const res = await fetch(deletion.action,{method:'POST',credentials:'same-origin',headers:{Accept:'application/json','X-CSRF-Token':csrf}});
      if (res.status===409) throw new Error('Пакет ещё используется. Завершите передачу, обработку или скачивание архива.');
      if (!res.ok || !res.headers.get('content-type')?.includes('application/json')) throw new Error('Удаление не подтверждено. Обновите страницу.');
      const result = await res.json();
      labels?.forget(deletion.dataset.deleteBatch);
      location.assign(result.url);
    } catch (error) {
      message.textContent = error.message;
      button.disabled = false;
    }
  });

  form.addEventListener('submit', async event => {
    if (busy) { event.preventDefault(); return; }
    if (starting && !field.files.length) return;
    event.preventDefault();
    if (!field.files.length) return;
    const files = Array.from(field.files);
    busy = true;
    uploadVersion++;
    field.disabled = true;
    const button = form.querySelector('button');
    button.disabled = true;
    try {
      if (!address) {
        const body = new URLSearchParams({nonce: form.elements.nonce.value, csrf_token: csrf});
        address = await post(form.action, {body, headers: {Accept: 'application/json'}});
      }
      link.href = address.url;
      link.hidden = false;
      for (const [index, file] of files.entries()) {
        if (ready.has(file)) continue;
        status.textContent = 'Передача ' + (index + 1) + ' из ' + files.length + ' · ' + file.name;
        if (!keys.has(file)) keys.set(file, prefix + (++counter).toString(16).padStart(16, '0'));
        const headers = {'X-CSRF-Token': csrf, 'X-Upload-Key': keys.get(file)};
        const dot = file.name.lastIndexOf('.');
        const ext = dot < 0 ? '' : file.name.slice(dot + 1).toLowerCase();
        let receipt;
        if (file.size > Number(form.dataset.limit) || !formats.has(ext)) {
          headers['Content-Type'] = 'application/json';
          receipt = await post(address.upload, {headers, body: JSON.stringify({ext,size:file.size,hint:invalidHint(file)})});
        } else {
          headers['Content-Type'] = 'application/octet-stream';
          receipt = await post(address.upload + '?ext=' + encodeURIComponent(ext), {headers, body:file});
        }
        labels?.remember(address.id,receipt.ordinal,file.name);
        ready.add(file);
      }
      if (starting) {
        location.assign(address.url);
      } else {
        field.value = '';
        status.textContent = 'Все выбранные файлы переданы.';
      }
    } catch (error) {
      status.textContent = error.message;
    } finally {
      button.disabled = false;
      field.disabled = false;
      busy = false;
      if (!starting) refresh(true);
    }
  });

  document.addEventListener('click', event => {
    if (!event.target.closest('[data-refresh-batch]')) return;
    event.preventDefault();
    refresh(true);
  });

  let refreshVersion = 0;
  async function refresh(force = false) {
    const requestNumber = ++refreshVersion;
    clearTimeout(refreshTimer);
    const panel = document.getElementById('batch-results');
    if (!panel || (!force && !Number(panel.dataset.pending))) return;
    const version = uploadVersion;
    if (!busy && !document.hidden) {
      try {
        const res = await fetch(location.href, {headers:{'X-IS-Fragment':'batch-results'}, cache:'no-store'});
        if (!res.ok) throw new Error();
        const fresh = new DOMParser().parseFromString(await res.text(),'text/html').getElementById('batch-results');
        if (!fresh) throw new Error();
        if (version !== uploadVersion || requestNumber !== refreshVersion) return;
        labels?.display(address.id, fresh);
        const active = document.activeElement;
        const selected = window.getSelection();
        if (selected.isCollapsed || !panel.contains(selected.anchorNode)) {
          if (!panel.isEqualNode(fresh)) {
            const keepFocus = panel.contains(active);
            panel.replaceWith(fresh);
            if (keepFocus) {
              const same = [...fresh.querySelectorAll('a')].find(link => link.getAttribute('href') === active.getAttribute('href'));
              (same || fresh.querySelector('h2')).focus({preventScroll:true});
            }
          }
          if (!Number(fresh.dataset.pending)) return;
        }
      } catch { /* Retry on the same page after a temporary network failure. */ }
    }
    if (version === uploadVersion && requestNumber === refreshVersion) refreshTimer = setTimeout(() => refresh(force), 5000);
  }
  refreshTimer = setTimeout(refresh, 5000);
})();

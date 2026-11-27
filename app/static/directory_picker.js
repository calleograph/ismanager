'use strict';
(() => {
  const field = document.querySelector('#directory-admins[data-search]');
  if (!field) return;
  const input = field.querySelector('#principal-query');
  const list = field.querySelector('#principal-results');
  const message = field.querySelector('#principal-status');
  const groups = field.querySelector('[name="admin_groups"]');
  const users = field.querySelector('#principal-users');
  let timer;
  let controller;

  function close() {
    clearTimeout(timer);
    controller?.abort();
    list.hidden = true;
    list.replaceChildren();
  }

  function select(item) {
    if (item.kind === 'group') {
      const dns = groups.value.split('\n').map(line => line.trim()).filter(Boolean);
      if (!dns.some(dn => dn.toLowerCase() === item.id.toLowerCase())) dns.push(item.id);
      groups.value = dns.join('\n');
    } else {
      let selected = Array.from(users.querySelectorAll('input')).find(box => box.value.split('|')[0] === item.id);
      if (!selected) {
        const label = document.createElement('label');
        selected = document.createElement('input');
        selected.type = 'checkbox';
        selected.name = 'admin_user';
        const name = item.login ? item.label + ' (' + item.login + ')' : item.label;
        selected.value = item.id + '|' + name;
        label.append(selected, ' ' + name);
        users.append(label);
      }
      selected.checked = true;
    }
    input.value = '';
    input.focus();
    close();
    message.textContent = 'Выбрано: ' + item.label + '. Сохраните подключение, чтобы применить права.';
  }

  async function search() {
    const request = new AbortController();
    controller = request;
    message.textContent = 'Поиск в каталоге…';
    try {
      const url = new URL(field.dataset.search, location.origin);
      url.searchParams.set('q', input.value.trim());
      const reply = await fetch(url, {signal: request.signal, headers: {Accept: 'application/json'}});
      const data = await reply.json();
      if (request.signal.aborted) return;
      if (!reply.ok) throw new Error(data.error || 'Не удалось выполнить поиск.');
      for (const item of data.items) {
        const button = document.createElement('button');
        button.type = 'button';
        const dn = document.createElement('small');
        dn.textContent = item.dn;
        button.append((item.kind === 'group' ? 'Группа · ' : 'Пользователь · ') + item.label, dn);
        button.addEventListener('click', () => select(item));
        list.append(button);
      }
      list.hidden = !data.items.length;
      message.textContent = data.items.length ? 'Выберите запись. Для уточнения введите часть имени.' : 'Совпадений нет.';
    } catch (error) {
      if (!request.signal.aborted) message.textContent = error instanceof SyntaxError ? 'Обновите страницу и повторите вход.' : error.message;
    }
  }

  function schedule() {
    close();
    timer = setTimeout(search, 180);
  }
  input.addEventListener('focus', schedule);
  input.addEventListener('input', schedule);
  field.addEventListener('keydown', event => {
    if (event.key === 'Escape') { close(); message.textContent = ''; }
    if (event.target === input && event.key === 'ArrowDown') list.querySelector('button')?.focus();
  });
  field.addEventListener('focusout', event => {
    if (!field.contains(event.relatedTarget)) { close(); message.textContent = ''; }
  });
})();

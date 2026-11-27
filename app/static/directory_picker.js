'use strict';
(() => {
  const connection = document.getElementById('directory-form');
  const port = connection.elements.port;
  const protocol = connection.elements.protocol;
  const defaults = {ldaps:'636', starttls:'389'};
  let previous = protocol.value;
  protocol.addEventListener('change', () => {
    if (port.value === defaults[previous]) port.value = defaults[protocol.value];
    previous = protocol.value;
  });
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
    groups.dispatchEvent(new Event('change', {bubbles:true}));
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
      if (reply.redirected) throw new Error('Сеанс администратора завершён. Войдите в другой вкладке и повторите поиск.');
      const data = await reply.json().catch(() => null);
      if (request.signal.aborted) return;
      if (!reply.ok || !Array.isArray(data?.items)) throw new Error(data?.error || 'Каталог не ответил на поиск. Проверьте подключение к каталогу и повторите поиск по имени.');
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
      message.textContent = data.items.length ? 'Выберите запись. Для уточнения введите часть имени.' : 'Совпадений нет. Попробуйте ввести часть имени пользователя или группы.';
    } catch (error) {
      if (!request.signal.aborted) message.textContent = error instanceof TypeError ? 'Нет связи с IS Manager. Проверьте подключение и повторите поиск.' : error.message;
    }
  }

  function schedule() {
    close();
    timer = setTimeout(search, 180);
  }
  input.addEventListener('focus', schedule);
  input.addEventListener('input', schedule);
  field.addEventListener('keydown', event => {
    const buttons = [...list.querySelectorAll('button')];
    if (event.key === 'Escape' && !list.hidden) {
      event.preventDefault();
      input.focus();
      close();
      message.textContent = '';
      return;
    }
    const index = buttons.indexOf(event.target);
    if (event.key === 'ArrowDown' && buttons.length && (event.target === input || index >= 0)) {
      event.preventDefault();
      buttons[Math.min(index + 1, buttons.length - 1)].focus();
    } else if (event.key === 'ArrowUp' && index >= 0) {
      event.preventDefault();
      (buttons[index - 1] || input).focus();
    }
  });
  field.addEventListener('focusout', event => {
    if (!field.contains(event.relatedTarget)) { close(); message.textContent = ''; }
  });
})();

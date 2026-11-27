'use strict';

(() => {
  const alert = document.querySelector('.admin-space [role=alert]');
  if (alert) {
    const target = alert.dataset.invalidField && document.querySelector('form[data-warn-unsaved]')?.elements.namedItem(alert.dataset.invalidField);
    if (target) {
      target.setAttribute('aria-invalid', 'true');
      target.setAttribute('aria-describedby', alert.id);
      target.focus();
    } else {
      alert.tabIndex = -1;
      alert.focus();
    }
  }
})();

for (const picker of document.querySelectorAll('[data-resource-options]')) {
  const input = picker.querySelector('input');
  const select = picker.closest('fieldset').querySelector('select');
  const status = picker.querySelector('[role=status]');
  const placeholder = select.options[0].cloneNode(true);
  let timer;
  let controller;
  picker.hidden = false;
  input.addEventListener('input', () => {
    clearTimeout(timer);
    controller?.abort();
    controller = new AbortController();
    const {signal} = controller;
    timer = setTimeout(async () => {
      const url = new URL(picker.dataset.resourceOptions, location.origin);
      url.searchParams.set('q', input.value.trim());
      status.textContent = 'Ищем ресурсы…';
      try {
        const reply = await fetch(url, {signal, headers:{Accept:'application/json'}});
        if (!reply.ok) throw new Error();
        const data = await reply.json();
        if (signal.aborted) return;
        const current = select.selectedOptions[0];
        const options = data.items.map(item => new Option(item.name, String(item.id)));
        if (current?.value && !options.some(option => option.value === current.value)) options.unshift(current.cloneNode(true));
        select.replaceChildren(placeholder.cloneNode(true), ...options);
        select.value = current?.value || '';
        status.textContent = data.more ? 'Первые 50 совпадений. Уточните запрос.' : data.items.length ? 'Найдены ресурсы — ' + data.items.length + '.' : 'Совпадений нет. Измените запрос.';
      } catch {
        if (!signal.aborted) status.textContent = 'Поиск недоступен. Повторите запрос. Текущий выбор сохранён.';
      }
    }, 180);
  });
}

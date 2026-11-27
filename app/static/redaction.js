'use strict';
const redactionForm = document.getElementById('redaction-form');
const redactionStatus = document.getElementById('redaction-status');
redactionForm.addEventListener('submit', event => {
  if (redactionForm.getAttribute('aria-busy') === 'true') {
    event.preventDefault();
    return;
  }
  const source = redactionForm.elements.text;
  const file = redactionForm.elements.file;
  if (Boolean(source.value.trim()) === Boolean(file.files.length)) {
    event.preventDefault();
    redactionStatus.textContent = source.value.trim()
      ? 'Оставьте один источник: удалите текст или снимите выбор файла.'
      : 'Вставьте текст или выберите файл для обработки.';
    source.focus();
    return;
  }
  redactionForm.setAttribute('aria-busy', 'true');
  redactionStatus.textContent = 'Обработка материала и проверка результата…';
});
redactionForm.addEventListener('input', () => { redactionStatus.textContent = ''; });
window.addEventListener('pageshow', () => {
  redactionForm.removeAttribute('aria-busy');
  redactionStatus.textContent = '';
});

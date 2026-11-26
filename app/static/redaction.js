'use strict';
const redactionForm = document.getElementById('redaction-form');
redactionForm.addEventListener('submit', event => {
  if (redactionForm.getAttribute('aria-busy') === 'true') {
    event.preventDefault();
    return;
  }
  redactionForm.setAttribute('aria-busy', 'true');
  document.getElementById('redaction-status').textContent = 'Обработка материала и проверка результата…';
});
window.addEventListener('pageshow', () => {
  redactionForm.removeAttribute('aria-busy');
  document.getElementById('redaction-status').textContent = '';
});

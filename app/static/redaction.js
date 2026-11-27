'use strict';
const redactionForm = document.getElementById('redaction-form');
const redactionStatus = document.getElementById('redaction-status');
const redactionError = document.getElementById('redaction-error');
const hints = JSON.parse(redactionForm.dataset.hints);
const sourceField = redactionForm.elements.text;
const fileField = redactionForm.elements.file;

function clearError() {
  redactionError.textContent = '';
  for (const field of redactionForm.querySelectorAll('[aria-invalid]')) field.removeAttribute('aria-invalid');
}

redactionForm.addEventListener('submit', event => {
  if (redactionForm.getAttribute('aria-busy') === 'true') {
    event.preventDefault();
    return;
  }
  clearError();
  const file = fileField.files[0];
  const hasText = Boolean(sourceField.value.trim());
  let field = sourceField;
  let message;
  if (!hasText && !file) message = hints.empty;
  else if (hasText && file) message = hints.conflict;
  else if (file) {
    field = fileField;
    if (!fileField.accept.split(',').includes(file.name.toLowerCase().match(/\.[^.]+$/)?.[0])) message = hints.format;
    else if (!file.size) message = hints.empty_file;
    else if (file.size > Number(redactionForm.dataset.fileLimit)) message = hints.large_file;
  } else {
    const limit = Number(redactionForm.dataset.textLimit);
    if (sourceField.value.length > limit && Array.from(sourceField.value).length > limit) message = hints.long;
  }
  if (message) {
    event.preventDefault();
    redactionError.textContent = message;
    field.setAttribute('aria-invalid', 'true');
    field.focus();
    return;
  }
  redactionForm.setAttribute('aria-busy', 'true');
  redactionStatus.textContent = 'Обработка материала и проверка результата…';
});
redactionForm.addEventListener('input', clearError);
window.addEventListener('pageshow', () => {
  redactionForm.removeAttribute('aria-busy');
  redactionStatus.textContent = '';
});

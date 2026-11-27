'use strict';

(() => {
  const form = document.getElementById('pass-form');
  const fields = form.elements;
  const list = document.getElementById('pass-results');
  const output = document.getElementById('pass-output');
  const status = document.getElementById('pass-status');
  const submit = document.getElementById('pass-generate');
  let vocabulary;
  const localAvailable = typeof globalThis.crypto?.getRandomValues === 'function';
  if (!localAvailable) {
    fields.processor.querySelector('option[value="browser"]').disabled = true;
    fields.processor.value = 'server';
    fields.processor.closest('details').open = true;
  }

  function reset() {
    list.replaceChildren();
    output.hidden = true;
    status.textContent = '';
    for (const panel of form.querySelectorAll('[data-modes]')) {
      panel.hidden = !panel.dataset.modes.split(' ').includes(fields.mode.value);
    }
    const hint = document.getElementById('pass-mode-note');
    if (fields.processor.value === 'browser') {
      hint.textContent = 'Ваша фраза и полученные пароли остаются в этой вкладке.';
    } else {
      const reason = localAvailable ? '' : 'В браузере недоступен генератор случайных чисел. ';
      hint.textContent = reason + 'По нажатию кнопки параметры и своя фраза передаются серверу IS Manager. Пароли не записываются в историю.';
    }
  }
  async function loadWords() {
    if (!vocabulary) {
      vocabulary = fetch(form.dataset.dictionary, {credentials: 'same-origin'})
        .then(response => { if (!response.ok) throw new Error(); return response.json(); })
        .then(data => {
          Generator.setDictionary(data.dictionary.map(pair => pair[0]));
          Generator.setDictionaryRussian(data.dictionary);
          Generator.setStoryData(data);
        }).catch(() => { vocabulary = null; throw new Error('Не удалось загрузить словари. Повторите генерацию.'); });
    }
    await vocabulary;
  }
  async function locally() {
    const mode = fields.mode.value;
    const position = fields.position.value;
    if (mode === 'random') {
      const options = {length: Number(fields.random_length.value), useUpper: fields.upper.checked,
        useLower: fields.lower.checked, useDigits: fields.digits.checked, useSpecial: fields.special.checked,
        specialChars: fields.specials.value, excludeAmbiguous: fields.exclude.checked};
      const seen = new Set();
      for (let attempt = 0; seen.size < 7 && attempt < 100; attempt++) {
        seen.add(Generator.generateRandomPassword(options));
      }
      return [...seen].map(password => ({password, words: []}));
    }
    if (mode !== 'custom') await loadWords();
    const options = {source: mode, insertPosition: position, length: Number(fields.word_length.value),
      customWords: fields.phrase.value.trim().split(/\s+/)};
    const batch = mode === 'story' ? Generator.generateStoryBatch(options, 7) : Generator.generateConstructedBatch(options, 7);
    return batch.map(item => ({password: item.password, words: item.breakdown.wordsRu}));
  }
  async function generate(event) {
    event.preventDefault();
    if (!form.reportValidity() || submit.disabled) return;
    reset();
    submit.disabled = true;
    const data = new FormData(form);
    if (fields.mode.value !== 'custom') data.delete('phrase');
    // Lock mode while any asynchronous request is pending.
    const enabled = [...fields].filter(field => !field.disabled);
    try {
      const result = fields.processor.value === 'server'
        ? fetch(form.action, {method: 'POST', body: data, credentials: 'same-origin', cache: 'no-store'})
            .then(async response => {
              if (!response.headers.get('content-type')?.includes('application/json')) {
                throw new Error('Обновите страницу и повторите генерацию.');
              }
              const payload = await response.json();
              if (!response.ok) throw new Error(payload.error || 'Ошибка генерации.');
              return payload.results;
            })
        : locally();
      enabled.forEach(field => { field.disabled = true; });
      for (const item of await result) {
        const li = document.createElement('li');
        const password = document.createElement('code');
        password.textContent = item.password;
        const copy = document.createElement('button');
        copy.type = 'button';
        copy.textContent = 'Копировать';
        copy.addEventListener('click', async () => {
          try {
            await navigator.clipboard.writeText(item.password);
            status.textContent = 'Пароль скопирован.';
          } catch {
            const selection = window.getSelection();
            const range = document.createRange();
            range.selectNodeContents(password);
            selection.removeAllRanges();
            selection.addRange(range);
            status.textContent = 'Пароль выделен. Скопируйте его сочетанием клавиш.';
          }
        });
        li.append(password, ' ', copy);
        if (item.words.length) {
          const hint = document.createElement('p');
          hint.textContent = item.words.join(' · ');
          li.append(hint);
        }
        list.append(li);
      }
      output.hidden = false;
      status.textContent = 'Готово. Вариантов: ' + list.children.length + '.';
    } catch (error) {
      status.textContent = error.message;
    } finally {
      enabled.forEach(field => { field.disabled = false; });
      submit.disabled = false;
    }
  }
  form.addEventListener('input', reset);
  form.addEventListener('submit', generate);
  submit.disabled = false;
  reset();
})();

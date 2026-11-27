'use strict';

(() => {
  const byId = id => document.getElementById(id);
  const form = byId('pass-form');
  const fields = form.elements;
  const list = byId('pass-results');
  const status = byId('pass-status');
  const empty = byId('pass-empty');
  const submit = byId('pass-generate');
  const more = byId('pass-more');
  const all = byId('pass-copy-all');
  const manual = byId('pass-manual');
  const settings = byId('pass-settings');
  const narrow = matchMedia('(max-width:820px)');
  const tabs = [...form.querySelectorAll('[role=tab]')];
  const labels = {
    custom: ['Пароли из вашей фразы', 'Создать из моей фразы'],
    dictionary: ['Пароли из словаря', 'Создать из словаря'],
    story: ['Пароли-истории', 'Создать пароль-историю'],
    random: ['Случайные пароли', 'Создать случайные пароли'],
  };
  let generation = 0;
  let vocabulary;
  const localAvailable = typeof globalThis.crypto?.getRandomValues === 'function';
  if (!localAvailable) {
    fields.processor.querySelector('[value=browser]').disabled = true;
    fields.processor.value = 'server';
    fields.processor.closest('details').open = true;
  }
  function clear() {
    generation++;
    list.replaceChildren();
    empty.hidden = false;
    manual.hidden = true;
    manual.value = '';
    all.disabled = true;
    status.textContent = '';
  }
  function words() { return fields.phrase.value.trim().split(/[\s,;—–-]+/).filter(Boolean); }
  function updateControls() {
    const mode = fields.mode.value;
    const latin = words().map(Generator.transliterate);
    const minLength = latin.reduce((size, word) => size + word.length, Generator.SALT_MIN_LENGTH);
    let message = '';
    if (latin.length < 3 || latin.length > 5) message = 'Введите от трёх до пяти слов.';
    else if (latin.some(word => word.length < 2)) message = 'В каждом слове нужно хотя бы две буквы.';
    else if (words().some(word => word.length > 64)) message = 'Максимальная длина одного слова — 64 буквы.';
    else if (new Set(latin).size !== latin.length) message = 'Слова должны различаться после транслитерации.';
    else if (minLength < 15) message = 'Добавьте буквы, чтобы получить не менее 15 знаков.';
    byId('pass-preview').textContent = latin.filter(Boolean).map(word => word[0].toUpperCase() + word.slice(1)).join(' · ') || 'Mayak · Oblako · Bereg';
    byId('pass-guidance').textContent = message || 'В готовом пароле будет не менее ' + minLength + ' знаков.';
    byId('pass-mode-note').textContent = fields.processor.value === 'browser'
      ? 'Ваша фраза и готовые пароли остаются в этой вкладке.'
      : (localAvailable ? '' : 'В браузере недоступен генератор случайных чисел. ') + 'По нажатию кнопки параметры передаются серверу IS Manager. Пароли не записываются в историю.';
    for (const range of form.querySelectorAll('[type=range]')) {
      form.querySelector('output[for="' + range.id + '"]').value = range.value;
    }
    let issue = mode === 'custom' ? message : '';
    if (mode === 'random') {
      if (![fields.upper, fields.lower, fields.digits, fields.special].some(control => control.checked))
        issue = 'Выберите хотя бы один набор символов.';
    }
    byId('pass-error').textContent = mode === 'custom' ? '' : issue;
    submit.disabled = more.disabled = Boolean(issue);
    empty.textContent = submit.disabled ? issue : 'Нажмите «' + labels[mode][1] + '», чтобы получить варианты.';
  }
  function setMode(mode) {
    clear();
    fields.mode.value = mode;
    if (!narrow.matches || mode === 'custom') settings.open = true;
    tabs.forEach(tab => {
      const active = tab.dataset.mode === mode;
      tab.setAttribute('aria-selected', String(active));
      tab.tabIndex = active ? 0 : -1;
    });
    for (const panel of form.querySelectorAll('[data-modes]')) {
      panel.hidden = !panel.dataset.modes.split(' ').includes(mode);
    }
    byId('pass-title').textContent = labels[mode][0];
    submit.querySelector('span').textContent = labels[mode][1];
    updateControls();
    if (fields.processor.value === 'browser' && !submit.disabled) generate();
  }
  async function loadWords() {
    if (!vocabulary) {
      vocabulary = fetch(form.dataset.dictionary, {credentials:'same-origin'})
        .then(response => { if (!response.ok) throw new Error(); return response.json(); })
        .then(data => {
          Generator.setDictionary(data.dictionary.map(pair => pair[0]));
          Generator.setDictionaryRussian(data.dictionary);
          Generator.setStoryData(data);
        }).catch(() => { vocabulary = null; throw new Error('Не удалось загрузить словари. Повторите генерацию.'); });
    }
    return vocabulary;
  }
  async function locally(mode) {
    if (mode === 'random') {
      const options = {length: Number(fields.random_length.value), useUpper: fields.upper.checked,
        useLower: fields.lower.checked, useDigits: fields.digits.checked, useSpecial: fields.special.checked,
        specialChars: fields.specials.value, excludeAmbiguous: fields.exclude.checked};
      const seen = new Set();
      for (let attempt = 0; seen.size < 7 && attempt < 100; attempt++) seen.add(Generator.generateRandomPassword(options));
      return [...seen].map(password => ({password}));
    }
    const options = {source: mode, insertPosition: fields.position.value, length: Number(fields.word_length.value), customWords: words()};
    if (mode !== 'custom') await loadWords();
    return mode === 'story' ? Generator.generateStoryBatch(options, 7) : Generator.generateConstructedBatch(options, 7);
  }
  async function onServer(mode) {
    const formData = new FormData(form);
    if (mode !== 'custom') formData.delete('phrase');
    let response;
    try {
      response = await fetch(form.action, {method:'POST', body:formData, credentials:'same-origin',
        cache:'no-store', headers:{Accept:'application/json'}});
    } catch {
      throw new Error('Нет связи с IS Manager. Проверьте подключение и нажмите кнопку генерации ещё раз.');
    }
    const payload = await response.json().catch(() => null);
    if (!response.ok || !Array.isArray(payload?.results)) {
      throw new Error(payload?.error || 'Сервер не вернул пароли. Повторите генерацию. Если ошибка повторится, сообщите администратору.');
    }
    return payload.results;
  }
  async function copy(text, code) {
    try {
      await navigator.clipboard.writeText(text);
      status.textContent = code ? 'Пароль скопирован.' : 'Все варианты скопированы.';
    } catch {
      if (code) {
        const range = document.createRange();
        range.selectNodeContents(code);
        window.getSelection().removeAllRanges();
        window.getSelection().addRange(range);
      } else {
        manual.hidden = false;
        manual.value = text;
        manual.focus();
        manual.select();
      }
      status.textContent = (code ? 'Пароль выделен.' : 'Все варианты выделены.') + (matchMedia('(pointer: coarse)').matches ? ' Удерживайте выделение и выберите «Копировать».' : ' Нажмите Ctrl+C или ⌘C.');
    }
  }
  function appendRow(item, index) {
    const row = byId('pass-row').content.firstElementChild.cloneNode(true);
    const code = row.querySelector('code');
    const hint = row.querySelector('small');
    const info = row.querySelector('.pass-info');
    const explanation = row.querySelector('.pass-breakdown');
    const copier = row.querySelector('.pass-copy');
    code.textContent = item.password;
    const breakdown = item.breakdown;
    const rows = [];
    if (breakdown) {
      const mode = fields.mode.value;
      const source = {custom:'Ваши слова', dictionary:'Из словаря', story:'История'}[mode];
      hint.textContent = source + ' · ' + breakdown.wordsRu.join(' + ') + ' · ' + item.password.length + ' зн.';
      const at = breakdown.structure.indexOf('I');
      const position = at === 0 ? 'в начале' : at === breakdown.fragments.length ? 'в конце' : 'между словами';
      const salt = document.createElement('span');
      salt.className = 'pass-salt';
      salt.textContent = breakdown.insert;
      code.replaceChildren(breakdown.fragments.slice(0, at).join(''), salt, breakdown.fragments.slice(at).join(''));
      rows.push(['Слова', breakdown.wordsRu.join(' + ')], ['В пароле', breakdown.fragments.join(' + ')],
        ['Случайная вставка', breakdown.insert + ' — ' + position]);
    } else {
      hint.textContent = 'Случайный набор · ' + item.password.length + ' зн.';
      const groups = [[/[A-Z]/,'заглавные'], [/[a-z]/,'строчные'], [/[0-9]/,'цифры'], [/[^a-zA-Z0-9]/,'спецсимволы']];
      rows.push(['Длина', String(item.password.length)], ['Состав', groups.filter(([regex]) => regex.test(item.password)).map(([,name]) => name).join(', ')]);
    }
    for (const [label, value] of rows) {
      const term = document.createElement('dt');
      const detail = document.createElement('dd');
      term.textContent = label;
      detail.textContent = value;
      explanation.querySelector('dl').append(term, detail);
    }
    explanation.id = 'pass-detail-' + index;
    info.setAttribute('aria-controls', explanation.id);
    for (const [button, label] of [[copier,'Скопировать вариант '],[info,'Как собран вариант ']]) {
      button.title = label + (index + 1);
      button.setAttribute('aria-label', button.title);
    }
    copier.addEventListener('click', () => copy(item.password, code));
    info.addEventListener('click', () => {
      explanation.hidden = !explanation.hidden;
      info.setAttribute('aria-expanded', String(!explanation.hidden));
    });
    list.append(row);
  }
  async function generate() {
    if (submit.disabled || !form.reportValidity()) return;
    clear();
    const current = generation;
    const mode = fields.mode.value;
    empty.textContent = 'Генерируем варианты…';
    submit.disabled = more.disabled = true;
    try {
      const result = await (fields.processor.value === 'server' ? onServer(mode) : locally(mode));
      if (current !== generation) return;
      result.forEach(appendRow);
      all.disabled = false;
      empty.hidden = true;
      status.textContent = 'Готово. Вариантов — ' + result.length + '.';
    } catch (error) {
      if (current === generation) { empty.hidden = true; status.textContent = error.message; }
    } finally {
      if (current === generation) updateControls();
    }
  }
  tabs.forEach((tab, i) => {
    tab.addEventListener('click', () => setMode(tab.dataset.mode));
    tab.addEventListener('keydown', event => {
      let target;
      if (event.key === 'ArrowRight') target = (i + 1) % tabs.length;
      if (event.key === 'ArrowLeft') target = (i + tabs.length - 1) % tabs.length;
      if (event.key === 'Home') target = 0;
      if (event.key === 'End') target = tabs.length - 1;
      if (target !== undefined) {
        event.preventDefault();
        tabs[target].focus();
        tabs[target].click();
      }
    });
  });
  form.addEventListener('input', () => { clear(); updateControls(); });
  form.addEventListener('submit', event => { event.preventDefault(); generate(); });
  more.addEventListener('click', generate);
  all.addEventListener('click', () => copy([...list.querySelectorAll('code')].map(code => code.textContent).join('\n')));
  const advice = document.querySelector('.pass-advice');
  const nextTip = byId('pass-tip');
  let tips;
  let tipIndex = 0;
  nextTip.hidden = false;
  async function showTip() {
    if (nextTip.disabled) return;
    nextTip.disabled = true;
    try {
      if (!tips) {
        const response = await fetch(advice.dataset.tips);
        if (!response.ok) throw new Error();
        tips = await response.json();
      }
      const paragraph = advice.querySelector('p');
      const tip = tips[tipIndex];
      tipIndex = (tipIndex + 1) % tips.length;
      paragraph.textContent = tip.text;
      const link = advice.querySelector('a');
      link.textContent = tip.source;
      link.href = tip.url;
    } catch {
      status.textContent = 'Не удалось загрузить подсказки. Повторите попытку.';
    } finally {
      nextTip.disabled = false;
    }
  }
  const rotation = byId('pass-rotation');
  let tipTimer;
  function rotate(enabled) {
    clearInterval(tipTimer);
    rotation.setAttribute('aria-pressed', String(enabled));
    rotation.title = enabled ? 'Приостановить смену советов' : 'Возобновить смену советов';
    if (enabled) tipTimer = setInterval(() => {
      if (!document.hidden && !advice.matches(':hover, :focus-within')) showTip();
    }, 15000);
  }
  const motion = matchMedia('(prefers-reduced-motion: reduce)');
  rotation.hidden = false;
  rotate(!motion.matches);
  motion.addEventListener('change', () => rotate(!motion.matches));
  rotation.addEventListener('click', () => rotate(rotation.getAttribute('aria-pressed') === 'false'));
  nextTip.addEventListener('click', showTip);
  narrow.addEventListener('change', () => { settings.open = !narrow.matches || fields.mode.value === 'custom'; });
  settings.open = !narrow.matches;
  setMode(fields.mode.value);
})();

'use strict';

const panel = document.getElementById('maintenance');
if (panel) {
  const form = panel.querySelector('form');
  const message = panel.querySelector('[data-message]');
  const connection = panel.querySelector('[data-connection]');
  const history = panel.querySelector('[data-history]');
  const progress = panel.querySelector('[data-running]');
  const statusUrl = panel.dataset.url;
  const openVersion = panel.querySelector('[data-open-version]');
  let timer, lastEvents, sending = false, waiting = false, acceptedAt = 0;
  let reportId = panel.dataset.id, feedback = '';

  function enableButtons(enabled) {
    for (const button of form?.querySelectorAll('button') || []) button.disabled = !enabled;
  }
  function notice(text) {
    connection.hidden = !text;
    connection.textContent = text;
  }
  function schedule(delay) {
    clearTimeout(timer);
    timer = setTimeout(read, delay);
  }
  async function read() {
    if (document.hidden) { schedule(3000); return; }
    try {
      const response = await fetch(statusUrl, {cache: 'no-store', headers: {Accept: 'application/json'}});
      if (response.redirected || response.status === 404) {
        const admin = response.redirected ? response : await fetch(openVersion.href, {cache:'no-store'});
        if (!admin.ok) throw new Error();
        if (admin.redirected) {
          notice('Для просмотра состояния снова войдите в администрирование.');
          openVersion.textContent = 'Войти в администрирование';
        } else {
          const health = await fetch(panel.dataset.health, {cache:'no-store'});
          if (!health.ok) throw new Error();
          const info = await health.json();
          panel.querySelector('[data-installed]').textContent = info.version;
          notice('Текущая версия сервера использует прежнюю панель обслуживания.');
          openVersion.textContent = 'Открыть панель установленной версии';
        }
        openVersion.hidden = false;
        progress.hidden = true;
        enableButtons(false);
        return;
      }
      if (!response.ok) throw new Error();
      const data = await response.json();
      const report = data.report;
      const busy = data.operator === 'busy';
      if (report.id !== reportId || Date.now() - acceptedAt > 10000) waiting = false;
      if (!waiting) {
        if (message.textContent !== report.message) message.textContent = report.message || '';
        const events = report.events || [];
        const key = JSON.stringify(events);
        if (key !== lastEvents) {
          history.querySelector('ol').replaceChildren(...events.map(event => {
            const li = document.createElement('li');
            li.textContent = event.message;
            return li;
          }));
          history.hidden = !events.length;
          lastEvents = key;
        }
        reportId = report.id;
        panel.dataset.state = report.state;
      }
      panel.querySelector('[data-installed]').textContent = data.installed;
      panel.querySelector('[data-release]').textContent = data.release.version || 'не проверен';
      const releaseLink = panel.querySelector('[data-release-link]');
      releaseLink.hidden = !data.release.url;
      if (data.release.url) releaseLink.href = data.release.url;
      const canAct = ['ready','legacy'].includes(data.operator);
      enableButtons(canAct && !waiting && !sending && report.state !== 'running');
      progress.hidden = !(busy || waiting || report.state === 'running');
      panel.querySelector('[data-open-version]').hidden = data.installed === panel.dataset.version;
      notice(canAct || busy ? feedback : 'Веб-управление недоступно. Проверьте помощник на сервере.');
      if (!progress.hidden) schedule(1800);
    } catch {
      notice('Связь с сервисом временно прервана. Ожидаем ответ сервера…');
      schedule(3500);
    }
  }
  form?.addEventListener('submit', async event => {
    event.preventDefault();
    if (sending || waiting || !event.submitter) return;
    const data = new FormData(form);
    data.set('operation', event.submitter.value);
    sending = true;
    feedback = '';
    enableButtons(false);
    notice('Отправка команды…');
    try {
      const response = await fetch(form.action, {method:'POST', body:data, headers:{Accept:'application/json'}});
      if (response.redirected) throw new Error();
      const result = await response.json();
      message.textContent = result.message;
      notice('');
      if (!result.accepted) feedback = result.message;
      if (result.accepted) {
        waiting = true;
        acceptedAt = Date.now();
        progress.hidden = false;
      }
    } catch {
      feedback = 'Ответ на команду не получен. Проверьте последнюю операцию перед повторной отправкой.';
      notice(feedback);
    } finally {
      sending = false;
      schedule(450);
    }
  });
  if (panel.dataset.operator === 'busy' || panel.dataset.state === 'running') schedule(900);
}

"use strict";

const uploadForm = document.querySelector("[data-asr-upload]");
if (uploadForm) {
  uploadForm.addEventListener("submit", event => {
    event.preventDefault();
    const panel = uploadForm.querySelector("[data-upload-console]");
    const stage = panel.querySelector("[data-upload-stage]");
    const progress = panel.querySelector("progress");
    const count = panel.querySelector("[data-upload-count]");
    const button = uploadForm.querySelector("button[type=submit]");
    const file = uploadForm.elements.media.files[0];
    panel.hidden = false;
    progress.value = 0;
    count.textContent = "";
    if (!file || file.size === 0 || file.size > 512 * 1024 ** 2) {
      stage.textContent = "Выберите непустой файл размером до 512 МиБ.";
      return;
    }
    button.disabled = true;
    stage.textContent = "Отправка записи на сервер";
    const xhr = new XMLHttpRequest();
    xhr.open("POST", uploadForm.action || location.href);
    xhr.responseType = "json";
    xhr.setRequestHeader("Accept", "application/json");
    xhr.upload.onprogress = e => {
      if (!e.lengthComputable) return;
      const percent = Math.round(100 * e.loaded / e.total);
      progress.value = percent;
      count.textContent = percent + "% · " + (e.loaded / 1048576).toFixed(1) + " из " +
        (e.total / 1048576).toFixed(1) + " МиБ";
    };
    xhr.upload.onload = () => { stage.textContent = "Файл передан. Сервер принимает запись в очередь."; };
    const failed = () => {
      stage.textContent = xhr.status === 413 ? "Файл превышает допустимый размер." :
        "Передача не подтверждена. Проверьте раздел с вашими записями и соединение.";
      button.disabled = false;
    };
    xhr.onerror = xhr.onabort = failed;
    xhr.onload = () => {
      if (xhr.status === 201 && xhr.response?.location) location.assign(xhr.response.location);
      else failed();
    };
    xhr.send(new FormData(uploadForm));
  });
}

const panel = document.querySelector("[data-status-url]");
if (panel) {
  const log = panel.querySelector("[data-asr-log]");
  const progress = panel.querySelector("progress");
  const connection = panel.querySelector("[data-asr-connection]");
  const poll = async () => {
    if (!document.hidden) {
      try {
        const response = await fetch(panel.dataset.statusUrl, {headers: {"Accept": "application/json"}, cache: "no-store"});
        if (!response.ok) throw new Error();
        const job = await response.json();
        if (job.state === "done" || job.state === "failed") {
          const result = await fetch(location.href, {cache: "no-store"});
          if (!result.ok) throw new Error();
          const fresh = new DOMParser().parseFromString(await result.text(), "text/html").querySelector("#asr-result");
          if (!fresh || !["done", "failed"].includes(fresh.dataset.state)) throw new Error();
          document.querySelector("#asr-result").replaceWith(fresh);
          document.querySelector(".asr-remove").hidden = false;
          document.getElementById("asr-announcement").textContent = job.state === "done" ? "Стенограмма готова." : "Запись не удалось расшифровать.";
          prepareEditor();
          return;
        }
        document.querySelector(".asr-remove").hidden = job.state === "running";
        document.querySelector("[data-stage]").textContent = job.stage;
        const events = job.events.join("\n");
        if (log.textContent !== events) log.textContent = events;
        if (job.percent) progress.value = job.percent;
        else progress.removeAttribute("value");
        panel.querySelector("[data-asr-percent]").textContent = job.percent ? job.percent + "%" : "";
        panel.querySelector("[data-asr-time]").textContent = (job.elapsed == null ? "" : "Прошло " +
          job.elapsed + " с · ") + "Обработано " + job.seconds + " с аудио";
        const r = job.resources;
        const metrics = [];
        if (r.cores != null) metrics.push("CPU GigaAM · " + (r.busy_cores == null ? "" :
          r.busy_cores + " из ") + r.cores + " ядер");
        if (r.memory_mib != null) metrics.push("RAM · " + r.memory_mib +
          (r.capacity_mib == null ? "" : " из " + r.capacity_mib) + " МиБ");
        panel.querySelector("[data-asr-resources]").textContent = metrics.join("   ");
        connection.textContent = "";
      } catch {
        connection.textContent = "Статус временно недоступен. Повторяем соединение.";
      }
    }
    setTimeout(poll, 2000);
  };
  poll();
}

function prepareEditor() {
  const editor = document.querySelector("[data-asr-editor]");
  if (!editor) return;
  const field = editor.elements.body;
  const pending = editor.querySelector("[data-pending-edits]");
  function markChanges() {
    const changed = field.value !== field.defaultValue;
    editor.querySelector("button[type=submit]").disabled = !changed;
    pending.textContent = changed ? "Сохраните правки, чтобы они попали в TXT." : "";
  }
  field.addEventListener("input", markChanges);
  markChanges();
}
prepareEditor();

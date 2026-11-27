const search = document.getElementById("threat-search");
search?.addEventListener("input", () => {
  const value = search.value.trim().toLowerCase();
  let total = 0;
  let found = 0;
  document.querySelectorAll(".threat-group").forEach((group, index) => {
    const labels = [...group.querySelectorAll("[data-search]")];
    for (const label of labels) label.hidden = !label.dataset.search.includes(value);
    const visible = labels.filter(label => !label.hidden).length;
    total += labels.length;
    found += visible;
    group.hidden = visible === 0;
    group.open = Boolean(value && !group.hidden) || index === 0;
  });
  document.querySelector("#threat-matches").textContent = found ? "Показано угроз: " + found + " из " + total + "." :
    "Совпадений нет. Измените код или название угрозы.";
});

document.getElementById("apply-consequences")?.addEventListener("click", () => {
  const value = document.getElementById("consequence-preset").value;
  if (!value) return;
  const selected = new Set(value.split(","));
  document.querySelectorAll('input[name="consequences"]').forEach(box => {
    box.checked = selected.has(box.value);
  });
});

const sheet = document.getElementById('threat-sheet');
if (sheet) {
  const apply = document.getElementById('sheet-import');
  sheet.addEventListener('change', () => {
    if (sheet.files.length) sheet.form.requestSubmit(apply);
  });
}
const network = document.getElementById('threat-systemNetworkCondition');
if (network) {
  const infrastructure = document.querySelector('[name=objectType][value=infrastructure_object]');
  const single = document.querySelector('[name=objectType][value=ispdn]');
  function updateProfile() {
    const singleOnly = network.selectedOptions[0].hasAttribute('data-single-system');
    document.getElementById('infra-note').hidden = !singleOnly;
    if (singleOnly && infrastructure.checked) single.checked = true;
    infrastructure.disabled = singleOnly;
  }
  network.addEventListener('change', updateProfile);
  updateProfile();
}
const stepMenu = document.querySelector('.threat-nav');
if (stepMenu) {
  const narrow = window.matchMedia('(max-width:760px)');
  function fitMenu() { stepMenu.open = !narrow.matches; }
  narrow.addEventListener('change', fitMenu);
  fitMenu();
}

for (const select of document.querySelectorAll('select[id^=threat-]')) {
  const tips = document.querySelectorAll('[data-profile-tip="' + select.name + '"]');
  select.addEventListener('change', () => {
    for (const tip of tips) tip.hidden = tip.dataset.option !== select.value;
  });
}


// An associated sidebar button can precede the form in document order.
const wizardForm = document.getElementById('threat-form');
wizardForm?.addEventListener('keydown', event => {
  if (event.key !== 'Enter' || event.isComposing || !(event.target instanceof HTMLInputElement)) return;
  if (event.target.type === 'search') event.preventDefault();
  if (event.target.type === 'text') {
    event.preventDefault();
    wizardForm.requestSubmit(wizardForm.querySelector('button[value=next]'));
  }
});

// The ordinary POST keeps validation and redirects to the reviewed questionnaire.
// Only the tab that requested the generation starts the completed download.
const generateForm = document.getElementById('threat-generate');
const archiveLink = document.getElementById('threat-zip');
if (generateForm || archiveLink) {
  const marker = 'ismanager.threat-download.' + location.pathname;
  try {
    const requested = Number(sessionStorage.getItem(marker));
    sessionStorage.removeItem(marker);
    if (archiveLink && requested > Date.now() - 300000) archiveLink.click();
    if (generateForm) {
      const button = generateForm.querySelector('button');
      button.textContent = 'Сформировать и скачать ZIP';
      generateForm.addEventListener('submit', () => {
        sessionStorage.setItem(marker, String(Date.now()));
        button.disabled = true;
        button.textContent = 'Формируем документы…';
      });
      window.addEventListener('pageshow', event => {
        if (event.persisted) {
          button.disabled = false;
          button.textContent = 'Сформировать и скачать ZIP';
        }
      });
    }
  } catch { /* The download link remains available when browser storage is disabled. */ }
}

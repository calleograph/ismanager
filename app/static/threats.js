const search = document.getElementById("threat-search");
search?.addEventListener("input", () => {
  const value = search.value.trim().toLowerCase();
  document.querySelectorAll(".threat-group").forEach((group, index) => {
    const labels = [...group.querySelectorAll("[data-search]")];
    for (const label of labels) label.hidden = !label.dataset.search.includes(value);
    group.hidden = labels.every(label => label.hidden);
    group.open = Boolean(value && !group.hidden) || index === 0;
  });
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

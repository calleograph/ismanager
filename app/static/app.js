const themeButton = document.querySelector("#theme");
const themes = {glass: ["Стекло", "monitor"], dark: ["Тёмная", "moon"], light: ["Светлая", "sun"]};

function labelTheme() {
  const [name, icon] = themes[document.documentElement.dataset.theme] || themes.glass;
  const label = "Сменить тему. Текущая тема — " + name;
  themeButton.title = label;
  themeButton.setAttribute("aria-label", label);
  const use = themeButton.querySelector("use");
  use.setAttribute("href", use.getAttribute("href").split("#")[0] + "#" + icon);
}
if (themeButton) {
  labelTheme();
  themeButton.addEventListener("click", () => {
    const root = document.documentElement;
    const options = Object.keys(themes);
    root.dataset.theme = options[(options.indexOf(root.dataset.theme) + 1) % options.length];
    try { localStorage.setItem("ismanager-theme", root.dataset.theme); } catch {}
    labelTheme();
  });
}

document.addEventListener("click", async event => {
  const confirmButton = event.target.closest("[data-confirm]");
  if (confirmButton && !window.confirm(confirmButton.dataset.confirm)) {
    event.preventDefault();
    return;
  }
  const button = event.target.closest("[data-copy]");
  if (!button) return;
  const target = document.querySelector(button.dataset.copy);
  if (!target) return;
  let message = button.parentElement.querySelector("[data-copy-message]");
  if (!message) {
    message = document.createElement("span");
    message.dataset.copyMessage = "";
    message.setAttribute("role", "status");
    button.after(message);
  }
  try {
    await navigator.clipboard.writeText(target.value ?? target.textContent);
    message.textContent = "Скопировано";
  } catch {
    target.focus();
    if (target.select) target.select();
    else {
      const range = document.createRange();
      range.selectNodeContents(target);
      getSelection().removeAllRanges();
      getSelection().addRange(range);
    }
    message.textContent = "Текст выделен. Используйте команду «Копировать» на устройстве.";
  }
});

// Only edited forms need a navigation guard; a clean page can use the browser's back cache.
const dirtyForms = new Set();
function warnOnLeave(event) {
  event.preventDefault();
  event.returnValue = "";
}
function markDirty(event) {
  const form = event.target.form;
  if (!form?.hasAttribute("data-warn-unsaved") || (!event.target.name && event.target.type === "search")) return;
  dirtyForms.add(form);
  window.addEventListener("beforeunload", warnOnLeave);
}
document.addEventListener("input", markDirty, true);
document.addEventListener("change", markDirty, true);
function markSaved(form) {
  if (dirtyForms.delete(form) && !dirtyForms.size) window.removeEventListener("beforeunload", warnOnLeave);
}
document.addEventListener("submit", event => {
  if (!event.defaultPrevented) markSaved(event.target);
});
document.addEventListener("is-manager:saved", event => markSaved(event.target));

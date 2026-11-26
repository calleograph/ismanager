const themeButton = document.querySelector("#theme");
themeButton?.addEventListener("click", () => {
  const themes = ["glass", "dark", "light"];
  const root = document.documentElement;
  root.dataset.theme = themes[(themes.indexOf(root.dataset.theme) + 1) % themes.length];
  try { localStorage.setItem("ismanager-theme", root.dataset.theme); } catch {}
});
document.addEventListener("click", async event => {
  const confirmButton = event.target.closest("[data-confirm]");
  if (confirmButton && !window.confirm(confirmButton.dataset.confirm)) event.preventDefault();
  const button = event.target.closest("[data-copy]");
  if (!button) return;
  const target = document.querySelector(button.dataset.copy);
  if (!target) return;
  try {
    await navigator.clipboard.writeText(target.value ?? target.textContent);
    const previous = button.textContent;
    button.textContent = "Скопировано";
    setTimeout(() => { button.textContent = previous; }, 1500);
  } catch {
    target.focus();
    if (target.select) target.select();
    else { const range = document.createRange(); range.selectNodeContents(target); getSelection().removeAllRanges(); getSelection().addRange(range); }
  }
});

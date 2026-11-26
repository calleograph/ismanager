try {
  const theme = localStorage.getItem("ismanager-theme");
  if (["glass", "light", "dark"].includes(theme)) document.documentElement.dataset.theme = theme;
} catch {}

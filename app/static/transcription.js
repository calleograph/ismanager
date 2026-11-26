if (document.querySelector("[data-asr-refresh]")) {
  setInterval(() => {
    if (!document.hidden && !document.querySelector("details[open]")) location.reload();
  }, 5000);
}

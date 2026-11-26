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

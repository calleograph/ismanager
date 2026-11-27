"use strict";
const systemPanel = document.querySelector("[data-system-metrics]");
if (systemPanel) {
  const write = (name, value) => { systemPanel.querySelector("[data-" + name + "]").textContent = value; };
  const missing = "Нет свежих данных";
  const update = async () => {
    if (!document.hidden) {
      try {
        const response = await fetch(systemPanel.dataset.systemMetrics, {cache: "no-store"});
        if (!response.ok || response.redirected) throw new Error();
        const m = await response.json();
        write("machine-cpu", m.cpu.percent == null ? missing : m.cpu.percent + "% · " + m.cpu.busy_cores + " из " + m.cores + " ядер");
        write("machine-ram", m.total == null || m.available == null ? missing :
          "Занято " + (m.total - m.available) + " из " + m.total + " МиБ");
        write("worker-cpu", m.worker.busy_cores == null ? missing : m.worker.busy_cores + " из " + m.worker.cores + " ядер");
        write("worker-ram", m.worker.memory_mib == null ? missing : m.worker.memory_mib +
          (m.worker.capacity_mib == null ? "" : " из " + m.worker.capacity_mib) + " МиБ");
      } catch {
        for (const key of ["machine-cpu", "machine-ram", "worker-cpu", "worker-ram"]) write(key, missing);
      }
    }
    setTimeout(update, 3000);
  };
  setTimeout(update, 3000);
}

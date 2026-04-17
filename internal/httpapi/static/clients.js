const elements = {
  preset: document.querySelector("#preset"),
  date: document.querySelector("#date"),
  from: document.querySelector("#from"),
  to: document.querySelector("#to"),
  clientIP: document.querySelector("#clientIP"),
  autoRefresh: document.querySelector("#autoRefresh"),
  queryButton: document.querySelector("#queryButton"),
  status: document.querySelector("#status"),
  uploadTotal: document.querySelector("#uploadTotal"),
  downloadTotal: document.querySelector("#downloadTotal"),
  clientTotal: document.querySelector("#clientTotal"),
  packetTotal: document.querySelector("#packetTotal"),
  rangeText: document.querySelector("#rangeText"),
  clientsBody: document.querySelector("#clientsBody"),
  liveClientsBody: document.querySelector("#liveClientsBody"),
};

let refreshTimer = null;
let eventSource = null;

function formatBytes(bytes) {
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let value = Number(bytes || 0);
  let unit = units[0];
  for (let index = 1; index < units.length && value >= 1024; index += 1) {
    value /= 1024;
    unit = units[index];
  }
  if (unit === "B") {
    return `${Math.round(value)} ${unit}`;
  }
  return `${value.toFixed(2)} ${unit}`;
}

function todayText() {
  return new Date().toISOString().slice(0, 10);
}

function buildRangeParams() {
  const params = new URLSearchParams();
  if (elements.preset.value === "date") {
    params.set("date", elements.date.value || todayText());
  } else if (elements.preset.value === "custom") {
    if (elements.from.value.trim()) {
      params.set("from", elements.from.value.trim());
    }
    if (elements.to.value.trim()) {
      params.set("to", elements.to.value.trim());
    }
  } else {
    params.set("last", elements.preset.value);
  }
  if (elements.clientIP.value.trim()) {
    params.set("client_ip", elements.clientIP.value.trim());
  }
  return params;
}

function buildClientsURL() {
  return `/api/clients?${buildRangeParams().toString()}`;
}

async function loadClients() {
  elements.status.textContent = "查询中";
  elements.status.style.background = "var(--accent)";

  try {
    const response = await fetch(buildClientsURL(), { headers: { Accept: "application/json" } });
    if (!response.ok) {
      throw new Error(await response.text());
    }
    renderClients(await response.json());
    elements.status.textContent = "已更新";
    elements.status.style.background = "#b9dfcc";
  } catch (error) {
    elements.status.textContent = "查询失败";
    elements.status.style.background = "#f1b1aa";
    console.error(error);
  }
}

function renderClients(data) {
  const rows = data.clients || [];
  const totals = rows.reduce(
    (acc, row) => {
      acc.upload += Number(row.upload_bytes || 0);
      acc.download += Number(row.download_bytes || 0);
      acc.packets += Number(row.packets || 0);
      return acc;
    },
    { upload: 0, download: 0, packets: 0 },
  );

  elements.uploadTotal.textContent = formatBytes(totals.upload);
  elements.downloadTotal.textContent = formatBytes(totals.download);
  elements.clientTotal.textContent = Number(rows.length).toLocaleString();
  elements.packetTotal.textContent = Number(totals.packets).toLocaleString();
  elements.rangeText.textContent = `${data.range.from} 到 ${data.range.to}`;

  if (rows.length === 0) {
    elements.clientsBody.innerHTML = `<tr><td colspan="8">暂无客户端数据</td></tr>`;
    return;
  }

  elements.clientsBody.innerHTML = rows
    .map((row) => {
      const total = Number(row.upload_bytes || 0) + Number(row.download_bytes || 0);
      return `
        <tr>
          <td>${escapeHTML(row.display_name || row.client_ip)}</td>
          <td>${escapeHTML(row.name_source || "-")}</td>
          <td>${escapeHTML(row.client_ip)}</td>
          <td>${escapeHTML(row.client_mac || "-")}</td>
          <td>${formatBytes(row.upload_bytes)}</td>
          <td>${formatBytes(row.download_bytes)}</td>
          <td>${formatBytes(total)}</td>
          <td>${Number(row.packets || 0).toLocaleString()}</td>
        </tr>
      `;
    })
    .join("");
}

function renderLiveClients(clients) {
  const rows = clients || [];
  if (rows.length === 0) {
    elements.liveClientsBody.innerHTML = `<tr><td colspan="6">等待实时数据</td></tr>`;
    return;
  }

  elements.liveClientsBody.innerHTML = rows
    .map((row) => `
      <tr>
        <td>${escapeHTML(row.display_name || row.client_ip)}</td>
        <td>${escapeHTML(row.client_ip)}</td>
        <td>${escapeHTML(row.client_mac || "-")}</td>
        <td>${formatBytes(row.upload_bps)}/s</td>
        <td>${formatBytes(row.download_bps)}/s</td>
        <td>${Number(row.packets || 0).toLocaleString()}</td>
      </tr>
    `)
    .join("");
}

function escapeHTML(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function syncControls() {
  const mode = elements.preset.value;
  elements.date.disabled = mode !== "date";
  elements.from.disabled = mode !== "custom";
  elements.to.disabled = mode !== "custom";
}

function stopPolling() {
  if (refreshTimer) {
    clearInterval(refreshTimer);
    refreshTimer = null;
  }
}

function startPolling(intervalMs) {
  if (refreshTimer) {
    clearInterval(refreshTimer);
  }
  refreshTimer = setInterval(loadClients, intervalMs);
}

function updateAutoRefresh() {
  stopPolling();
  if (elements.autoRefresh.checked) {
    startPolling(5000);
  }
}

function startLiveStream() {
  if (!window.EventSource) {
    return;
  }
  if (eventSource) {
    eventSource.close();
  }
  eventSource = new EventSource("/api/live");
  eventSource.addEventListener("snapshot", (event) => {
    try {
      renderLiveClients(JSON.parse(event.data).clients || []);
    } catch (error) {
      console.error(error);
    }
  });
  eventSource.onerror = () => {
    renderLiveClients([]);
  };
}

elements.queryButton.addEventListener("click", loadClients);
elements.preset.addEventListener("change", () => {
  syncControls();
  loadClients();
});
elements.autoRefresh.addEventListener("change", updateAutoRefresh);
elements.clientIP.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    loadClients();
  }
});

elements.date.value = todayText();
syncControls();
startLiveStream();
loadClients();

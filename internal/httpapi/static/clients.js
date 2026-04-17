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
};

let refreshTimer = null;
let eventSource = null;
const clientsByKey = new Map();
const liveKeys = new Set();

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

function clientKey(row) {
  return `${row.client_ip || ""}|${row.client_mac || ""}`;
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

function clientMatchesFilter(row) {
  const filter = elements.clientIP.value.trim();
  return filter === "" || row.client_ip === filter;
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
  const historicalKeys = new Set();
  for (const row of data.clients || []) {
    const key = clientKey(row);
    historicalKeys.add(key);
    const existing = clientsByKey.get(key) || {};
    clientsByKey.set(key, {
      ...existing,
      ...row,
      upload_bps: existing.upload_bps || 0,
      download_bps: existing.download_bps || 0,
      live_packets: existing.live_packets || 0,
      live_only: false,
    });
  }

  for (const [key, row] of clientsByKey) {
    if (!clientMatchesFilter(row)) {
      clientsByKey.delete(key);
      continue;
    }
    if (!historicalKeys.has(key) && !liveKeys.has(key)) {
      clientsByKey.delete(key);
      continue;
    }
    if (!historicalKeys.has(key)) {
      clientsByKey.set(key, { ...row, live_only: true });
    }
  }

  elements.rangeText.textContent = `${data.range.from} 到 ${data.range.to}`;
  renderClientRows();
}

function mergeLiveClients(clients) {
  const activeKeys = new Set();
  for (const row of clients || []) {
    if (!clientMatchesFilter(row)) {
      continue;
    }
    const key = clientKey(row);
    activeKeys.add(key);
    liveKeys.add(key);
    const existing = clientsByKey.get(key) || {
      client_ip: row.client_ip,
      client_mac: row.client_mac,
      display_name: row.display_name || row.client_ip || row.client_mac,
      name_source: "",
      alias: "",
      learned_name: "",
      upload_bytes: 0,
      download_bytes: 0,
      packets: 0,
      live_only: true,
    };
    clientsByKey.set(key, {
      ...existing,
      display_name: existing.alias || row.display_name || existing.display_name,
      upload_bps: row.upload_bps || 0,
      download_bps: row.download_bps || 0,
      live_packets: row.packets || 0,
    });
  }

  for (const [key, row] of clientsByKey) {
    if (!activeKeys.has(key)) {
      clientsByKey.set(key, {
        ...row,
        upload_bps: 0,
        download_bps: 0,
        live_packets: 0,
      });
    }
  }
  renderClientRows();
}

function renderClientRows() {
  const rows = Array.from(clientsByKey.values()).sort((left, right) => {
    const leftLive = Number(left.upload_bps || 0) + Number(left.download_bps || 0);
    const rightLive = Number(right.upload_bps || 0) + Number(right.download_bps || 0);
    if (leftLive !== rightLive) {
      return rightLive - leftLive;
    }
    const leftTotal = Number(left.upload_bytes || 0) + Number(left.download_bytes || 0);
    const rightTotal = Number(right.upload_bytes || 0) + Number(right.download_bytes || 0);
    if (leftTotal !== rightTotal) {
      return rightTotal - leftTotal;
    }
    return String(left.display_name || left.client_ip).localeCompare(String(right.display_name || right.client_ip));
  });

  const historicalRows = rows.filter((row) => !row.live_only);
  const totals = historicalRows.reduce(
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

  if (rows.length === 0) {
    elements.clientsBody.innerHTML = `<tr><td colspan="11">暂无客户端数据</td></tr>`;
    return;
  }

  elements.clientsBody.innerHTML = rows.map(renderClientRow).join("");
  bindAliasButtons();
}

function renderClientRow(row) {
  const key = escapeHTML(clientKey(row));
  const total = Number(row.upload_bytes || 0) + Number(row.download_bytes || 0);
  const source = row.alias ? "alias" : row.name_source || (row.live_only ? "live" : "-");
  return `
    <tr data-client-key="${key}">
      <td class="nameCell">${escapeHTML(row.display_name || row.client_ip || row.client_mac)}</td>
      <td>${escapeHTML(source)}</td>
      <td>${escapeHTML(row.client_ip)}</td>
      <td>${escapeHTML(row.client_mac || "-")}</td>
      <td class="rateCell">${formatBytes(row.upload_bps)}/s</td>
      <td class="rateCell">${formatBytes(row.download_bps)}/s</td>
      <td>${row.live_only ? "-" : formatBytes(row.upload_bytes)}</td>
      <td>${row.live_only ? "-" : formatBytes(row.download_bytes)}</td>
      <td>${row.live_only ? "-" : formatBytes(total)}</td>
      <td>${Number(row.packets || 0).toLocaleString()}</td>
      <td>
        <div class="aliasEditor">
          <input type="text" value="${escapeAttribute(row.alias || "")}" placeholder="${escapeAttribute(row.learned_name || row.display_name || "设备别名")}" aria-label="设备别名" />
          <button type="button" data-alias-key="${key}">保存</button>
        </div>
      </td>
    </tr>
  `;
}

function bindAliasButtons() {
  for (const button of elements.clientsBody.querySelectorAll("[data-alias-key]")) {
    button.addEventListener("click", () => saveAlias(button.dataset.aliasKey, button));
  }
}

async function saveAlias(key, button) {
  const row = clientsByKey.get(key);
  if (!row) {
    return;
  }
  const input = button.parentElement.querySelector("input");
  const alias = input.value.trim();
  button.disabled = true;
  try {
    const response = await fetch("/api/clients/alias", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_ip: row.client_ip,
        client_mac: row.client_mac,
        alias,
      }),
    });
    if (!response.ok) {
      throw new Error(await response.text());
    }
    const displayName = alias || row.learned_name || row.client_mac || row.client_ip;
    clientsByKey.set(key, {
      ...row,
      alias,
      display_name: displayName,
      name_source: alias ? "alias" : row.name_source,
    });
    elements.status.textContent = "别名已保存";
    elements.status.style.background = "#b9dfcc";
    renderClientRows();
  } catch (error) {
    elements.status.textContent = "保存失败";
    elements.status.style.background = "#f1b1aa";
    console.error(error);
  } finally {
    button.disabled = false;
  }
}

function escapeHTML(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function escapeAttribute(value) {
  return escapeHTML(value).replaceAll("`", "&#096;");
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
      mergeLiveClients(JSON.parse(event.data).clients || []);
    } catch (error) {
      console.error(error);
    }
  });
  eventSource.onerror = () => {
    mergeLiveClients([]);
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

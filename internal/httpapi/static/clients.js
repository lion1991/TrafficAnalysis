const elements = {
  preset: document.querySelector("#preset"),
  date: document.querySelector("#date"),
  from: document.querySelector("#from"),
  to: document.querySelector("#to"),
  clientIP: document.querySelector("#clientIP"),
  autoRefresh: document.querySelector("#autoRefresh"),
  queryButton: document.querySelector("#queryButton"),
  resetButton: document.querySelector("#resetButton"),
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
let sortState = { field: "total_bytes", direction: "desc" };

const CLIENTS_PREFS_KEY = "ta_clients_prefs";

function loadSavedPrefs() {
  try {
    return JSON.parse(localStorage.getItem(CLIENTS_PREFS_KEY) || "{}");
  } catch {
    return {};
  }
}

function savePrefs() {
  try {
    localStorage.setItem(
      CLIENTS_PREFS_KEY,
      JSON.stringify({
        preset: elements.preset.value,
        date: elements.date.value,
        from: elements.from.value,
        to: elements.to.value,
        clientIP: elements.clientIP.value,
        autoRefresh: elements.autoRefresh.checked,
        sortField: sortState.field,
        sortDirection: sortState.direction,
      }),
    );
  } catch {}
}

function resetPrefs() {
  try {
    localStorage.removeItem(CLIENTS_PREFS_KEY);
  } catch {}
  elements.preset.value = "1h";
  elements.date.value = todayText();
  elements.from.value = "";
  elements.to.value = "";
  elements.clientIP.value = "";
  elements.autoRefresh.checked = false;
  sortState = { field: "total_bytes", direction: "desc" };
  syncControls();
  stopPolling();
  renderSortHeaders();
  loadClients();
}

function formatUTC8(isoStr) {
  const date = new Date(isoStr);
  if (isNaN(date.getTime())) {
    return isoStr;
  }
  const offsetMs = 8 * 60 * 60 * 1000;
  const local = new Date(date.getTime() + offsetMs);
  const iso = local.toISOString();
  return iso.slice(0, 10) + " " + iso.slice(11, 16);
}

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

  elements.rangeText.textContent = `${formatUTC8(data.range.from)} 到 ${formatUTC8(data.range.to)}`;
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
      display_name: existing.alias || existing.learned_name || liveDisplayName(row, existing),
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

function liveDisplayName(row, existing) {
  const liveName = String(row.display_name || "").trim();
  const liveFallbacks = new Set([String(row.client_ip || ""), String(row.client_mac || "")]);
  if (liveName && !liveFallbacks.has(liveName)) {
    return liveName;
  }
  return existing.display_name || row.display_name || row.client_ip || row.client_mac;
}

function renderClientRows() {
  const aliasDrafts = captureAliasDrafts();
  const rows = Array.from(clientsByKey.values()).sort(compareClientRows);

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
  restoreAliasDrafts(aliasDrafts);
  renderSortHeaders();
}

function captureAliasDrafts() {
  const drafts = new Map();
  const activeKey = document.activeElement?.dataset?.aliasInputKey || "";
  for (const input of elements.clientsBody.querySelectorAll("[data-alias-input-key]")) {
    const key = input.dataset.aliasInputKey;
    drafts.set(key, {
      value: input.value,
      selectionStart: input.selectionStart,
      selectionEnd: input.selectionEnd,
      focused: key === activeKey,
    });
  }
  return drafts;
}

function restoreAliasDrafts(drafts) {
  for (const input of elements.clientsBody.querySelectorAll("[data-alias-input-key]")) {
    const draft = drafts.get(input.dataset.aliasInputKey);
    if (!draft) {
      continue;
    }
    input.value = draft.value;
    if (draft.focused) {
      input.focus({ preventScroll: true });
      input.setSelectionRange(draft.selectionStart, draft.selectionEnd);
    }
  }
}

function compareClientRows(left, right) {
  const result = compareSortValues(sortValue(left, sortState.field), sortValue(right, sortState.field));
  if (result !== 0) {
    return sortState.direction === "asc" ? result : -result;
  }
  return compareSortValues(sortValue(left, "display_name"), sortValue(right, "display_name"));
}

function sortValue(row, field) {
  switch (field) {
    case "display_name":
      return row.display_name || row.client_ip || row.client_mac || "";
    case "name_source":
      return row.alias ? "alias" : row.name_source || "";
    case "client_ip":
      return row.client_ip || "";
    case "upload_bps":
      return Number(row.upload_bps || 0);
    case "download_bps":
      return Number(row.download_bps || 0);
    case "upload_bytes":
      return Number(row.upload_bytes || 0);
    case "download_bytes":
      return Number(row.download_bytes || 0);
    case "total_bytes":
      return Number(row.upload_bytes || 0) + Number(row.download_bytes || 0);
    case "packets":
      return Number(row.packets || 0);
    default:
      return "";
  }
}

function compareSortValues(left, right) {
  if (typeof left === "number" || typeof right === "number") {
    return Number(left || 0) - Number(right || 0);
  }
  return String(left || "").localeCompare(String(right || ""), "zh-Hans-CN", { numeric: true, sensitivity: "base" });
}

function setSort(field) {
  if (sortState.field === field) {
    sortState = { field, direction: sortState.direction === "asc" ? "desc" : "asc" };
  } else {
    const numericFields = new Set(["upload_bps", "download_bps", "upload_bytes", "download_bytes", "total_bytes", "packets"]);
    sortState = { field, direction: numericFields.has(field) ? "desc" : "asc" };
  }
  savePrefs();
  renderClientRows();
}

function renderSortHeaders() {
  for (const button of document.querySelectorAll("[data-sort]")) {
    const active = button.dataset.sort === sortState.field;
    button.setAttribute("aria-sort", active ? (sortState.direction === "asc" ? "ascending" : "descending") : "none");
    button.dataset.direction = active ? sortState.direction : "";
  }
}

function renderClientRow(row) {
  const key = escapeHTML(clientKey(row));
  const total = Number(row.upload_bytes || 0) + Number(row.download_bytes || 0);
  const source = row.alias ? "alias" : row.name_source || (row.live_only ? "live" : "-");
  return `
    <tr data-client-key="${key}">
      <td class="nameCell" data-label="名称">${escapeHTML(row.display_name || row.client_ip || row.client_mac)}</td>
      <td data-label="来源">${escapeHTML(source)}</td>
      <td data-label="IP">${escapeHTML(row.client_ip)}</td>
      <td data-label="MAC">${escapeHTML(row.client_mac || "-")}</td>
      <td class="rateCell" data-label="实时上传">${formatBytes(row.upload_bps)}/s</td>
      <td class="rateCell" data-label="实时下载">${formatBytes(row.download_bps)}/s</td>
      <td data-label="上传">${row.live_only ? "-" : formatBytes(row.upload_bytes)}</td>
      <td data-label="下载">${row.live_only ? "-" : formatBytes(row.download_bytes)}</td>
      <td data-label="总计">${row.live_only ? "-" : formatBytes(total)}</td>
      <td data-label="包">${Number(row.packets || 0).toLocaleString()}</td>
      <td data-label="别名">
        <div class="aliasEditor">
          <input type="text" data-alias-input-key="${key}" value="${escapeAttribute(row.alias || "")}" placeholder="${escapeAttribute(row.learned_name || row.display_name || "设备别名")}" aria-label="设备别名" />
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

function stopLiveStream() {
  if (eventSource) {
    eventSource.close();
    eventSource = null;
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
  stopLiveStream();
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

function cleanupPage() {
  stopPolling();
  stopLiveStream();
}

elements.queryButton.addEventListener("click", () => { savePrefs(); loadClients(); });
for (const button of document.querySelectorAll("[data-sort]")) {
  button.addEventListener("click", () => setSort(button.dataset.sort));
}
elements.preset.addEventListener("change", () => {
  syncControls();
  savePrefs();
  loadClients();
});
elements.autoRefresh.addEventListener("change", () => { savePrefs(); updateAutoRefresh(); });
elements.resetButton.addEventListener("click", resetPrefs);
elements.clientIP.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    savePrefs();
    loadClients();
  }
});
window.addEventListener("pagehide", cleanupPage);
window.addEventListener("beforeunload", cleanupPage);

// 恢复已保存的偏好设置
const savedPrefs = loadSavedPrefs();
if (savedPrefs.preset) { elements.preset.value = savedPrefs.preset; }
if (savedPrefs.date) { elements.date.value = savedPrefs.date; }
else { elements.date.value = todayText(); }
if (savedPrefs.from) { elements.from.value = savedPrefs.from; }
if (savedPrefs.to) { elements.to.value = savedPrefs.to; }
if (savedPrefs.clientIP) { elements.clientIP.value = savedPrefs.clientIP; }
if (savedPrefs.autoRefresh) { elements.autoRefresh.checked = true; }
if (savedPrefs.sortField) {
  sortState = { field: savedPrefs.sortField, direction: savedPrefs.sortDirection || "desc" };
}
syncControls();
renderSortHeaders();
loadClients().finally(() => {
  startLiveStream();
  if (elements.autoRefresh.checked) {
    updateAutoRefresh();
  }
});

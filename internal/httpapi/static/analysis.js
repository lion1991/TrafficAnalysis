const elements = {
  preset: document.querySelector("#preset"),
  date: document.querySelector("#date"),
  fromDate: document.querySelector("#fromDate"),
  toDate: document.querySelector("#toDate"),
  from: document.querySelector("#from"),
  to: document.querySelector("#to"),
  autoRefresh: document.querySelector("#autoRefresh"),
  queryButton: document.querySelector("#queryButton"),
  resetButton: document.querySelector("#resetButton"),
  status: document.querySelector("#status"),
  uploadTotal: document.querySelector("#uploadTotal"),
  downloadTotal: document.querySelector("#downloadTotal"),
  uploadShare: document.querySelector("#uploadShare"),
  peakUpload: document.querySelector("#peakUpload"),
  activeClients: document.querySelector("#activeClients"),
  rangeText: document.querySelector("#rangeText"),
  signalsBody: document.querySelector("#signalsBody"),
  uploadClientsBody: document.querySelector("#uploadClientsBody"),
  downloadClientsBody: document.querySelector("#downloadClientsBody"),
  remoteEndpointsBody: document.querySelector("#remoteEndpointsBody"),
  wanRemoteEndpointsBody: document.querySelector("#wanRemoteEndpointsBody"),
  wanUDPRemoteEndpointsBody: document.querySelector("#wanUDPRemoteEndpointsBody"),
  wanUDPClientGapsBody: document.querySelector("#wanUDPClientGapsBody"),
  objectsBody: document.querySelector("#objectsBody"),
  reconcileBody: document.querySelector("#reconcileBody"),
  limitationsBody: document.querySelector("#limitationsBody"),
};

let refreshTimer = null;
let activeRequestController = null;
const ANALYSIS_PREFS_KEY = "ta_analysis_prefs";
const MAX_OBJECT_ROWS = 200;
const MAX_RECONCILE_ROWS = 200;
const defaultSortStates = {
  uploadClients: { field: "upload_bytes", direction: "desc" },
  downloadClients: { field: "download_bytes", direction: "desc" },
  remoteEndpoints: { field: "total_bytes", direction: "desc" },
  wanRemoteEndpoints: { field: "total_bytes", direction: "desc" },
  wanUDPRemoteEndpoints: { field: "total_bytes", direction: "desc" },
  wanUDPClientGaps: { field: "unattributed_total", direction: "desc" },
  objects: { field: "total_bytes", direction: "desc" },
  reconcile: { field: "unattributed_total", direction: "desc" },
};
let sortStates = cloneSortStates(defaultSortStates);

function loadSavedPrefs() {
  try {
    return JSON.parse(localStorage.getItem(ANALYSIS_PREFS_KEY) || "{}");
  } catch {
    return {};
  }
}

function savePrefs() {
  try {
    localStorage.setItem(
      ANALYSIS_PREFS_KEY,
      JSON.stringify({
        preset: elements.preset.value,
        date: elements.date.value,
        fromDate: elements.fromDate.value,
        toDate: elements.toDate.value,
        from: elements.from.value,
        to: elements.to.value,
        autoRefresh: elements.autoRefresh.checked,
        sortStates,
      }),
    );
  } catch {}
}

function resetPrefs() {
  try {
    localStorage.removeItem(ANALYSIS_PREFS_KEY);
  } catch {}
  elements.preset.value = "24h";
  elements.date.value = todayText();
  elements.fromDate.value = "";
  elements.toDate.value = "";
  elements.from.value = "";
  elements.to.value = "";
  elements.autoRefresh.checked = false;
  sortStates = cloneSortStates(defaultSortStates);
  syncControls();
  stopPolling();
  renderSortHeaders();
  loadAnalysis();
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

function formatPercent(value) {
  return `${(Number(value || 0) * 100).toFixed(1)}%`;
}

function todayText() {
  return new Date().toISOString().slice(0, 10);
}

function datetimeLocalToApi(value) {
  return value.trim().replace("T", " ");
}

function normalizeDatetimeLocalPref(value) {
  return String(value || "").trim().replace(" ", "T");
}

function formatDateInputValue(date) {
  const year = date.getUTCFullYear();
  const month = String(date.getUTCMonth() + 1).padStart(2, "0");
  const day = String(date.getUTCDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
}

function addDays(dateStr, days) {
  const [year, month, day] = dateStr.split("-").map(Number);
  const date = new Date(Date.UTC(year, month - 1, day));
  date.setUTCDate(date.getUTCDate() + days);
  return formatDateInputValue(date);
}

function buildRangeParams() {
  const params = new URLSearchParams();
  const mode = elements.preset.value;
  if (mode === "date") {
    params.set("date", elements.date.value || todayText());
  } else if (mode === "daterange") {
    if (elements.fromDate.value) {
      params.set("from", elements.fromDate.value + " 00:00");
    }
    if (elements.toDate.value) {
      params.set("to", addDays(elements.toDate.value, 1) + " 00:00");
    }
  } else if (mode === "custom") {
    if (elements.from.value.trim()) {
      params.set("from", datetimeLocalToApi(elements.from.value));
    }
    if (elements.to.value.trim()) {
      params.set("to", datetimeLocalToApi(elements.to.value));
    }
  } else {
    params.set("last", mode);
  }
  return params;
}

function buildAnalysisURL() {
  return `/api/analysis?${buildRangeParams().toString()}`;
}

function buildObjectsURL() {
  return `/api/analysis/objects?${buildRangeParams().toString()}`;
}

function buildReconcileURL() {
  return `/api/analysis/reconcile?${buildRangeParams().toString()}`;
}

async function fetchJSON(url, signal) {
  const response = await fetch(url, {
    headers: { Accept: "application/json" },
    signal,
  });
  if (!response.ok) {
    throw new Error(await response.text());
  }
  return response.json();
}

function abortActiveRequest() {
  if (!activeRequestController) {
    return;
  }
  activeRequestController.abort();
  activeRequestController = null;
}

async function loadAnalysis() {
  abortActiveRequest();
  const requestController = new AbortController();
  activeRequestController = requestController;
  elements.status.textContent = "分析中";
  elements.status.style.background = "var(--accent)";

  try {
    const analysis = await fetchJSON(buildAnalysisURL(), requestController.signal);
    if (activeRequestController !== requestController) {
      return;
    }
    renderAnalysis(analysis);
    elements.status.textContent = "基础结果已更新，正在补充访问对象和 WAN/LAN 对账";
    elements.status.style.background = "#dfe9b1";
    const [objectsResult, reconcileResult] = await Promise.allSettled([
      fetchJSON(buildObjectsURL(), requestController.signal),
      fetchJSON(buildReconcileURL(), requestController.signal),
    ]);
    if (activeRequestController !== requestController) {
      return;
    }
    renderObjects(objectsResult.status === "fulfilled" ? (objectsResult.value.objects || []) : []);
    renderReconcile(reconcileResult.status === "fulfilled" ? (reconcileResult.value.rows || []) : []);
    elements.status.textContent = "已更新";
    elements.status.style.background = "#b9dfcc";
  } catch (error) {
    if (error?.name === "AbortError") {
      return;
    }
    elements.status.textContent = "分析失败";
    elements.status.style.background = "#f1b1aa";
    console.error(error);
  } finally {
    if (activeRequestController === requestController) {
      activeRequestController = null;
    }
  }
}

function renderAnalysis(data) {
  const totals = data.totals || {};
  elements.uploadTotal.textContent = formatBytes(totals.upload_bytes);
  elements.downloadTotal.textContent = formatBytes(totals.download_bytes);
  elements.uploadShare.textContent = formatPercent(totals.upload_share);
  elements.peakUpload.textContent = formatBytes(totals.peak_upload_bytes);
  elements.activeClients.textContent = Number(totals.active_client_count || 0).toLocaleString();
  elements.rangeText.textContent = `${formatUTC8(data.range.from)} 到 ${formatUTC8(data.range.to)}`;

  renderSignals(data.signals || []);
  renderClientRows(elements.uploadClientsBody, data.top_upload_clients || [], "upload");
  renderClientRows(elements.downloadClientsBody, data.top_download_clients || [], "download");
  renderRemoteEndpoints(data.remote_endpoints || []);
  renderWANRemoteEndpoints(elements.wanRemoteEndpointsBody, data.wan_remote_endpoints || [], "暂无 WAN 远端数据");
  renderWANRemoteEndpoints(
    elements.wanUDPRemoteEndpointsBody,
    data.wan_udp_remote_endpoints || [],
    "暂无 WAN UDP 远端数据",
  );
  renderWANUDPClientGaps(data.wan_udp_client_gaps || []);
  renderLimitations(data.limitations || []);
}

function renderSignals(signals) {
  if (signals.length === 0) {
    elements.signalsBody.innerHTML = `
      <article class="signal">
        <span>状态</span>
        <strong>暂无数据</strong>
        <p>当前时间范围没有可分析数据。</p>
      </article>
    `;
    return;
  }
  elements.signalsBody.innerHTML = signals
    .map((signal) => `
      <article class="signal ${escapeHTML(signal.level || "info")}">
        <span>${escapeHTML(signal.label)}</span>
        <strong>${escapeHTML(signal.value)}</strong>
        <p>${escapeHTML(signal.note || "")}</p>
      </article>
    `)
    .join("");
}

function renderClientRows(target, rows, mode) {
  const table = mode === "upload" ? "uploadClients" : "downloadClients";
  rows = sortRows(table, rows);
  if (rows.length === 0) {
    target.innerHTML = `<tr><td colspan="5">暂无客户端数据</td></tr>`;
    return;
  }
  target.innerHTML = rows
    .map((row) => {
      const firstBytes = mode === "upload" ? row.upload_bytes : row.download_bytes;
      const secondBytes = mode === "upload" ? row.download_bytes : row.upload_bytes;
      return `
        <tr>
          <td>${escapeHTML(row.display_name || row.client_ip || row.client_mac)}</td>
          <td>${escapeHTML(row.client_ip || "-")}</td>
          <td>${formatBytes(firstBytes)}</td>
          <td>${formatBytes(secondBytes)}</td>
          <td>${Number(row.packets || 0).toLocaleString()}</td>
        </tr>
      `;
    })
    .join("");
}

function renderRemoteEndpoints(remote_endpoints) {
  remote_endpoints = sortRows("remoteEndpoints", remote_endpoints);
  if (remote_endpoints.length === 0) {
    elements.remoteEndpointsBody.innerHTML = `<tr><td colspan="8">暂无远程 IP 数据</td></tr>`;
    return;
  }
  elements.remoteEndpointsBody.innerHTML = remote_endpoints
    .map((row) => {
      const total = Number(row.upload_bytes || 0) + Number(row.download_bytes || 0);
      return `
        <tr>
          <td>${escapeHTML(row.remote_ip || "-")}</td>
          <td>${row.remote_port ? Number(row.remote_port).toLocaleString() : "-"}</td>
          <td>${escapeHTML(row.protocol || "-")}</td>
          <td>${formatBytes(row.upload_bytes)}</td>
          <td>${formatBytes(row.download_bytes)}</td>
          <td>${formatBytes(total)}</td>
          <td>${Number(row.client_count || 0).toLocaleString()}</td>
          <td>${Number(row.packets || 0).toLocaleString()}</td>
        </tr>
      `;
    })
    .join("");
}

function renderWANRemoteEndpoints(target, remoteEndpoints, emptyText) {
  const table = target === elements.wanUDPRemoteEndpointsBody ? "wanUDPRemoteEndpoints" : "wanRemoteEndpoints";
  remoteEndpoints = sortRows(table, remoteEndpoints);
  if (remoteEndpoints.length === 0) {
    target.innerHTML = `<tr><td colspan="7">${escapeHTML(emptyText)}</td></tr>`;
    return;
  }
  target.innerHTML = remoteEndpoints
    .map((row) => {
      const total = Number(row.upload_bytes || 0) + Number(row.download_bytes || 0);
      return `
        <tr>
          <td>${escapeHTML(row.remote_ip || "-")}</td>
          <td>${row.remote_port ? Number(row.remote_port).toLocaleString() : "-"}</td>
          <td>${escapeHTML(row.protocol || "-")}</td>
          <td>${formatBytes(row.upload_bytes)}</td>
          <td>${formatBytes(row.download_bytes)}</td>
          <td>${formatBytes(total)}</td>
          <td>${Number(row.packets || 0).toLocaleString()}</td>
        </tr>
      `;
    })
    .join("");
}

function renderWANUDPClientGaps(rows) {
  rows = sortRows("wanUDPClientGaps", rows);
  if (rows.length === 0) {
    elements.wanUDPClientGapsBody.innerHTML = `<tr><td colspan="10">暂无 WAN UDP 对照数据</td></tr>`;
    return;
  }
  elements.wanUDPClientGapsBody.innerHTML = rows
    .map((row) => `
      <tr>
        <td>${escapeHTML(row.remote_ip || "-")}</td>
        <td>${row.remote_port ? Number(row.remote_port).toLocaleString() : "-"}</td>
        <td>${escapeHTML(row.protocol || "-")}</td>
        <td>${formatBytes(row.wan_upload_bytes)}</td>
        <td>${formatBytes(row.client_upload_bytes)}</td>
        <td>${formatBytes(row.unattributed_upload_bytes)}</td>
        <td>${formatBytes(row.wan_download_bytes)}</td>
        <td>${formatBytes(row.client_download_bytes)}</td>
        <td>${formatBytes(row.unattributed_download_bytes)}</td>
        <td>${Number(row.client_count || 0).toLocaleString()}</td>
      </tr>
    `)
    .join("");
}

function renderLimitations(limitations) {
  if (limitations.length === 0) {
    elements.limitationsBody.innerHTML = `<li>当前没有额外说明。</li>`;
    return;
  }
  elements.limitationsBody.innerHTML = limitations.map((item) => `<li>${escapeHTML(item)}</li>`).join("");
}

function limitRows(rows, limit) {
  if (!Array.isArray(rows)) {
    return [];
  }
  if (!Number.isFinite(limit) || limit <= 0 || rows.length <= limit) {
    return Array.from(rows);
  }
  return rows.slice(0, limit);
}

function renderObjects(rows) {
  rows = limitRows(sortRows("objects", rows), MAX_OBJECT_ROWS);
  if (rows.length === 0) {
    elements.objectsBody.innerHTML = `<tr><td colspan="8">暂无访问对象数据</td></tr>`;
    return;
  }
  elements.objectsBody.innerHTML = rows
    .map((row) => `
      <tr>
        <td>${escapeHTML(row.label || "-")}</td>
        <td>${escapeHTML(row.label_source || "-")}</td>
        <td>${escapeHTML(row.protocol || "-")}</td>
        <td>${escapeHTML(row.remote_ip || "-")}${row.remote_port ? `:${Number(row.remote_port).toLocaleString()}` : ""}</td>
        <td>${formatBytes(row.upload_bytes)}</td>
        <td>${formatBytes(row.download_bytes)}</td>
        <td>${Number(row.session_count || 0).toLocaleString()}</td>
        <td>${Number(row.client_count || 0).toLocaleString()}</td>
      </tr>
    `)
    .join("");
}

function renderReconcile(rows) {
  rows = limitRows(sortRows("reconcile", rows), MAX_RECONCILE_ROWS);
  if (rows.length === 0) {
    elements.reconcileBody.innerHTML = `<tr><td colspan="9">暂无对账数据</td></tr>`;
    return;
  }
  elements.reconcileBody.innerHTML = rows
    .map((row) => `
      <tr>
        <td>${escapeHTML(row.status || "-")}</td>
        <td>${escapeHTML(row.reason || "-")}</td>
        <td>${row.wan_session_id ? Number(row.wan_session_id).toLocaleString() : "-"}</td>
        <td>${row.lan_session_id ? Number(row.lan_session_id).toLocaleString() : "-"}</td>
        <td>${escapeHTML(row.remote_ip || "-")}${row.remote_port ? `:${Number(row.remote_port).toLocaleString()}` : ""}</td>
        <td>${escapeHTML(row.protocol || "-")}</td>
        <td>${formatBytes(row.unattributed_upload_bytes)}</td>
        <td>${formatBytes(row.unattributed_download_bytes)}</td>
        <td>${(Number(row.confidence || 0) * 100).toFixed(0)}%</td>
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

function cloneSortStates(source) {
  return Object.fromEntries(Object.entries(source).map(([table, state]) => [table, { ...state }]));
}

function compareSortValues(left, right) {
  if (typeof left === "number" || typeof right === "number") {
    return Number(left || 0) - Number(right || 0);
  }
  return String(left || "").localeCompare(String(right || ""), "zh-Hans-CN", { numeric: true, sensitivity: "base" });
}

function sortRows(table, rows) {
  const state = sortStates[table] || defaultSortStates[table];
  if (!state || !Array.isArray(rows)) {
    return Array.from(rows || []);
  }
  return Array.from(rows).sort((left, right) => {
    const result = compareSortValues(sortValue(table, left, state.field), sortValue(table, right, state.field));
    if (result !== 0) {
      return state.direction === "asc" ? result : -result;
    }
    return compareSortValues(sortValue(table, left, defaultSortStates[table].field), sortValue(table, right, defaultSortStates[table].field));
  });
}

function sortValue(table, row, field) {
  const totalBytes = Number(row.upload_bytes || 0) + Number(row.download_bytes || 0);
  const unattributedTotal = Number(row.unattributed_upload_bytes || 0) + Number(row.unattributed_download_bytes || 0);
  switch (field) {
    case "display_name":
      return row.display_name || row.client_ip || row.client_mac || "";
    case "client_ip":
      return row.client_ip || "";
    case "remote_ip":
      return row.remote_ip || "";
    case "remote_port":
      return Number(row.remote_port || 0);
    case "protocol":
      return row.protocol || "";
    case "upload_bytes":
      return Number(row.upload_bytes || 0);
    case "download_bytes":
      return Number(row.download_bytes || 0);
    case "packets":
      return Number(row.packets || 0);
    case "client_count":
      return Number(row.client_count || 0);
    case "wan_upload_bytes":
      return Number(row.wan_upload_bytes || 0);
    case "wan_download_bytes":
      return Number(row.wan_download_bytes || 0);
    case "client_upload_bytes":
      return Number(row.client_upload_bytes || 0);
    case "client_download_bytes":
      return Number(row.client_download_bytes || 0);
    case "unattributed_upload_bytes":
      return Number(row.unattributed_upload_bytes || 0);
    case "unattributed_download_bytes":
      return Number(row.unattributed_download_bytes || 0);
    case "label":
      return row.label || "";
    case "label_source":
      return row.label_source || "";
    case "session_count":
      return Number(row.session_count || 0);
    case "status":
      return row.status || "";
    case "reason":
      return row.reason || "";
    case "wan_session_id":
      return Number(row.wan_session_id || 0);
    case "lan_session_id":
      return Number(row.lan_session_id || 0);
    case "confidence":
      return Number(row.confidence || 0);
    case "remote_endpoint":
      return `${row.remote_ip || ""}:${Number(row.remote_port || 0)}`;
    case "total_bytes":
      return totalBytes;
    case "unattributed_total":
      return unattributedTotal;
    default:
      return table === "uploadClients" || table === "downloadClients" ? totalBytes : "";
  }
}

function setSort(table, field) {
  const current = sortStates[table] || defaultSortStates[table];
  if (current.field === field) {
    sortStates[table] = { field, direction: current.direction === "asc" ? "desc" : "asc" };
  } else {
    const numericFields = new Set([
      "upload_bytes", "download_bytes", "packets", "remote_port", "client_count",
      "wan_upload_bytes", "wan_download_bytes", "client_upload_bytes", "client_download_bytes",
      "unattributed_upload_bytes", "unattributed_download_bytes", "session_count",
      "wan_session_id", "lan_session_id", "confidence", "total_bytes", "unattributed_total",
    ]);
    sortStates[table] = { field, direction: numericFields.has(field) ? "desc" : "asc" };
  }
  savePrefs();
  renderSortHeaders();
  loadAnalysis();
}

function renderSortHeaders() {
  for (const button of document.querySelectorAll("[data-sort-table][data-sort-field]")) {
    const table = button.dataset.sortTable;
    const field = button.dataset.sortField;
    const state = sortStates[table] || defaultSortStates[table];
    const active = state.field === field;
    button.setAttribute("aria-sort", active ? (state.direction === "asc" ? "ascending" : "descending") : "none");
    button.dataset.direction = active ? state.direction : "";
  }
}

function syncControls() {
  const mode = elements.preset.value;
  const isDate = mode === "date";
  const isDaterange = mode === "daterange";
  const isCustom = mode === "custom";
  elements.date.disabled = !isDate;
  elements.fromDate.disabled = !isDaterange;
  elements.toDate.disabled = !isDaterange;
  elements.from.disabled = !isCustom;
  elements.to.disabled = !isCustom;
  elements.date.closest("label").hidden = !isDate;
  elements.fromDate.closest("label").hidden = !isDaterange;
  elements.toDate.closest("label").hidden = !isDaterange;
  elements.from.closest("label").hidden = !isCustom;
  elements.to.closest("label").hidden = !isCustom;
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
  refreshTimer = setInterval(loadAnalysis, intervalMs);
}

function updateAutoRefresh() {
  stopPolling();
  if (elements.autoRefresh.checked) {
    startPolling(10000);
  }
}

function cleanupPage() {
  stopPolling();
  abortActiveRequest();
}

elements.queryButton.addEventListener("click", () => { savePrefs(); loadAnalysis(); });
elements.preset.addEventListener("change", () => {
  syncControls();
  savePrefs();
  loadAnalysis();
});
elements.autoRefresh.addEventListener("change", () => { savePrefs(); updateAutoRefresh(); });
elements.resetButton.addEventListener("click", resetPrefs);
for (const button of document.querySelectorAll("[data-sort-table][data-sort-field]")) {
  button.addEventListener("click", () => setSort(button.dataset.sortTable, button.dataset.sortField));
}
window.addEventListener("pagehide", cleanupPage);
window.addEventListener("beforeunload", cleanupPage);

const savedPrefs = loadSavedPrefs();
if (savedPrefs.preset) { elements.preset.value = savedPrefs.preset; }
else { elements.preset.value = "24h"; }
if (savedPrefs.date) { elements.date.value = savedPrefs.date; }
else { elements.date.value = todayText(); }
if (savedPrefs.fromDate) { elements.fromDate.value = savedPrefs.fromDate; }
if (savedPrefs.toDate) { elements.toDate.value = savedPrefs.toDate; }
if (savedPrefs.from) { elements.from.value = normalizeDatetimeLocalPref(savedPrefs.from); }
if (savedPrefs.to) { elements.to.value = normalizeDatetimeLocalPref(savedPrefs.to); }
if (savedPrefs.autoRefresh) { elements.autoRefresh.checked = true; }
if (savedPrefs.sortStates && typeof savedPrefs.sortStates === "object") {
  sortStates = {
    ...cloneSortStates(defaultSortStates),
    ...Object.fromEntries(
      Object.entries(savedPrefs.sortStates)
        .filter(([table, state]) => defaultSortStates[table] && state && state.field && state.direction)
        .map(([table, state]) => [table, { field: state.field, direction: state.direction }]),
    ),
  };
}
syncControls();
renderSortHeaders();
loadAnalysis();
if (elements.autoRefresh.checked) {
  updateAutoRefresh();
}

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
  limitationsBody: document.querySelector("#limitationsBody"),
};

let refreshTimer = null;
const ANALYSIS_PREFS_KEY = "ta_analysis_prefs";

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
  syncControls();
  stopPolling();
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

async function loadAnalysis() {
  elements.status.textContent = "分析中";
  elements.status.style.background = "var(--accent)";

  try {
    const response = await fetch(buildAnalysisURL(), { headers: { Accept: "application/json" } });
    if (!response.ok) {
      throw new Error(await response.text());
    }
    renderAnalysis(await response.json());
    elements.status.textContent = "已更新";
    elements.status.style.background = "#b9dfcc";
  } catch (error) {
    elements.status.textContent = "分析失败";
    elements.status.style.background = "#f1b1aa";
    console.error(error);
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

function renderLimitations(limitations) {
  if (limitations.length === 0) {
    elements.limitationsBody.innerHTML = `<li>当前没有额外说明。</li>`;
    return;
  }
  elements.limitationsBody.innerHTML = limitations.map((item) => `<li>${escapeHTML(item)}</li>`).join("");
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
}

elements.queryButton.addEventListener("click", () => { savePrefs(); loadAnalysis(); });
elements.preset.addEventListener("change", () => {
  syncControls();
  savePrefs();
  loadAnalysis();
});
elements.autoRefresh.addEventListener("change", () => { savePrefs(); updateAutoRefresh(); });
elements.resetButton.addEventListener("click", resetPrefs);
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
syncControls();
loadAnalysis();
if (elements.autoRefresh.checked) {
  updateAutoRefresh();
}

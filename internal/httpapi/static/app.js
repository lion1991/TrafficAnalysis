const elements = {
  preset: document.querySelector("#preset"),
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
  lanTotal: document.querySelector("#lanTotal"),
  otherTotal: document.querySelector("#otherTotal"),
  packetTotal: document.querySelector("#packetTotal"),
  liveUploadRate: document.querySelector("#liveUploadRate"),
  liveDownloadRate: document.querySelector("#liveDownloadRate"),
  liveWan: document.querySelector("#liveWan"),
  livePackets: document.querySelector("#livePackets"),
  rangeText: document.querySelector("#rangeText"),
  chart: document.querySelector("#trafficChart"),
  breakdownBody: document.querySelector("#breakdownBody"),
};

let refreshTimer = null;
let eventSource = null;
let lastData = null;

const OVERVIEW_PREFS_KEY = "ta_overview_prefs";
const LIVE_RECONNECT_DELAY_MS = 3000;
const LIVE_STALE_TIMEOUT_MS = 45000;
const LIVE_WATCHDOG_INTERVAL_MS = 5000;

function loadSavedPrefs() {
  try {
    return JSON.parse(localStorage.getItem(OVERVIEW_PREFS_KEY) || "{}");
  } catch {
    return {};
  }
}

function savePrefs() {
  try {
    localStorage.setItem(
      OVERVIEW_PREFS_KEY,
      JSON.stringify({
        preset: elements.preset.value,
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
    localStorage.removeItem(OVERVIEW_PREFS_KEY);
  } catch {}
  elements.preset.value = "1h";
  elements.fromDate.value = "";
  elements.toDate.value = "";
  elements.from.value = "";
  elements.to.value = "";
  elements.autoRefresh.checked = false;
  syncControls();
  stopPolling();
  stopLiveStream();
  startLiveStream();
  loadTraffic();
}

function formatUTC8(isoStr) {
  const date = new Date(isoStr);
  if (isNaN(date.getTime())) {
    return isoStr;
  }
  // 手动转为 UTC+8（固定偏移，不受浏览器时区影响）
  const offsetMs = 8 * 60 * 60 * 1000;
  const local = new Date(date.getTime() + offsetMs);
  const iso = local.toISOString(); // 始终是 UTC，但加了 +8h 的偏移
  // 格式化为 "YYYY-MM-DD HH:mm"
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

function buildURL() {
  return `/api/traffic?${buildRangeParams().toString()}`;
}

function datetimeLocalToApi(value) {
  // datetime-local 的格式是 YYYY-MM-DDTHH:MM，后端期望 YYYY-MM-DD HH:MM
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

// 日期加 N 天（用于计算包含整个结束日的开区间结束点）
function addDays(dateStr, days) {
  const [year, month, day] = dateStr.split("-").map(Number);
  const date = new Date(Date.UTC(year, month - 1, day));
  date.setUTCDate(date.getUTCDate() + days);
  return formatDateInputValue(date);
}

function buildRangeParams() {
  const params = new URLSearchParams();
  const mode = elements.preset.value;
  if (mode === "daterange") {
    if (elements.fromDate.value) {
      params.set("from", elements.fromDate.value + " 00:00");
    }
    if (elements.toDate.value) {
      // 包含结束日整天：发送次日 00:00 作为开区间结束点
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

async function loadTraffic() {
  elements.status.textContent = "查询中";
  elements.status.style.background = "var(--accent)";

  try {
    const trafficResponse = await fetch(buildURL(), { headers: { Accept: "application/json" } });
    if (!trafficResponse.ok) {
      throw new Error(await trafficResponse.text());
    }
    const data = await trafficResponse.json();
    renderTraffic(data);
    elements.status.textContent = "已更新";
    elements.status.style.background = "#b9dfcc";
  } catch (error) {
    elements.status.textContent = "查询失败";
    elements.status.style.background = "#f1b1aa";
    console.error(error);
  }
}

function renderTraffic(data) {
  lastData = data;
  elements.uploadTotal.textContent = formatBytes(data.totals.upload_bytes);
  elements.downloadTotal.textContent = formatBytes(data.totals.download_bytes);
  elements.lanTotal.textContent = formatBytes(data.totals.lan_bytes);
  elements.otherTotal.textContent = formatBytes((data.totals.other_bytes || 0) + (data.totals.unknown_bytes || 0));
  elements.packetTotal.textContent = Number(data.totals.packets || 0).toLocaleString();
  elements.rangeText.textContent = `${formatUTC8(data.range.from)} 到 ${formatUTC8(data.range.to)}`;

  renderChart(data.series || []);
  renderBreakdown(data.breakdown || []);
}

function renderLive(snapshot) {
  elements.liveUploadRate.textContent = `${formatBytes(snapshot.rates.upload_bps)}/s`;
  elements.liveDownloadRate.textContent = `${formatBytes(snapshot.rates.download_bps)}/s`;
  elements.liveWan.textContent = snapshot.wan_available ? snapshot.wan_ip : "不可用";
  elements.livePackets.textContent = Number(snapshot.totals.packets || 0).toLocaleString();
  elements.status.textContent = "实时连接";
  elements.status.style.background = "#b9dfcc";
}

function renderBreakdown(rows) {
  if (rows.length === 0) {
    elements.breakdownBody.innerHTML = `<tr><td colspan="4">暂无数据</td></tr>`;
    return;
  }

  elements.breakdownBody.innerHTML = rows
    .map((row) => `
      <tr>
        <td>${escapeHTML(row.direction)}</td>
        <td>${escapeHTML(row.protocol)}</td>
        <td>${formatBytes(row.bytes)}</td>
        <td>${Number(row.packets || 0).toLocaleString()}</td>
      </tr>
    `)
    .join("");
}

function renderChart(series) {
  const canvas = elements.chart;
  const ratio = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  canvas.width = Math.max(1, Math.floor(rect.width * ratio));
  canvas.height = Math.max(1, Math.floor(rect.height * ratio));

  const ctx = canvas.getContext("2d");
  ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
  ctx.clearRect(0, 0, rect.width, rect.height);

  const padding = { top: 20, right: 18, bottom: 34, left: 58 };
  const width = rect.width - padding.left - padding.right;
  const height = rect.height - padding.top - padding.bottom;
  const maxValue = Math.max(1, ...series.map((point) => Math.max(point.upload_bytes || 0, point.download_bytes || 0)));

  ctx.strokeStyle = "#d9e0dc";
  ctx.lineWidth = 1;
  ctx.fillStyle = "#66716c";
  ctx.font = "12px Aptos, sans-serif";

  for (let index = 0; index <= 4; index += 1) {
    const y = padding.top + (height * index) / 4;
    ctx.beginPath();
    ctx.moveTo(padding.left, y);
    ctx.lineTo(padding.left + width, y);
    ctx.stroke();
    const label = formatBytes(maxValue * (1 - index / 4));
    ctx.fillText(label, 8, y + 4);
  }

  if (series.length === 0) {
    ctx.fillStyle = "#66716c";
    ctx.fillText("暂无数据", padding.left, padding.top + 28);
    return;
  }

  drawLine(ctx, series, "upload_bytes", "#0f8b5f", padding, width, height, maxValue);
  drawLine(ctx, series, "download_bytes", "#1264a3", padding, width, height, maxValue);
  drawLegend(ctx, padding.left + width, padding.top);
}

function drawLine(ctx, series, field, color, padding, width, height, maxValue) {
  ctx.strokeStyle = color;
  ctx.lineWidth = 3;
  ctx.beginPath();

  series.forEach((point, index) => {
    const x = padding.left + (series.length === 1 ? width / 2 : (width * index) / (series.length - 1));
    const y = padding.top + height - (height * Number(point[field] || 0)) / maxValue;
    if (index === 0) {
      ctx.moveTo(x, y);
    } else {
      ctx.lineTo(x, y);
    }
  });

  ctx.stroke();
}

function drawLegend(ctx, chartRight, y) {
  const items = [
    ["上传", "#0f8b5f"],
    ["下载", "#1264a3"],
  ];
  // 从右向左排列，避免遮挡 Y 轴标签
  const itemWidth = 72;
  const startX = chartRight - items.length * itemWidth;
  items.forEach((item, index) => {
    const offset = index * itemWidth;
    ctx.fillStyle = item[1];
    ctx.fillRect(startX + offset, y, 22, 5);
    ctx.fillStyle = "#171a18";
    ctx.fillText(item[0], startX + offset + 28, y + 7);
  });
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
  const isDaterange = mode === "daterange";
  const isCustom = mode === "custom";
  elements.fromDate.disabled = !isDaterange;
  elements.toDate.disabled = !isDaterange;
  elements.from.disabled = !isCustom;
  elements.to.disabled = !isCustom;
  // 隐藏不需要的输入组，减少视觉干扰
  elements.fromDate.closest("label").hidden = !isDaterange;
  elements.toDate.closest("label").hidden = !isDaterange;
  elements.from.closest("label").hidden = !isCustom;
  elements.to.closest("label").hidden = !isCustom;
}

function updateAutoRefresh() {
  stopPolling();
  if (elements.autoRefresh.checked) {
    startPolling(5000);
  }
}

let liveReconnectTimer = null;
let liveWatchdogTimer = null;
let lastLiveMessageAt = 0;

function markLiveMessage() {
  lastLiveMessageAt = Date.now();
}

function clearLiveReconnect() {
  if (liveReconnectTimer) {
    clearTimeout(liveReconnectTimer);
    liveReconnectTimer = null;
  }
}

function scheduleLiveReconnect() {
  if (liveReconnectTimer) {
    return;
  }
  liveReconnectTimer = setTimeout(startLiveStream, LIVE_RECONNECT_DELAY_MS);
}

function clearLiveWatchdog() {
  if (liveWatchdogTimer) {
    clearInterval(liveWatchdogTimer);
    liveWatchdogTimer = null;
  }
}

function startLiveWatchdog() {
  clearLiveWatchdog();
  liveWatchdogTimer = setInterval(() => {
    if (!eventSource || Date.now() - lastLiveMessageAt < LIVE_STALE_TIMEOUT_MS) {
      return;
    }
    const source = eventSource;
    source.close();
    if (eventSource === source) {
      eventSource = null;
    }
    elements.status.textContent = "实时重连";
    elements.status.style.background = "var(--accent)";
    scheduleLiveReconnect();
  }, LIVE_WATCHDOG_INTERVAL_MS);
}

function stopPolling() {
  if (refreshTimer) {
    clearInterval(refreshTimer);
    refreshTimer = null;
  }
}

function stopLiveStream() {
  clearLiveReconnect();
  clearLiveWatchdog();
  if (eventSource) {
    eventSource.close();
    eventSource = null;
  }
}

function startLiveStream() {
  clearLiveReconnect();
  stopLiveStream();
  if (!window.EventSource) {
    elements.status.textContent = "轮询刷新";
    elements.status.style.background = "var(--accent)";
    startPolling(5000);
    return;
  }

  const source = new EventSource("/api/live");
  eventSource = source;
  markLiveMessage();
  startLiveWatchdog();
  source.addEventListener("snapshot", (event) => {
    try {
      markLiveMessage();
      renderLive(JSON.parse(event.data));
    } catch (error) {
      console.error(error);
    }
  });
  source.addEventListener("heartbeat", markLiveMessage);
  source.onerror = () => {
    if (eventSource !== source) {
      return;
    }
    source.close();
    eventSource = null;
    clearLiveWatchdog();
    elements.status.textContent = "轮询刷新";
    elements.status.style.background = "var(--accent)";
    if (!refreshTimer) {
      startPolling(5000);
    }
    scheduleLiveReconnect();
  };

  if (!refreshTimer) {
    startPolling(30000);
  }
}

function startPolling(intervalMs) {
  if (refreshTimer) {
    clearInterval(refreshTimer);
  }
  refreshTimer = setInterval(loadTraffic, intervalMs);
}

function cleanupPage() {
  stopPolling();
  stopLiveStream();
}

elements.queryButton.addEventListener("click", () => { savePrefs(); loadTraffic(); });
elements.preset.addEventListener("change", () => {
  syncControls();
  savePrefs();
  loadTraffic();
});
elements.autoRefresh.addEventListener("change", () => { savePrefs(); updateAutoRefresh(); });
elements.resetButton.addEventListener("click", resetPrefs);
window.addEventListener("resize", () => {
  if (lastData) {
    renderChart(lastData.series || []);
  }
});
window.addEventListener("pagehide", cleanupPage);
window.addEventListener("beforeunload", cleanupPage);

// 恢复已保存的偏好设置
const savedPrefs = loadSavedPrefs();
if (savedPrefs.preset) { elements.preset.value = savedPrefs.preset; }
if (savedPrefs.fromDate) { elements.fromDate.value = savedPrefs.fromDate; }
if (savedPrefs.toDate) { elements.toDate.value = savedPrefs.toDate; }
if (savedPrefs.from) { elements.from.value = normalizeDatetimeLocalPref(savedPrefs.from); }
if (savedPrefs.to) { elements.to.value = normalizeDatetimeLocalPref(savedPrefs.to); }
if (savedPrefs.autoRefresh) { elements.autoRefresh.checked = true; }
syncControls();
startLiveStream();
loadTraffic();
if (elements.autoRefresh.checked) {
  updateAutoRefresh();
}

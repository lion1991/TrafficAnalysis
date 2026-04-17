const elements = {
  preset: document.querySelector("#preset"),
  from: document.querySelector("#from"),
  to: document.querySelector("#to"),
  autoRefresh: document.querySelector("#autoRefresh"),
  queryButton: document.querySelector("#queryButton"),
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
  const params = new URLSearchParams();
  if (elements.preset.value === "custom") {
    if (elements.from.value.trim()) {
      params.set("from", elements.from.value.trim());
    }
    if (elements.to.value.trim()) {
      params.set("to", elements.to.value.trim());
    }
  } else {
    params.set("last", elements.preset.value);
  }
  return `/api/traffic?${params.toString()}`;
}

async function loadTraffic() {
  elements.status.textContent = "查询中";
  elements.status.style.background = "var(--accent)";

  try {
    const response = await fetch(buildURL(), { headers: { Accept: "application/json" } });
    if (!response.ok) {
      throw new Error(await response.text());
    }
    const data = await response.json();
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
  elements.rangeText.textContent = `${data.range.from} 到 ${data.range.to}`;

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
  drawLegend(ctx, padding.left, padding.top);
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

function drawLegend(ctx, x, y) {
  const items = [
    ["上传", "#0f8b5f"],
    ["下载", "#1264a3"],
  ];
  items.forEach((item, index) => {
    const offset = index * 72;
    ctx.fillStyle = item[1];
    ctx.fillRect(x + offset, y, 22, 5);
    ctx.fillStyle = "#171a18";
    ctx.fillText(item[0], x + offset + 28, y + 7);
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
  const custom = elements.preset.value === "custom";
  elements.from.disabled = !custom;
  elements.to.disabled = !custom;
}

function updateAutoRefresh() {
  stopAutoRefresh();
  if (elements.autoRefresh.checked) {
    startLiveStream();
  }
}

function stopAutoRefresh() {
  if (refreshTimer) {
    clearInterval(refreshTimer);
    refreshTimer = null;
  }
  if (eventSource) {
    eventSource.close();
    eventSource = null;
  }
}

function startLiveStream() {
  if (!window.EventSource) {
    startPolling();
    return;
  }

  const source = new EventSource("/api/live");
  eventSource = source;
  source.addEventListener("snapshot", (event) => {
    try {
      renderLive(JSON.parse(event.data));
    } catch (error) {
      console.error(error);
    }
  });
  source.onerror = () => {
    if (eventSource !== source) {
      return;
    }
    source.close();
    eventSource = null;
    elements.status.textContent = "轮询刷新";
    elements.status.style.background = "var(--accent)";
    startPolling();
  };

  refreshTimer = setInterval(loadTraffic, 30000);
}

function startPolling() {
  if (refreshTimer) {
    clearInterval(refreshTimer);
  }
  refreshTimer = setInterval(loadTraffic, 5000);
}

elements.queryButton.addEventListener("click", loadTraffic);
elements.preset.addEventListener("change", () => {
  syncControls();
  loadTraffic();
});
elements.autoRefresh.addEventListener("change", updateAutoRefresh);
window.addEventListener("resize", () => {
  if (lastData) {
    renderChart(lastData.series || []);
  }
});

syncControls();
loadTraffic();

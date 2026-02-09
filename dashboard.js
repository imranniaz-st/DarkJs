const STORAGE_PREFIX = "tab:";

const scopeSelect = document.getElementById("scopeSelect");
const tabSelect = document.getElementById("tabSelect");
const typeFilter = document.getElementById("typeFilter");
const searchInput = document.getElementById("searchInput");
const dedupeToggle = document.getElementById("dedupeToggle");
const rescanBtn = document.getElementById("rescanBtn");
const exportCsvBtn = document.getElementById("exportCsvBtn");
const exportJsonBtn = document.getElementById("exportJsonBtn");
const statusPill = document.getElementById("statusPill");

const totalCount = document.getElementById("totalCount");
const endpointCount = document.getElementById("endpointCount");
const payloadCount = document.getElementById("payloadCount");
const dupeCount = document.getElementById("dupeCount");
const resultsBody = document.getElementById("resultsBody");
const footerNote = document.getElementById("footerNote");

function classify(findings) {
  const endpointSet = new Set();
  const payloadSet = new Set();
  const allSet = new Set();

  findings.forEach(item => {
    const key = `${item.type}::${item.value}`;
    allSet.add(key);
    if (item.type === "Route" || item.type === "URL") {
      endpointSet.add(item.value);
    }
    if (item.type === "API Key or Secret") {
      payloadSet.add(item.value);
    }
  });

  const total = findings.length;
  const uniqueTotal = allSet.size;
  const dupes = Math.max(0, total - uniqueTotal);

  return {
    total,
    endpoints: endpointSet.size,
    payloads: payloadSet.size,
    dupes
  };
}

async function getTabRecords(tabIds) {
  if (!tabIds.length) return [];
  const keys = tabIds.map(id => `${STORAGE_PREFIX}${id}`);
  const data = await chrome.storage.session.get(keys);
  return tabIds.map(id => data[`${STORAGE_PREFIX}${id}`]).filter(Boolean);
}

function flattenRecords(records, tabLookup) {
  const flattened = [];
  records.forEach(record => {
    const tabTitle = tabLookup.get(record.tabId) || record.pageTitle || "Untitled";
    (record.findings || []).forEach(([type, value, source]) => {
      flattened.push({
        type,
        value,
        source,
        tabId: record.tabId,
        tabTitle,
        pageUrl: record.pageUrl || "",
        scannedAt: record.scannedAt || 0
      });
    });
  });
  return flattened;
}

function applyFilters(findings, filter, searchTerm, dedupe) {
  let filtered = findings;

  if (filter === "endpoints") {
    filtered = filtered.filter(item => item.type === "Route" || item.type === "URL");
  } else if (filter === "payloads") {
    filtered = filtered.filter(item => item.type === "API Key or Secret");
  }

  if (searchTerm) {
    const needle = searchTerm.toLowerCase();
    filtered = filtered.filter(item => {
      return [item.value, item.source, item.tabTitle, item.pageUrl]
        .join(" ")
        .toLowerCase()
        .includes(needle);
    });
  }

  let deduped = filtered;
  if (dedupe) {
    const seen = new Set();
    deduped = [];
    filtered.forEach(item => {
      const key = `${item.type}::${item.value}`;
      if (!seen.has(key)) {
        seen.add(key);
        deduped.push(item);
      }
    });
  }

  return { filtered, deduped };
}

function renderTable(rows) {
  resultsBody.innerHTML = "";
  if (!rows.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 5;
    td.className = "mono";
    td.textContent = "No findings.";
    tr.appendChild(td);
    resultsBody.appendChild(tr);
    return;
  }

  rows.forEach(item => {
    const tr = document.createElement("tr");
    const typeCell = document.createElement("td");
    const tag = document.createElement("span");
    tag.className = "tag";
    tag.textContent = item.type;
    typeCell.appendChild(tag);

    const valueCell = document.createElement("td");
    valueCell.className = "mono";
    valueCell.textContent = item.value;

    const sourceCell = document.createElement("td");
    sourceCell.className = "mono";
    sourceCell.textContent = item.source;

    const tabCell = document.createElement("td");
    tabCell.textContent = item.tabTitle;

    const pageCell = document.createElement("td");
    pageCell.className = "mono";
    pageCell.textContent = item.pageUrl;

    tr.appendChild(typeCell);
    tr.appendChild(valueCell);
    tr.appendChild(sourceCell);
    tr.appendChild(tabCell);
    tr.appendChild(pageCell);
    resultsBody.appendChild(tr);
  });
}

function updateStatus(text) {
  statusPill.textContent = text;
}

function buildCsv(rows) {
  let csv = "Type,Value,Source,Tab,PageUrl,ScannedAt\n";
  rows.forEach(item => {
    const safe = value => String(value).replace(/"/g, '""');
    csv += `"${safe(item.type)}","${safe(item.value)}","${safe(item.source)}","${safe(item.tabTitle)}","${safe(item.pageUrl)}","${safe(item.scannedAt)}"\n`;
  });
  return csv;
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

async function loadDashboard() {
  updateStatus("Loading");
  const tabs = await chrome.tabs.query({});
  const tabLookup = new Map(tabs.map(tab => [tab.id, tab.title || "Untitled"]));

  tabSelect.innerHTML = "";
  tabs.forEach(tab => {
    const option = document.createElement("option");
    option.value = String(tab.id);
    option.textContent = `${tab.title || "Untitled"}`;
    tabSelect.appendChild(option);
  });

  const scope = scopeSelect.value;
  tabSelect.disabled = scope !== "single";
  rescanBtn.disabled = scope !== "single";

  const tabIds = scope === "single"
    ? [Number(tabSelect.value || tabs[0]?.id)]
    : tabs.map(tab => tab.id).filter(Boolean);

  const records = await getTabRecords(tabIds);
  const flattened = flattenRecords(records, tabLookup);

  const filter = typeFilter.value;
  const searchTerm = searchInput.value.trim();
  const dedupe = dedupeToggle.value === "on";

  const { filtered, deduped } = applyFilters(flattened, filter, searchTerm, dedupe);
  const stats = classify(deduped);
  const statsWithDupes = classify(filtered);

  totalCount.textContent = String(statsWithDupes.total);
  endpointCount.textContent = String(stats.endpoints);
  payloadCount.textContent = String(stats.payloads);
  dupeCount.textContent = String(statsWithDupes.dupes);

  renderTable(deduped);
  footerNote.textContent = `Updated ${new Date().toLocaleTimeString()}.`;
  updateStatus("Ready");
}

async function rescanSelected() {
  const scope = scopeSelect.value;
  if (scope !== "single") return;
  const tabId = Number(tabSelect.value);
  if (!tabId) return;
  updateStatus("Rescanning");
  await chrome.runtime.sendMessage({ action: "scan_tab", tabId });
  await loadDashboard();
}

async function exportCsv() {
  const rows = collectExportRows();
  const csv = buildCsv(rows);
  downloadBlob(new Blob([csv], { type: "text/csv" }), "darkjs_dashboard.csv");
}

async function exportJson() {
  const rows = collectExportRows();
  downloadBlob(new Blob([JSON.stringify(rows, null, 2)], { type: "application/json" }), "darkjs_dashboard.json");
}

function collectExportRows() {
  const rows = [];
  const tableRows = resultsBody.querySelectorAll("tr");
  tableRows.forEach(tr => {
    const cells = tr.querySelectorAll("td");
    if (cells.length < 5) return;
    rows.push({
      type: cells[0].innerText.trim(),
      value: cells[1].innerText.trim(),
      source: cells[2].innerText.trim(),
      tab: cells[3].innerText.trim(),
      pageUrl: cells[4].innerText.trim()
    });
  });
  return rows;
}

scopeSelect.addEventListener("change", loadDashboard);
searchInput.addEventListener("input", loadDashboard);
typeFilter.addEventListener("change", loadDashboard);
dedupeToggle.addEventListener("change", loadDashboard);
tabSelect.addEventListener("change", loadDashboard);
rescanBtn.addEventListener("click", rescanSelected);
exportCsvBtn.addEventListener("click", exportCsv);
exportJsonBtn.addEventListener("click", exportJson);

loadDashboard();

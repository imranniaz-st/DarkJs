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
const enableDom = document.getElementById("enableDom");
const enableStorage = document.getElementById("enableStorage");
const enableSourceMaps = document.getElementById("enableSourceMaps");
const enableNetwork = document.getElementById("enableNetwork");
const enableRuntime = document.getElementById("enableRuntime");
const allowlistInput = document.getElementById("allowlistInput");
const denylistInput = document.getElementById("denylistInput");
const saveSettingsBtn = document.getElementById("saveSettingsBtn");
const tabPicker = document.getElementById("tabPicker");
const tabList = document.getElementById("tabList");
const selectAllTabsBtn = document.getElementById("selectAllTabsBtn");
const clearAllTabsBtn = document.getElementById("clearAllTabsBtn");

const totalCount = document.getElementById("totalCount");
const endpointCount = document.getElementById("endpointCount");
const payloadCount = document.getElementById("payloadCount");
const dupeCount = document.getElementById("dupeCount");
const resultsBody = document.getElementById("resultsBody");
const footerNote = document.getElementById("footerNote");
let lastRenderedRows = [];
let selectedTabIds = new Set();
let latestTabs = [];
let customInitialized = false;

function classify(findings) {
  const endpointSet = new Set();
  const payloadSet = new Set();
  const allSet = new Set();

  findings.forEach(item => {
    const key = `${item.type}::${item.value}`;
    allSet.add(key);
    if (item.type === "Route" || item.type === "URL" || item.type === "API Endpoint") {
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
    const tabMeta = tabLookup.get(record.tabId) || {};
    const tabTitle = tabMeta.title || record.pageTitle || "Untitled";
    const tabUrl = tabMeta.url || record.pageUrl || "";
    (record.findings || []).forEach(([type, value, source]) => {
      flattened.push({
        type,
        value,
        source,
        tabId: record.tabId,
        tabTitle,
        tabUrl,
        pageUrl: record.pageUrl || "",
        scannedAt: record.scannedAt || 0
      });
    });
  });
  return flattened;
}

function deriveStatus(source) {
  if (!source) return "";
  if (source.startsWith("network:")) {
    return source.replace("network:", "");
  }
  if (source.startsWith("runtime:")) {
    const parts = source.split(":");
    return parts[2] || "";
  }
  return "";
}

function applyFilters(findings, filter, searchTerm, dedupe) {
  let filtered = findings;

  if (filter === "endpoints") {
    filtered = filtered.filter(item => item.type === "Route" || item.type === "URL" || item.type === "API Endpoint");
  } else if (filter === "payloads") {
    filtered = filtered.filter(item => item.type === "API Key or Secret");
  } else if (filter === "storage") {
    filtered = filtered.filter(item => item.type === "Storage Item");
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
  lastRenderedRows = rows;
  if (!rows.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 6;
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

    const statusCell = document.createElement("td");
    statusCell.className = "mono";
    statusCell.textContent = deriveStatus(item.source);

    const tabCell = document.createElement("td");
    tabCell.className = "mono";
    tabCell.textContent = item.tabUrl || item.tabTitle;
    tabCell.title = item.tabTitle;

    const pageCell = document.createElement("td");
    pageCell.className = "mono";
    pageCell.textContent = item.pageUrl;

    tr.appendChild(typeCell);
    tr.appendChild(valueCell);
    tr.appendChild(sourceCell);
    tr.appendChild(statusCell);
    tr.appendChild(tabCell);
    tr.appendChild(pageCell);
    resultsBody.appendChild(tr);
  });
}

function updateStatus(text) {
  statusPill.textContent = text;
}

function parsePatterns(value) {
  return value
    .split(/\n|,/)
    .map(item => item.trim())
    .filter(Boolean);
}

async function loadSettings() {
  const data = await chrome.storage.local.get("settings");
  const settings = data.settings || {};

  enableDom.value = settings.enableDom === false ? "off" : "on";
  enableStorage.value = settings.enableStorage === false ? "off" : "on";
  enableSourceMaps.value = settings.enableSourceMaps === false ? "off" : "on";
  enableNetwork.value = settings.enableNetwork === false ? "off" : "on";
  enableRuntime.value = settings.enableRuntime === false ? "off" : "on";

  allowlistInput.value = (settings.allowlist || []).join("\n");
  denylistInput.value = (settings.denylist || []).join("\n");
}

async function saveSettings() {
  updateStatus("Saving");
  const settings = {
    enableDom: enableDom.value === "on",
    enableStorage: enableStorage.value === "on",
    enableSourceMaps: enableSourceMaps.value === "on",
    enableNetwork: enableNetwork.value === "on",
    enableRuntime: enableRuntime.value === "on",
    allowlist: parsePatterns(allowlistInput.value),
    denylist: parsePatterns(denylistInput.value)
  };

  await chrome.storage.local.set({ settings });
  updateStatus("Saved");
}

function buildCsv(rows) {
  let csv = "Type,Value,Source,Status,TabUrl,PageUrl,ScannedAt\n";
  rows.forEach(item => {
    const safe = value => String(value).replace(/"/g, '""');
    csv += `"${safe(item.type)}","${safe(item.value)}","${safe(item.source)}","${safe(deriveStatus(item.source))}","${safe(item.tabUrl)}","${safe(item.pageUrl)}","${safe(item.scannedAt)}"\n`;
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
  latestTabs = tabs;
  const tabLookup = new Map(tabs.map(tab => [tab.id, { title: tab.title || "Untitled", url: tab.url || "" }]));

  tabSelect.innerHTML = "";
  tabs.forEach(tab => {
    const option = document.createElement("option");
    option.value = String(tab.id);
    option.textContent = tab.url || tab.title || "Untitled";
    option.title = tab.title || "Untitled";
    tabSelect.appendChild(option);
  });

  const scope = scopeSelect.value;
  tabSelect.disabled = scope !== "single";
  rescanBtn.disabled = scope !== "single";
  tabPicker.hidden = scope !== "custom";

  if (scope === "custom" && !customInitialized) {
    selectedTabIds = new Set(tabs.map(tab => tab.id).filter(Boolean));
    customInitialized = true;
  }

  renderTabPicker(tabs);

  let tabIds = [];
  if (scope === "single") {
    tabIds = [Number(tabSelect.value || tabs[0]?.id)];
  } else if (scope === "custom") {
    tabIds = Array.from(selectedTabIds);
  } else {
    tabIds = tabs.map(tab => tab.id).filter(Boolean);
  }

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

function renderTabPicker(tabs) {
  if (!tabList) return;
  const currentIds = new Set(tabs.map(tab => tab.id));
  selectedTabIds.forEach(id => {
    if (!currentIds.has(id)) selectedTabIds.delete(id);
  });

  tabList.innerHTML = "";
  if (!tabs.length) {
    const empty = document.createElement("div");
    empty.className = "mono";
    empty.textContent = "No tabs found.";
    tabList.appendChild(empty);
    return;
  }

  tabs.forEach(tab => {
    const row = document.createElement("label");
    row.className = "tab-item";

    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.checked = selectedTabIds.has(tab.id);
    checkbox.addEventListener("change", () => {
      if (checkbox.checked) {
        selectedTabIds.add(tab.id);
      } else {
        selectedTabIds.delete(tab.id);
      }
      loadDashboard();
    });

    const meta = document.createElement("div");
    meta.className = "tab-meta";

    const title = document.createElement("div");
    title.className = "tab-title";
    title.textContent = tab.title || "Untitled";

    const url = document.createElement("div");
    url.className = "tab-url";
    url.textContent = tab.url || "";

    meta.appendChild(title);
    meta.appendChild(url);

    row.appendChild(checkbox);
    row.appendChild(meta);
    tabList.appendChild(row);
  });
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
  const rows = lastRenderedRows;
  const csv = buildCsv(rows);
  downloadBlob(new Blob([csv], { type: "text/csv" }), "darkjs_dashboard.csv");
}

async function exportJson() {
  const rows = lastRenderedRows;
  downloadBlob(new Blob([JSON.stringify(rows, null, 2)], { type: "application/json" }), "darkjs_dashboard.json");
}

scopeSelect.addEventListener("change", loadDashboard);
searchInput.addEventListener("input", loadDashboard);
typeFilter.addEventListener("change", loadDashboard);
dedupeToggle.addEventListener("change", loadDashboard);
tabSelect.addEventListener("change", loadDashboard);
rescanBtn.addEventListener("click", rescanSelected);
exportCsvBtn.addEventListener("click", exportCsv);
exportJsonBtn.addEventListener("click", exportJson);
saveSettingsBtn.addEventListener("click", saveSettings);
selectAllTabsBtn.addEventListener("click", () => {
  selectedTabIds = new Set(latestTabs.map(tab => tab.id).filter(Boolean));
  loadDashboard();
});
clearAllTabsBtn.addEventListener("click", () => {
  selectedTabIds.clear();
  loadDashboard();
});

loadSettings().then(loadDashboard);

const STORAGE_PREFIX = "tab:";

function classify(findings) {
  const endpointSet = new Set();
  const payloadSet = new Set();
  const allSet = new Set();

  findings.forEach(([type, value]) => {
    const key = `${type}::${value}`;
    allSet.add(key);
    if (type === "Route" || type === "URL" || type === "API Endpoint") {
      endpointSet.add(value);
    }
    if (type === "API Key or Secret") {
      payloadSet.add(value);
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

async function getCurrentTabId() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  return tabs[0]?.id || null;
}

async function getTabData(tabIds) {
  const keys = tabIds.map(id => `${STORAGE_PREFIX}${id}`);
  const data = await chrome.storage.session.get(keys);
  return tabIds.map(id => data[`${STORAGE_PREFIX}${id}`]).filter(Boolean);
}

async function loadStats(scope) {
  const totalEl = document.getElementById("totalCount");
  const endpointEl = document.getElementById("endpointCount");
  const payloadEl = document.getElementById("payloadCount");
  const dupeEl = document.getElementById("dupeCount");
  const noteEl = document.getElementById("note");

  if (scope === "all") {
    const tabs = await chrome.tabs.query({});
    const tabIds = tabs.map(tab => tab.id).filter(Boolean);
    const records = await getTabData(tabIds);
    const allFindings = records.flatMap(record => record.findings || []);
    const stats = classify(allFindings);

    totalEl.textContent = String(stats.total);
    endpointEl.textContent = String(stats.endpoints);
    payloadEl.textContent = String(stats.payloads);
    dupeEl.textContent = String(stats.dupes);
    noteEl.textContent = "Duplicates are filtered across all tabs in All Tabs view.";
    return;
  }

  const tabId = await getCurrentTabId();
  if (!tabId) {
    totalEl.textContent = "0";
    endpointEl.textContent = "0";
    payloadEl.textContent = "0";
    dupeEl.textContent = "0";
    noteEl.textContent = "No active tab.";
    return;
  }

  const [record] = await getTabData([tabId]);
  const findings = record?.findings || [];
  const stats = classify(findings);

  totalEl.textContent = String(stats.total);
  endpointEl.textContent = String(stats.endpoints);
  payloadEl.textContent = String(stats.payloads);
  dupeEl.textContent = String(stats.dupes);
  noteEl.textContent = "Duplicates are filtered per tab in Current Tab view.";
}

async function getFindingsForScope(scope) {
  if (scope === "all") {
    const tabs = await chrome.tabs.query({});
    const tabIds = tabs.map(tab => tab.id).filter(Boolean);
    const records = await getTabData(tabIds);
    return records.flatMap(record => record.findings || []);
  }

  const tabId = await getCurrentTabId();
  if (!tabId) return [];
  const [record] = await getTabData([tabId]);
  return record?.findings || [];
}

function dedupeFindings(findings) {
  const seen = new Set();
  return findings.filter(([type, value]) => {
    const key = `${type}::${value}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function buildCsv(findings) {
  let csv = "Type,Value,Source\n";
  findings.forEach(([type, value, source]) => {
    const safeType = String(type).replace(/"/g, '""');
    const safeValue = String(value).replace(/"/g, '""');
    const safeSource = String(source).replace(/"/g, '""');
    csv += `"${safeType}","${safeValue}","${safeSource}"\n`;
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

async function exportCsv() {
  const scope = document.getElementById("scopeSelect").value;
  const findings = dedupeFindings(await getFindingsForScope(scope));
  const csv = buildCsv(findings);
  const blob = new Blob([csv], { type: "text/csv" });
  downloadBlob(blob, `darkjs_${scope}_findings.csv`);
}

async function exportJson() {
  const scope = document.getElementById("scopeSelect").value;
  const findings = dedupeFindings(await getFindingsForScope(scope));
  const payload = findings.map(([type, value, source]) => ({
    type,
    value,
    source
  }));
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  downloadBlob(blob, `darkjs_${scope}_findings.json`);
}

function openDashboard() {
  chrome.tabs.create({ url: chrome.runtime.getURL("dashboard.html") });
}

async function rescanCurrentTab() {
  const tabId = await getCurrentTabId();
  if (!tabId) return;
  await chrome.runtime.sendMessage({ action: "scan_tab", tabId });
  await loadStats(document.getElementById("scopeSelect").value);
}

document.addEventListener("DOMContentLoaded", () => {
  const scopeSelect = document.getElementById("scopeSelect");
  const rescanBtn = document.getElementById("rescanBtn");
  const exportCsvBtn = document.getElementById("exportCsvBtn");
  const exportJsonBtn = document.getElementById("exportJsonBtn");
  const openDashboardBtn = document.getElementById("openDashboardBtn");

  scopeSelect.addEventListener("change", () => loadStats(scopeSelect.value));
  rescanBtn.addEventListener("click", rescanCurrentTab);
  exportCsvBtn.addEventListener("click", exportCsv);
  exportJsonBtn.addEventListener("click", exportJson);
  openDashboardBtn.addEventListener("click", openDashboard);

  loadStats(scopeSelect.value);
});

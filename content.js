let runtimeEnabled = true;

chrome.storage.local.get("settings").then(data => {
	runtimeEnabled = data.settings?.enableRuntime !== false;
	if (runtimeEnabled) {
		chrome.runtime.sendMessage({ action: "init_runtime" });
	}
});

chrome.storage.onChanged.addListener((changes, area) => {
	if (area === "local" && changes.settings) {
		runtimeEnabled = changes.settings.newValue?.enableRuntime !== false;
	}
});

window.addEventListener("message", event => {
	if (!runtimeEnabled) return;
	if (event.source !== window) return;
	const data = event.data;
	if (!data || data.source !== "darkjs-hook") return;
	chrome.runtime.sendMessage({
		action: "runtime_event",
		url: data.url,
		method: data.method,
		status: data.status,
		pageUrl: window.location.href
	});
});

chrome.runtime.sendMessage({ action: "scan_page" });
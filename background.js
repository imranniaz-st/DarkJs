const STORAGE_PREFIX = "tab:";

async function runScanOnTab(tabId) {
  const [{ result }] = await chrome.scripting.executeScript({
    target: { tabId },
    func: async function () {
      const findings = [];
      const scripts = [...document.scripts];

      for (const script of scripts) {
        let code = "";
        let source = script.src || "inline-script";

        try {
          if (script.src) {
            const res = await fetch(script.src);
            code = await res.text();
          } else {
            code = script.textContent;
          }

          const routes = code.match(/\/[a-zA-Z0-9_\-\/]{3,}/g) || [];
          routes.forEach(r => findings.push(["Route", r, source]));

          const urls = code.match(/https?:\/\/[^\s"'<>\\]+/g) || [];
          urls.forEach(u => findings.push(["URL", u, source]));

          const keyPatterns = [
            /\b(api[_-]?key|apikey|secret|token|auth[_-]?token|access[_-]?token)\b\s*[:=]\s*["']?[A-Za-z0-9_\-\.]{8,}["']?/gi,
            /AWS[_-]?ACCESS[_-]?KEY[_-]?ID\s*[:=]\s*["']?AKIA[0-9A-Z]{16}["']?/g,
            /AWS[_-]?SECRET[_-]?ACCESS[_-]?KEY\s*[:=]\s*["']?[A-Za-z0-9\/+]{40}["']?/g,
            /firebaseConfig\s*=\s*{[^}]+}/gi,
            /AIza[0-9A-Za-z\-_]{35}/g,
            /sk_live_[0-9a-zA-Z]{24}/g,
            /pk_live_[0-9a-zA-Z]{24}/g,
            /key-[0-9a-zA-Z]{32}/g,
            /SG\.[0-9A-Za-z\-_]{22,}\.[0-9A-Za-z\-_]{22,}/g,
            /AC[a-zA-Z0-9]{32}/g,
            /SK[a-zA-Z0-9]{32}/g,
            /eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+/g,
            /-----BEGIN (RSA|DSA|EC|PGP|OPENSSH) PRIVATE KEY-----[\s\S]+?-----END \1 PRIVATE KEY-----/g,
            /[a-zA-Z0-9._%+-]+:[a-zA-Z0-9!@#$%^&*()_+=\-{}[\]|\\;:'",.<>?]{3,}@/g,
            /mongodb(\+srv)?:\/\/[^"'\s]+/g,
            /DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+;EndpointSuffix=core\.windows\.net/g,
            /heroku[a-z0-9]{32}/g,
            /\b(?:[A-Za-z0-9+\/]{40,}={0,2})\b/g
          ];

          keyPatterns.forEach(pattern => {
            const matches = code.match(pattern) || [];
            matches.forEach(k => {
              findings.push(["API Key or Secret", k.trim(), source]);
            });
          });
        } catch (e) {
          console.warn(`Could not fetch or parse script: ${source}`, e);
        }
      }

      return {
        findings,
        pageUrl: location.href,
        pageTitle: document.title,
        scannedAt: Date.now()
      };
    }
  });

  const key = `${STORAGE_PREFIX}${tabId}`;
  await chrome.storage.session.set({
    [key]: {
      tabId,
      findings: result.findings || [],
      pageUrl: result.pageUrl || "",
      pageTitle: result.pageTitle || "",
      scannedAt: result.scannedAt || Date.now()
    }
  });
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "scan_page" && sender.tab && sender.tab.id) {
    runScanOnTab(sender.tab.id).then(() => sendResponse({ ok: true })).catch(() => {
      sendResponse({ ok: false });
    });
    return true;
  }

  if (request.action === "scan_tab" && request.tabId) {
    runScanOnTab(request.tabId).then(() => sendResponse({ ok: true })).catch(() => {
      sendResponse({ ok: false });
    });
    return true;
  }
});

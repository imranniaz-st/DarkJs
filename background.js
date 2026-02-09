const STORAGE_PREFIX = "tab:";
const MAX_FINDINGS = 5000;
const DEFAULT_SETTINGS = {
  enableDom: true,
  enableStorage: true,
  enableSourceMaps: true,
  enableNetwork: true,
  enableRuntime: true,
  allowlist: [],
  denylist: []
};

const KEY_PATTERNS = [
  /\b(api[_-]?key|apikey|secret|token|auth[_-]?token|access[_-]?token)\b\s*[:=]\s*["']?[A-Za-z0-9_\-\.]{8,}["']?/gi,
  /AWS[_-]?ACCESS[_-]?KEY[_-]?ID\s*[:=]\s*["']?AKIA[0-9A-Z]{16}["']?/g,
  /AWS[_-]?SECRET[_-]?ACCESS[_-]?KEY\s*[:=]\s*["']?[A-Za-z0-9\/+]{40}["']?/g,
  /firebaseConfig\s*=\s*{[^}]+}/gi,
  /AIza[0-9A-Za-z\-_]{35}/g,
  /sk_live_[0-9a-zA-Z]{24}/g,
  /pk_live_[0-9a-zA-Z]{24}/g,
  /key-[0-9a-zA-Z]{32}/g,
  /SG\.[0-9A-Za-z\-_]{22,}\.[0-9A-Za-z\-_]{22,}/g,
  /xox[baprs]-[0-9A-Za-z-]{10,48}/g,
  /ghp_[0-9A-Za-z]{36}/g,
  /ya29\.[0-9A-Za-z\-_]+/g,
  /EAACEdEose0cBA[0-9A-Za-z]+/g,
  /EAA[A-Za-z0-9]{32,}/g,
  /AC[a-zA-Z0-9]{32}/g,
  /SK[a-zA-Z0-9]{32}/g,
  /eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+/g,
  /-----BEGIN (RSA|DSA|EC|PGP|OPENSSH) PRIVATE KEY-----[\s\S]+?-----END \1 PRIVATE KEY-----/g,
  /[a-zA-Z0-9._%+-]+:[a-zA-Z0-9!@#$%^&*()_+=\-{}[\]|\\;:'",.<>?]{3,}@/g,
  /mongodb(\+srv)?:\/\/[^"'\s]+/g,
  /DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+;EndpointSuffix=core\.windows\.net/g,
  /ASIA[0-9A-Z]{16}/g,
  /AKIA[0-9A-Z]{16}/g,
  /-----BEGIN PRIVATE KEY-----[\s\S]+?-----END PRIVATE KEY-----/g,
  /heroku[a-z0-9]{32}/g,
  /\b(?:[A-Za-z0-9+\/]{40,}={0,2})\b/g
];

const EXTRA_PATTERNS = [
  ["Email", /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi],
  ["UUID", /\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/gi],
  ["Phone", /(?:\+?\d[\d\s().-]{7,}\d)/g],
  ["Hostname", /\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/gi]
];

const LARAVEL_PATTERNS = [
  /\bAPP_KEY=base64:[A-Za-z0-9+/=]{40,}\b/g,
  /\bAPP_KEY=[A-Za-z0-9+/=]{20,}\b/g,
  /\bAPP_ENV=(local|staging|production|testing)\b/gi,
  /\bAPP_URL=https?:\/\/[^\s"']+/gi,
  /\bDB_(HOST|DATABASE|USERNAME|PASSWORD)=[^\s"']+/gi,
  /\bREDIS_(HOST|PASSWORD|PORT)=[^\s"']+/gi,
  /\bMAIL_(HOST|PORT|USERNAME|PASSWORD|ENCRYPTION)=[^\s"']+/gi,
  /\bQUEUE_CONNECTION=[^\s"']+/gi,
  /\bSESSION_(DRIVER|LIFETIME|DOMAIN)=[^\s"']+/gi,
  /\bSANCTUM_STATEFUL_DOMAINS=[^\s"']+/gi,
  /\bJWT_SECRET=[^\s"']+/gi
];

const API_ENDPOINT_REGEX = /(\/api\/|\/v\d+\/|graphql)/i;
const MAX_SCRIPT_BYTES = 1500000;
const MAX_EXTRA_FETCH = 25;
const MAX_DEPTH = 2;

let settingsCache = null;

async function getSettings() {
  if (settingsCache) return settingsCache;
  const data = await chrome.storage.local.get("settings");
  settingsCache = { ...DEFAULT_SETTINGS, ...(data.settings || {}) };
  return settingsCache;
}

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.settings) {
    settingsCache = { ...DEFAULT_SETTINGS, ...(changes.settings.newValue || {}) };
  }
});

function normalizePatterns(patterns) {
  return (patterns || []).map(pattern => {
    const escaped = String(pattern)
      .trim()
      .replace(/[.+?^${}()|[\]\\]/g, "\\$&")
      .replace(/\*/g, ".*");
    return new RegExp(escaped, "i");
  });
}

function resolveValue(value, pageUrl) {
  if (!value) return "";
  if (value.startsWith("http://") || value.startsWith("https://")) return value;
  try {
    return new URL(value, pageUrl || "").href;
  } catch {
    return value;
  }
}

function isAllowed(value, pageUrl, settings) {
  const target = resolveValue(String(value), pageUrl).toLowerCase();
  const allowlist = normalizePatterns(settings.allowlist);
  const denylist = normalizePatterns(settings.denylist);

  if (allowlist.length && !allowlist.some(regex => regex.test(target))) {
    return false;
  }

  if (denylist.some(regex => regex.test(target))) {
    return false;
  }

  return true;
}

function isApiEndpoint(value) {
  return API_ENDPOINT_REGEX.test(String(value || ""));
}

function scanTextInWorker(text, source, findings) {
  const routes = text.match(/\/[a-zA-Z0-9_\-\/]{3,}/g) || [];
  routes.forEach(route => {
    findings.push(["Route", route, source]);
    if (isApiEndpoint(route)) {
      findings.push(["API Endpoint", route, source]);
    }
  });

  const urls = text.match(/https?:\/\/[^\s"'<>\\]+/g) || [];
  urls.forEach(url => {
    findings.push(["URL", url, source]);
    if (isApiEndpoint(url)) {
      findings.push(["API Endpoint", url, source]);
    }
  });

  KEY_PATTERNS.forEach(pattern => {
    const matches = text.match(pattern) || [];
    matches.forEach(match => findings.push(["API Key or Secret", match.trim(), source]));
  });

  EXTRA_PATTERNS.forEach(([label, pattern]) => {
    const matches = text.match(pattern) || [];
    matches.forEach(match => findings.push([label, match.trim(), source]));
  });

  LARAVEL_PATTERNS.forEach(pattern => {
    const matches = text.match(pattern) || [];
    matches.forEach(match => findings.push(["Laravel", match.trim(), source]));
  });
}

function collectImportsFromText(text) {
  const imports = [];
  const importRegex = /(?:import\s+[^'"]*?from\s+|import\s*\(|require\s*\()\s*['"]([^'"]+)['"]/g;
  let match;
  while ((match = importRegex.exec(text)) !== null) {
    imports.push(match[1]);
  }
  return imports;
}

async function scanExternalScripts(urls) {
  const findings = [];
  const queue = urls.filter(Boolean).map(url => ({ url, depth: 0, source: url }));
  const seen = new Set();

  while (queue.length && seen.size < MAX_EXTRA_FETCH) {
    const { url, depth, source } = queue.shift();
    if (!url || seen.has(url)) continue;
    seen.add(url);
    try {
      const res = await fetch(url);
      const text = await res.text();
      if (text.length > MAX_SCRIPT_BYTES) continue;
      scanTextInWorker(text, `script:${source}`, findings);

      if (depth < MAX_DEPTH) {
        const imports = collectImportsFromText(text);
        imports.forEach(entry => {
          if (!entry || entry.startsWith("data:")) return;
          let resolved = entry;
          if (!entry.startsWith("http://") && !entry.startsWith("https://")) {
            try {
              resolved = new URL(entry, url).href;
            } catch {
              return;
            }
          }
          queue.push({ url: resolved, depth: depth + 1, source: resolved });
        });
      }
    } catch {
      // Ignore fetch failures
    }
  }

  return findings;
}

function filterFindings(findings, pageUrl, settings) {
  return (findings || []).filter(([type, value]) => {
    if (type === "API Key or Secret" || type === "Storage Item" || type === "Laravel") {
      return true;
    }
    return isAllowed(value, pageUrl, settings);
  });
}

async function appendFindings(tabId, newFindings) {
  const key = `${STORAGE_PREFIX}${tabId}`;
  const data = await chrome.storage.session.get(key);
  const record = data[key] || {
    tabId,
    findings: [],
    pageUrl: "",
    pageTitle: "",
    scannedAt: Date.now()
  };

  record.findings = record.findings.concat(newFindings);
  if (record.findings.length > MAX_FINDINGS) {
    record.findings = record.findings.slice(-MAX_FINDINGS);
  }

  await chrome.storage.session.set({ [key]: record });
}

async function runScanOnTab(tabId) {
  const settings = await getSettings();
  const [{ result }] = await chrome.scripting.executeScript({
    target: { tabId },
    func: async function (options) {
      const findings = [];
      const scripts = [...document.scripts];
      const externalScripts = new Set();
      const processedMaps = new Set();
      const processedScripts = new Set();
      const MAX_SCRIPT_BYTES = 1500000;
      const MAX_EXTRA_FETCH = 25;
      const MAX_DEPTH = 2;

      const addFinding = (type, value, source) => {
        if (!value) return;
        findings.push([type, value, source]);
      };

      const truncate = (value, max = 300) => {
        if (typeof value !== "string") return String(value);
        return value.length > max ? `${value.slice(0, max)}...` : value;
      };

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
        /xox[baprs]-[0-9A-Za-z-]{10,48}/g,
        /ghp_[0-9A-Za-z]{36}/g,
        /AIza[0-9A-Za-z\-_]{35}/g,
        /ya29\.[0-9A-Za-z\-_]+/g,
        /EAACEdEose0cBA[0-9A-Za-z]+/g,
        /EAA[A-Za-z0-9]{32,}/g,
        /AC[a-zA-Z0-9]{32}/g,
        /SK[a-zA-Z0-9]{32}/g,
        /eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+/g,
        /-----BEGIN (RSA|DSA|EC|PGP|OPENSSH) PRIVATE KEY-----[\s\S]+?-----END \1 PRIVATE KEY-----/g,
        /[a-zA-Z0-9._%+-]+:[a-zA-Z0-9!@#$%^&*()_+=\-{}[\]|\\;:'",.<>?]{3,}@/g,
        /mongodb(\+srv)?:\/\/[^"'\s]+/g,
        /DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+;EndpointSuffix=core\.windows\.net/g,
        /ASIA[0-9A-Z]{16}/g,
        /AKIA[0-9A-Z]{16}/g,
        /AIza[0-9A-Za-z\-_]{35}/g,
        /-----BEGIN PRIVATE KEY-----[\s\S]+?-----END PRIVATE KEY-----/g,
        /heroku[a-z0-9]{32}/g,
        /\b(?:[A-Za-z0-9+\/]{40,}={0,2})\b/g
      ];

      const extraPatterns = [
        ["Email", /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi],
        ["UUID", /\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/gi],
        ["Phone", /(?:\+?\d[\d\s().-]{7,}\d)/g],
        ["Hostname", /\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/gi]
      ];

      const laravelPatterns = [
        /\bAPP_KEY=base64:[A-Za-z0-9+/=]{40,}\b/g,
        /\bAPP_KEY=[A-Za-z0-9+/=]{20,}\b/g,
        /\bAPP_ENV=(local|staging|production|testing)\b/gi,
        /\bAPP_URL=https?:\/\/[^\s"']+/gi,
        /\bDB_(HOST|DATABASE|USERNAME|PASSWORD)=[^\s"']+/gi,
        /\bREDIS_(HOST|PASSWORD|PORT)=[^\s"']+/gi,
        /\bMAIL_(HOST|PORT|USERNAME|PASSWORD|ENCRYPTION)=[^\s"']+/gi,
        /\bQUEUE_CONNECTION=[^\s"']+/gi,
        /\bSESSION_(DRIVER|LIFETIME|DOMAIN)=[^\s"']+/gi,
        /\bSANCTUM_STATEFUL_DOMAINS=[^\s"']+/gi,
        /\bJWT_SECRET=[^\s"']+/gi
      ];

      const scanSecrets = (text, source) => {
        keyPatterns.forEach(pattern => {
          const matches = text.match(pattern) || [];
          matches.forEach(match => {
            addFinding("API Key or Secret", match.trim(), source);
          });
        });
      };

      const scanExtras = (text, source) => {
        extraPatterns.forEach(([label, pattern]) => {
          const matches = text.match(pattern) || [];
          matches.forEach(match => addFinding(label, match.trim(), source));
        });
      };

      const scanLaravel = (text, source) => {
        laravelPatterns.forEach(pattern => {
          const matches = text.match(pattern) || [];
          matches.forEach(match => addFinding("Laravel", match.trim(), source));
        });
      };

      const collectImports = code => {
        const imports = [];
        const importRegex = /(?:import\s+[^'"]*?from\s+|import\s*\(|require\s*\()\s*['"]([^'"]+)['"]/g;
        let match;
        while ((match = importRegex.exec(code)) !== null) {
          imports.push(match[1]);
        }
        return imports;
      };

      const apiEndpointRegex = /(\/api\/|\/v\d+\/|graphql)/i;

      const maybeAddApiEndpoint = (value, source) => {
        if (apiEndpointRegex.test(String(value || ""))) {
          addFinding("API Endpoint", value, source);
        }
      };

      const scanText = (text, source) => {
        const routes = text.match(/\/[a-zA-Z0-9_\-\/]{3,}/g) || [];
        routes.forEach(r => {
          addFinding("Route", r, source);
          maybeAddApiEndpoint(r, source);
        });

        const urls = text.match(/https?:\/\/[^\s"'<>\\]+/g) || [];
        urls.forEach(u => {
          addFinding("URL", u, source);
          maybeAddApiEndpoint(u, source);
        });

        scanSecrets(text, source);
        scanExtras(text, source);
        scanLaravel(text, source);

        const graphqlHits = text.match(/graphql[^\s"'<>]*/gi) || [];
        graphqlHits.forEach(hit => addFinding("GraphQL", hit, source));
      };

      const fetchAndScan = async (targetUrl, source, depth) => {
        if (!targetUrl || processedScripts.has(targetUrl)) return;
        if (processedScripts.size >= MAX_EXTRA_FETCH) return;
        processedScripts.add(targetUrl);
        try {
          const res = await fetch(targetUrl);
          const text = await res.text();
          if (text.length > MAX_SCRIPT_BYTES) return;
          await scanScript(text, source, targetUrl, depth + 1);
        } catch (e) {
          console.warn(`Could not fetch deep script: ${targetUrl}`, e);
        }
      };

      const scanScript = async (code, source, baseUrl, depth) => {
        scanText(code, source);

        if (options.enableSourceMaps && !source.startsWith("sourcemap:")) {
          const mapMatch = code.match(/sourceMappingURL=([^\s]+)/);
          if (mapMatch && mapMatch[1]) {
            const mapUrl = new URL(mapMatch[1], baseUrl || location.href).href;
            if (!processedMaps.has(mapUrl)) {
              processedMaps.add(mapUrl);
              try {
                const mapRes = await fetch(mapUrl);
                const mapText = await mapRes.text();
                if (mapText.length < 2000000) {
                  const mapData = JSON.parse(mapText);
                  const sourcesContent = mapData.sourcesContent || [];
                  sourcesContent.forEach(content => {
                    scanText(content, `sourcemap:${mapUrl}`);
                  });
                }
              } catch (e) {
                console.warn(`Could not load sourcemap: ${mapUrl}`, e);
              }
            }
          }
        }

        if (depth >= MAX_DEPTH) return;
        const imports = collectImports(code);
        for (const entry of imports) {
          if (!entry || entry.startsWith("data:")) continue;
          let resolved = entry;
          if (!entry.startsWith("http://") && !entry.startsWith("https://")) {
            try {
              resolved = new URL(entry, baseUrl || location.href).href;
            } catch {
              continue;
            }
          }
          await fetchAndScan(resolved, `import:${resolved}`, depth);
        }
      };

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
          await scanScript(code, source, script.src || location.href, 0);
        } catch (e) {
          if (script.src) {
            externalScripts.add(script.src);
          }
          console.warn(`Could not fetch or parse script: ${source}`, e);
        }
      }

      if (options.enableDom) {
        const domTargets = [
          ["a", "href"],
          ["link", "href"],
          ["form", "action"],
          ["iframe", "src"],
          ["img", "src"],
          ["script", "src"]
        ];
        domTargets.forEach(([selector, attr]) => {
          document.querySelectorAll(selector).forEach(node => {
            const value = node.getAttribute(attr);
            if (!value || value.startsWith("javascript:")) return;
            if (value.startsWith("http://") || value.startsWith("https://")) {
              addFinding("URL", value, `dom:${selector}`);
            } else {
              addFinding("Route", value, `dom:${selector}`);
            }
          });
        });

        const htmlText = document.documentElement?.innerHTML || "";
        const domUrls = htmlText.match(/https?:\/\/[^\s"'<>\\]+/g) || [];
        domUrls.forEach(url => addFinding("URL", url, "dom:html"));
        scanExtras(htmlText, "dom:html");
      }

      if (options.enableStorage) {
        const scanStorage = (storage, label, limit = 200) => {
          if (!storage) return;
          const length = Math.min(storage.length, limit);
          for (let i = 0; i < length; i += 1) {
            const key = storage.key(i);
            const value = storage.getItem(key);
            addFinding("Storage Item", `${key}=${truncate(value)}`, `${label}:${key}`);
            scanSecrets(String(value || ""), `${label}:${key}`);
          }
        };

        scanStorage(window.localStorage, "localStorage");
        scanStorage(window.sessionStorage, "sessionStorage");

        const cookies = document.cookie.split(";").map(cookie => cookie.trim()).filter(Boolean);
        cookies.forEach(cookie => {
          addFinding("Storage Item", `cookie:${truncate(cookie)}`, "cookie");
          scanSecrets(cookie, "cookie");
        });
      }

      return {
        findings,
        pageUrl: location.href,
        pageTitle: document.title,
        scannedAt: Date.now(),
        externalScripts: Array.from(externalScripts)
      };
    },
    args: [
      {
        enableDom: settings.enableDom,
        enableStorage: settings.enableStorage,
        enableSourceMaps: settings.enableSourceMaps
      }
    ]
  });

  const key = `${STORAGE_PREFIX}${tabId}`;
  const data = await chrome.storage.session.get(key);
  const existing = data[key];
  const preserved = (existing?.findings || []).filter(([, , source]) => {
    return typeof source === "string" && (source.startsWith("runtime:") || source.startsWith("network:"));
  });

  const filteredFindings = filterFindings(result.findings || [], result.pageUrl, settings);

  if (result.externalScripts && result.externalScripts.length) {
    const extraFindings = await scanExternalScripts(result.externalScripts);
    const filteredExtra = filterFindings(extraFindings, result.pageUrl, settings);
    filteredFindings.push(...filteredExtra);
  }

  await chrome.storage.session.set({
    [key]: {
      tabId,
      findings: preserved.concat(filteredFindings),
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

  if (request.action === "runtime_event" && sender.tab && sender.tab.id) {
    getSettings().then(settings => {
      if (!settings.enableRuntime) return;
      const value = request.url || "";
      if (!isAllowed(value, request.pageUrl || "", settings)) return;
      const source = `runtime:${request.method || ""}:${request.status || ""}`;
      const items = [["URL", value, source]];
      if (isApiEndpoint(value)) {
        items.push(["API Endpoint", value, source]);
      }
      appendFindings(sender.tab.id, items);
    });
  }

  if (request.action === "init_runtime" && sender.tab && sender.tab.id) {
    getSettings().then(settings => {
      if (!settings.enableRuntime) return;
      chrome.scripting.executeScript({
        target: { tabId: sender.tab.id },
        files: ["runtime-hook.js"],
        world: "MAIN"
      }).catch(() => {});
    });
  }
});

chrome.webRequest.onCompleted.addListener(
  details => {
    if (details.tabId < 0) return;
    getSettings().then(settings => {
      if (!settings.enableNetwork) return;
      if (!isAllowed(details.url, "", settings)) return;
      const source = `network:${details.statusCode}`;
      const items = [["URL", details.url, source]];
      if (isApiEndpoint(details.url)) {
        items.push(["API Endpoint", details.url, source]);
      }
      appendFindings(details.tabId, items);
    });
  },
  { urls: ["<all_urls>"] }
);

chrome.webRequest.onErrorOccurred.addListener(
  details => {
    if (details.tabId < 0) return;
    getSettings().then(settings => {
      if (!settings.enableNetwork) return;
      if (!isAllowed(details.url, "", settings)) return;
      const source = "network:error";
      const items = [["URL", details.url, source]];
      if (isApiEndpoint(details.url)) {
        items.push(["API Endpoint", details.url, source]);
      }
      appendFindings(details.tabId, items);
    });
  },
  { urls: ["<all_urls>"] }
);

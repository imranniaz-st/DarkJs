chrome.runtime.onMessage.addListener((request, sender) => {
  if (request.action === 'scan_page') {
    chrome.scripting.executeScript({
      target: { tabId: sender.tab.id },
      func: async function () {
        const findings = [];

        // Get all script elements
        const scripts = [...document.scripts];

        for (const script of scripts) {
          let code = '';
          let source = script.src || 'inline-script';

          try {
            if (script.src) {
              const res = await fetch(script.src);
              code = await res.text();
            } else {
              code = script.textContent;
            }

            // Extract routes
            const routes = code.match(/\/[a-zA-Z0-9_\-\/]{3,}/g) || [];
            routes.forEach(r => findings.push(["Route", r, source]));

            // Extract full URLs
            const urls = code.match(/https?:\/\/[^\s"'<>\\]+/g) || [];
            urls.forEach(u => findings.push(["URL", u, source]));

            // Extract API keys, secrets, tokens
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

        if (findings.length > 0) {
          let csv = "Type,Value,Source JS URL\n";
          findings.forEach(([type, value, src]) => {
            csv += `"${type}","${value}","${src}"\n`;
          });

          const blob = new Blob([csv], { type: "text/csv" });
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a");

          const hostname = location.hostname.replace(/\./g, "_");
          const random = Math.random().toString(36).substring(2, 6);
          a.download = `${hostname}_${random}.csv`;

          a.href = url;
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          URL.revokeObjectURL(url);

          console.log(`✅ Downloaded: ${a.download}`);
        } else {
          console.log("No findings found in JS files.");
        }
      }
    });
  }
});

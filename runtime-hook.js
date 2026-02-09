(() => {
  if (window.__darkjsHookInstalled) return;
  window.__darkjsHookInstalled = true;

  const post = payload => {
    window.postMessage({ source: "darkjs-hook", ...payload }, "*");
  };

  const originalFetch = window.fetch;
  if (originalFetch) {
    window.fetch = function (...args) {
      const input = args[0];
      const init = args[1] || {};
      const method = (init.method || "GET").toUpperCase();
      const url = typeof input === "string" ? input : input?.url || "";
      return originalFetch.apply(this, args).then(response => {
        try {
          post({ kind: "fetch", url, method, status: response.status });
        } catch {
          // Ignore post errors
        }
        return response;
      });
    };
  }

  const OriginalXHR = window.XMLHttpRequest;
  if (OriginalXHR) {
    const open = OriginalXHR.prototype.open;
    const send = OriginalXHR.prototype.send;

    OriginalXHR.prototype.open = function (method, url, ...rest) {
      this.__darkjsMethod = (method || "GET").toUpperCase();
      this.__darkjsUrl = url;
      return open.call(this, method, url, ...rest);
    };

    OriginalXHR.prototype.send = function (...args) {
      this.addEventListener("loadend", () => {
        try {
          post({
            kind: "xhr",
            url: this.__darkjsUrl || "",
            method: this.__darkjsMethod || "GET",
            status: this.status
          });
        } catch {
          // Ignore post errors
        }
      });
      return send.apply(this, args);
    };
  }
})();

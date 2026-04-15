/**
 * Surface API client.
 */
(function() {
"use strict";

var BASE = "api";

async function _fetch(url, opts) {
    opts = opts || {};
    opts.credentials = "same-origin";
    if (opts.body && typeof opts.body === "object" && !(opts.body instanceof FormData)) {
        opts.headers = opts.headers || {};
        opts.headers["Content-Type"] = "application/json";
        opts.body = JSON.stringify(opts.body);
    }
    var resp = await fetch(BASE + url, opts);
    if (resp.status === 401) {
        window.location.href = "/login.html?redirect=" + encodeURIComponent(window.location.pathname);
        throw new Error("Not authenticated");
    }
    if (resp.status === 204) return null;
    if (!resp.ok) throw new Error("API " + resp.status);
    return resp.json();
}

window.SurfaceAPI = {
    listFindings: function(filters) {
        var qs = "";
        if (filters) {
            var parts = [];
            for (var k in filters) if (filters[k]) parts.push(encodeURIComponent(k) + "=" + encodeURIComponent(filters[k]));
            if (parts.length) qs = "?" + parts.join("&");
        }
        return _fetch("/findings" + qs);
    },
    deleteFinding: function(id) { return _fetch("/findings/" + id, { method: "DELETE" }); },
    triageFinding: function(id, payload) {
        return _fetch("/findings/" + id + "/triage", { method: "PATCH", body: payload });
    },
    bulkTriageFindings: function(payload) {
        return _fetch("/findings/bulk-triage", { method: "POST", body: payload });
    },
    bulkDeleteFindings: function(ids) {
        return _fetch("/findings/bulk-delete", { method: "POST", body: { ids: ids } });
    },
    quickScan: function(targetHost) {
        return _fetch("/scans/quick", { method: "POST", body: { target_host: targetHost } });
    },
    bulkImport: function(findings) {
        return _fetch("/scans/bulk-import", { method: "POST", body: { findings: findings } });
    },
    listMonitored: function() { return _fetch("/monitored-assets"); },
    scannersCatalog: function() { return _fetch("/monitored-assets/scanners-catalog"); },
    createMonitored: function(data) { return _fetch("/monitored-assets", { method: "POST", body: data }); },
    updateMonitored: function(id, data) { return _fetch("/monitored-assets/" + id, { method: "PATCH", body: data }); },
    deleteMonitored: function(id) { return _fetch("/monitored-assets/" + id, { method: "DELETE" }); },
    scanMonitored: function(id) { return _fetch("/monitored-assets/" + id + "/scan", { method: "POST" }); },
    scanAllMonitored: function() { return _fetch("/monitored-assets/scan-all", { method: "POST" }); },
    nucleiConfig: function() { return _fetch("/scans/nuclei/config"); },
    nucleiUpdateConfig: function(data) { return _fetch("/scans/nuclei/config", { method: "PUT", body: data }); },
    nucleiUpdateTemplates: function() { return _fetch("/scans/nuclei/update-templates", { method: "POST" }); },
    shodanConfig: function() { return _fetch("/scans/shodan/config"); },
    shodanSaveKey: function(apiKey) { return _fetch("/scans/shodan/config", { method: "PUT", body: { api_key: apiKey } }); },
    shodanDeleteKey: function() { return _fetch("/scans/shodan/config", { method: "DELETE" }); },
    listJobs: function() { return _fetch("/scans/jobs"); },
    createJob: function(data) { return _fetch("/scans/jobs", { method: "POST", body: data }); },
    deleteJob: function(id) { return _fetch("/scans/jobs/" + id, { method: "DELETE" }); },
    listMeasures: function() { return _fetch("/measures"); },
    updateMeasure: function(id, data) { return _fetch("/measures/" + id, { method: "PATCH", body: data }); },
    // v0.3 — executive report + github + smtp config
    executiveReport: function() { return _fetch("/reports/executive"); },
    smtpConfig: function() { return _fetch("/reports/smtp/config"); },
    smtpSetConfig: function(data) { return _fetch("/reports/smtp/config", { method: "PUT", body: data }); },
    sendEmailDigest: function() { return _fetch("/reports/email-digest/send", { method: "POST" }); },
    githubConfig: function() { return _fetch("/scans/github/config"); },
    githubSetConfig: function(data) { return _fetch("/scans/github/config", { method: "PUT", body: data }); },
    githubDeleteConfig: function() { return _fetch("/scans/github/config", { method: "DELETE" }); }
};

// ── Init: check auth ──
window._appInitCallback = function() {
    if (typeof _initDataAndRender === "function") _initDataAndRender();
    else if (typeof renderAll === "function") renderAll();
};

})();

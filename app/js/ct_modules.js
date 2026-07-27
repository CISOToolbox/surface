// ─────────────────────────────────────────────────────────────
// GENERATED from shared/ts/ — do NOT edit here.
// Edit the shared TypeScript source and run shared/ts-build.sh.
// ─────────────────────────────────────────────────────────────
var CT_EDITION = ((window.CT_CONFIG || {}).edition) || "opensource";
// Reference catalogue — the nine modules + no scan (scan is a job kind, not a
// module). Marks keep their own colour (SPEC §5); paths are relative to app/.
var _CT_MODULE_CATALOG = [
    { id: "risk", name: "Risk", url: "/risk/", mark: "img/modules/risk.svg" },
    { id: "compliance", name: "Compliance", url: "/compliance/", mark: "img/modules/compliance.svg" },
    { id: "audit", name: "Audit", url: "/audit/", mark: "img/modules/audit.svg" },
    { id: "vendor", name: "Vendor", url: "/vendor/", mark: "img/modules/vendor.svg" },
    { id: "asset", name: "Asset", url: "/asset/", mark: "img/modules/asset.svg" },
    { id: "access", name: "Access", url: "/access/", mark: "img/modules/access.svg" },
    { id: "surface", name: "Surface", url: "/surface/", mark: "img/modules/surface.svg" },
    { id: "appsec", name: "AppSec", url: "/appsec/", mark: "img/modules/appsec.svg" },
    { id: "pilot", name: "Pilot", url: "/", mark: "img/modules/pilot.svg" },
];
function _ctCurrentModuleId() {
    return ((window.CT_CONFIG || {}).module) || "";
}
function ct_currentModule() {
    var id = _ctCurrentModuleId();
    for (var i = 0; i < _CT_MODULE_CATALOG.length; i++) {
        if (_CT_MODULE_CATALOG[i].id === id)
            return _CT_MODULE_CATALOG[i];
    }
    // Unknown / not in catalogue: synthesize a minimal entry so the appbar
    // still shows a name (standalone/opensource never browse a list anyway).
    return id ? { id: id, name: id.charAt(0).toUpperCase() + id.slice(1), url: "", mark: "img/modules/" + id + ".svg" } : null;
}
function ct_modules() {
    if (CT_EDITION === "opensource")
        return [];
    if (CT_EDITION === "standalone") {
        var c = ct_currentModule();
        return c ? [c] : [];
    }
    // suite — Pilot injects the full deployed list (with alert counts) via
    // CT_CONFIG.modules; when absent, filter the catalogue to the deployed ids
    // (CT_CONFIG.deployed). Falls back to the whole catalogue only if neither
    // is provided (dev convenience).
    var cfg = (window.CT_CONFIG || {});
    if (cfg.modules && cfg.modules.length)
        return cfg.modules;
    if (cfg.deployed && cfg.deployed.length) {
        var set = cfg.deployed;
        return _CT_MODULE_CATALOG.filter(function (m) { return set.indexOf(m.id) >= 0; });
    }
    return _CT_MODULE_CATALOG;
}
// CT_EDITION is frozen at script-load; but window.CT_CONFIG is set later by the
// app bundle. Re-sync it once the app config is available (called from boot).
function _ctSyncEdition() {
    CT_EDITION = ((window.CT_CONFIG || {}).edition) || "opensource";
    window.CT_EDITION = CT_EDITION;
}
window._ctSyncEdition = _ctSyncEdition;
window.CT_EDITION = CT_EDITION;
window.ct_modules = ct_modules;
window.ct_currentModule = ct_currentModule;

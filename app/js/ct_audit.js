// ─────────────────────────────────────────────────────────────
// GENERATED from shared/ts/ — do NOT edit here.
// Edit the shared TypeScript source and run shared/ts-build.sh.
// ─────────────────────────────────────────────────────────────
/**
 * CISO Toolbox — Audit Log Panel (shared)
 *
 * Provides _renderAuditLog(container) for all backend modules.
 * Each module calls this from its panel switch/render logic.
 * Requires: cisotoolbox.js (esc, _icon, t), i18n.js (_registerTranslations).
 */
var _auditFilter = { q: "" };
function _renderAuditLog(c) {
    var h = '<div style="display:flex;align-items:center;gap:8px;margin-bottom:12px;flex-wrap:wrap">';
    h += '<h2 style="margin:0">' + t("audit.title") + '</h2><span style="flex:1"></span>';
    h += '<input type="search" class="ct-input" placeholder="' + t("audit.search") + '" value="' + esc(_auditFilter.q || "") + '" data-input="_setAuditSearch" data-pass-value style="min-width:200px;max-width:300px">';
    h += '</div>';
    h += '<div id="audit-body"><p style="color:var(--text-muted)">' + t("audit.loading") + '</p></div>';
    c.innerHTML = h;
    _refreshAuditBody();
}
async function _refreshAuditBody() {
    var el = document.getElementById("audit-body");
    if (!el)
        return;
    try {
        var qs = _auditFilter.q ? "?q=" + encodeURIComponent(_auditFilter.q) : "";
        var resp = await fetch("api/audit-log" + qs, { credentials: "same-origin" });
        if (!resp.ok)
            throw new Error("HTTP " + resp.status);
        var data = await resp.json();
        var items = data.items || [];
        var h = '';
        if (items.length === 0) {
            h = '<p style="color:var(--text-muted)">' + t("audit.empty") + '</p>';
        }
        else {
            h = '<table class="ct-table" style="font-size:0.85em"><thead><tr>';
            h += '<th>' + t("audit.col_date") + '</th>';
            h += '<th>' + t("audit.col_user") + '</th>';
            h += '<th>' + t("audit.col_action") + '</th>';
            h += '<th>' + t("audit.col_target") + '</th>';
            h += '<th>' + t("audit.col_details") + '</th>';
            h += '<th>IP</th></tr></thead><tbody>';
            for (var i = 0; i < items.length; i++) {
                var e = items[i];
                var d = new Date(e.logged_at);
                var dateStr = isNaN(d.getTime()) ? e.logged_at : d.toLocaleString();
                var actionLabel = t("audit.action." + e.action);
                if (actionLabel === "audit.action." + e.action)
                    actionLabel = e.action;
                h += '<tr>';
                h += '<td style="white-space:nowrap;color:var(--text-muted)">' + esc(dateStr) + '</td>';
                h += '<td>' + esc(e.user_email || "") + '</td>';
                h += '<td><code style="font-size:0.85em">' + esc(actionLabel) + '</code></td>';
                h += '<td style="max-width:250px;overflow:hidden;text-overflow:ellipsis">' + esc(e.target || "") + '</td>';
                h += '<td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;color:var(--text-muted)" title="' + esc(e.details || "") + '">' + esc(e.details || "") + '</td>';
                h += '<td style="color:var(--text-muted)">' + esc(e.ip_address || "") + '</td>';
                h += '</tr>';
            }
            h += '</tbody></table>';
            h += '<p style="font-size:0.78em;color:var(--text-muted)">' + data.total + ' ' + t("audit.entries") + '</p>';
        }
        el.innerHTML = h;
    }
    catch (e) {
        el.innerHTML = '<p style="color:var(--red)">' + esc(e.message || String(e)) + '</p>';
    }
}
window._setAuditSearch = function (v) { _auditFilter.q = v; _refreshAuditBody(); };
// i18n — shared across all modules
_registerTranslations("fr", {
    "nav.audit": "Journal d'audit",
    "audit.title": "Journal d'audit",
    "audit.search": "Rechercher...",
    "audit.loading": "Chargement...",
    "audit.empty": "Aucune entree dans le journal",
    "audit.entries": "entrees",
    "audit.col_date": "Date",
    "audit.col_user": "Utilisateur",
    "audit.col_action": "Action",
    "audit.col_target": "Cible",
    "audit.col_details": "Details",
});
_registerTranslations("en", {
    "nav.audit": "Audit Log",
    "audit.title": "Audit Log",
    "audit.search": "Search...",
    "audit.loading": "Loading...",
    "audit.empty": "No entries in the audit log",
    "audit.entries": "entries",
    "audit.col_date": "Date",
    "audit.col_user": "User",
    "audit.col_action": "Action",
    "audit.col_target": "Target",
    "audit.col_details": "Details",
});

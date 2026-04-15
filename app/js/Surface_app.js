/**
 * CISO Toolbox — Surface App
 */

// AI_APP_CONFIG must be set BEFORE ai_common.js runs (ai_common.js reads it
// at IIFE init time). Surface_app.js is loaded before ai_common.js in
// index.html, so this global assignment runs first.
window.AI_APP_CONFIG = {
    storagePrefix: "surface",
    hideDemo: true,
    settingsExtraHTML: function() {
        // Nuclei + Shodan sections rendered inside the shared side panel.
        // Called at user-click time (t() is available).
        var tt = typeof t === "function" ? t : function(k) { return k; };
        var nucleiTitle = tt("nuclei.section") || "Nuclei (DAST scanner)";
        var shodanTitle = tt("shodan.section") || "Shodan API";
        var loading = tt("common.loading") || "Loading...";
        return (
            '<div class="settings-section" style="margin-top:20px;border-top:1px solid var(--border);padding-top:16px">' +
                '<div class="settings-label">' + nucleiTitle + '</div>' +
                '<div id="surface-nuclei-section" style="font-size:0.85em">' +
                    '<div style="color:var(--text-muted)">' + loading + '</div>' +
                '</div>' +
            '</div>' +
            '<div class="settings-section" style="margin-top:20px;border-top:1px solid var(--border);padding-top:16px">' +
                '<div class="settings-label">' + shodanTitle + '</div>' +
                '<div id="surface-shodan-section" style="font-size:0.85em">' +
                    '<div style="color:var(--text-muted)">' + loading + '</div>' +
                '</div>' +
            '</div>'
        );
    },
    onSettingsSaved: function() {
        // Nuclei & Shodan have their own save buttons; nothing on the shared path.
    }
};

// _ASSET_BASE is defined in Surface_config.js, loaded before i18n.js.

(function() {
"use strict";

// ═══════════════════════════════════════════════════════════════
// SVG icon set (Feather-style stroke icons, 24×24 viewBox)
// ═══════════════════════════════════════════════════════════════
// Each entry is the inner <path>/<polyline>/... markup for the icon.
// _icon(name, size) wraps it in a <svg> with `currentColor` stroke so
// the icon inherits the parent's text color (no hardcoded colors).

var _ICON_PATHS = {
    // Actions
    check:    '<polyline points="20 6 9 17 4 12"/>',
    x:        '<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>',
    plus:     '<line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>',
    edit:     '<path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>',
    trash:    '<polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/>',
    refresh:  '<polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>',
    // Navigation
    arrow_left:  '<line x1="19" y1="12" x2="5" y2="12"/><polyline points="12 19 5 12 12 5"/>',
    arrow_right: '<line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/>',
    menu:     '<line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="18" x2="21" y2="18"/>',
    // Concepts
    search:   '<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>',
    clock:    '<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>',
    pin:      '<path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="3"/>',
    target:   '<circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/>',
    shield:   '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
    server:   '<rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/>',
    alert:    '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
    list:     '<line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/>',
    // Panels
    grid:     '<rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/>',
    globe:    '<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>',
    check_circle: '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>',
    // Findings
    zap:      '<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>',
    activity: '<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>',
};

function _icon(name, size, extraClass) {
    var path = _ICON_PATHS[name];
    if (!path) return "";
    var sz = size || 16;
    var cls = extraClass ? ' class="' + extraClass + '"' : '';
    return '<svg' + cls + ' width="' + sz + '" height="' + sz + '" viewBox="0 0 24 24"'
        + ' fill="none" stroke="currentColor" stroke-width="2"'
        + ' stroke-linecap="round" stroke-linejoin="round"'
        + ' style="vertical-align:middle;flex-shrink:0">'
        + path
        + '</svg>';
}

var _panel = "dashboard";
var _findings = [];
var _monitored = [];
var _jobs = [];
var _jobsPollTimer = null;
var _jobsFilterScanner = "";
var _jobsFilterStatus = "";
var _scannersCatalog = null;
var _measures = [];
var _filterStatus = "new";  // default: only show findings that need triage
var _filterSeverities = [];  // multi-select; empty = all
var _filterScanners = [];    // multi-select; empty = all
var _monitoredFilterScanners = []; // multi-select scanner filter on Surveillance page
var _selectedFinding = null;
var _selectedHost = null;    // MonitoredAsset object, set when user clicks a host card
var _hostHideFP = true;      // Host detail: hide false-positive findings by default
var _hostSearch = "";        // free-text filter for the Hosts panel
var _bulkSelection = {};     // { [finding_id]: true } — checked rows in findings table
var _monitoredSearch = "";   // free-text search for the Surveillance panel
var _findingsSearch = "";    // free-text search for the Findings panel

// tiny helper: t() with {n} substitution — fallback to the raw string if
// the i18n registry returns the key as-is (when the key isn't registered).
function _tn(key, n) {
    var s = typeof t === "function" ? t(key) : key;
    if (!s) s = key;
    return String(s).replace("{n}", n);
}

window.selectPanel = function(id) {
    _panel = id;
    _selectedFinding = null;
    _selectedHost = null;
    _bulkSelection = {};
    document.querySelectorAll(".sidebar-item").forEach(function(el) {
        var args = el.getAttribute("data-args");
        if (args) try { el.classList.toggle("active", JSON.parse(args)[0] === id); } catch(e) {}
    });
    document.querySelector(".sidebar").classList.remove("open");
    _loadAndRender();
};

function _loadAndRender() {
    var p1 = SurfaceAPI.listFindings().then(function(d) { _findings = d || []; }).catch(function() { _findings = []; });
    var p2 = SurfaceAPI.listMeasures().then(function(d) { _measures = d || []; }).catch(function() { _measures = []; });
    var p3 = SurfaceAPI.listMonitored().then(function(d) { _monitored = d || []; }).catch(function() { _monitored = []; });
    var p4 = SurfaceAPI.listJobs().then(function(d) { _jobs = d || []; }).catch(function() { _jobs = []; });
    var p5 = _scannersCatalog
        ? Promise.resolve()
        : SurfaceAPI.scannersCatalog().then(function(d) { _scannersCatalog = d || {}; }).catch(function() { _scannersCatalog = {}; });
    Promise.all([p1, p2, p3, p4, p5]).then(function() { renderPanel(); });
}

function renderPanel() {
    var c = document.getElementById("content");
    if (!c) return;
    if (_jobsPollTimer) { clearInterval(_jobsPollTimer); _jobsPollTimer = null; }
    switch (_panel) {
        case "dashboard": _renderDashboard(c); break;
        case "monitored": _renderMonitored(c); break;
        case "hosts": _renderHosts(c); break;
        case "jobs": _renderJobs(c); break;
        case "findings": _renderFindings(c); break;
        case "measures": _renderMeasures(c); break;
        default: _renderDashboard(c);
    }
    var tr = document.getElementById("toolbar-right");
    if (tr && typeof _getSettingsButtonHTML === "function") tr.innerHTML = _getSettingsButtonHTML();
}
window.renderPanel = renderPanel;
window.renderAll = renderPanel;
window._initDataAndRender = function() { _panel = "dashboard"; _loadAndRender(); };

// ═══════════════════════════════════════════════════════════════
// SCAN JOBS (real nmap scans, async background tasks)
// ═══════════════════════════════════════════════════════════════
function _scannerLabel(s) {
    if (!s) return "";
    var key = {
        "nmap":                 "scanner.nmap",
        "scheduled-host":       "scanner.scheduled_host",
        "scheduled-domain":     "scanner.scheduled_domain",
        "scheduled-discovery":  "scanner.scheduled_discovery",
    }[s];
    if (key) return t(key);
    // Fall back to the friendly label declared in SCANNER_REGISTRY
    // (returned via /api/monitored-assets/scanners-catalog) so the UI
    // never shows raw scanner IDs like "ct_logs" / "dns_brute".
    if (_scannersCatalog) {
        for (var kind in _scannersCatalog) {
            var entry = _scannersCatalog[kind];
            var list = entry && entry.scanners ? entry.scanners : [];
            for (var i = 0; i < list.length; i++) {
                if (list[i].name === s && list[i].label) return list[i].label;
            }
        }
    }
    return s;
}

function _renderJobs(c) {
    var h = '<div style="display:flex;align-items:center;gap:8px;margin-bottom:12px;flex-wrap:wrap">';
    h += '<h2 style="margin:0">' + esc(t("jobs.title")) + '</h2>';
    h += '<span style="flex:1"></span>';
    h += '<button class="btn-add btn-icon" style="background:#dc2626;color:white" data-click="_newJobDialog">' + _icon("plus", 14) + ' ' + esc(t("jobs.new")) + '</button>';
    h += '</div>';
    h += '<div style="font-size:0.85em;color:var(--text-muted);margin-bottom:12px">' + esc(t("jobs.help")) + '</div>';

    if (!_jobs.length) {
        h += '<div class="empty-state">' + esc(t("jobs.empty")) + '</div>';
        c.innerHTML = h;
        return;
    }

    // Build set of distinct scanner types from current data
    var scannerSet = {};
    _jobs.forEach(function(j) { if (j.scanner) scannerSet[j.scanner] = true; });
    var scannerTypes = Object.keys(scannerSet).sort();

    // Filters bar
    h += '<div class="surface-filters">';
    h += '<select class="surface-filter" data-change="_setJobsScannerFilter" data-pass-value>';
    h += '<option value=""' + (_jobsFilterScanner === "" ? " selected" : "") + '>' + esc(t("jobs.filter.all")) + ' (' + _jobs.length + ')</option>';
    scannerTypes.forEach(function(s) {
        var count = _jobs.filter(function(j) { return j.scanner === s; }).length;
        h += '<option value="' + esc(s) + '"' + (_jobsFilterScanner === s ? " selected" : "") + '>' + esc(_scannerLabel(s)) + ' (' + count + ')</option>';
    });
    h += '</select>';
    h += '<select class="surface-filter" data-change="_setJobsStatusFilter" data-pass-value>';
    h += '<option value=""' + (_jobsFilterStatus === "" ? " selected" : "") + '>' + esc(t("jobs.filter.all")) + '</option>';
    ["pending", "running", "completed", "failed"].forEach(function(s) {
        var count = _jobs.filter(function(j) { return j.status === s; }).length;
        if (!count) return;
        h += '<option value="' + s + '"' + (_jobsFilterStatus === s ? " selected" : "") + '>' + _jobStatusLabel(s) + ' (' + count + ')</option>';
    });
    h += '</select>';
    h += '</div>';

    var filtered = _jobs.filter(function(j) {
        if (_jobsFilterScanner && j.scanner !== _jobsFilterScanner) return false;
        if (_jobsFilterStatus && j.status !== _jobsFilterStatus) return false;
        return true;
    });

    if (!filtered.length) {
        h += '<div class="empty-state">' + esc(t("jobs.no_match")) + '</div>';
        c.innerHTML = h;
        return;
    }

    var hasRunning = filtered.some(function(j) { return j.status === "pending" || j.status === "running"; });

    h += '<div style="font-size:0.78em;color:var(--text-muted);margin-bottom:8px">' + filtered.length + ' / ' + _jobs.length + ' ' + esc(t("jobs.title").toLowerCase()) + '</div>';
    h += '<table class="surface-table"><thead><tr>'
      + '<th>' + esc(t("jobs.col.target")) + '</th>'
      + '<th>' + esc(t("jobs.col.scanner")) + '</th>'
      + '<th>' + esc(t("jobs.col.source")) + '</th>'
      + '<th>' + esc(t("jobs.col.status")) + '</th>'
      + '<th>' + esc(t("jobs.col.findings")) + '</th>'
      + '<th>' + esc(t("jobs.col.started")) + '</th>'
      + '<th>' + esc(t("jobs.col.duration")) + '</th>'
      + '<th></th></tr></thead><tbody>';
    filtered.forEach(function(j) {
        var dur = "";
        if (j.started_at) {
            var start = new Date(j.started_at);
            var end = j.completed_at ? new Date(j.completed_at) : new Date();
            var s = Math.round((end - start) / 1000);
            dur = s < 60 ? s + "s" : Math.floor(s / 60) + "m" + (s % 60) + "s";
        }
        var isScheduled = j.triggered_by === "scheduler" || j.profile === "scheduled";
        var sourceBadge = isScheduled
            ? '<span class="source-badge source-auto">' + _icon("clock", 12) + ' ' + esc(t("jobs.source.auto").toUpperCase()) + '</span>'
            : '<span class="source-badge source-manual">' + _icon("pin", 12) + ' ' + esc(t("jobs.source.manual").toUpperCase()) + '</span>';
        var scannerCls = "scanner-" + (j.scanner || "unknown").replace(/[^a-z0-9]/g, "-");
        h += '<tr>';
        h += '<td style="font-family:monospace;font-size:0.85em;font-weight:600">' + esc(j.target) + '</td>';
        h += '<td><span class="scanner-badge ' + scannerCls + '" title="' + esc(j.scanner || "") + '">' + esc(_scannerLabel(j.scanner)) + '</span>';
        if (j.profile && j.profile !== "scheduled") h += '<div style="font-size:0.7em;color:var(--text-muted);margin-top:2px">profil: ' + esc(j.profile) + '</div>';
        h += '</td>';
        h += '<td>' + sourceBadge + '</td>';
        h += '<td><span class="job-status job-' + esc(j.status) + '">' + _jobStatusLabel(j.status) + '</span>';
        if (j.error) h += '<div style="font-size:0.72em;color:#991b1b;margin-top:2px;max-width:240px;word-break:break-word">' + esc(j.error.substring(0, 120)) + '</div>';
        h += '</td>';
        h += '<td style="text-align:center;font-weight:600">' + j.findings_count;
        if (j.diff && (j.diff.added || j.diff.reopened)) {
            var diffParts = [];
            if (j.diff.added)    diffParts.push('<span class="job-diff-added">+' + j.diff.added + '</span>');
            if (j.diff.reopened) diffParts.push('<span class="job-diff-reopened">↻' + j.diff.reopened + '</span>');
            h += '<div class="job-diff">' + diffParts.join(" ") + '</div>';
        }
        h += '</td>';
        h += '<td style="font-size:0.78em;color:var(--text-muted)">' + esc((j.created_at || "").substring(0, 16).replace("T", " ")) + '<br><span style="font-size:0.9em">' + esc(j.triggered_by || "") + '</span></td>';
        h += '<td style="font-size:0.82em;color:var(--text-muted)">' + esc(dur) + '</td>';
        h += '<td style="white-space:nowrap">';
        // Rerun is offered on every completed/failed job. The handler picks
        // the right path: manual nmap → POST /scans/jobs, scheduled jobs →
        // POST /monitored-assets/{id}/scan based on target match.
        if (j.status !== "pending" && j.status !== "running") {
            h += '<button class="btn-mini" data-click="_rerunJob" data-args=\'' + _da(j.id) + '\' data-pass-el title="' + esc(t("jobs.rerun")) + '">' + _icon("refresh", 14) + '</button> ';
        }
        h += '<button class="btn-mini" data-click="_deleteJob" data-args=\'' + _da(j.id) + '\' title="' + esc(t("action.delete")) + '">' + _icon("trash", 14) + '</button>';
        h += '</td>';
        h += '</tr>';
    });
    h += '</tbody></table>';

    c.innerHTML = h;

    // Auto-refresh while at least one job is running
    if (hasRunning) {
        _jobsPollTimer = setInterval(function() {
            if (_panel !== "jobs") { clearInterval(_jobsPollTimer); _jobsPollTimer = null; return; }
            SurfaceAPI.listJobs().then(function(d) {
                if (_panel !== "jobs") return;
                _jobs = d || [];
                _renderJobs(document.getElementById("content"));
            });
        }, 3000);
    }
}

function _jobStatusLabel(s) {
    return t("jobs.status." + s) || s;
}

window._setJobsScannerFilter = function(v) { _jobsFilterScanner = v || ""; renderPanel(); };
window._setJobsStatusFilter = function(v) { _jobsFilterStatus = v || ""; renderPanel(); };

window._deleteJob = function(id) {
    if (!confirm(t("prompt.job_delete_confirm"))) return;
    SurfaceAPI.deleteJob(id).then(function() {
        showStatus(t("action.delete"));
        _loadAndRender();
    }).catch(function(e) { showStatus(e.message || t("common.error"), true); });
};

window._rerunJob = function(id, el) {
    var job = _jobs.find(function(j) { return j.id === id; });
    if (!job) return;
    // Disable the button to prevent double-clicks while the scan runs.
    var btn = el && el.tagName === "BUTTON" ? el : (el ? el.closest("button") : null);
    if (btn) { btn.disabled = true; btn.style.opacity = "0.5"; }

    // Immediate feedback — the scheduled-* endpoint is synchronous and can
    // take 30s+ to return, so the user needs to see something happen NOW.
    showStatus(t("jobs.rerun_in_progress").replace("{target}", job.target));

    var ok = function(r) {
        var n = (r && (r.findings_created != null ? r.findings_created : r.findings_count)) || 0;
        showStatus(
            t("jobs.rerun_done")
                .replace("{target}", job.target)
                .replace("{n}", n)
        );
        _loadAndRender();
    };
    var fail = function(e) {
        if (btn) { btn.disabled = false; btn.style.opacity = "1"; }
        showStatus(e.message || t("common.error"), true);
    };

    // Manual nmap jobs replay through the create-job endpoint (async,
    // returns immediately with a pending job).
    if (job.scanner === "nmap") {
        SurfaceAPI.createJob({ target: job.target, profile: job.profile || "quick" }).then(ok).catch(fail);
        return;
    }
    // Scheduled jobs (scheduled-host / scheduled-domain / scheduled-discovery)
    // are bound to a MonitoredAsset — find it by value and trigger its
    // /scan endpoint, which runs the scanner synchronously.
    var asset = (_monitored || []).find(function(a) { return a.value === job.target; });
    if (asset) {
        SurfaceAPI.scanMonitored(asset.id).then(ok).catch(fail);
        return;
    }
    // Fallback: try a quick port scan
    SurfaceAPI.quickScan(job.target).then(ok).catch(fail);
};

function _ensureJobModal() {
    var ov = document.getElementById("job-overlay");
    if (!ov) {
        ov = document.createElement("div");
        ov.id = "job-overlay";
        ov.className = "ct-modal-overlay";
        document.body.appendChild(ov);
        ov.addEventListener("click", function(e) { if (e.target === ov) _closeJobModal(); });
    }
    // Rebuild innerHTML on every call so the modal picks up the current locale
    // (user may have switched FR↔EN after the first render).
    ov.innerHTML =
        '<div class="ct-modal">' +
            '<div class="ct-modal-header"><span>' + esc(t("jobs.new_title")) + '</span><button class="ct-modal-close" data-click="_closeJobModal">' + _icon("x", 18) + '</button></div>' +
            '<div class="ct-modal-body">' +
                '<div class="ct-field"><label class="ct-field-lbl">' + esc(t("jobs.target")) + '</label>' +
                    '<input type="text" class="ct-input" id="job-target" placeholder="' + esc(t("jobs.target_placeholder")) + '">' +
                    '<div class="ct-field-help">' + esc(t("jobs.target_help")) + '</div>' +
                '</div>' +
                '<div class="ct-field"><label class="ct-field-lbl">' + esc(t("jobs.profile")) + '</label>' +
                    '<div class="ct-radio-group">' +
                        '<label class="ct-radio"><input type="radio" name="job-profile" value="quick" checked> <span>' + esc(t("jobs.profile.quick")) + '<br><small>' + esc(t("jobs.profile.quick_help")) + '</small></span></label>' +
                        '<label class="ct-radio"><input type="radio" name="job-profile" value="standard"> <span>' + esc(t("jobs.profile.standard")) + '<br><small>' + esc(t("jobs.profile.standard_help")) + '</small></span></label>' +
                        '<label class="ct-radio"><input type="radio" name="job-profile" value="deep"> <span>' + esc(t("jobs.profile.deep")) + '<br><small>' + esc(t("jobs.profile.deep_help")) + '</small></span></label>' +
                    '</div>' +
                '</div>' +
                '<div class="ct-field" id="job-monitored-shortcut" style="display:none">' +
                    '<label class="ct-field-lbl">' + esc(t("jobs.pick_monitored")) + '</label>' +
                    '<select class="ct-input" id="job-monitored-select" data-change="_pickMonitoredTarget" data-pass-value>' +
                        '<option value="">-</option>' +
                    '</select>' +
                '</div>' +
                '<div class="ct-error" id="job-error" style="display:none"></div>' +
            '</div>' +
            '<div class="ct-modal-footer">' +
                '<button class="btn-add" data-click="_closeJobModal">' + esc(t("action.cancel")) + '</button>' +
                '<button class="btn-add" style="background:#dc2626;color:white" data-click="_launchJob">' + esc(t("jobs.launch")) + '</button>' +
            '</div>' +
        '</div>';
    return ov;
}

window._newJobDialog = function() {
    var ov = _ensureJobModal();
    document.getElementById("job-target").value = "";
    document.querySelector('input[name="job-profile"][value="quick"]').checked = true;
    document.getElementById("job-error").style.display = "none";
    // Populate monitored shortcut
    var sel = document.getElementById("job-monitored-select");
    var shortcut = document.getElementById("job-monitored-shortcut");
    if (_monitored.length) {
        sel.innerHTML = '<option value="">-</option>' + _monitored.map(function(a) {
            return '<option value="' + esc(a.value) + '">[' + _kindLabel(a.kind) + '] ' + esc(a.value) + (a.label ? ' — ' + esc(a.label) : '') + '</option>';
        }).join("");
        shortcut.style.display = "";
    } else {
        shortcut.style.display = "none";
    }
    ov.classList.add("open");
    setTimeout(function() { document.getElementById("job-target").focus(); }, 50);
};

window._closeJobModal = function() {
    var ov = document.getElementById("job-overlay");
    if (ov) ov.classList.remove("open");
};

window._pickMonitoredTarget = function(val) {
    if (val) document.getElementById("job-target").value = val;
};

window._launchJob = function() {
    var target = document.getElementById("job-target").value.trim();
    var profile = (document.querySelector('input[name="job-profile"]:checked') || {}).value || "quick";
    var err = document.getElementById("job-error");
    err.style.display = "none";
    if (!target) { err.textContent = t("jobs.target_required"); err.style.display = "block"; return; }
    SurfaceAPI.createJob({ target: target, profile: profile }).then(function(job) {
        _closeJobModal();
        showStatus(t("jobs.launched") + " : " + job.target);
        _loadAndRender();
    }).catch(function(e) {
        err.textContent = e.message || t("common.error");
        err.style.display = "block";
    });
};

// ═══════════════════════════════════════════════════════════════
// MONITORED ASSETS
// ═══════════════════════════════════════════════════════════════
function _renderMonitored(c) {
    var h = '<div style="display:flex;align-items:center;gap:8px;margin-bottom:12px;flex-wrap:wrap">';
    h += '<h2 style="margin:0">' + esc(t("monitored.title")) + '</h2>';
    h += '<span style="flex:1"></span>';
    if (_monitored.length) h += '<button class="btn-add btn-icon" style="background:#dc2626;color:white" data-click="_scanAllMonitored">' + _icon("search", 14) + ' ' + esc(t("monitored.scan_all")) + '</button>';
    h += '<button class="btn-add btn-icon" data-click="_newMonitoredDialog">' + _icon("plus", 14) + ' ' + esc(t("monitored.add")) + '</button>';
    h += '</div>';
    h += '<div style="font-size:0.85em;color:var(--text-muted);margin-bottom:12px">' + esc(t("monitored.help")) + '</div>';

    if (!_monitored.length) {
        h += '<div class="empty-state">' + esc(t("monitored.empty")) + '</div>';
        c.innerHTML = h;
        return;
    }

    // Search bar (rendered once — the table below lives in a wrapper the
    // search handler refreshes in place so the input keeps focus).
    h += '<div class="surface-filters" style="margin-bottom:12px">';
    h += '<input type="text" class="surface-filter" placeholder="' + esc(t("monitored.search.placeholder")) + '" style="min-width:320px;flex:1"';
    h += ' id="monitored-search" value="' + esc(_monitoredSearch) + '" data-input="_setMonitoredSearch" data-pass-value autocomplete="off">';
    h += '<button class="btn-add" id="monitored-search-clear" data-click="_clearMonitoredSearch"' + (_monitoredSearch ? '' : ' style="display:none"') + '>x</button>';
    h += '</div>';

    // Scanner-type filter pills — the union of every scanner declared on
    // any monitored asset, sorted alphabetically. Multi-select.
    var scannerSet = {};
    _monitored.forEach(function(a) { (a.enabled_scanners || []).forEach(function(s) { if (s) scannerSet[s] = true; }); });
    var scannerList = Object.keys(scannerSet).sort();
    if (scannerList.length) {
        h += '<div class="filter-pills-row" style="margin-bottom:12px">';
        h += '<span class="filter-pills-lbl">' + esc(t("monitored.filter.scanner")) + '</span>';
        scannerList.forEach(function(s) {
            var on = _monitoredFilterScanners.indexOf(s) >= 0;
            h += '<button type="button" class="filter-pill' + (on ? " active" : "") + '" data-click="_toggleMonitoredScanner" data-args=\'' + _da(s) + '\'>' + esc(_scannerLabel(s)) + '</button>';
        });
        if (_monitoredFilterScanners.length) {
            h += '<button type="button" class="filter-pill filter-pill-clear" data-click="_clearMonitoredScannerFilter">' + esc(t("findings.filter.reset")) + '</button>';
        } else {
            h += '<span class="filter-pills-hint">' + esc(t("findings.filter.hint_m")) + '</span>';
        }
        h += '</div>';
    }

    h += '<div id="monitored-table-wrap"></div>';

    c.innerHTML = h;
    _refreshMonitoredTable();
}

function _refreshMonitoredTable() {
    var wrap = document.getElementById("monitored-table-wrap");
    if (!wrap) return;

    var q = _monitoredSearch.trim().toLowerCase();
    var filtered = _monitored.filter(function(a) {
        // Scanner filter pills (ANY-match — show the asset if at least one
        // of its scanners matches at least one selected pill).
        if (_monitoredFilterScanners.length) {
            var scs = a.enabled_scanners || [];
            var matched = false;
            for (var i = 0; i < scs.length; i++) {
                if (_monitoredFilterScanners.indexOf(scs[i]) >= 0) { matched = true; break; }
            }
            if (!matched) return false;
        }
        if (!q) return true;
        if ((a.value || "").toLowerCase().indexOf(q) >= 0) return true;
        if ((a.label || "").toLowerCase().indexOf(q) >= 0) return true;
        if ((a.notes || "").toLowerCase().indexOf(q) >= 0) return true;
        if ((a.kind || "").toLowerCase().indexOf(q) >= 0) return true;
        if ((a.enabled_scanners || []).some(function(s) { return (s || "").toLowerCase().indexOf(q) >= 0; })) return true;
        return false;
    });

    var h = '<div style="font-size:0.78em;color:var(--text-muted);margin-bottom:8px">' + filtered.length + ' / ' + _monitored.length + ' ' + esc(t("monitored.count")) + '</div>';

    if (!filtered.length) {
        h += '<div class="empty-state">' + esc(t("monitored.no_match")) + '</div>';
        wrap.innerHTML = h;
        return;
    }

    h += '<table class="surface-table"><thead><tr>'
      + '<th>' + esc(t("monitored.col.type")) + '</th>'
      + '<th>' + esc(t("monitored.col.value")) + '</th>'
      + '<th>' + esc(t("monitored.col.label")) + '</th>'
      + '<th>' + esc(t("monitored.col.scanners")) + '</th>'
      + '<th>' + esc(t("monitored.col.frequency")) + '</th>'
      + '<th>' + esc(t("monitored.col.enabled")) + '</th>'
      + '<th>' + esc(t("monitored.col.last_scan")) + '</th>'
      + '<th>' + esc(t("monitored.col.next_scan")) + '</th>'
      + '<th></th></tr></thead><tbody>';
    var now = Date.now();
    filtered.forEach(function(a) {
        var disabled = !a.enabled;
        var freq = a.scan_frequency_hours || 0;
        var nextStr = "—";
        if (freq > 0) {
            if (!a.last_scan_at) {
                nextStr = '<span style="color:#16a34a">' + esc(t("monitored.next.imminent")) + '</span>';
            } else {
                var nextMs = new Date(a.last_scan_at).getTime() + freq * 3600 * 1000;
                if (nextMs <= now) nextStr = '<span style="color:#16a34a">' + esc(t("monitored.next.imminent")) + '</span>';
                else {
                    var inH = Math.round((nextMs - now) / 3600000);
                    nextStr = inH < 1 ? "< 1 h" : inH + " h";
                }
            }
        } else {
            nextStr = '<span style="color:var(--text-muted)">' + esc(t("monitored.next.disabled")) + '</span>';
        }
        h += '<tr style="' + (disabled ? "opacity:0.5;" : "") + '">';
        h += '<td><span class="kind-badge kind-' + esc(a.kind) + '">' + _kindLabel(a.kind) + '</span></td>';
        h += '<td style="font-family:monospace;font-size:0.85em;font-weight:600">' + esc(a.value) + '</td>';
        h += '<td style="font-size:0.85em">' + esc(a.label || "-") + '</td>';
        var scs = a.enabled_scanners || [];
        if (scs.length) {
            var badges = scs.map(function(s) { return '<span class="scanner-mini" title="' + esc(s) + '">' + esc(_scannerLabel(s)) + '</span>'; }).join("");
            h += '<td style="max-width:240px">' + badges + '</td>';
        } else {
            h += '<td><span class="scanner-mini scanner-mini-none">aucun</span></td>';
        }
        h += '<td style="font-size:0.82em;color:var(--text-muted)">' + (freq > 0 ? String(t("monitored.frequency_hours")).replace("{n}", freq) : "—") + '</td>';
        h += '<td><label style="cursor:pointer"><input type="checkbox"' + (a.enabled ? " checked" : "") + ' data-change="_toggleMonitored" data-args=\'' + _da(a.id) + '\' data-pass-el></label></td>';
        h += '<td style="font-size:0.78em;color:var(--text-muted)">' + esc(a.last_scan_at ? (a.last_scan_at || "").substring(0, 16).replace("T", " ") : t("monitored.last.never")) + '</td>';
        h += '<td style="font-size:0.78em">' + nextStr + '</td>';
        h += '<td style="white-space:nowrap">';
        h += '<button class="btn-mini" data-click="_editMonitoredDialog" data-args=\'' + _da(a.id) + '\' title="' + esc(t("action.edit")) + '">' + _icon("edit", 14) + '</button> ';
        h += '<button class="btn-mini" data-click="_deleteMonitored" data-args=\'' + _da(a.id) + '\' title="' + esc(t("action.delete")) + '">' + _icon("trash", 14) + '</button>';
        h += '</td>';
        h += '</tr>';
    });
    h += '</tbody></table>';

    wrap.innerHTML = h;
}

window._setMonitoredSearch = function(v) {
    _monitoredSearch = v || "";
    _refreshMonitoredTable();
    var clearBtn = document.getElementById("monitored-search-clear");
    if (clearBtn) clearBtn.style.display = _monitoredSearch ? "" : "none";
};
window._clearMonitoredSearch = function() {
    _monitoredSearch = "";
    var inp = document.getElementById("monitored-search");
    if (inp) inp.value = "";
    _refreshMonitoredTable();
    var clearBtn = document.getElementById("monitored-search-clear");
    if (clearBtn) clearBtn.style.display = "none";
    if (inp) inp.focus();
};

function _kindLabel(k) { return t("kind." + k) || k; }

function _kindHelp(k) {
    return t("kind.help." + k) || "";
}

function _ensureMonitoredModal() {
    var ov = document.getElementById("monitored-overlay");
    if (!ov) {
        ov = document.createElement("div");
        ov.id = "monitored-overlay";
        ov.className = "ct-modal-overlay";
        document.body.appendChild(ov);
        ov.addEventListener("click", function(e) { if (e.target === ov) _closeMonitoredModal(); });
    }
    // Rebuild innerHTML on every open so the locale is always current.
    ov.innerHTML =
        '<div class="ct-modal">' +
            '<div class="ct-modal-header"><span id="monitored-modal-title">' + esc(t("mon_modal.title_add")) + '</span><button class="ct-modal-close" data-click="_closeMonitoredModal">' + _icon("x", 18) + '</button></div>' +
            '<div class="ct-modal-body">' +
                '<div class="ct-field"><label class="ct-field-lbl">' + esc(t("mon_modal.type")) + '</label>' +
                    '<div class="ct-radio-group">' +
                        '<label class="ct-radio"><input type="radio" name="monitored-kind" value="domain" checked> <span>' + esc(t("kind.domain")) + '</span></label>' +
                        '<label class="ct-radio"><input type="radio" name="monitored-kind" value="host"> <span>' + esc(t("kind.host")) + '</span></label>' +
                        '<label class="ct-radio"><input type="radio" name="monitored-kind" value="ip_range"> <span>' + esc(t("kind.ip_range")) + '</span></label>' +
                    '</div>' +
                    '<div class="ct-field-help" id="monitored-kind-help"></div>' +
                '</div>' +
                '<div class="ct-field"><label class="ct-field-lbl">' + esc(t("mon_modal.value")) + '</label>' +
                    '<input type="text" class="ct-input" id="monitored-value" placeholder="example.com">' +
                '</div>' +
                '<div class="ct-field"><label class="ct-field-lbl">' + esc(t("mon_modal.label")) + '</label>' +
                    '<input type="text" class="ct-input" id="monitored-label" placeholder="' + esc(t("mon_modal.label_ph")) + '">' +
                '</div>' +
                '<div class="ct-field"><label class="ct-field-lbl">' + esc(t("mon_modal.notes")) + '</label>' +
                    '<textarea class="ct-input" id="monitored-notes" rows="3" placeholder="' + esc(t("mon_modal.notes_ph")) + '"></textarea>' +
                '</div>' +
                '<div class="ct-field"><label class="ct-field-lbl">' + esc(t("mon_modal.criticality")) + '</label>' +
                    '<select class="ct-input" id="monitored-criticality">' +
                        '<option value="low">' + esc(t("mon_modal.crit_low")) + '</option>' +
                        '<option value="medium" selected>' + esc(t("mon_modal.crit_medium")) + '</option>' +
                        '<option value="high">' + esc(t("mon_modal.crit_high")) + '</option>' +
                        '<option value="critical">' + esc(t("mon_modal.crit_critical")) + '</option>' +
                    '</select>' +
                    '<div class="ct-field-help">' + esc(t("mon_modal.criticality_help")) + '</div>' +
                '</div>' +
                '<div class="ct-field"><label class="ct-field-lbl">' + esc(t("mon_modal.tags")) + '</label>' +
                    '<input type="text" class="ct-input" id="monitored-tags" placeholder="' + esc(t("mon_modal.tags_ph")) + '">' +
                    '<div class="ct-field-help">' + esc(t("mon_modal.tags_help")) + '</div>' +
                '</div>' +
                '<div class="ct-field"><label class="ct-field-lbl">' + esc(t("mon_modal.frequency")) + '</label>' +
                    '<select class="ct-input" id="monitored-frequency">' +
                        '<option value="1">1 h</option>' +
                        '<option value="6">6 h</option>' +
                        '<option value="24" selected>24 h</option>' +
                        '<option value="168">168 h (7d)</option>' +
                        '<option value="720">720 h (30d)</option>' +
                        '<option value="0">0 (' + esc(t("monitored.next.disabled")) + ')</option>' +
                    '</select>' +
                    '<div class="ct-field-help">' + esc(t("mon_modal.frequency_help")) + '</div>' +
                '</div>' +
                '<div class="ct-field"><label class="ct-field-lbl">' + esc(t("mon_modal.scanners")) + '</label>' +
                    '<div id="monitored-scanners" class="scanner-checklist"></div>' +
                    '<div class="ct-field-help">' + esc(t("mon_modal.scanners_help")) + '</div>' +
                '</div>' +
                '<div class="ct-field"><label class="ct-checkbox"><input type="checkbox" id="monitored-enabled" checked> <span>' + esc(t("mon_modal.enabled")) + '</span></label></div>' +
                '<div class="ct-error" id="monitored-error" style="display:none"></div>' +
            '</div>' +
            '<div class="ct-modal-footer">' +
                '<button class="btn-add" data-click="_closeMonitoredModal">' + esc(t("action.cancel")) + '</button>' +
                '<button class="btn-add" style="background:#dc2626;color:white" data-click="_saveMonitored">' + esc(t("action.save")) + '</button>' +
            '</div>' +
        '</div>';
    document.querySelectorAll('input[name="monitored-kind"]').forEach(function(r) {
        r.addEventListener("change", function() {
            _updateMonitoredKindHelp();
            _renderScannerChecklist(null);
        });
    });
    return ov;
}

function _renderScannerChecklist(currentSelection) {
    var sel = document.querySelector('input[name="monitored-kind"]:checked');
    var kind = sel ? sel.value : "domain";
    var container = document.getElementById("monitored-scanners");
    if (!container) return;
    var entry = (_scannersCatalog && _scannersCatalog[kind]) || { scanners: [], defaults: [] };
    var enabled = currentSelection;
    if (enabled == null) enabled = entry.defaults || [];
    var enabledSet = {};
    (enabled || []).forEach(function(n) { enabledSet[n] = true; });
    if (!entry.scanners || !entry.scanners.length) {
        container.innerHTML = '<div class="ct-field-help">Aucun scanner disponible pour ce type.</div>';
        return;
    }
    var h = "";
    entry.scanners.forEach(function(s) {
        var checked = enabledSet[s.name] ? " checked" : "";
        h += '<label class="scanner-check">' +
                '<input type="checkbox" value="' + esc(s.name) + '"' + checked + '> ' +
                '<span>' + esc(s.label) + '</span>' +
             '</label>';
    });
    container.innerHTML = h;
}

function _updateMonitoredKindHelp() {
    var sel = document.querySelector('input[name="monitored-kind"]:checked');
    var k = sel ? sel.value : "domain";
    var help = document.getElementById("monitored-kind-help");
    if (help) help.textContent = _kindHelp(k);
    var input = document.getElementById("monitored-value");
    if (input) input.placeholder = { domain: "example.com", host: "1.2.3.4 ou api.example.com", ip_range: "192.168.1.0/24" }[k] || "";
}

var _editingMonitoredId = null;

window._newMonitoredDialog = function() {
    _editingMonitoredId = null;
    var ov = _ensureMonitoredModal();
    document.getElementById("monitored-modal-title").textContent = t("mon_modal.title_add");
    document.querySelector('input[name="monitored-kind"][value="domain"]').checked = true;
    document.getElementById("monitored-value").value = "";
    document.getElementById("monitored-label").value = "";
    document.getElementById("monitored-notes").value = "";
    document.getElementById("monitored-enabled").checked = true;
    document.getElementById("monitored-frequency").value = "24";
    document.getElementById("monitored-criticality").value = "medium";
    document.getElementById("monitored-tags").value = "";
    document.getElementById("monitored-error").style.display = "none";
    _updateMonitoredKindHelp();
    _renderScannerChecklist(null);
    ov.classList.add("open");
    setTimeout(function() {
        var v = document.getElementById("monitored-value");
        if (v) v.focus();
    }, 50);
};

window._editMonitoredDialog = function(id) {
    var a = _monitored.find(function(x) { return x.id === id; });
    if (!a) return;
    _editingMonitoredId = id;
    var ov = _ensureMonitoredModal();
    document.getElementById("monitored-modal-title").textContent = t("mon_modal.title_edit");
    var radio = document.querySelector('input[name="monitored-kind"][value="' + a.kind + '"]');
    if (radio) radio.checked = true;
    document.getElementById("monitored-value").value = a.value;
    document.getElementById("monitored-label").value = a.label || "";
    document.getElementById("monitored-notes").value = a.notes || "";
    document.getElementById("monitored-enabled").checked = !!a.enabled;
    document.getElementById("monitored-frequency").value = String(a.scan_frequency_hours != null ? a.scan_frequency_hours : 24);
    document.getElementById("monitored-criticality").value = a.criticality || "medium";
    document.getElementById("monitored-tags").value = (a.tags || []).join(", ");
    document.getElementById("monitored-error").style.display = "none";
    _updateMonitoredKindHelp();
    _renderScannerChecklist(a.enabled_scanners || null);
    ov.classList.add("open");
};

window._closeMonitoredModal = function() {
    var ov = document.getElementById("monitored-overlay");
    if (ov) ov.classList.remove("open");
};

window._saveMonitored = function() {
    var sel = document.querySelector('input[name="monitored-kind"]:checked');
    var enabledScanners = [];
    document.querySelectorAll("#monitored-scanners input[type=checkbox]:checked").forEach(function(cb) {
        enabledScanners.push(cb.value);
    });
    var rawTags = (document.getElementById("monitored-tags").value || "")
        .split(",").map(function(s) { return s.trim(); }).filter(Boolean);
    var data = {
        kind: sel ? sel.value : "domain",
        value: document.getElementById("monitored-value").value.trim(),
        label: document.getElementById("monitored-label").value.trim(),
        notes: document.getElementById("monitored-notes").value.trim(),
        enabled: document.getElementById("monitored-enabled").checked,
        scan_frequency_hours: parseInt(document.getElementById("monitored-frequency").value, 10),
        enabled_scanners: enabledScanners,
        criticality: document.getElementById("monitored-criticality").value || "medium",
        tags: rawTags,
    };
    var err = document.getElementById("monitored-error");
    err.style.display = "none";
    if (!data.value) {
        err.textContent = t("mon_modal.value_required");
        err.style.display = "block";
        return;
    }
    var promise = _editingMonitoredId
        ? SurfaceAPI.updateMonitored(_editingMonitoredId, data)
        : SurfaceAPI.createMonitored(data);
    promise.then(function() {
        _closeMonitoredModal();
        showStatus(_editingMonitoredId ? t("mon_modal.updated") : t("mon_modal.added"));
        _editingMonitoredId = null;
        _loadAndRender();
    }).catch(function(e) {
        err.textContent = e.message || t("common.error");
        err.style.display = "block";
    });
};

window._toggleMonitored = function(id, el) {
    SurfaceAPI.updateMonitored(id, { enabled: el.checked })
        .then(function() { var a = _monitored.find(function(x) { return x.id === id; }); if (a) a.enabled = el.checked; })
        .catch(function(e) { showStatus(e.message || t("common.error"), true); });
};

window._deleteMonitored = function(id) {
    if (!confirm(t("monitored.delete_confirm"))) return;
    SurfaceAPI.deleteMonitored(id)
        .then(function() { showStatus(t("mon_modal.deleted")); _loadAndRender(); })
        .catch(function(e) { showStatus(e.message || t("common.error"), true); });
};

window._scanMonitored = function(id) {
    showStatus(t("mon_modal.scan_in_progress"));
    SurfaceAPI.scanMonitored(id).then(function(r) {
        showStatus(t("mon_modal.scan_done").replace("{n}", r.findings_created).replace("{target}", r.target));
        _loadAndRender();
    }).catch(function(e) { showStatus(e.message || t("common.error"), true); });
};

window._scanAllMonitored = function() {
    if (!confirm(t("mon_modal.scan_all_confirm"))) return;
    showStatus(t("mon_modal.scan_all_in_progress"));
    SurfaceAPI.scanAllMonitored().then(function(r) {
        var msg = t("mon_modal.scan_all_done").replace("{scanned}", r.scanned).replace("{n}", r.findings_created);
        if (r.errors && r.errors.length) msg += ", " + t("mon_modal.scan_all_errors").replace("{n}", r.errors.length);
        showStatus(msg);
        _loadAndRender();
    }).catch(function(e) { showStatus(e.message || t("common.error"), true); });
};

// ═══════════════════════════════════════════════════════════════
// DASHBOARD
// ═══════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════
// DASHBOARD — stat helpers
// ═══════════════════════════════════════════════════════════════

var _DAY_MS = 86400000;
var _SEV_ORDER = ["critical", "high", "medium", "low", "info"];
var _SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function _dayKey(d) {
    // YYYY-MM-DD in local time
    var y = d.getFullYear(), m = d.getMonth() + 1, dd = d.getDate();
    return y + "-" + (m < 10 ? "0" + m : m) + "-" + (dd < 10 ? "0" + dd : dd);
}

function _daysAgo(iso) {
    if (!iso) return Infinity;
    var then = new Date(iso).getTime();
    if (isNaN(then)) return Infinity;
    return Math.floor((Date.now() - then) / _DAY_MS);
}

function _dashStats() {
    // bySev   — severity breakdown of actionable findings (new/to_fix),
    //           includes info for display
    // active  — actionable findings EXCLUDING info (drives alert counts)
    // byStatus— raw status counts (all severities)
    var bySev = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    var byStatus = { new: 0, false_positive: 0, to_fix: 0, fixed: 0 };
    var active = [];
    _findings.forEach(function(f) {
        if (byStatus[f.status] != null) byStatus[f.status]++;
        if (f.status === "new" || f.status === "to_fix") {
            if (bySev[f.severity] != null) bySev[f.severity]++;
            if (f.severity !== "info") active.push(f);
        }
    });
    return { bySev: bySev, byStatus: byStatus, active: active };
}

function _topHostsByFindings(n) {
    // Aggregate actionable findings per host.value (excluding info
    // so audit-only findings don't push a host into the "at risk" list).
    var map = {};
    _findings.forEach(function(f) {
        if (f.status !== "new" && f.status !== "to_fix") return;
        if (f.severity === "info") return;
        var tgt = (f.target || "").split(":")[0];
        if (!tgt) return;
        if (!map[tgt]) map[tgt] = { host: tgt, total: 0, maxSev: 9 };
        map[tgt].total++;
        var r = _SEV_RANK[f.severity];
        if (r != null && r < map[tgt].maxSev) map[tgt].maxSev = r;
    });
    var list = Object.keys(map).map(function(k) { return map[k]; });
    list.sort(function(a, b) {
        if (a.maxSev !== b.maxSev) return a.maxSev - b.maxSev;
        return b.total - a.total;
    });
    // Resolve host id if the target matches a monitored host
    list.forEach(function(row) {
        var m = _monitored.find(function(a) { return a.value === row.host; });
        if (m) { row.id = m.id; row.kind = m.kind; }
    });
    return list.slice(0, n);
}

function _topFindingTypes(n) {
    // Actionable types only — info findings (scan_clean, ct_discovery,
    // tls_valid...) would otherwise dominate the list with noise.
    var map = {};
    _findings.forEach(function(f) {
        if (f.status !== "new" && f.status !== "to_fix") return;
        if (f.severity === "info") return;
        var k = f.type || "other";
        map[k] = (map[k] || 0) + 1;
    });
    return Object.keys(map).map(function(k) { return { type: k, count: map[k] }; })
        .sort(function(a, b) { return b.count - a.count; })
        .slice(0, n);
}

function _topScanners(n) {
    var map = {};
    _findings.forEach(function(f) {
        var k = f.scanner || "manual";
        map[k] = (map[k] || 0) + 1;
    });
    return Object.keys(map).map(function(k) { return { scanner: k, count: map[k] }; })
        .sort(function(a, b) { return b.count - a.count; })
        .slice(0, n);
}

function _timelineDaily(days) {
    // Returns [{key, label, critical, high, medium, low, info, triaged}]
    // for the last `days` days, inclusive of today. The severity columns are
    // CUMULATIVE — each entry reflects the total number of findings of that
    // severity that existed at the end of the day, not just the ones created
    // that day. That way the curve never drops on a quiet day.
    // `triaged` stays a daily count: the line overlay accumulates it
    // separately to show triage velocity.
    var out = [];
    var now = new Date();
    now.setHours(23, 59, 59, 999);
    var msPerDay = _DAY_MS;
    var dayLabels = [];
    var dayEnds = [];
    for (var i = days - 1; i >= 0; i--) {
        var d = new Date(now.getTime() - i * msPerDay);
        dayLabels.push({
            key: _dayKey(d),
            label: d.getDate() + "/" + (d.getMonth() + 1),
            endTs: d.getTime(),
        });
        dayEnds.push(d.getTime());
    }

    // Pre-extract finding timestamps once so the loop stays O(N + days)
    var prepped = _findings.map(function(f) {
        return {
            sev: f.severity,
            created: f.created_at ? new Date(f.created_at).getTime() : 0,
            triaged: f.triaged_at ? new Date(f.triaged_at).getTime() : 0,
        };
    });

    dayLabels.forEach(function(slot, idx) {
        var bucket = { key: slot.key, label: slot.label,
            critical: 0, high: 0, medium: 0, low: 0, info: 0, triaged: 0 };
        var end = slot.endTs;
        prepped.forEach(function(f) {
            if (f.created && f.created <= end && bucket[f.sev] != null) {
                bucket[f.sev]++;
            }
            // Daily triaged count: only triaged_at falling on this day
            if (f.triaged) {
                var dayStart = end - msPerDay + 1;
                if (f.triaged >= dayStart && f.triaged <= end) bucket.triaged++;
            }
        });
        out.push(bucket);
    });
    return out;
}

function _surfaceInventory() {
    var byKind = { domain: 0, host: 0, ip_range: 0 };
    var hostsSource = { auto: 0, manual: 0 };
    var discoveredThisWeek = 0;
    var sevenDaysAgo = Date.now() - 7 * _DAY_MS;
    _monitored.forEach(function(a) {
        if (byKind[a.kind] != null) byKind[a.kind]++;
        if (a.kind === "host") {
            var auto = (a.notes || "").indexOf("Auto-decouvert") === 0;
            if (auto) hostsSource.auto++;
            else hostsSource.manual++;
            // Auto-discovered host creation date unknown in state; fall back to created_at field if present
            if (auto && a.created_at && new Date(a.created_at).getTime() > sevenDaysAgo) {
                discoveredThisWeek++;
            }
        }
    });
    return {
        byKind: byKind,
        hostsSource: hostsSource,
        discoveredThisWeek: discoveredThisWeek,
        totalAssets: _monitored.length,
    };
}

function _measuresStats() {
    var byStatus = { a_faire: 0, en_cours: 0, termine: 0 };
    var overdue = [];
    var staleDays = 30;
    var now = new Date();
    var todayIso = now.toISOString().substring(0, 10);
    var createdThisWeek = 0;
    var doneThisWeek = 0;
    var sevenDaysAgo = now.getTime() - 7 * _DAY_MS;
    _measures.forEach(function(m) {
        if (byStatus[m.statut] != null) byStatus[m.statut]++;
        if (m.statut !== "termine" && m.echeance && m.echeance < todayIso) {
            overdue.push(m);
        }
        if (m.created_at && new Date(m.created_at).getTime() > sevenDaysAgo) createdThisWeek++;
        if (m.statut === "termine" && m.updated_at && new Date(m.updated_at).getTime() > sevenDaysAgo) doneThisWeek++;
    });
    return {
        byStatus: byStatus,
        total: _measures.length,
        overdue: overdue,
        createdThisWeek: createdThisWeek,
        doneThisWeek: doneThisWeek,
    };
}

function _schedulerHealth() {
    var last24 = Date.now() - _DAY_MS;
    var jobs24 = _jobs.filter(function(j) {
        return j.created_at && new Date(j.created_at).getTime() > last24;
    });
    var ok = jobs24.filter(function(j) { return j.status === "completed"; }).length;
    var failed = jobs24.filter(function(j) { return j.status === "failed"; }).length;
    var running = _jobs.filter(function(j) { return j.status === "running" || j.status === "pending"; }).length;
    var lastJob = _jobs.length ? _jobs[0] : null;
    // Next due asset
    var now = Date.now();
    var nextAsset = null, nextMs = Infinity;
    _monitored.forEach(function(a) {
        if (!a.enabled || !a.scan_frequency_hours) return;
        if (!a.last_scan_at) { if (nextMs > 0) { nextMs = 0; nextAsset = a; } return; }
        var due = new Date(a.last_scan_at).getTime() + a.scan_frequency_hours * 3600000;
        if (due < nextMs) { nextMs = due; nextAsset = a; }
    });
    var nextInHours = nextAsset ? Math.max(0, Math.round((nextMs - now) / 3600000)) : null;
    return {
        ok: ok, failed: failed, running: running, total24: jobs24.length,
        successRate: jobs24.length ? Math.round(ok / jobs24.length * 100) : null,
        lastJob: lastJob,
        nextAsset: nextAsset,
        nextInHours: nextInHours,
    };
}

function _coverageGaps() {
    var staleHosts = [];
    var sparseHosts = [];
    var disabledLong = [];
    var now = Date.now();
    _monitored.forEach(function(a) {
        if (a.kind === "host" && a.enabled) {
            var age = _daysAgo(a.last_scan_at);
            if (age > 7) staleHosts.push({ host: a.value, id: a.id, age: age });
            if ((a.enabled_scanners || []).length < 2) sparseHosts.push(a);
        }
        if (!a.enabled && a.created_at) {
            var days = Math.floor((now - new Date(a.created_at).getTime()) / _DAY_MS);
            if (days > 30) disabledLong.push(a);
        }
    });
    staleHosts.sort(function(a, b) { return (b.age === Infinity ? 9999 : b.age) - (a.age === Infinity ? 9999 : a.age); });
    return { staleHosts: staleHosts, sparseHosts: sparseHosts, disabledLong: disabledLong };
}

// ═══════════════════════════════════════════════════════════════
// DASHBOARD — render
// ═══════════════════════════════════════════════════════════════

function _renderDashboard(c) {
    var stats = _dashStats();
    // "Nouveaux 24h" counter excludes info — it's meant to flag fresh
    // actionable findings, not routine scan summaries.
    var recent24 = _findings.filter(function(f) {
        if (f.severity === "info") return false;
        return f.created_at && new Date(f.created_at).getTime() > Date.now() - _DAY_MS;
    });

    var h = '<div class="dash-header">';
    h += '<h2 style="margin:0">' + esc(t("dash.title")) + '</h2>';
    h += '<div class="dash-actions">';
    h += '<button class="btn-add btn-icon" data-click="_scanAllMonitored" title="' + esc(t("monitored.scan_all")) + '">' + _icon("search", 14) + ' ' + esc(t("monitored.scan_all")) + '</button>';
    h += '<button class="btn-add btn-icon" data-click="_newMonitoredDialog">' + _icon("plus", 14) + ' ' + esc(t("monitored.add")) + '</button>';
    h += '<button class="btn-add btn-icon" data-click="_bulkImportDialog">' + _icon("list", 14) + ' ' + esc(t("findings.bulk_import")) + '</button>';
    h += '</div></div>';

    // ── A. Critical banner ────────────────────────────────────
    h += _dashBanner(stats, recent24);

    // ── B. Timeline 30 days ───────────────────────────────────
    h += _dashTimeline();

    // ── Row 1 : Top hosts + Top types ────────────────────────
    h += '<div class="dash-row">';
    h += _dashTopHosts();
    h += _dashTopTypes();
    h += '</div>';

    // ── Row 2 : Surface inventory + Measures burndown ────────
    h += '<div class="dash-row">';
    h += _dashSurface();
    h += _dashMeasures();
    h += '</div>';

    // ── Row 3 : Scanner health + Top scanners ────────────────
    h += '<div class="dash-row">';
    h += _dashHealth();
    h += _dashTopScanners();
    h += '</div>';

    c.innerHTML = h;
}

// v0.2 — per-asset risk score = severity-weighted active findings × business
// criticality. Returns 0–100. The weights mirror the Surface dashboard
// gradient: critical hurts 10×, high 5×, medium 2×, low/info 0. Multiplying
// by the criticality factor (1–4) lets a "critical" asset bubble up even
// with fewer findings than a "low" asset that has many medium findings.
var _CRIT_FACTOR = { low: 1, medium: 2, high: 3, critical: 4 };
function _riskScoreFor(asset, counts) {
    if (!counts) return 0;
    var raw = (counts.critical || 0) * 10
            + (counts.high     || 0) * 5
            + (counts.medium   || 0) * 2
            + (counts.low      || 0) * 0.5;
    var crit = _CRIT_FACTOR[(asset && asset.criticality) || "medium"] || 2;
    var score = raw * crit;
    return Math.min(100, Math.round(score));
}
function _riskTier(score) {
    if (score >= 70) return { lvl: "critical", lbl: t("risk.tier_critical") };
    if (score >= 40) return { lvl: "high",     lbl: t("risk.tier_high") };
    if (score >= 15) return { lvl: "medium",   lbl: t("risk.tier_medium") };
    if (score > 0)   return { lvl: "low",      lbl: t("risk.tier_low") };
    return                  { lvl: "info",     lbl: t("risk.tier_clean") };
}

function _statCard(value, label, cls) {
    return '<div class="surface-stat"><div class="surface-stat-val ' + cls + '">' + value + '</div><div class="surface-stat-lbl">' + esc(label) + '</div></div>';
}

// ── A. Critical banner split into two dash-cards ──────────────
function _dashBanner(stats, recent24) {
    var crit = stats.bySev.critical;
    var high = stats.bySev.high;
    var topHosts = _topHostsByFindings(3);

    // Left card color reflects the severity of the situation.
    var leftState = crit > 0 ? "critical" : high > 0 ? "high" : "ok";
    var headline = crit > 0 ? esc(t("dash.headline_critical")).replace("{n}", crit)
                 : high > 0 ? esc(t("dash.headline_high")).replace("{n}", high)
                 : esc(t("dash.headline_ok"));
    var icon = leftState === "ok" ? _icon("check_circle", 16) : _icon("alert", 16);

    var h = '<div class="dash-row">';

    // LEFT CARD — alert + 3 count tiles (orange/red/green by state)
    h += '<div class="dash-card dash-card-alert dash-card-alert-' + leftState + '">';
    h += '<div class="dash-card-head">' + icon + ' <span>' + headline + '</span></div>';
    h += '<div class="dash-banner-counts">';
    h += '<div class="dash-count-tile sev-critical" data-click="_dashGotoSeverity" data-args=\'["critical"]\'>';
    h += '<div class="dash-count-val">' + crit + '</div><div class="dash-count-lbl">' + esc(t("sev.critical")) + '</div>';
    h += '</div>';
    h += '<div class="dash-count-tile sev-high" data-click="_dashGotoSeverity" data-args=\'["high"]\'>';
    h += '<div class="dash-count-val">' + high + '</div><div class="dash-count-lbl">' + esc(t("sev.high")) + '</div>';
    h += '</div>';
    h += '<div class="dash-count-tile dash-count-recent" data-click="_dashGotoRecent">';
    h += '<div class="dash-count-val">' + recent24.length + '</div><div class="dash-count-lbl">' + esc(t("dash.new_24h")) + '</div>';
    h += '</div>';
    h += '</div>';
    h += '</div>';

    // RIGHT CARD — top 3 exposed hosts
    h += '<div class="dash-card">';
    h += '<div class="dash-card-head">' + _icon("server", 16) + ' ' + esc(t("dash.top_exposed_hosts")) + '</div>';
    if (topHosts.length) {
        h += '<div class="dash-list">';
        topHosts.forEach(function(row) {
            var sev = _SEV_ORDER[row.maxSev] || "info";
            var clickable = row.id ? ' data-click="_openHost" data-args=\'' + _da(row.id) + '\'' : '';
            h += '<div class="dash-list-row"' + clickable + '>';
            h += '<span class="sev-badge sev-' + sev + '">' + esc(t("sev." + sev)) + '</span>';
            h += '<span class="dash-list-main mono" title="' + esc(row.host) + '">' + esc(row.host) + '</span>';
            h += '<span class="dash-list-count">' + row.total + '</span>';
            h += '</div>';
        });
        h += '</div>';
    } else {
        h += '<div class="dash-empty">' + esc(t("dash.no_hosts_at_risk")) + '</div>';
    }
    h += '</div>';

    h += '</div>';
    return h;
}

// ── B. Timeline 30 days ───────────────────────────────────────
function _dashTimeline() {
    var days = _timelineDaily(30);
    // Match the canonical severity badge palette (Surface.css .sev-*).
    // Same hues used everywhere in the app — filter pills, badges, host
    // counters — so the chart reads instantly.
    // Shifted from the badge palette to give critical/high more chromatic
    // distance — at 1.4px stroke #dc2626 and #ea580c looked nearly identical.
    // Critical stays the deepest red, high jumps to a clearly brighter orange.
    var colors = {
        critical: "#b91c1c",
        high:     "#f97316",
        medium:   "#eab308",
        low:      "#65a30d",
        info:     "#0284c7",
    };

    // Per-severity max for the Y scale (lines, not stacked)
    var maxVal = 1;
    days.forEach(function(d) {
        _SEV_ORDER.forEach(function(s) {
            if ((d[s] || 0) > maxVal) maxVal = d[s];
        });
    });

    var W = 800, H = 260, ML = 32, MR = 12, MT = 14, MB = 44;
    var cW = W - ML - MR, cH = H - MT - MB;

    function xFor(i) { return ML + (i / Math.max(1, days.length - 1)) * cW; }
    function yFor(v) { return MT + cH - (v / maxVal) * cH; }

    function smoothPath(pts) {
        if (pts.length < 2) return "";
        var d = "M" + pts[0].x.toFixed(1) + "," + pts[0].y.toFixed(1);
        for (var i = 0; i < pts.length - 1; i++) {
            var p0 = pts[Math.max(i - 1, 0)];
            var p1 = pts[i];
            var p2 = pts[i + 1];
            var p3 = pts[Math.min(i + 2, pts.length - 1)];
            var cp1x = p1.x + (p2.x - p0.x) / 6;
            var cp1y = Math.min(p1.y + (p2.y - p0.y) / 6, MT + cH);
            var cp2x = p2.x - (p3.x - p1.x) / 6;
            var cp2y = Math.min(p2.y - (p3.y - p1.y) / 6, MT + cH);
            d += " C" + cp1x.toFixed(1) + "," + cp1y.toFixed(1)
               + " "  + cp2x.toFixed(1) + "," + cp2y.toFixed(1)
               + " "  + p2.x.toFixed(1) + "," + p2.y.toFixed(1);
        }
        return d;
    }

    // Cap the rendered height so the chart never dominates the dashboard,
    // even on very wide cards. width:100% keeps it responsive horizontally.
    var svg = '<svg viewBox="0 0 ' + W + ' ' + H + '" preserveAspectRatio="xMidYMid meet" style="width:100%;max-height:280px;display:block">';

    // Grid lines + Y labels (5 levels)
    for (var g = 0; g <= 4; g++) {
        var gy = MT + cH - (g / 4 * cH);
        svg += '<line x1="' + ML + '" y1="' + gy + '" x2="' + (W - MR) + '" y2="' + gy + '" stroke="#e2e8f0" stroke-width="0.6"/>';
        svg += '<text x="' + (ML - 4) + '" y="' + (gy + 4) + '" text-anchor="end" font-size="10" fill="#94a3b8">' + Math.round(g / 4 * maxVal) + '</text>';
    }

    // One smooth thin line per severity, painted from low → critical so
    // critical is on top and never gets visually overwritten by lighter
    // shades crossing through it.
    _SEV_ORDER.slice().reverse().forEach(function(sev) {
        var pts = days.map(function(d, i) {
            return { x: xFor(i), y: yFor(d[sev] || 0) };
        });
        if (pts.length < 2) return;
        var sw = sev === "critical" ? 1.8 : 1.4;
        svg += '<path d="' + smoothPath(pts) + '" fill="none" stroke="' + colors[sev] + '" stroke-width="' + sw + '" stroke-linecap="round" stroke-linejoin="round"/>';
    });

    // Triaged cumulative — distinct from severities (dashed gray-blue)
    var tcum = 0, maxCum = 1;
    var triagedPoints = days.map(function(d) { tcum += d.triaged; if (tcum > maxCum) maxCum = tcum; return tcum; });
    if (tcum > 0) {
        var linePts = triagedPoints.map(function(y, i) {
            return { x: xFor(i), y: MT + cH - (y / maxCum) * cH };
        });
        svg += '<path d="' + smoothPath(linePts) + '" fill="none" stroke="#94a3b8" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round" stroke-dasharray="4,3"/>';
    }

    // X axis labels (every ~5 days)
    days.forEach(function(d, i) {
        if (i % 5 !== 0 && i !== days.length - 1) return;
        svg += '<text x="' + xFor(i).toFixed(1) + '" y="' + (H - MB + 16) + '" text-anchor="middle" font-size="10" fill="#94a3b8">' + esc(d.label) + '</text>';
    });

    svg += '</svg>';

    var legend = '<div class="dash-timeline-legend" style="display:flex;gap:10px;justify-content:center;margin-top:4px;font-size:0.72em;flex-wrap:wrap">';
    _SEV_ORDER.forEach(function(sev) {
        var h = sev === "critical" ? 3 : 2;
        legend += '<span style="display:flex;align-items:center;gap:4px">' +
            '<span style="width:16px;height:' + h + 'px;border-radius:1px;background:' + colors[sev] + '"></span>' +
            esc(t("sev." + sev)) +
            '</span>';
    });
    legend += '<span style="display:flex;align-items:center;gap:3px">' +
        '<span style="width:14px;height:0;border-top:1px dashed #94a3b8"></span>' +
        esc(t("dash.timeline_triaged")) +
        '</span>';
    legend += '</div>';

    return '<div class="dash-card dash-card-full">' +
        '<div class="dash-card-head">' + _icon("activity", 16) + ' ' + esc(t("dash.timeline_title")) + '</div>' +
        svg + legend +
        '</div>';
}

// ── Top hosts ─────────────────────────────────────────────────
function _dashTopHosts() {
    var rows = _topHostsByFindings(5);
    var h = '<div class="dash-card">';
    h += '<div class="dash-card-head">' + _icon("server", 16) + ' ' + esc(t("dash.top_hosts")) + '</div>';
    if (!rows.length) {
        h += '<div class="dash-empty">' + esc(t("dash.no_active_findings")) + '</div>';
    } else {
        h += '<div class="dash-list">';
        rows.forEach(function(row) {
            var sev = _SEV_ORDER[row.maxSev] || "info";
            var clickable = row.id ? ' data-click="_openHost" data-args=\'' + _da(row.id) + '\'' : '';
            h += '<div class="dash-list-row"' + clickable + '>';
            h += '<span class="sev-badge sev-' + sev + '">' + esc(sev) + '</span>';
            h += '<span class="dash-list-main" title="' + esc(row.host) + '">' + esc(row.host) + '</span>';
            h += '<span class="dash-list-count">' + row.total + '</span>';
            h += '</div>';
        });
        h += '</div>';
    }
    h += '</div>';
    return h;
}

function _dashTopTypes() {
    var rows = _topFindingTypes(5);
    var h = '<div class="dash-card">';
    h += '<div class="dash-card-head">' + _icon("zap", 16) + ' ' + esc(t("dash.top_types")) + '</div>';
    if (!rows.length) {
        h += '<div class="dash-empty">' + esc(t("dash.no_active_findings")) + '</div>';
    } else {
        h += '<div class="dash-list">';
        rows.forEach(function(row) {
            h += '<div class="dash-list-row">';
            h += '<span class="dash-list-main" title="' + esc(row.type) + '">' + esc(row.type) + '</span>';
            h += '<span class="dash-list-count">' + row.count + '</span>';
            h += '</div>';
        });
        h += '</div>';
    }
    h += '</div>';
    return h;
}

function _dashTopScanners() {
    var rows = _topScanners(5);
    var h = '<div class="dash-card">';
    h += '<div class="dash-card-head">' + _icon("target", 16) + ' ' + esc(t("dash.top_scanners")) + '</div>';
    if (!rows.length) {
        h += '<div class="dash-empty">' + esc(t("dash.no_findings")) + '</div>';
    } else {
        h += '<div class="dash-list">';
        rows.forEach(function(row) {
            h += '<div class="dash-list-row" data-click="_dashGotoScanner" data-args=\'' + _da(row.scanner) + '\'>';
            h += '<span class="dash-list-main">' + esc(row.scanner) + '</span>';
            h += '<span class="dash-list-count">' + row.count + '</span>';
            h += '</div>';
        });
        h += '</div>';
    }
    h += '</div>';
    return h;
}

// ── Surface inventory ─────────────────────────────────────────
function _dashSurface() {
    var inv = _surfaceInventory();
    var total = inv.totalAssets;
    var h = '<div class="dash-card">';
    h += '<div class="dash-card-head">' + _icon("globe", 16) + ' ' + esc(t("dash.surface_title")) + '</div>';

    // Bars per kind
    var kinds = [
        { k: "domain", color: "#3b82f6", v: inv.byKind.domain },
        { k: "host", color: "#10b981", v: inv.byKind.host },
        { k: "ip_range", color: "#8b5cf6", v: inv.byKind.ip_range },
    ];
    h += '<div class="dash-surface-bars">';
    kinds.forEach(function(row) {
        var pct = total ? (row.v / total * 100) : 0;
        h += '<div class="dash-surface-row">';
        h += '<span class="dash-surface-lbl">' + esc(t("kind." + row.k)) + '</span>';
        h += '<div class="dash-bar-bg"><div class="dash-bar-fill" style="width:' + pct + '%;background:' + row.color + '"></div></div>';
        h += '<span class="dash-surface-count">' + row.v + '</span>';
        h += '</div>';
    });
    h += '</div>';

    // Hosts source split
    var src = inv.hostsSource;
    var srcTotal = src.auto + src.manual;
    h += '<div class="dash-surface-sub">' + esc(t("dash.hosts_source")) + '</div>';
    h += '<div class="dash-surface-bars">';
    h += '<div class="dash-surface-row">';
    h += '<span class="dash-surface-lbl">' + esc(t("hosts.source.auto")) + '</span>';
    h += '<div class="dash-bar-bg"><div class="dash-bar-fill" style="width:' + (srcTotal ? src.auto / srcTotal * 100 : 0) + '%;background:#a855f7"></div></div>';
    h += '<span class="dash-surface-count">' + src.auto + '</span>';
    h += '</div>';
    h += '<div class="dash-surface-row">';
    h += '<span class="dash-surface-lbl">' + esc(t("hosts.source.manual")) + '</span>';
    h += '<div class="dash-bar-bg"><div class="dash-bar-fill" style="width:' + (srcTotal ? src.manual / srcTotal * 100 : 0) + '%;background:#60a5fa"></div></div>';
    h += '<span class="dash-surface-count">' + src.manual + '</span>';
    h += '</div>';
    h += '</div>';

    h += '</div>';
    return h;
}

// ── Measures burndown ────────────────────────────────────────
function _dashMeasures() {
    var m = _measuresStats();
    var h = '<div class="dash-card">';
    h += '<div class="dash-card-head">' + _icon("check_circle", 16) + ' ' + esc(t("dash.measures_title")) + '</div>';

    var total = m.total || 1;
    // Stacked bar: a_faire / en_cours / termine
    var segments = [
        { key: "a_faire", label: t("measures.status.a_faire"), color: "#f59e0b", v: m.byStatus.a_faire },
        { key: "en_cours", label: t("measures.status.en_cours"), color: "#3b82f6", v: m.byStatus.en_cours },
        { key: "termine", label: t("measures.status.termine"), color: "#16a34a", v: m.byStatus.termine },
    ];
    h += '<div class="dash-burndown">';
    h += '<div class="dash-burndown-bar">';
    segments.forEach(function(s) {
        var pct = m.total ? (s.v / m.total * 100) : 0;
        if (pct > 0) {
            h += '<div class="dash-burndown-seg" style="width:' + pct + '%;background:' + s.color + '" title="' + esc(s.label) + ': ' + s.v + '"></div>';
        }
    });
    h += '</div>';
    h += '<div class="dash-burndown-legend">';
    segments.forEach(function(s) {
        h += '<span class="dash-legend-item"><span class="dash-legend-sq" style="background:' + s.color + '"></span>' + esc(s.label) + ' <strong>' + s.v + '</strong></span>';
    });
    h += '</div>';
    h += '</div>';

    // Weekly delta
    var delta = m.doneThisWeek - m.createdThisWeek;
    var deltaCls = delta > 0 ? "positive" : delta < 0 ? "negative" : "";
    h += '<div class="dash-measures-delta">';
    h += '<div class="dash-measures-stat"><strong>' + m.createdThisWeek + '</strong> ' + esc(t("dash.measures_created_7d")) + '</div>';
    h += '<div class="dash-measures-stat"><strong>' + m.doneThisWeek + '</strong> ' + esc(t("dash.measures_done_7d")) + '</div>';
    h += '<div class="dash-measures-stat ' + deltaCls + '"><strong>' + (delta >= 0 ? "+" : "") + delta + '</strong> ' + esc(t("dash.measures_delta")) + '</div>';
    h += '</div>';

    if (m.overdue.length) {
        h += '<div class="dash-measures-overdue">';
        h += '<div class="dash-overdue-head">' + _icon("alert", 14) + ' ' + esc(t("dash.measures_overdue")).replace("{n}", m.overdue.length) + '</div>';
        m.overdue.slice(0, 3).forEach(function(mm) {
            h += '<div class="dash-overdue-row">';
            h += '<span class="dash-overdue-id">' + esc(mm.id) + '</span>';
            h += '<span class="dash-overdue-title">' + esc(mm.title) + '</span>';
            h += '<span class="dash-overdue-date">' + esc(mm.echeance) + '</span>';
            h += '</div>';
        });
        h += '</div>';
    }

    h += '</div>';
    return h;
}

// ── Scanner health ───────────────────────────────────────────
function _dashHealth() {
    var hs = _schedulerHealth();
    var h = '<div class="dash-card">';
    h += '<div class="dash-card-head">' + _icon("clock", 16) + ' ' + esc(t("dash.health_title")) + '</div>';

    var rateCls = hs.successRate == null ? "" : hs.successRate >= 90 ? "positive" : hs.successRate >= 70 ? "warning" : "negative";
    h += '<div class="dash-health-stats">';
    h += '<div class="dash-health-row"><span>' + esc(t("dash.health_jobs_24h")) + '</span><strong>' + hs.total24 + '</strong></div>';
    h += '<div class="dash-health-row"><span>' + esc(t("dash.health_success_rate")) + '</span><strong class="' + rateCls + '">' + (hs.successRate == null ? "—" : hs.successRate + "%") + '</strong></div>';
    h += '<div class="dash-health-row"><span>' + esc(t("dash.health_failed_24h")) + '</span><strong class="' + (hs.failed ? "negative" : "") + '">' + hs.failed + '</strong></div>';
    h += '<div class="dash-health-row"><span>' + esc(t("dash.health_running")) + '</span><strong>' + hs.running + '</strong></div>';
    h += '</div>';

    if (hs.lastJob) {
        var last = (hs.lastJob.created_at || "").substring(0, 16).replace("T", " ");
        h += '<div class="dash-health-last"><span class="text-muted">' + esc(t("dash.health_last_job")) + '</span> ' + esc(last) + ' <span class="text-muted">(' + esc(_scannerLabel(hs.lastJob.scanner)) + ')</span></div>';
    }

    if (hs.nextAsset) {
        var nextStr = hs.nextInHours === 0 ? t("monitored.next.imminent") : ("~" + hs.nextInHours + " h");
        h += '<div class="dash-health-next"><span class="text-muted">' + esc(t("dash.health_next")) + '</span> <span class="mono">' + esc(hs.nextAsset.value) + '</span> ' + nextStr + '</div>';
    }

    h += '</div>';
    return h;
}

// ── Coverage gaps ────────────────────────────────────────────
function _dashGaps() {
    var g = _coverageGaps();
    var h = '<div class="dash-card">';
    h += '<div class="dash-card-head">' + _icon("alert", 16) + ' ' + esc(t("dash.gaps_title")) + '</div>';

    // Counters
    h += '<div class="dash-gaps-counts">';
    h += '<div class="dash-gap-tile' + (g.staleHosts.length ? " warning" : "") + '" data-click="_dashShowStale">';
    h += '<div class="dash-gap-val">' + g.staleHosts.length + '</div>';
    h += '<div class="dash-gap-lbl">' + esc(t("dash.gaps_stale_hosts")) + '</div>';
    h += '</div>';
    h += '<div class="dash-gap-tile' + (g.sparseHosts.length ? " warning" : "") + '">';
    h += '<div class="dash-gap-val">' + g.sparseHosts.length + '</div>';
    h += '<div class="dash-gap-lbl">' + esc(t("dash.gaps_sparse_hosts")) + '</div>';
    h += '</div>';
    h += '<div class="dash-gap-tile' + (g.disabledLong.length ? " muted" : "") + '">';
    h += '<div class="dash-gap-val">' + g.disabledLong.length + '</div>';
    h += '<div class="dash-gap-lbl">' + esc(t("dash.gaps_disabled_long")) + '</div>';
    h += '</div>';
    h += '</div>';

    if (g.staleHosts.length) {
        h += '<div class="dash-gaps-sub">' + esc(t("dash.gaps_stale_list")) + '</div>';
        h += '<div class="dash-list">';
        g.staleHosts.slice(0, 5).forEach(function(row) {
            var ageStr = row.age === Infinity ? t("monitored.last.never") : (row.age + " j");
            h += '<div class="dash-list-row" data-click="_openHost" data-args=\'' + _da(row.id) + '\'>';
            h += '<span class="dash-list-main mono" title="' + esc(row.host) + '">' + esc(row.host) + '</span>';
            h += '<span class="dash-list-count">' + esc(ageStr) + '</span>';
            h += '</div>';
        });
        h += '</div>';
    }

    h += '</div>';
    return h;
}

// ── Navigation helpers ───────────────────────────────────────
window._dashGotoSeverity = function(sev) {
    _filterStatus = "new";
    _filterSeverities = [sev];
    _filterScanners = [];
    _findingsSearch = "";
    selectPanel("findings");
};
window._dashGotoRecent = function() {
    _filterStatus = "";
    _filterSeverities = [];
    _filterScanners = [];
    _findingsSearch = "";
    selectPanel("findings");
};
window._dashGotoScanner = function(scanner) {
    _filterStatus = "";
    _filterSeverities = [];
    _filterScanners = [scanner];
    _findingsSearch = "";
    selectPanel("findings");
};
window._dashShowStale = function() {
    selectPanel("hosts");
};

// ═══════════════════════════════════════════════════════════════
// FINDINGS
// ═══════════════════════════════════════════════════════════════
function _renderFindings(c) {
    if (_selectedFinding) { _renderFindingDetail(c); return; }

    // Header (title + action buttons) and search bar are rendered ONCE.
    // The pills + table + bulk bar live inside #findings-body-wrap and are
    // refreshed by _refreshFindingsBody() on every filter/search change,
    // leaving the search input alive in the DOM so focus/caret is preserved.
    var h = '<div style="display:flex;align-items:center;gap:8px;margin-bottom:12px;flex-wrap:wrap">';
    h += '<h2 style="margin:0">' + esc(t("findings.title")) + '</h2>';
    h += '<span style="flex:1"></span>';
    h += '<button class="btn-add btn-icon" style="background:#dc2626;color:white" data-click="_quickScanDialog">' + _icon("search", 14) + ' ' + esc(t("findings.quick_scan")) + '</button>';
    h += '<button class="btn-add btn-icon" data-click="_bulkImportDialog">' + _icon("list", 14) + ' ' + esc(t("findings.bulk_import")) + '</button>';
    h += '</div>';

    h += '<div class="surface-filters" style="margin-bottom:12px">';
    h += '<input type="text" class="surface-filter" placeholder="' + esc(t("findings.search.placeholder")) + '" style="min-width:320px;flex:1"';
    h += ' id="findings-search" value="' + esc(_findingsSearch) + '" data-input="_setFindingsSearch" data-pass-value autocomplete="off">';
    h += '<button class="btn-add" id="findings-search-clear" data-click="_clearFindingsSearch"' + (_findingsSearch ? '' : ' style="display:none"') + '>x</button>';
    h += '</div>';

    h += '<div id="findings-body-wrap"></div>';

    c.innerHTML = h;
    _refreshFindingsBody();
}

function _refreshFindingsBody() {
    var wrap = document.getElementById("findings-body-wrap");
    if (!wrap) return;

    // Build distinct scanner list from current data
    var scannerSetFindings = {};
    _findings.forEach(function(f) { if (f.scanner) scannerSetFindings[f.scanner] = true; });
    var scannerList = Object.keys(scannerSetFindings).sort();

    var h = "";

    // ── Status filter pills ────────────────────────────────
    var statusOptions = [
        { v: "new",            key: "status.to_triage" },
        { v: "to_fix",         key: "status.to_fix" },
        { v: "false_positive", key: "dash.false_positive" },
        { v: "fixed",          key: "status.fixed" },
        { v: "",               key: "status.all" }
    ];
    h += '<div class="filter-pills-row">';
    h += '<span class="filter-pills-lbl">' + esc(t("findings.filter.status")) + '</span>';
    statusOptions.forEach(function(opt) {
        var on = _filterStatus === opt.v;
        h += '<button type="button" class="filter-pill status-pill-' + (opt.v || "all") + (on ? " active" : "") + '" data-click="_setStatusFilter" data-args=\'' + _da(opt.v) + '\'>' + esc(t(opt.key)) + '</button>';
    });
    h += '</div>';

    // ── Severity multi-select pills ────────────────────────
    h += '<div class="filter-pills-row">';
    h += '<span class="filter-pills-lbl">' + esc(t("findings.filter.severity")) + '</span>';
    ["critical", "high", "medium", "low", "info"].forEach(function(s) {
        var on = _filterSeverities.indexOf(s) >= 0;
        h += '<button type="button" class="filter-pill sev-' + s + (on ? " active" : "") + '" data-click="_toggleSeverity" data-args=\'' + _da(s) + '\'>' + esc(t("sev." + s)) + '</button>';
    });
    if (_filterSeverities.length) {
        h += '<button type="button" class="filter-pill filter-pill-clear" data-click="_clearSeverityFilter">' + esc(t("findings.filter.reset")) + '</button>';
    } else {
        h += '<span class="filter-pills-hint">' + esc(t("findings.filter.hint")) + '</span>';
    }
    h += '</div>';

    // ── Scanner multi-select pills ─────────────────────────
    if (scannerList.length) {
        h += '<div class="filter-pills-row">';
        h += '<span class="filter-pills-lbl">' + esc(t("findings.filter.scanner")) + '</span>';
        scannerList.forEach(function(s) {
            var on = _filterScanners.indexOf(s) >= 0;
            h += '<button type="button" class="filter-pill' + (on ? " active" : "") + '" data-click="_toggleScanner" data-args=\'' + _da(s) + '\'>' + esc(_scannerLabel(s)) + '</button>';
        });
        if (_filterScanners.length) {
            h += '<button type="button" class="filter-pill filter-pill-clear" data-click="_clearScannerFilter">' + esc(t("findings.filter.reset")) + '</button>';
        } else {
            h += '<span class="filter-pills-hint">' + esc(t("findings.filter.hint_m")) + '</span>';
        }
        h += '</div>';
    }

    var searchQ = _findingsSearch.trim().toLowerCase();
    var filtered = _findings.filter(function(f) {
        if (_filterStatus && f.status !== _filterStatus) return false;
        if (_filterSeverities.length && _filterSeverities.indexOf(f.severity) < 0) return false;
        if (_filterScanners.length && _filterScanners.indexOf(f.scanner) < 0) return false;
        if (searchQ) {
            var hay = ((f.title || "") + " " + (f.target || "") + " " + (f.description || "") + " " + (f.scanner || "") + " " + (f.type || "")).toLowerCase();
            if (hay.indexOf(searchQ) < 0) return false;
        }
        return true;
    });

    h += '<div style="font-size:0.78em;color:var(--text-muted);margin-bottom:8px">' + filtered.length + ' / ' + _findings.length + ' ' + esc(t("findings.count")) + '</div>';

    if (!filtered.length) {
        h += '<div class="empty-state">' + esc(t("findings.empty")) + '</div>';
        wrap.innerHTML = h;
        return;
    }

    // Prune the bulk selection to only IDs still in the filtered view
    var filteredIds = {};
    filtered.forEach(function(f) { filteredIds[f.id] = true; });
    Object.keys(_bulkSelection).forEach(function(id) {
        if (!filteredIds[id]) delete _bulkSelection[id];
    });
    var selectedCount = Object.keys(_bulkSelection).length;
    var allChecked = filtered.length > 0 && filtered.every(function(f) { return _bulkSelection[f.id]; });

    h += '<div class="findings-scroll"><table class="surface-table findings-table"><thead><tr>';
    h += '<th><input type="checkbox" id="bulk-select-all"' + (allChecked ? " checked" : "") + ' data-change="_toggleBulkAll" data-pass-value></th>';
    h += '<th>' + esc(t("findings.col.severity")) + '</th>';
    h += '<th>' + esc(t("findings.col.type")) + '</th>';
    h += '<th>' + esc(t("findings.col.title")) + '</th>';
    h += '<th>' + esc(t("findings.col.target")) + '</th>';
    h += '<th>' + esc(t("findings.col.status")) + '</th>';
    h += '<th>' + esc(t("findings.col.datetime")) + '</th>';
    h += '<th></th></tr></thead><tbody>';
    filtered.forEach(function(f) {
        var checked = _bulkSelection[f.id] ? " checked" : "";
        var dateDisplay = f.created_at ? (f.created_at.substring(0, 16).replace("T", " ")) : "-";
        h += '<tr class="finding-row sev-' + esc(f.severity) + ' status-' + esc(f.status) + '" data-click="_openFinding" data-args=\'' + _da(f.id) + '\'>';
        h += '<td data-stop><input type="checkbox" class="bulk-check"' + checked + ' data-click="_toggleBulkOne" data-args=\'' + _da(f.id) + '\' data-stop></td>';
        h += '<td><span class="sev-badge sev-' + esc(f.severity) + '">' + esc(f.severity) + '</span></td>';
        h += '<td style="font-size:0.82em;color:var(--text-muted)">' + esc(f.type) + '</td>';
        h += '<td style="font-weight:600">' + esc(f.title) + '</td>';
        h += '<td style="font-size:0.82em;color:var(--text-muted)">' + esc(f.target || "-") + '</td>';
        h += '<td><span class="status-badge status-' + esc(f.status) + '">' + _statusLabel(f.status) + '</span></td>';
        h += '<td style="font-size:0.78em;color:var(--text-muted);white-space:nowrap">' + esc(dateDisplay) + '</td>';
        h += '<td style="white-space:nowrap">';
        if (f.status !== "to_fix") h += '<button class="btn-mini btn-fix" data-click="_quickTriage" data-args=\'' + _da(f.id, "to_fix") + '\' data-stop title="' + esc(t("status.to_fix")) + '">' + _icon("check", 14) + '</button> ';
        if (f.status !== "false_positive") h += '<button class="btn-mini btn-fp" data-click="_quickTriage" data-args=\'' + _da(f.id, "false_positive") + '\' data-stop title="' + esc(t("status.false_positive")) + '">' + _icon("x", 14) + '</button>';
        h += '</td>';
        h += '</tr>';
    });
    h += '</tbody></table></div>';

    if (selectedCount > 0) {
        h += '<div class="bulk-action-bar">';
        h += '<span class="bulk-count">' + selectedCount + ' ' + esc(t("bulk.selected")) + '</span>';
        h += '<button class="btn-add btn-fp btn-icon" data-click="_bulkFalsePositiveDialog">' + _icon("x", 14) + ' ' + esc(t("bulk.false_positive")) + '</button>';
        h += '<button class="btn-add btn-fix btn-icon" data-click="_bulkToFixDialog">' + _icon("check", 14) + ' ' + esc(t("bulk.to_fix")) + '</button>';
        h += '<button class="btn-add btn-icon" style="background:#dc2626;color:white" data-click="_bulkDelete">' + _icon("trash", 14) + ' ' + esc(t("bulk.delete")) + '</button>';
        h += '<span style="flex:1"></span>';
        h += '<button class="btn-add" data-click="_bulkClearSelection">' + esc(t("bulk.clear")) + '</button>';
        h += '</div>';
    }

    wrap.innerHTML = h;
}

window._toggleBulkAll = function(v) {
    // v is the checkbox .value ('on') — use the state via event target instead
    var el = document.getElementById("bulk-select-all");
    var checked = el && el.checked;
    var searchQ = _findingsSearch.trim().toLowerCase();
    var filtered = _findings.filter(function(f) {
        if (_filterStatus && f.status !== _filterStatus) return false;
        if (_filterSeverities.length && _filterSeverities.indexOf(f.severity) < 0) return false;
        if (_filterScanners.length && _filterScanners.indexOf(f.scanner) < 0) return false;
        if (searchQ) {
            var hay = ((f.title || "") + " " + (f.target || "") + " " + (f.description || "") + " " + (f.scanner || "") + " " + (f.type || "")).toLowerCase();
            if (hay.indexOf(searchQ) < 0) return false;
        }
        return true;
    });
    if (checked) {
        filtered.forEach(function(f) { _bulkSelection[f.id] = true; });
    } else {
        _bulkSelection = {};
    }
    renderPanel();
};

window._toggleBulkOne = function(id) {
    if (_bulkSelection[id]) delete _bulkSelection[id];
    else _bulkSelection[id] = true;
    renderPanel();
};

window._bulkClearSelection = function() {
    _bulkSelection = {};
    renderPanel();
};

// ── Bulk triage modals ─────────────────────────────────────────

function _ensureBulkModal() {
    var ov = document.getElementById("bulk-overlay");
    if (ov) return ov;
    ov = document.createElement("div");
    ov.id = "bulk-overlay";
    ov.className = "ct-modal-overlay";
    ov.innerHTML =
        '<div class="ct-modal">' +
            '<div class="ct-modal-header"><span id="bulk-modal-title"></span><button class="ct-modal-close" data-click="_closeBulkModal">' + _icon("x", 18) + '</button></div>' +
            '<div class="ct-modal-body" id="bulk-modal-body"></div>' +
            '<div class="ct-modal-footer">' +
                '<button class="btn-add" data-click="_closeBulkModal">Annuler</button>' +
                '<button class="btn-add" id="bulk-confirm-btn" data-click="_submitBulk">Confirmer</button>' +
            '</div>' +
        '</div>';
    document.body.appendChild(ov);
    ov.addEventListener("click", function(e) { if (e.target === ov) _closeBulkModal(); });
    return ov;
}

window._closeBulkModal = function() {
    var ov = document.getElementById("bulk-overlay");
    if (ov) ov.classList.remove("open");
};

var _bulkModalContext = null;  // {action: "to_fix" | "false_positive", ids: [...]}

window._bulkFalsePositiveDialog = function() {
    var ids = Object.keys(_bulkSelection);
    if (!ids.length) return;
    _bulkModalContext = { action: "false_positive", ids: ids };
    var ov = _ensureBulkModal();
    document.getElementById("bulk-modal-title").textContent = _tn("bulk.fp_title", ids.length);
    var btn = document.getElementById("bulk-confirm-btn");
    btn.disabled = false;  // reset from any previous submit attempt
    btn.textContent = _tn("bulk.fp_confirm", ids.length);
    btn.style.background = "#6b7280";
    btn.style.color = "white";
    document.getElementById("bulk-modal-body").innerHTML =
        '<div style="font-size:0.82em;color:var(--text-muted);margin-bottom:12px">' + esc(_tn("bulk.fp_help", ids.length)) + '</div>' +
        '<div class="ct-field"><label class="ct-field-lbl">' + esc(t("bulk.fp_justification")) + '</label>' +
            '<textarea class="ct-input" id="bulk-fp-notes" rows="5" placeholder="' + esc(t("bulk.fp_placeholder")) + '"></textarea>' +
        '</div>' +
        '<div class="ct-error" id="bulk-error" style="display:none"></div>';
    ov.classList.add("open");
    setTimeout(function() { var el = document.getElementById("bulk-fp-notes"); if (el) el.focus(); }, 50);
};

window._bulkToFixDialog = function() {
    var ids = Object.keys(_bulkSelection);
    if (!ids.length) return;
    _bulkModalContext = { action: "to_fix", ids: ids };
    var ov = _ensureBulkModal();
    document.getElementById("bulk-modal-title").textContent = _tn("bulk.measure_title", ids.length);
    var btn = document.getElementById("bulk-confirm-btn");
    btn.disabled = false;  // reset from any previous submit attempt
    btn.textContent = _tn("bulk.measure_confirm", ids.length);
    btn.style.background = "#16a34a";
    btn.style.color = "white";
    document.getElementById("bulk-modal-body").innerHTML =
        '<div style="font-size:0.82em;color:var(--text-muted);margin-bottom:12px">' + esc(_tn("bulk.measure_help", ids.length)) + '</div>' +
        '<div class="ct-field"><label class="ct-field-lbl">' + esc(t("bulk.measure_name")) + '</label>' +
            '<input type="text" class="ct-input" id="bulk-measure-title" placeholder="' + esc(t("bulk.measure_name_ph")) + '">' +
        '</div>' +
        '<div class="ct-field"><label class="ct-field-lbl">' + esc(t("bulk.measure_desc")) + '</label>' +
            '<textarea class="ct-input" id="bulk-measure-desc" rows="4" placeholder="' + esc(t("bulk.measure_desc_ph")) + '"></textarea>' +
        '</div>' +
        '<div class="ct-field"><label class="ct-field-lbl">' + esc(t("bulk.measure_resp")) + '</label>' +
            '<input type="text" class="ct-input" id="bulk-measure-resp" placeholder="' + esc(t("bulk.measure_resp_ph")) + '">' +
        '</div>' +
        '<div class="ct-field"><label class="ct-field-lbl">' + esc(t("bulk.measure_due")) + '</label>' +
            '<input type="date" class="ct-input" id="bulk-measure-due">' +
        '</div>' +
        '<div class="ct-error" id="bulk-error" style="display:none"></div>';
    ov.classList.add("open");
    setTimeout(function() { var el = document.getElementById("bulk-measure-title"); if (el) el.focus(); }, 50);
};

window._submitBulk = function() {
    if (!_bulkModalContext) return;
    var ctx = _bulkModalContext;
    var err = document.getElementById("bulk-error");
    if (err) err.style.display = "none";
    var payload = { ids: ctx.ids, status: ctx.action };

    if (ctx.action === "false_positive") {
        var notes = (document.getElementById("bulk-fp-notes").value || "").trim();
        if (!notes) {
            err.textContent = t("tm.justif_required");
            err.style.display = "block";
            return;
        }
        payload.notes = notes;
    } else if (ctx.action === "to_fix") {
        var title = (document.getElementById("bulk-measure-title").value || "").trim();
        if (!title) {
            err.textContent = t("tm.name_required");
            err.style.display = "block";
            return;
        }
        payload.measure_title = title;
        payload.measure_description = (document.getElementById("bulk-measure-desc").value || "").trim();
        payload.responsable = (document.getElementById("bulk-measure-resp").value || "").trim();
        payload.echeance = (document.getElementById("bulk-measure-due").value || "").trim();
    }

    var btn = document.getElementById("bulk-confirm-btn");
    if (btn) { btn.disabled = true; btn.textContent = "..."; }

    SurfaceAPI.bulkTriageFindings(payload).then(function(r) {
        _closeBulkModal();
        _bulkSelection = {};
        _bulkModalContext = null;
        showStatus(r.updated + " finding(s) mis a jour" + (r.measures_created ? ", " + r.measures_created + " mesure(s) creee(s)" : ""));
        _loadAndRender();
    }).catch(function(e) {
        if (err) {
            err.textContent = e.message || t("common.error");
            err.style.display = "block";
        }
        if (btn) { btn.disabled = false; btn.textContent = t("action.confirm"); }
    });
};

window._bulkDelete = function() {
    var ids = Object.keys(_bulkSelection);
    if (!ids.length) return;
    if (!confirm(_tn("bulk.delete_confirm", ids.length))) return;
    SurfaceAPI.bulkDeleteFindings(ids).then(function(r) {
        showStatus(r.deleted + " finding(s) supprime(s)");
        _bulkSelection = {};
        _loadAndRender();
    }).catch(function(e) {
        showStatus(e.message || t("common.error"), true);
    });
};

function _statusLabel(s) {
    return t("status." + s) || s;
}

// All findings filter toggles refresh ONLY the body wrapper, leaving the
// search input alive so keyboard focus/caret stays with the user.
window._setStatusFilter = function(v) { _filterStatus = v || ""; _refreshFindingsBody(); };
window._setFindingsSearch = function(v) {
    _findingsSearch = v || "";
    _refreshFindingsBody();
    var clearBtn = document.getElementById("findings-search-clear");
    if (clearBtn) clearBtn.style.display = _findingsSearch ? "" : "none";
};
window._clearFindingsSearch = function() {
    _findingsSearch = "";
    var inp = document.getElementById("findings-search");
    if (inp) inp.value = "";
    _refreshFindingsBody();
    var clearBtn = document.getElementById("findings-search-clear");
    if (clearBtn) clearBtn.style.display = "none";
    if (inp) inp.focus();
};
window._toggleSeverity = function(s) {
    var i = _filterSeverities.indexOf(s);
    if (i >= 0) _filterSeverities.splice(i, 1);
    else _filterSeverities.push(s);
    _refreshFindingsBody();
};
window._clearSeverityFilter = function() { _filterSeverities = []; _refreshFindingsBody(); };
window._toggleScanner = function(s) {
    var i = _filterScanners.indexOf(s);
    if (i >= 0) _filterScanners.splice(i, 1);
    else _filterScanners.push(s);
    _refreshFindingsBody();
};
window._clearScannerFilter = function() { _filterScanners = []; _refreshFindingsBody(); };

window._openFinding = function(id) {
    var f = _findings.find(function(x) { return x.id === id; });
    if (!f) return;
    _selectedFinding = f;
    renderPanel();
};

window._backToFindings = function() { _selectedFinding = null; renderPanel(); };

function _renderFindingDetail(c) {
    var f = _selectedFinding;
    var h = '<div style="display:flex;align-items:center;gap:8px;margin-bottom:12px;flex-wrap:wrap">';
    h += '<button class="btn-add btn-icon" data-click="_backToFindings">' + _icon("arrow_left", 14) + ' ' + esc(t("fd.back")) + '</button>';
    h += '<h2 style="margin:0;flex:1">' + esc(f.title) + '</h2>';
    h += '<span class="sev-badge sev-' + esc(f.severity) + '">' + esc(t("sev." + f.severity)) + '</span>';
    h += '<span class="status-badge status-' + esc(f.status) + '">' + _statusLabel(f.status) + '</span>';
    h += '</div>';

    h += '<div class="surface-card">';
    h += '<div class="surface-row"><div class="surface-lbl">' + esc(t("fd.scanner")) + '</div><div>' + esc(f.scanner) + '</div></div>';
    h += '<div class="surface-row"><div class="surface-lbl">' + esc(t("fd.type")) + '</div><div>' + esc(f.type) + '</div></div>';
    h += '<div class="surface-row"><div class="surface-lbl">' + esc(t("fd.target")) + '</div><div>' + esc(f.target || "-") + '</div></div>';
    h += '<div class="surface-row"><div class="surface-lbl">' + esc(t("fd.created")) + '</div><div>' + esc((f.created_at || "").substring(0, 19).replace("T", " ")) + '</div></div>';
    if (f.triaged_at) {
        h += '<div class="surface-row"><div class="surface-lbl">' + esc(t("fd.triaged")) + '</div><div>' + esc((f.triaged_at || "").substring(0, 19).replace("T", " ")) + ' ' + esc(t("fd.triaged_by")) + ' ' + esc(f.triaged_by || "?") + '</div></div>';
    }
    h += '<div class="surface-row"><div class="surface-lbl">' + esc(t("fd.description")) + '</div><div style="white-space:pre-wrap">' + esc(f.description || t("fd.description_none")) + '</div></div>';
    if (f.evidence && Object.keys(f.evidence).length) {
        h += '<div class="surface-row"><div class="surface-lbl">' + esc(t("fd.evidence")) + '</div><div><pre style="background:#f9fafb;padding:8px;border-radius:4px;font-size:0.75em;overflow:auto;max-height:240px">' + esc(JSON.stringify(f.evidence, null, 2)) + '</pre></div></div>';
    }
    if (f.triage_notes) {
        h += '<div class="surface-row"><div class="surface-lbl">' + esc(t("fd.notes")) + '</div><div style="white-space:pre-wrap">' + esc(f.triage_notes) + '</div></div>';
    }
    h += '</div>';

    h += '<div class="surface-card">';
    h += '<h3 style="margin-top:0;font-size:0.95em">' + esc(t("fd.triage")) + '</h3>';
    h += '<textarea id="triage-notes" placeholder="' + esc(t("fd.triage_notes_ph")) + '" style="width:100%;min-height:60px;padding:8px;border:1px solid var(--border);border-radius:4px;font-size:0.85em;margin-bottom:8px">' + esc(f.triage_notes || "") + '</textarea>';
    h += '<div style="display:flex;gap:8px;flex-wrap:wrap">';
    h += '<button class="btn-add btn-fix btn-icon" data-click="_triageDetail" data-args=\'["to_fix"]\'>' + _icon("check", 14) + ' ' + esc(t("fd.triage_to_fix")) + '</button>';
    h += '<button class="btn-add btn-fp btn-icon" data-click="_triageDetail" data-args=\'["false_positive"]\'>' + _icon("x", 14) + ' ' + esc(t("fd.triage_fp")) + '</button>';
    if (f.status !== "new") {
        h += '<button class="btn-add" data-click="_triageDetail" data-args=\'["new"]\'>' + esc(t("fd.triage_reset")) + '</button>';
    }
    h += '<span style="flex:1"></span>';
    h += '<button class="btn-add" style="background:#dc2626;color:white" data-click="_deleteFindingDetail">' + esc(t("fd.delete")) + '</button>';
    h += '</div>';
    h += '</div>';

    if (f.measure_id) {
        var m = _measures.find(function(x) { return x.id === f.measure_id; });
        if (m) {
            h += '<div class="surface-card">';
            h += '<h3 style="margin-top:0;font-size:0.95em">' + esc(t("fd.measure_linked")) + '</h3>';
            h += '<div style="font-weight:600">' + esc(m.id) + ' &mdash; ' + esc(m.title) + '</div>';
            h += '<div style="font-size:0.82em;color:var(--text-muted);margin-top:4px">' + esc(t("fd.measure_status")) + ' : ' + esc(t("measures.status." + m.statut) || m.statut) + (m.responsable ? ' &middot; ' + esc(t("fd.measure_owner")) + ' : ' + esc(m.responsable) : '') + (m.echeance ? ' &middot; ' + esc(t("fd.measure_due")) + ' : ' + esc(m.echeance) : '') + '</div>';
            h += '</div>';
        }
    }

    c.innerHTML = h;
}

// ── Triage modals ─────────────────────────────────────────────

var _triageContext = null;  // {id, status, finding}

function _ensureTriageModal() {
    var ov = document.getElementById("triage-overlay");
    if (ov) return ov;
    ov = document.createElement("div");
    ov.id = "triage-overlay";
    ov.className = "ct-modal-overlay";
    ov.innerHTML =
        '<div class="ct-modal">' +
            '<div class="ct-modal-header"><span id="triage-modal-title"></span><button class="ct-modal-close" data-click="_closeTriageModal">' + _icon("x", 18) + '</button></div>' +
            '<div class="ct-modal-body" id="triage-modal-body"></div>' +
            '<div class="ct-modal-footer">' +
                '<button class="btn-add" data-click="_closeTriageModal">' + esc(t("action.cancel")) + '</button>' +
                '<button class="btn-add" id="triage-confirm-btn" data-click="_submitTriage">' + esc(t("action.confirm")) + '</button>' +
            '</div>' +
        '</div>';
    document.body.appendChild(ov);
    ov.addEventListener("click", function(e) { if (e.target === ov) _closeTriageModal(); });
    return ov;
}

window._closeTriageModal = function() {
    var ov = document.getElementById("triage-overlay");
    if (ov) ov.classList.remove("open");
    _triageContext = null;
};

function _openTriageModal(finding, status) {
    _triageContext = { id: finding.id, status: status, finding: finding };
    var ov = _ensureTriageModal();
    var title = document.getElementById("triage-modal-title");
    var body = document.getElementById("triage-modal-body");
    var btn = document.getElementById("triage-confirm-btn");

    if (status === "to_fix") {
        title.textContent = t("tm.title_to_fix");
        btn.textContent = t("tm.confirm_to_fix");
        btn.style.background = "#16a34a";
        btn.style.color = "white";
        body.innerHTML =
            '<div style="font-size:0.82em;color:var(--text-muted);margin-bottom:12px"><strong>' + esc(t("tm.finding")) + '</strong> ' + esc(finding.title) + '</div>' +
            '<div class="ct-field"><label class="ct-field-lbl">' + esc(t("tm.measure_name")) + '</label>' +
                '<input type="text" class="ct-input" id="triage-measure-title" value="' + esc(finding.title) + '">' +
                '<div class="ct-field-help">' + esc(t("tm.measure_name_help")) + '</div>' +
            '</div>' +
            '<div class="ct-field"><label class="ct-field-lbl">' + esc(t("tm.measure_desc")) + '</label>' +
                '<textarea class="ct-input" id="triage-measure-desc" rows="5">' + esc(finding.description || "") + '</textarea>' +
            '</div>' +
            '<div class="ct-field"><label class="ct-field-lbl">' + esc(t("tm.measure_owner")) + '</label>' +
                '<input type="text" class="ct-input" id="triage-measure-resp" placeholder="' + esc(t("tm.measure_owner_ph")) + '">' +
            '</div>' +
            '<div class="ct-field"><label class="ct-field-lbl">' + esc(t("tm.measure_due")) + '</label>' +
                '<input type="date" class="ct-input" id="triage-measure-due">' +
            '</div>' +
            '<div class="ct-error" id="triage-error" style="display:none"></div>';
    } else if (status === "false_positive") {
        title.textContent = t("tm.title_fp");
        btn.textContent = t("tm.confirm_fp");
        btn.style.background = "#6b7280";
        btn.style.color = "white";
        body.innerHTML =
            '<div style="font-size:0.82em;color:var(--text-muted);margin-bottom:12px"><strong>' + esc(t("tm.finding")) + '</strong> ' + esc(finding.title) + '</div>' +
            '<div class="ct-field"><label class="ct-field-lbl">' + esc(t("tm.fp_justif")) + '</label>' +
                '<textarea class="ct-input" id="triage-fp-notes" rows="5" placeholder="' + esc(t("tm.fp_justif_ph")) + '"></textarea>' +
                '<div class="ct-field-help">' + esc(t("tm.fp_justif_help")) + '</div>' +
            '</div>' +
            '<div class="ct-error" id="triage-error" style="display:none"></div>';
    } else {
        // status reset to "new"
        title.textContent = t("tm.title_reset");
        btn.textContent = t("tm.confirm_reset");
        btn.style.background = "";
        btn.style.color = "";
        body.innerHTML =
            '<div style="font-size:0.85em">' + esc(t("tm.reset_help")) + '</div>' +
            '<div class="ct-error" id="triage-error" style="display:none"></div>';
    }

    ov.classList.add("open");
    setTimeout(function() {
        var first = body.querySelector("input[type=text], textarea");
        if (first) first.focus();
    }, 50);
}

window._submitTriage = function() {
    if (!_triageContext) return;
    var payload = { status: _triageContext.status };
    var err = document.getElementById("triage-error");
    err.style.display = "none";

    if (_triageContext.status === "to_fix") {
        var mTitle = (document.getElementById("triage-measure-title").value || "").trim();
        if (!mTitle) { err.textContent = t("tm.name_required"); err.style.display = "block"; return; }
        payload.measure_title = mTitle;
        payload.measure_description = (document.getElementById("triage-measure-desc").value || "").trim();
        payload.responsable = (document.getElementById("triage-measure-resp").value || "").trim();
        payload.echeance = (document.getElementById("triage-measure-due").value || "").trim();
    } else if (_triageContext.status === "false_positive") {
        var fpNotes = (document.getElementById("triage-fp-notes").value || "").trim();
        if (!fpNotes) { err.textContent = t("tm.justif_required"); err.style.display = "block"; return; }
        payload.notes = fpNotes;
    }

    SurfaceAPI.triageFinding(_triageContext.id, payload).then(function() {
        _closeTriageModal();
        showStatus(t("triage.status_prefix") + " " + _statusLabel(_triageContext ? _triageContext.status : payload.status));
        _selectedFinding = null;
        _loadAndRender();
    }).catch(function(e) {
        err.textContent = e.message || t("common.error");
        err.style.display = "block";
    });
};

window._triageDetail = function(status) {
    if (!_selectedFinding) return;
    _openTriageModal(_selectedFinding, status);
};

window._quickTriage = function(id, status) {
    var f = _findings.find(function(x) { return x.id === id; });
    if (!f) return;
    _openTriageModal(f, status);
};

window._deleteFindingDetail = function() {
    if (!_selectedFinding) return;
    if (!confirm(t("fd.delete_confirm"))) return;
    SurfaceAPI.deleteFinding(_selectedFinding.id).then(function() {
        _selectedFinding = null;
        showStatus(t("fd.deleted"));
        _loadAndRender();
    }).catch(function(e) { showStatus(e.message || t("common.error"), true); });
};

window._quickScanDialog = function() {
    var host = prompt(t("prompt.quick_scan_host"), "");
    if (!host) return;
    showStatus(t("mon_modal.scan_in_progress"));
    SurfaceAPI.quickScan(host).then(function(r) {
        showStatus(r.findings_created + " " + t("prompt.findings_on") + " " + r.target);
        _loadAndRender();
    }).catch(function(e) { showStatus(e.message || t("common.error"), true); });
};

// ── Bulk import modal ───────────────────────────────────────────
// A rich dialog that documents the expected JSON schema inline,
// offers a downloadable template, accepts either file upload or
// textarea paste, and validates the payload before sending.

var _IMPORT_TEMPLATE = [
    {
        scanner: "nmap",
        type: "open_port",
        severity: "high",
        title: "Port 3306 (MySQL) exposé sur db-prod.example.com",
        description: "MySQL 5.7 detecté avec authentification anonyme désactivée mais port ouvert en externe. Restreindre l'accès au sous-réseau administratif ou fermer le port.",
        target: "db-prod.example.com:3306",
        evidence: {
            port: 3306,
            service: "mysql",
            version: "5.7.38",
            banner: "5.7.38-log MySQL Community Server (GPL)"
        }
    },
    {
        scanner: "shodan",
        type: "exposed_service",
        severity: "medium",
        title: "Service RDP exposé sur Internet",
        description: "Shodan a observé un service RDP (3389) joignable depuis Internet. Recommandation : placer derrière un VPN ou un bastion.",
        target: "rdp.example.com",
        evidence: {
            port: 3389,
            source: "https://www.shodan.io/host/1.2.3.4"
        }
    },
    {
        scanner: "manual",
        type: "other",
        severity: "low",
        title: "En-tête HSTS manquant sur www.example.com",
        description: "Le site ne renvoie pas Strict-Transport-Security. Ajouter 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
        target: "www.example.com",
        evidence: {}
    }
];

function _bulkImportMarkup(tt) {
    var sampleJson = JSON.stringify(_IMPORT_TEMPLATE, null, 2);
    var h = "";
    // Format spec block
    h += '<div style="font-size:0.82em;color:var(--text-muted);margin-bottom:10px">' + esc(tt("bulk_import.intro")) + '</div>';

    h += '<details class="bulk-import-spec">';
    h += '<summary>' + esc(tt("bulk_import.spec_title")) + '</summary>';
    h += '<table class="bulk-import-table"><thead><tr><th>' + esc(tt("bulk_import.col_field")) + '</th><th>' + esc(tt("bulk_import.col_required")) + '</th><th>' + esc(tt("bulk_import.col_description")) + '</th></tr></thead><tbody>';
    var fields = [
        { name: "title", required: true,
          desc: tt("bulk_import.f_title") },
        { name: "severity", required: false,
          desc: tt("bulk_import.f_severity") },
        { name: "scanner", required: false,
          desc: tt("bulk_import.f_scanner") },
        { name: "type", required: false,
          desc: tt("bulk_import.f_type") },
        { name: "target", required: false,
          desc: tt("bulk_import.f_target") },
        { name: "description", required: false,
          desc: tt("bulk_import.f_description") },
        { name: "evidence", required: false,
          desc: tt("bulk_import.f_evidence") },
    ];
    fields.forEach(function(f) {
        h += '<tr>';
        h += '<td><code>' + esc(f.name) + '</code></td>';
        h += '<td style="text-align:center">' + (f.required ? '<span style="color:#dc2626;font-weight:600">*</span>' : '–') + '</td>';
        h += '<td>' + esc(f.desc) + '</td>';
        h += '</tr>';
    });
    h += '</tbody></table>';
    h += '<div style="font-size:0.75em;color:var(--text-muted);margin-top:6px">' + esc(tt("bulk_import.wrapper_note")) + '</div>';
    h += '</details>';

    // Sample + actions
    h += '<div class="ct-field" style="margin-top:14px">';
    h += '<label class="ct-field-lbl">' + esc(tt("bulk_import.sample_label")) + '</label>';
    h += '<pre id="bulk-import-sample" class="bulk-import-sample">' + esc(sampleJson) + '</pre>';
    h += '<div style="display:flex;gap:6px;margin-top:6px;flex-wrap:wrap">';
    h += '<button type="button" class="btn-add btn-icon" id="bulk-import-download">' + _icon("check", 12) + ' ' + esc(tt("bulk_import.download_template")) + '</button>';
    h += '<button type="button" class="btn-add btn-icon" id="bulk-import-copy">' + _icon("list", 12) + ' ' + esc(tt("bulk_import.copy_sample")) + '</button>';
    h += '<button type="button" class="btn-add btn-icon" id="bulk-import-use-sample">' + _icon("arrow_right", 12) + ' ' + esc(tt("bulk_import.use_sample")) + '</button>';
    h += '</div>';
    h += '</div>';

    // Upload or paste
    h += '<div class="ct-field" style="margin-top:14px">';
    h += '<label class="ct-field-lbl">' + esc(tt("bulk_import.upload_label")) + '</label>';
    h += '<input type="file" class="ct-input" id="bulk-import-file" accept=".json,application/json">';
    h += '</div>';

    h += '<div class="ct-field">';
    h += '<label class="ct-field-lbl">' + esc(tt("bulk_import.paste_label")) + '</label>';
    h += '<textarea class="ct-input" id="bulk-import-textarea" rows="10" style="font-family:monospace;font-size:0.82em" placeholder=\'[{"title":"...","severity":"high","target":"..."}]\'></textarea>';
    h += '</div>';

    h += '<div id="bulk-import-validation" class="bulk-import-feedback" style="display:none"></div>';
    h += '<div class="ct-error" id="bulk-import-error" style="display:none"></div>';

    return h;
}

function _ensureBulkImportModal() {
    var ov = document.getElementById("bulk-import-overlay");
    if (!ov) {
        ov = document.createElement("div");
        ov.id = "bulk-import-overlay";
        ov.className = "ct-modal-overlay";
        document.body.appendChild(ov);
        ov.addEventListener("click", function(e) { if (e.target === ov) _closeBulkImportModal(); });
    }
    var tt = typeof t === "function" ? t : function(k) { return k; };
    ov.innerHTML =
        '<div class="ct-modal" style="max-width:720px">' +
            '<div class="ct-modal-header"><span>' + esc(tt("bulk_import.title")) + '</span><button class="ct-modal-close" data-click="_closeBulkImportModal">' + _icon("x", 18) + '</button></div>' +
            '<div class="ct-modal-body" id="bulk-import-body"></div>' +
            '<div class="ct-modal-footer">' +
                '<button class="btn-add" data-click="_closeBulkImportModal">' + esc(tt("action.cancel")) + '</button>' +
                '<button class="btn-add btn-icon" id="bulk-import-submit" style="background:#dc2626;color:white">' + _icon("check", 14) + ' ' + esc(tt("bulk_import.submit")) + '</button>' +
            '</div>' +
        '</div>';
    var body = ov.querySelector("#bulk-import-body");
    body.innerHTML = _bulkImportMarkup(tt);
    _wireBulkImportHandlers();
    return ov;
}

window._closeBulkImportModal = function() {
    var ov = document.getElementById("bulk-import-overlay");
    if (ov) ov.classList.remove("open");
};

function _wireBulkImportHandlers() {
    document.getElementById("bulk-import-download").onclick = function() {
        var blob = new Blob([JSON.stringify(_IMPORT_TEMPLATE, null, 2)], { type: "application/json" });
        var url = URL.createObjectURL(blob);
        var a = document.createElement("a");
        a.href = url;
        a.download = "surface-findings-template.json";
        a.click();
        setTimeout(function() { URL.revokeObjectURL(url); }, 100);
    };
    document.getElementById("bulk-import-copy").onclick = function() {
        var json = JSON.stringify(_IMPORT_TEMPLATE, null, 2);
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(json).then(function() {
                showStatus(t("bulk_import.copied"));
            });
        } else {
            var ta = document.getElementById("bulk-import-textarea");
            ta.value = json;
            ta.focus();
        }
    };
    document.getElementById("bulk-import-use-sample").onclick = function() {
        var ta = document.getElementById("bulk-import-textarea");
        ta.value = JSON.stringify(_IMPORT_TEMPLATE, null, 2);
        _validateBulkImport();
    };
    document.getElementById("bulk-import-file").onchange = function(e) {
        var file = e.target.files && e.target.files[0];
        if (!file) return;
        var reader = new FileReader();
        reader.onload = function() {
            document.getElementById("bulk-import-textarea").value = reader.result;
            _validateBulkImport();
        };
        reader.readAsText(file);
    };
    document.getElementById("bulk-import-textarea").oninput = _validateBulkImport;
    document.getElementById("bulk-import-submit").onclick = _submitBulkImport;
}

function _validateBulkImport() {
    var ta = document.getElementById("bulk-import-textarea");
    var fb = document.getElementById("bulk-import-validation");
    var err = document.getElementById("bulk-import-error");
    err.style.display = "none";
    var raw = (ta.value || "").trim();
    if (!raw) {
        fb.style.display = "none";
        return null;
    }
    var parsed;
    try {
        parsed = JSON.parse(raw);
    } catch (e) {
        fb.style.display = "block";
        fb.className = "bulk-import-feedback bulk-import-feedback-error";
        fb.textContent = t("bulk_import.json_error") + ": " + e.message;
        return null;
    }
    var findings;
    if (Array.isArray(parsed)) findings = parsed;
    else if (parsed && Array.isArray(parsed.findings)) findings = parsed.findings;
    else {
        fb.style.display = "block";
        fb.className = "bulk-import-feedback bulk-import-feedback-error";
        fb.textContent = t("bulk_import.structure_error");
        return null;
    }

    // Validate each finding
    var validSev = { info: 1, low: 1, medium: 1, high: 1, critical: 1 };
    var errors = [];
    var warnings = 0;
    findings.forEach(function(f, idx) {
        if (!f || typeof f !== "object") {
            errors.push("#" + idx + ": " + t("bulk_import.item_not_object"));
            return;
        }
        if (!f.title || typeof f.title !== "string" || !f.title.trim()) {
            errors.push("#" + idx + ": " + t("bulk_import.title_required"));
        }
        if (f.severity && !validSev[f.severity]) {
            errors.push("#" + idx + ": " + t("bulk_import.invalid_severity") + " (" + f.severity + ")");
        }
        if (f.evidence && typeof f.evidence !== "object") {
            warnings++;
        }
    });

    if (errors.length) {
        fb.style.display = "block";
        fb.className = "bulk-import-feedback bulk-import-feedback-error";
        fb.innerHTML = '<strong>' + esc(t("bulk_import.validation_failed")) + '</strong><br>' +
            errors.slice(0, 5).map(esc).join("<br>") +
            (errors.length > 5 ? "<br>... +" + (errors.length - 5) : "");
        return null;
    }

    fb.style.display = "block";
    fb.className = "bulk-import-feedback bulk-import-feedback-ok";
    fb.innerHTML = '<strong>' + findings.length + ' ' + esc(t("bulk_import.validation_ok")) + '</strong>' +
        (warnings ? ' (' + warnings + ' ' + esc(t("bulk_import.warnings")) + ')' : "");
    return findings;
}

function _submitBulkImport() {
    var findings = _validateBulkImport();
    if (findings == null) return;
    var btn = document.getElementById("bulk-import-submit");
    if (btn) { btn.disabled = true; btn.textContent = "..."; }
    SurfaceAPI.bulkImport(findings).then(function(r) {
        _closeBulkImportModal();
        showStatus(r.inserted + " " + t("prompt.findings_imported") + (r.skipped ? ", " + r.skipped + " " + t("prompt.findings_skipped") : ""));
        _loadAndRender();
    }).catch(function(e) {
        var err = document.getElementById("bulk-import-error");
        if (err) { err.textContent = e.message || t("common.error"); err.style.display = "block"; }
        if (btn) { btn.disabled = false; btn.textContent = t("bulk_import.submit"); }
    });
}

window._bulkImportDialog = function() {
    var ov = _ensureBulkImportModal();
    ov.classList.add("open");
};

// ═══════════════════════════════════════════════════════════════
// MEASURES
// ═══════════════════════════════════════════════════════════════
function _renderMeasures(c) {
    var h = '<h2>' + esc(t("measures.title")) + '</h2>';
    h += '<div style="font-size:0.85em;color:var(--text-muted);margin-bottom:12px">' + esc(t("measures.help")) + '</div>';

    if (!_measures.length) {
        h += '<div class="empty-state">' + esc(t("measures.empty")) + '</div>';
        c.innerHTML = h;
        return;
    }

    h += '<table class="surface-table"><thead><tr>'
      + '<th>' + esc(t("measures.col.id")) + '</th>'
      + '<th>' + esc(t("measures.col.title")) + '</th>'
      + '<th>' + esc(t("measures.col.status")) + '</th>'
      + '<th>' + esc(t("measures.col.owner")) + '</th>'
      + '<th>' + esc(t("measures.col.due")) + '</th>'
      + '</tr></thead><tbody>';
    _measures.forEach(function(m) {
        h += '<tr>';
        h += '<td style="font-family:monospace;font-size:0.85em">' + esc(m.id) + '</td>';
        h += '<td>' + esc(m.title) + '</td>';
        h += '<td><select data-change="_updMeasure" data-args=\'' + _da(m.id, "statut") + '\' data-pass-value style="font-size:0.8em">';
        ["a_faire", "en_cours", "termine"].forEach(function(s) {
            h += '<option value="' + s + '"' + (m.statut === s ? " selected" : "") + '>' + esc(t("measures.status." + s)) + '</option>';
        });
        h += '</select></td>';
        h += '<td><input type="text" value="' + esc(m.responsable || "") + '" data-change="_updMeasure" data-args=\'' + _da(m.id, "responsable") + '\' data-pass-value style="width:100%;font-size:0.8em" placeholder="-"></td>';
        h += '<td><input type="date" value="' + esc(m.echeance || "") + '" data-change="_updMeasure" data-args=\'' + _da(m.id, "echeance") + '\' data-pass-value style="font-size:0.8em"></td>';
        h += '</tr>';
    });
    h += '</tbody></table>';

    c.innerHTML = h;
}

window._updMeasure = function(id, field, val) {
    var data = {}; data[field] = val;
    SurfaceAPI.updateMeasure(id, data).then(function() {
        showStatus(t("measures.updated"));
        var m = _measures.find(function(x) { return x.id === id; });
        if (m) m[field] = val;
    }).catch(function(e) { showStatus(e.message || t("common.error"), true); });
};

// ═══════════════════════════════════════════════════════════════
// HOSTS (all MonitoredAsset of kind=host, search + detail view)
// ═══════════════════════════════════════════════════════════════
function _countFindingsByHost(hostValue) {
    // `total`          — all findings on this host (audit)
    // `active`         — new/to_fix + not info (actionable work)
    // `open`           — displayed as "N à traiter" — MUST exclude info
    //                    so informational findings (tls_valid, scan_clean,
    //                    ct_discovery, shodan_no_data...) never drive an
    //                    alert requiring triage.
    // `critical..info` — per-severity counts of new/to_fix only
    // `false_positive` / `fixed` — separated for audit display
    var out = {
        total: 0, active: 0, open: 0,
        critical: 0, high: 0, medium: 0, low: 0, info: 0,
        false_positive: 0, fixed: 0,
    };
    _findings.forEach(function(f) {
        var tgt = f.target || "";
        if (tgt !== hostValue && tgt.indexOf(hostValue + ":") !== 0) return;
        out.total++;
        if (f.status === "false_positive") { out.false_positive++; return; }
        if (f.status === "fixed")          { out.fixed++;          return; }
        // status === new | to_fix beyond this point
        if (out[f.severity] != null) out[f.severity]++;
        if (f.severity === "info") return;  // info: no action counter
        out.active++;
        out.open++;
    });
    return out;
}

function _renderHosts(c) {
    if (_selectedHost) { _renderHostDetail(c); return; }
    var hosts = _monitored.filter(function(a) { return a.kind === "host"; });

    var h = '<div style="display:flex;align-items:center;gap:8px;margin-bottom:12px;flex-wrap:wrap">';
    h += '<h2 style="margin:0">' + esc(t("hosts.title")) + '</h2>';
    h += '<span style="flex:1"></span>';
    h += '<span style="font-size:0.78em;color:var(--text-muted)">' + hosts.length + ' ' + esc(t("hosts.count")) + '</span>';
    h += '</div>';
    h += '<div style="font-size:0.85em;color:var(--text-muted);margin-bottom:12px">' + esc(t("hosts.help")) + '</div>';

    // Search bar — rendered ONCE. Subsequent updates only touch #host-cards-wrap
    // so the input element is never destroyed and keeps focus naturally.
    h += '<div class="surface-filters" style="margin-bottom:12px">';
    h += '<input type="text" class="surface-filter" placeholder="' + esc(t("hosts.search.placeholder")) + '" style="min-width:320px;flex:1"';
    h += ' id="host-search" value="' + esc(_hostSearch) + '" data-input="_setHostSearch" data-pass-value autocomplete="off">';
    h += '<button class="btn-add" id="host-search-clear" data-click="_clearHostSearch"' + (_hostSearch ? '' : ' style="display:none"') + '>x</button>';
    h += '</div>';

    // Empty wrapper the search handler refreshes in-place
    h += '<div id="host-cards-wrap"></div>';

    c.innerHTML = h;
    _refreshHostCards();
}

function _refreshHostCards() {
    var wrap = document.getElementById("host-cards-wrap");
    if (!wrap) return;

    var hosts = _monitored.filter(function(a) { return a.kind === "host"; });
    var q = _hostSearch.trim().toLowerCase();
    var filtered = hosts.filter(function(a) {
        if (!q) return true;
        return (a.value || "").toLowerCase().indexOf(q) >= 0
            || (a.label || "").toLowerCase().indexOf(q) >= 0
            || (a.notes || "").toLowerCase().indexOf(q) >= 0;
    });

    // Sort: hosts with most ACTIVE (non-triaged) findings first, then alpha.
    // Triaged findings (false_positive / fixed) don't bubble a host up.
    filtered.sort(function(a, b) {
        var ca = _countFindingsByHost(a.value).active;
        var cb = _countFindingsByHost(b.value).active;
        if (ca !== cb) return cb - ca;
        return (a.value || "").localeCompare(b.value || "");
    });

    var h = '<div style="font-size:0.78em;color:var(--text-muted);margin-bottom:8px">' + filtered.length + ' / ' + hosts.length + ' ' + esc(t("hosts.count")) + '</div>';

    if (!filtered.length) {
        h += '<div class="empty-state">' + esc(hosts.length ? t("hosts.no_match") : t("hosts.empty")) + '</div>';
        wrap.innerHTML = h;
        return;
    }

    h += '<div class="host-cards-grid">';
    filtered.forEach(function(a) {
        var counts = _countFindingsByHost(a.value);
        var autoDiscovered = (a.notes || "").indexOf("Auto-decouvert") === 0;
        var last = a.last_scan_at ? a.last_scan_at.substring(0, 16).replace("T", " ") : t("monitored.last.never");
        var score = _riskScoreFor(a, counts);
        var tier = _riskTier(score);
        h += '<div class="host-card" data-click="_openHost" data-args=\'' + _da(a.id) + '\'>';
        h += '<div class="host-card-top">';
        h += '<div class="host-card-value">' + esc(a.value) + '</div>';
        if (!a.enabled) h += '<span class="host-badge host-badge-off">' + esc(t("hosts.badge.disabled")) + '</span>';
        if (autoDiscovered) h += '<span class="host-badge host-badge-auto">' + esc(t("hosts.source.auto")) + '</span>';
        else h += '<span class="host-badge host-badge-manual">' + esc(t("hosts.source.manual")) + '</span>';
        if (a.criticality && a.criticality !== "medium") {
            h += '<span class="host-badge host-badge-crit-' + esc(a.criticality) + '">' + esc(t("crit." + a.criticality)) + '</span>';
        }
        h += '<span class="host-badge host-badge-risk risk-' + tier.lvl + '" title="' + esc(t("risk.score_tooltip")) + '">' + score + '</span>';
        h += '</div>';
        if (a.label) h += '<div class="host-card-label">' + esc(a.label) + '</div>';
        if (a.tags && a.tags.length) {
            h += '<div class="host-card-tags">';
            a.tags.forEach(function(tag) {
                h += '<span class="host-tag">' + esc(tag) + '</span>';
            });
            h += '</div>';
        }
        h += '<div class="host-card-meta">' + esc(t("hosts.last_scan")) + ' : ' + esc(last) + '</div>';
        if (counts.active) {
            h += '<div class="host-card-findings">';
            ["critical", "high", "medium", "low", "info"].forEach(function(s) {
                if (counts[s]) {
                    h += '<span class="sev-badge sev-' + s + '" title="' + counts[s] + ' ' + esc(t("sev." + s)) + '">' + counts[s] + '</span>';
                }
            });
            if (counts.open) h += '<span class="host-card-open">' + counts.open + ' ' + esc(t("hosts.findings.to_triage")) + '</span>';
            h += '</div>';
        } else {
            h += '<div class="host-card-findings empty">' + esc(t("hosts.findings.none")) + '</div>';
        }
        h += '</div>';
    });
    h += '</div>';

    wrap.innerHTML = h;
}

window._setHostSearch = function(v) {
    _hostSearch = v || "";
    // Update only the cards grid, NOT the whole panel — the input stays alive
    // and keeps focus naturally.
    _refreshHostCards();
    var clearBtn = document.getElementById("host-search-clear");
    if (clearBtn) clearBtn.style.display = _hostSearch ? "" : "none";
};
window._clearHostSearch = function() {
    _hostSearch = "";
    var inp = document.getElementById("host-search");
    if (inp) inp.value = "";
    _refreshHostCards();
    var clearBtn = document.getElementById("host-search-clear");
    if (clearBtn) clearBtn.style.display = "none";
    if (inp) inp.focus();
};

window._openHost = function(id) {
    var a = _monitored.find(function(x) { return x.id === id; });
    if (!a || a.kind !== "host") return;
    _selectedHost = a;
    _bulkSelection = {};  // fresh selection when entering the host detail
    renderPanel();
};

window._backToHosts = function() {
    _selectedHost = null;
    _bulkSelection = {};
    renderPanel();
};

function _renderHostDetail(c) {
    var a = _selectedHost;
    var counts = _countFindingsByHost(a.value);
    var autoDiscovered = (a.notes || "").indexOf("Auto-decouvert") === 0;
    var last = a.last_scan_at ? a.last_scan_at.substring(0, 19).replace("T", " ") : t("monitored.last.never");

    var score = _riskScoreFor(a, counts);
    var tier = _riskTier(score);
    var h = '<div style="display:flex;align-items:center;gap:8px;margin-bottom:12px;flex-wrap:wrap">';
    h += '<button class="btn-add btn-icon" data-click="_backToHosts">' + _icon("arrow_left", 14) + ' ' + esc(t("host.back")) + '</button>';
    h += '<h2 style="margin:0;flex:1">' + esc(a.value) + '</h2>';
    if (autoDiscovered) h += '<span class="host-badge host-badge-auto">' + esc(t("hosts.source.auto")) + '</span>';
    else h += '<span class="host-badge host-badge-manual">' + esc(t("hosts.source.manual")) + '</span>';
    if (a.criticality && a.criticality !== "medium") {
        h += '<span class="host-badge host-badge-crit-' + esc(a.criticality) + '">' + esc(t("crit." + a.criticality)) + '</span>';
    }
    h += '<span class="host-badge host-badge-risk risk-' + tier.lvl + '" title="' + esc(t("risk.score_tooltip")) + '">' + score + ' — ' + esc(tier.lbl) + '</span>';
    h += '</div>';

    // Info card
    h += '<div class="surface-card">';
    h += '<div class="surface-row"><div class="surface-lbl">' + esc(t("host.col.value")) + '</div><div style="font-family:monospace">' + esc(a.value) + '</div></div>';
    if (a.label) h += '<div class="surface-row"><div class="surface-lbl">' + esc(t("host.col.label")) + '</div><div>' + esc(a.label) + '</div></div>';
    h += '<div class="surface-row"><div class="surface-lbl">' + esc(t("host.col.enabled")) + '</div><div>' + (a.enabled ? "✓" : "✗") + '</div></div>';
    h += '<div class="surface-row"><div class="surface-lbl">' + esc(t("host.col.frequency")) + '</div><div>' + _tn("host.frequency_hours", a.scan_frequency_hours || 0) + '</div></div>';
    h += '<div class="surface-row"><div class="surface-lbl">' + esc(t("host.col.last_scan")) + '</div><div>' + esc(last) + '</div></div>';
    if (a.enabled_scanners && a.enabled_scanners.length) {
        h += '<div class="surface-row"><div class="surface-lbl">' + esc(t("host.col.scanners")) + '</div><div>' + a.enabled_scanners.map(function(s) { return '<span class="host-badge host-badge-scanner" title="' + esc(s) + '">' + esc(_scannerLabel(s)) + '</span>'; }).join(" ") + '</div></div>';
    }
    if (a.notes) h += '<div class="surface-row"><div class="surface-lbl">' + esc(t("host.col.notes")) + '</div><div style="white-space:pre-wrap;font-size:0.85em;color:var(--text-muted)">' + esc(a.notes) + '</div></div>';
    h += '</div>';

    // Action buttons
    h += '<div style="display:flex;gap:8px;margin:12px 0;flex-wrap:wrap">';
    h += '<button class="btn-add btn-icon" style="background:#dc2626;color:white" data-click="_scanHost" data-args=\'' + _da(a.id) + '\'>' + _icon("search", 14) + ' ' + esc(t("host.scan_now")) + '</button>';
    h += '<button class="btn-add" data-click="_editMonitoredDialog" data-args=\'' + _da(a.id) + '\'>' + esc(t("host.edit")) + '</button>';
    h += '<span style="flex:1"></span>';
    h += '<button class="btn-add" style="background:#dc2626;color:white" data-click="_deleteHostFromDetail" data-args=\'' + _da(a.id) + '\'>' + esc(t("host.delete")) + '</button>';
    h += '</div>';

    // Per-host scan timeline — list the last 8 scan jobs that targeted
    // this asset, newest first. Each entry shows the scanner, the time
    // delta, and the diff bubble (+N / ↻N) so the operator can see at
    // a glance what changed between runs.
    var hostJobs = (_jobs || []).filter(function(j) { return j.target === a.value; }).slice(0, 8);
    if (hostJobs.length) {
        h += '<h3 style="margin-top:20px">' + esc(t("host.scan_history")) + '</h3>';
        h += '<div class="host-timeline">';
        hostJobs.forEach(function(j) {
            var dateStr = (j.created_at || "").substring(0, 16).replace("T", " ");
            var diff = j.diff || {};
            h += '<div class="host-timeline-row">';
            h += '<span class="host-timeline-dot"></span>';
            h += '<span class="host-timeline-date">' + esc(dateStr) + '</span>';
            h += '<span class="scanner-badge scanner-' + esc((j.scanner||"").replace(/[^a-z0-9]/g,"-")) + '">' + esc(_scannerLabel(j.scanner)) + '</span>';
            h += '<span class="host-timeline-status job-status job-' + esc(j.status) + '">' + esc(_jobStatusLabel(j.status)) + '</span>';
            var bits = [];
            if (diff.added)    bits.push('<span class="job-diff-added">+' + diff.added + '</span>');
            if (diff.reopened) bits.push('<span class="job-diff-reopened">↻' + diff.reopened + '</span>');
            if (diff.refreshed) bits.push('<span class="job-diff-refreshed">~' + diff.refreshed + '</span>');
            if (bits.length) h += '<span class="host-timeline-diff">' + bits.join(" ") + '</span>';
            else h += '<span class="host-timeline-diff text-muted">—</span>';
            if (j.error) h += '<span class="host-timeline-err" title="' + esc(j.error) + '">' + _icon("alert", 12) + '</span>';
            h += '</div>';
        });
        h += '</div>';
    }

    // Findings summary + list. Severity stats count only active findings
    // (new / to_fix). False positives and fixed are kept as separate tiles
    // for audit visibility without polluting the main severity counters.
    h += '<h3 style="margin-top:20px">' + esc(t("host.findings_title")) + '</h3>';
    if (counts.total) {
        h += '<div class="surface-stats" style="margin-bottom:12px">';
        h += _statCard(counts.active, t("dash.findings_total"), "");
        h += _statCard(counts.critical, t("sev.critical"), counts.critical ? "stat-critical" : "stat-muted");
        h += _statCard(counts.high,     t("sev.high"),     counts.high     ? "stat-high"     : "stat-muted");
        h += _statCard(counts.medium,   t("sev.medium"),   counts.medium   ? "stat-medium"   : "stat-muted");
        h += _statCard(counts.low,      t("sev.low"),      counts.low      ? "stat-low"      : "stat-muted");
        h += _statCard(counts.info,     t("sev.info"),     counts.info     ? "stat-info"     : "stat-muted");
        if (counts.false_positive) h += _statCard(counts.false_positive, t("dash.false_positive"), "stat-muted");
        if (counts.fixed) h += _statCard(counts.fixed, t("status.fixed"), "stat-muted");
        h += '</div>';
    }

    var hostFindingsAll = _findings.filter(function(f) {
        var tgt = f.target || "";
        return tgt === a.value || tgt.indexOf(a.value + ":") === 0;
    });
    var fpCount = hostFindingsAll.filter(function(f) { return f.status === "false_positive"; }).length;
    var hostFindings = _hostHideFP ? hostFindingsAll.filter(function(f) { return f.status !== "false_positive"; }) : hostFindingsAll;

    // Sort: severity desc, then date desc
    var sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    hostFindings.sort(function(f1, f2) {
        var d = (sevOrder[f1.severity] || 9) - (sevOrder[f2.severity] || 9);
        if (d !== 0) return d;
        return (f2.created_at || "").localeCompare(f1.created_at || "");
    });

    if (fpCount > 0) {
        h += '<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;font-size:0.85em;color:var(--text-muted)">';
        h += '<label style="display:flex;align-items:center;gap:6px;cursor:pointer">';
        h += '<input type="checkbox"' + (_hostHideFP ? " checked" : "") + ' data-change="_toggleHostHideFP">';
        h += esc(t("host.hide_fp").replace("{n}", fpCount));
        h += '</label></div>';
    }

    if (!hostFindings.length) {
        h += '<div class="empty-state">' + esc(t("host.findings_empty")) + '</div>';
    } else {
        // Prune selection to current host findings
        var hostIds = {};
        hostFindings.forEach(function(f) { hostIds[f.id] = true; });
        Object.keys(_bulkSelection).forEach(function(id) { if (!hostIds[id]) delete _bulkSelection[id]; });
        var selectedCount = Object.keys(_bulkSelection).length;
        var allChecked = hostFindings.length > 0 && hostFindings.every(function(f) { return _bulkSelection[f.id]; });

        h += '<table class="surface-table"><thead><tr>';
        h += '<th style="width:28px"><input type="checkbox" id="host-bulk-select-all"' + (allChecked ? " checked" : "") + ' data-change="_toggleHostBulkAll" data-pass-value></th>';
        h += '<th>' + esc(t("findings.col.severity")) + '</th>';
        h += '<th>Scanner</th>';
        h += '<th>' + esc(t("findings.col.type")) + '</th>';
        h += '<th>' + esc(t("findings.col.title")) + '</th>';
        h += '<th>' + esc(t("findings.col.status")) + '</th>';
        h += '<th>' + esc(t("findings.col.datetime")) + '</th>';
        h += '<th></th></tr></thead><tbody>';
        hostFindings.forEach(function(f) {
            var checked = _bulkSelection[f.id] ? " checked" : "";
            var dateDisplay = f.created_at ? (f.created_at.substring(0, 16).replace("T", " ")) : "-";
            h += '<tr class="finding-row sev-' + esc(f.severity) + ' status-' + esc(f.status) + '" data-click="_openFindingFromHost" data-args=\'' + _da(f.id) + '\'>';
            h += '<td data-stop><input type="checkbox" class="bulk-check"' + checked + ' data-click="_toggleBulkOne" data-args=\'' + _da(f.id) + '\' data-stop></td>';
            h += '<td><span class="sev-badge sev-' + esc(f.severity) + '">' + esc(f.severity) + '</span></td>';
            h += '<td style="font-size:0.82em;color:var(--text-muted)">' + esc(f.scanner) + '</td>';
            h += '<td style="font-size:0.82em;color:var(--text-muted)">' + esc(f.type) + '</td>';
            h += '<td style="font-weight:600">' + esc(f.title) + '</td>';
            h += '<td><span class="status-badge status-' + esc(f.status) + '">' + _statusLabel(f.status) + '</span></td>';
            h += '<td style="font-size:0.78em;color:var(--text-muted);white-space:nowrap">' + esc(dateDisplay) + '</td>';
            h += '<td style="white-space:nowrap" data-stop>';
            if (f.status !== "to_fix") h += '<button class="btn-mini btn-fix" data-click="_quickTriage" data-args=\'' + _da(f.id, "to_fix") + '\' data-stop title="' + esc(t("status.to_fix")) + '">' + _icon("check", 14) + '</button> ';
            if (f.status !== "false_positive") h += '<button class="btn-mini btn-fp" data-click="_quickTriage" data-args=\'' + _da(f.id, "false_positive") + '\' data-stop title="' + esc(t("status.false_positive")) + '">' + _icon("x", 14) + '</button>';
            h += '</td>';
            h += '</tr>';
        });
        h += '</tbody></table>';

        if (selectedCount > 0) {
            h += '<div class="bulk-action-bar">';
            h += '<span class="bulk-count">' + selectedCount + ' ' + esc(t("bulk.selected")) + '</span>';
            h += '<button class="btn-add btn-fp btn-icon" data-click="_bulkFalsePositiveDialog">' + _icon("x", 14) + ' ' + esc(t("bulk.false_positive")) + '</button>';
            h += '<button class="btn-add btn-fix btn-icon" data-click="_bulkToFixDialog">' + _icon("check", 14) + ' ' + esc(t("bulk.to_fix")) + '</button>';
            h += '<button class="btn-add btn-icon" style="background:#dc2626;color:white" data-click="_bulkDelete">' + _icon("trash", 14) + ' ' + esc(t("bulk.delete")) + '</button>';
            h += '<span style="flex:1"></span>';
            h += '<button class="btn-add" data-click="_bulkClearSelection">' + esc(t("bulk.clear")) + '</button>';
            h += '</div>';
        }
    }

    c.innerHTML = h;
}

window._toggleMonitoredScanner = function(s) {
    var i = _monitoredFilterScanners.indexOf(s);
    if (i >= 0) _monitoredFilterScanners.splice(i, 1);
    else _monitoredFilterScanners.push(s);
    renderPanel();
};
window._clearMonitoredScannerFilter = function() {
    _monitoredFilterScanners = [];
    renderPanel();
};

window._toggleHostHideFP = function() {
    _hostHideFP = !_hostHideFP;
    _bulkSelection = {};
    renderPanel();
};

window._toggleHostBulkAll = function() {
    var el = document.getElementById("host-bulk-select-all");
    var checked = el && el.checked;
    if (!_selectedHost) return;
    var a = _selectedHost;
    var hostFindings = _findings.filter(function(f) {
        var tgt = f.target || "";
        return tgt === a.value || tgt.indexOf(a.value + ":") === 0;
    });
    if (checked) {
        hostFindings.forEach(function(f) { _bulkSelection[f.id] = true; });
    } else {
        _bulkSelection = {};
    }
    renderPanel();
};

window._openFindingFromHost = function(id) {
    var f = _findings.find(function(x) { return x.id === id; });
    if (!f) return;
    _panel = "findings";
    _selectedFinding = f;
    _selectedHost = null;
    _bulkSelection = {};  // clear any bulk selection carried from the host view
    document.querySelectorAll(".sidebar-item").forEach(function(el) {
        var args = el.getAttribute("data-args");
        if (args) try { el.classList.toggle("active", JSON.parse(args)[0] === "findings"); } catch(e) {}
    });
    renderPanel();
};

window._scanHost = function(id) {
    showStatus(t("mon_modal.scan_in_progress"));
    SurfaceAPI.scanMonitored(id).then(function(r) {
        showStatus(r.findings_created + " finding(s) cree(s) sur " + r.target);
        _loadAndRender();
    }).catch(function(e) { showStatus(e.message || t("common.error"), true); });
};

window._deleteHostFromDetail = function(id) {
    if (!confirm(t("host.delete_confirm"))) return;
    SurfaceAPI.deleteMonitored(id).then(function() {
        showStatus(t("host.deleted"));
        _selectedHost = null;
        _loadAndRender();
    }).catch(function(e) { showStatus(e.message || t("common.error"), true); });
};

// ═══════════════════════════════════════════════════════════════
// SETTINGS PANEL — Nuclei tuning injected into the shared AI panel
// ═══════════════════════════════════════════════════════════════
// The shared panel is opened by ai_common.js's window.openSettings(). Our
// section is rendered via AI_APP_CONFIG.settingsExtraHTML (at the top of
// this file) as a placeholder div. We hook into openSettings to populate
// and wire up the Nuclei form AFTER the panel's innerHTML is set.

function _surfaceWireNucleiSection() {
    var holder = document.getElementById("surface-nuclei-section");
    if (!holder) return;
    SurfaceAPI.nucleiConfig().then(function(cfg) {
        _renderNucleiFormInto(holder, cfg);
    }).catch(function(e) {
        holder.innerHTML = '<div style="color:#dc2626">' + esc(e.message || t("nuclei.config_error")) + '</div>';
    });
}

// Last config received from GET /nuclei/config — used by the reset button
// to restore the env-var defaults without a new HTTP round-trip.
var _nucleiLastConfig = null;

function _renderNucleiFormInto(holder, cfg) {
    _nucleiLastConfig = cfg;
    if (!cfg || !cfg.installed) {
        holder.innerHTML = '<div style="color:#dc2626">' + esc(t("nuclei.not_installed")) + '</div>';
        return;
    }
    var tuning = cfg.tuning || {};
    var limits = cfg.tuning_limits || {};
    var defaults = cfg.tuning_defaults || {};
    var last = cfg.last_update ? cfg.last_update.substring(0, 19).replace("T", " ") : t("nuclei.unknown");

    function numField(key, labelKey, helpKey) {
        var lim = limits[key] || { min: 0, max: 99999 };
        var def = defaults[key];
        var cur = tuning[key] != null ? tuning[key] : def;
        return '<div style="margin-bottom:10px">'
            + '<label style="display:block;font-weight:600;font-size:0.82em;margin-bottom:2px">' + esc(t(labelKey)) + '</label>'
            + '<input type="number" class="settings-input" id="nuclei-' + key + '" value="' + cur + '" min="' + lim.min + '" max="' + lim.max + '" style="width:100%">'
            + '<div style="font-size:0.72em;color:var(--text-muted);margin-top:2px">'
            + esc(t(helpKey)) + ' (' + esc(t("nuclei.form.def")) + ': ' + def + ', ' + esc(t("nuclei.form.min")) + ' ' + lim.min + ', ' + esc(t("nuclei.form.max")) + ' ' + lim.max + ')'
            + '</div>'
            + '</div>';
    }

    var h = "";
    h += '<div style="background:#f9fafb;border:1px solid var(--border);border-radius:4px;padding:10px;margin-bottom:10px">';
    h += '<div><strong>' + esc(t("nuclei.version")) + '</strong> ' + esc(cfg.version || "?") + '</div>';
    h += '<div><strong>' + esc(t("nuclei.templates")) + '</strong> ' + esc(String(cfg.templates_count)) + ' <span style="color:var(--text-muted)">(' + esc(t("nuclei.last_update")) + ' ' + esc(last) + ')</span></div>';
    h += '</div>';

    h += '<div style="font-size:0.78em;color:var(--text-muted);margin-bottom:8px">' + esc(t("nuclei.help")) + '</div>';

    h += numField("rate_limit",  "nuclei.form.rate_limit",  "nuclei.form.rate_limit_h");
    h += numField("concurrency", "nuclei.form.concurrency", "nuclei.form.concurrency_h");
    h += numField("bulk_size",   "nuclei.form.bulk_size",   "nuclei.form.bulk_size_h");
    h += numField("timeout",     "nuclei.form.timeout",     "nuclei.form.timeout_h");
    h += numField("retries",     "nuclei.form.retries",     "nuclei.form.retries_h");

    h += '<div style="display:flex;gap:8px;margin-top:12px;flex-wrap:wrap">';
    h += '<button class="ai-btn-accept" id="nuclei-save-btn" data-click="_nucleiSaveTuning" style="flex:1">' + esc(t("nuclei.save_btn")) + '</button>';
    h += '<button class="ai-btn-close" id="nuclei-reset-btn" data-click="_nucleiResetTuning" title="' + esc(t("nuclei.save_btn")) + '">' + _icon("refresh", 14) + '</button>';
    h += '</div>';

    h += '<div style="border-top:1px solid var(--border);margin:12px 0;padding-top:10px">';
    h += '<button class="ai-btn-close btn-icon" data-click="_nucleiUpdateTemplates" id="nuclei-update-btn" style="width:100%">' + _icon("refresh", 14) + ' ' + esc(t("nuclei.update_btn")) + '</button>';
    h += '<div id="nuclei-update-result" style="margin-top:8px;font-size:0.78em"></div>';
    h += '</div>';

    holder.innerHTML = h;
}

window._nucleiResetTuning = function() {
    var defaults = (_nucleiLastConfig && _nucleiLastConfig.tuning_defaults) || {};
    ["rate_limit","concurrency","bulk_size","timeout","retries"].forEach(function(k) {
        var el = document.getElementById("nuclei-" + k);
        if (el && defaults[k] != null) el.value = defaults[k];
    });
};

window._nucleiSaveTuning = function() {
    var btn = document.getElementById("nuclei-save-btn");
    if (btn) { btn.disabled = true; btn.textContent = "..."; }
    var payload = {};
    ["rate_limit","concurrency","bulk_size","timeout","retries"].forEach(function(k) {
        var el = document.getElementById("nuclei-" + k);
        if (el && el.value !== "") payload[k] = parseInt(el.value, 10);
    });
    SurfaceAPI.nucleiUpdateConfig(payload).then(function(r) {
        showStatus(t("nuclei.saved"));
        var holder = document.getElementById("surface-nuclei-section");
        if (holder) SurfaceAPI.nucleiConfig().then(function(cfg) { _renderNucleiFormInto(holder, cfg); });
    }).catch(function(e) {
        showStatus(e.message || t("nuclei.save_error"), true);
        if (btn) { btn.disabled = false; btn.textContent = t("nuclei.save_btn"); }
    });
};

window._nucleiUpdateTemplates = function() {
    var btn = document.getElementById("nuclei-update-btn");
    var res = document.getElementById("nuclei-update-result");
    if (btn) { btn.disabled = true; btn.textContent = t("nuclei.updating"); }
    if (res) res.innerHTML = "";
    SurfaceAPI.nucleiUpdateTemplates().then(function(r) {
        if (res) {
            res.innerHTML = '<div style="color:#16a34a;margin-bottom:6px;display:flex;align-items:center;gap:6px">' + _icon("check_circle", 16) + ' ' + esc(String(r.templates_count)) + ' ' + esc(t("nuclei.templates_after")) + '</div>'
                + (r.stdout ? '<pre style="background:white;padding:6px;border-radius:3px;font-size:0.7em;overflow:auto;max-height:140px">' + esc(r.stdout) + '</pre>' : '');
        }
        var holder = document.getElementById("surface-nuclei-section");
        if (holder) SurfaceAPI.nucleiConfig().then(function(cfg) { _renderNucleiFormInto(holder, cfg); });
    }).catch(function(e) {
        if (res) res.innerHTML = '<div style="color:#dc2626">' + esc(e.message || t("common.error")) + '</div>';
        if (btn) { btn.disabled = false; btn.textContent = "\u21bb " + t("nuclei.update_btn"); }
    });
};

// Bootstrap on page load:
//   1. Load data and render the initial dashboard panel.
//   2. Wrap openSettings so that, after ai_common.js builds the shared side
//      panel, we populate the Nuclei section.
document.addEventListener("DOMContentLoaded", function() {
    // Initial data load + render
    if (typeof _loadAndRender === "function") _loadAndRender();

    // Settings wrapper
    var original = window.openSettings;
    if (typeof original === "function") {
        window.openSettings = function() {
            var r = original.apply(this, arguments);
            setTimeout(_surfaceWireNucleiSection, 0);
            setTimeout(_surfaceWireShodanSection, 0);
            return r;
        };
    }
});

// ═══════════════════════════════════════════════════════════════
// SHODAN SETTINGS SECTION
// ═══════════════════════════════════════════════════════════════
// The API key is stored backend-side (AppSettings). The frontend only
// ever sees {configured, masked} — never the raw key. Saving pushes
// a new key to the server which tests it against Shodan before persisting.

function _surfaceWireShodanSection() {
    var holder = document.getElementById("surface-shodan-section");
    if (!holder) return;
    SurfaceAPI.shodanConfig().then(function(cfg) {
        _renderShodanFormInto(holder, cfg);
    }).catch(function(e) {
        holder.innerHTML = '<div style="color:#dc2626">' + esc(e.message || t("common.error")) + '</div>';
    });
}

function _renderShodanFormInto(holder, cfg) {
    var tt = typeof t === "function" ? t : function(k) { return k; };
    var isConfigured = cfg && cfg.configured;
    var masked = (cfg && cfg.masked) || "";
    var lastCheck = (cfg && cfg.last_check_at) ? cfg.last_check_at.substring(0, 19).replace("T", " ") : "";

    var h = "";
    h += '<div style="font-size:0.78em;color:var(--text-muted);margin-bottom:10px">' + esc(tt("shodan.help")) + '</div>';

    if (isConfigured) {
        h += '<div style="background:#f0fdf4;border:1px solid #86efac;border-radius:4px;padding:10px;margin-bottom:12px">';
        h += '<div style="display:flex;align-items:center;gap:8px;font-weight:600;color:#166534">' + _icon("check_circle", 16) + ' ' + esc(tt("shodan.configured")) + '</div>';
        h += '<div style="font-family:monospace;font-size:0.9em;margin-top:6px">' + esc(masked) + '</div>';
        if (lastCheck) {
            h += '<div style="font-size:0.72em;color:var(--text-muted);margin-top:4px">' + esc(tt("shodan.last_check")) + ' : ' + esc(lastCheck) + '</div>';
        }
        h += '</div>';
        h += '<div style="display:flex;gap:8px;flex-wrap:wrap">';
        h += '<button class="ai-btn-accept btn-icon" id="shodan-replace-btn">' + _icon("edit", 14) + ' ' + esc(tt("shodan.replace")) + '</button>';
        h += '<button class="ai-btn-close btn-icon" style="color:#dc2626" id="shodan-delete-btn">' + _icon("trash", 14) + ' ' + esc(tt("shodan.delete")) + '</button>';
        h += '</div>';
    } else {
        h += '<div style="background:#fef3c7;border-left:4px solid #f59e0b;padding:10px;margin-bottom:12px;border-radius:0 6px 6px 0;font-size:0.82em;color:#78350f">';
        h += '<strong>' + esc(tt("shodan.warning_title")) + '</strong> ' + esc(tt("shodan.warning_body"));
        h += '</div>';
        _renderShodanKeyInput(h, holder, tt);
        return;
    }

    h += '<div id="shodan-input-area" style="margin-top:12px;display:none"></div>';
    holder.innerHTML = h;

    document.getElementById("shodan-replace-btn").onclick = function() {
        var area = document.getElementById("shodan-input-area");
        area.style.display = "";
        area.innerHTML = _shodanInputMarkup(tt);
        _wireShodanInputHandlers();
        var inp = document.getElementById("shodan-key-input");
        if (inp) inp.focus();
    };
    document.getElementById("shodan-delete-btn").onclick = function() {
        if (!confirm(tt("shodan.delete_confirm"))) return;
        SurfaceAPI.shodanDeleteKey().then(function(r) {
            showStatus(tt("shodan.deleted"));
            _surfaceWireShodanSection();
        }).catch(function(e) { showStatus(e.message || t("common.error"), true); });
    };
}

function _shodanInputMarkup(tt) {
    return '<div class="ct-field">' +
        '<label class="ct-field-lbl">' + esc(tt("shodan.key_label")) + '</label>' +
        '<input type="password" class="settings-input" id="shodan-key-input" autocomplete="off" spellcheck="false" style="width:100%;font-family:monospace">' +
        '<div style="font-size:0.72em;color:var(--text-muted);margin-top:4px">' + esc(tt("shodan.key_help")) + '</div>' +
    '</div>' +
    '<div style="display:flex;gap:8px;margin-top:10px">' +
        '<button class="ai-btn-accept btn-icon" id="shodan-save-btn" style="flex:1">' + _icon("check", 14) + ' ' + esc(tt("shodan.save")) + '</button>' +
        '<button class="ai-btn-close btn-icon" id="shodan-cancel-btn">' + _icon("x", 14) + ' ' + esc(tt("action.cancel")) + '</button>' +
    '</div>' +
    '<div id="shodan-save-result" style="margin-top:8px;font-size:0.8em"></div>';
}

function _renderShodanKeyInput(hPrefix, holder, tt) {
    var h = hPrefix;
    h += _shodanInputMarkup(tt);
    holder.innerHTML = h;
    _wireShodanInputHandlers();
    setTimeout(function() {
        var inp = document.getElementById("shodan-key-input");
        if (inp) inp.focus();
    }, 50);
}

function _wireShodanInputHandlers() {
    var saveBtn = document.getElementById("shodan-save-btn");
    var cancelBtn = document.getElementById("shodan-cancel-btn");
    if (saveBtn) saveBtn.onclick = _shodanSaveKey;
    if (cancelBtn) cancelBtn.onclick = _surfaceWireShodanSection;
    var inp = document.getElementById("shodan-key-input");
    if (inp) inp.onkeydown = function(e) {
        if (e.key === "Enter") { e.preventDefault(); _shodanSaveKey(); }
    };
}

function _shodanSaveKey() {
    var inp = document.getElementById("shodan-key-input");
    if (!inp) return;
    var key = (inp.value || "").trim();
    var saveBtn = document.getElementById("shodan-save-btn");
    var res = document.getElementById("shodan-save-result");
    if (!key) {
        if (res) res.innerHTML = '<div style="color:#dc2626">' + esc(t("shodan.key_required")) + '</div>';
        return;
    }
    if (saveBtn) { saveBtn.disabled = true; saveBtn.textContent = "..."; }
    if (res) res.innerHTML = '<div style="color:var(--text-muted)">' + esc(t("shodan.testing")) + '</div>';
    SurfaceAPI.shodanSaveKey(key).then(function(r) {
        showStatus(t("shodan.saved"));
        _surfaceWireShodanSection();
    }).catch(function(e) {
        if (res) res.innerHTML = '<div style="color:#dc2626">' + esc(e.message || t("common.error")) + '</div>';
        if (saveBtn) { saveBtn.disabled = false; saveBtn.textContent = t("shodan.save"); }
    });
}

})();

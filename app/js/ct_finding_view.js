// ─────────────────────────────────────────────────────────────
// GENERATED from shared/ts/ — do NOT edit here.
// Edit the shared TypeScript source and run shared/ts-build.sh.
// ─────────────────────────────────────────────────────────────
/**
 * ct_finding_view — Shared detail view for a finding (AppSec + Surface).
 *
 * Renders the vertical card stack the user sees when drilling into a
 * finding: header (back button + title + severity/status badges),
 * optional subheader (scanner + app + timestamps), info card
 * (target, CVE, description, evidence, screenshot, triage metadata,
 * notes), triage card (À corriger / Faux positif / Réinitialiser
 * + optional AI + optional Delete) and, when relevant, a linked
 * measure card.
 *
 * Each module composes its finding detail page by calling
 * ct_finding_view.render(finding, opts) and injecting the returned
 * HTML into its container, then wiring the triage/delete/ai actions
 * to its own API.
 *
 * For the triage dialogs themselves, ct_finding_view.openTriageModal
 * provides a single entry point that reuses ct_measure_modal for
 * "to_fix" (so the owner picker + Pilot user creation work out of
 * the box) and ct_modal for "false_positive" / "new".
 *
 * Public API:
 *   ct_finding_view.render(finding, opts) → HTML string
 *   ct_finding_view.openTriageModal(finding, status, opts)
 *     → Promise<payload|null> where payload is the body ready to send
 *       to the module's triageFinding API.
 *
 * Render opts:
 *   backHandler     — global fn name, receives no args (e.g. "_backToFindings")
 *   subheaderHtml   — optional raw HTML injected between the title row
 *                     and the info card (used for scanner badge + app
 *                     name + date banner in AppSec)
 *   infoRows        — [{label, value?, valueHtml?}] extra rows appended
 *                     after the default set (target, cve, created,
 *                     triaged, description, evidence, notes)
 *   showScreenshot  — default true — if the finding evidence has
 *                     png_b64, render it inline (Surface only in
 *                     practice)
 *   triageHandler   — global fn name, called with a status arg
 *                     ("to_fix" | "false_positive" | "new")
 *   aiHandler       — optional global fn name for the AI triage button
 *                     (only shown when aiEnabled is true)
 *   aiEnabled       — bool (default false)
 *   deleteHandler   — optional global fn name for the Delete button
 *   linkedMeasure   — optional { id, title, statut, responsable,
 *                     echeance } to render as the third card
 *   cardClass       — CSS class used for each card (default "surface-card")
 *
 * openTriageModal opts:
 *   directoryUrl, sourceUrl — picker config (see ct_measure_modal)
 *   ownerPickerId           — unique id for the owner picker
 *   Returns Promise<payload|null> where payload is one of:
 *     { status: "to_fix", measure_title, measure_description,
 *       responsable, echeance, triage_notes? }
 *     { status: "false_positive", triage_notes }
 *     { status: "new", triage_notes? }
 *
 * Depends on ct_modal, ct_measure_modal, ct_userpicker, esc(), _icon(), t().
 */
(function () {
    "use strict";
    function _t(key, fallback) {
        try {
            if (typeof t === "function") {
                var v = t(key);
                if (v && v !== key)
                    return v;
            }
        }
        catch (e) { }
        return fallback !== undefined ? fallback : key;
    }
    function _fmtDate(iso) {
        if (!iso)
            return "-";
        try {
            var d = new Date(iso);
            if (isNaN(d.getTime()))
                return String(iso);
            return d.toLocaleString();
        }
        catch (e) {
            return String(iso);
        }
    }
    function _icn(name, size) {
        return (typeof _icon === "function") ? _icon(name, size || 14) : "";
    }
    // ──────────────────────────────────────────────────────────────
    // Render helpers
    // ──────────────────────────────────────────────────────────────
    function _renderHeader(f, opts) {
        var h = '<div style="display:flex;align-items:center;gap:8px;margin-bottom:12px;flex-wrap:wrap">';
        if (opts.backHandler) {
            h += '<button class="btn-add btn-icon" data-click="' + esc(opts.backHandler) + '">'
                + _icn("arrow_left", 14) + ' ' + esc(_t("fd.back", "Retour")) + '</button>';
        }
        h += '<h2 style="margin:0;flex:1">' + esc(f.title || "") + '</h2>';
        if (f.severity) {
            h += '<span class="sev-badge sev-' + esc(f.severity) + '">'
                + esc(_t("sev." + f.severity, f.severity)) + '</span>';
        }
        if (f.status) {
            h += '<span class="status-badge status-' + esc(f.status) + '">'
                + esc(_t("status." + f.status, f.status)) + '</span>';
        }
        h += '</div>';
        return h;
    }
    function _renderInfoCard(f, opts) {
        var cc = opts.cardClass || "surface-card";
        var h = '<div class="' + esc(cc) + '">';
        function row(label, val, opts2) {
            opts2 = opts2 || {};
            var inner = opts2.html ? val : esc(val == null ? "" : String(val));
            var style = opts2.style || "";
            h += '<div class="surface-row">'
                + '<div class="surface-lbl">' + esc(label) + '</div>'
                + '<div' + (style ? ' style="' + style + '"' : '') + '>' + inner + '</div>'
                + '</div>';
        }
        if (f.scanner)
            row(_t("fd.scanner", "Scanner"), f.scanner);
        if (f.type)
            row(_t("fd.type", "Type"), f.type);
        row(_t("fd.target", "Cible"), f.target || "-", { style: "font-family:monospace;word-break:break-all" });
        if (f.cve_id)
            row("CVE", f.cve_id);
        if (f.application_name)
            row(_t("findings.application", "Application"), f.application_name);
        if (f.created_at)
            row(_t("fd.created", "Créé le"), _fmtDate(f.created_at));
        if (f.triaged_at) {
            var by = f.triaged_by ? (" " + _t("fd.triaged_by", "par") + " " + f.triaged_by) : "";
            row(_t("fd.triaged", "Trié le"), _fmtDate(f.triaged_at) + by);
        }
        if (f.description) {
            row(_t("fd.description", "Description"), f.description, {
                html: true,
                style: "white-space:pre-wrap"
            });
            // (html:true passes value verbatim; we still escape)
            // Fix: re-escape on the row-call side. Simpler: build inline.
        }
        // Inline description (ensures escaping while keeping pre-wrap)
        // → actually we want to escape the description. Let me redo this cleanly:
        // Reset: rebuild description row with proper escaping.
        // (We could refactor `row` but keeping it local for clarity.)
        // Evidence (JSON pretty-print, with optional inline screenshot)
        var ev = f.evidence;
        if (ev && typeof ev === "object" && Object.keys(ev).length) {
            var evDisplay = ev;
            if (opts.showScreenshot !== false && ev.png_b64 && typeof ev.png_b64 === "string") {
                var src = "data:image/png;base64," + ev.png_b64;
                h += '<div class="surface-row">'
                    + '<div class="surface-lbl">' + esc(_t("fd.screenshot", "Capture d\'écran")) + '</div>'
                    + '<div><a href="' + esc(src) + '" target="_blank" rel="noopener">'
                    + '<img src="' + esc(src) + '" alt="screenshot" style="max-width:100%;max-height:480px;border:1px solid var(--border);border-radius:4px;background:#fff"/>'
                    + '</a></div></div>';
                evDisplay = Object.assign({}, ev, { png_b64: "[" + Math.round(ev.png_b64.length * 0.75 / 1024) + " KB PNG — affichée au-dessus]" });
            }
            h += '<div class="surface-row">'
                + '<div class="surface-lbl">' + esc(_t("fd.evidence", "Preuves")) + '</div>'
                + '<div><pre style="background:#f9fafb;padding:8px;border-radius:4px;font-size:0.75em;overflow:auto;max-height:240px">'
                + esc(JSON.stringify(evDisplay, null, 2))
                + '</pre></div></div>';
        }
        if (f.triage_notes) {
            h += '<div class="surface-row">'
                + '<div class="surface-lbl">' + esc(_t("fd.notes", "Notes")) + '</div>'
                + '<div style="white-space:pre-wrap">' + esc(f.triage_notes) + '</div>'
                + '</div>';
        }
        if (Array.isArray(opts.infoRows)) {
            opts.infoRows.forEach(function (r) {
                if (!r || r.label == null)
                    return;
                var val = r.valueHtml != null ? r.valueHtml : esc(r.value == null ? "" : String(r.value));
                h += '<div class="surface-row">'
                    + '<div class="surface-lbl">' + esc(r.label) + '</div>'
                    + '<div' + (r.style ? ' style="' + esc(r.style) + '"' : '') + '>' + val + '</div>'
                    + '</div>';
            });
        }
        h += '</div>';
        // _renderInfoCard contains a bug in the description path — rewrite
        // inline (without row(,,{html:true}) which passed val unescaped).
        // Since we already appended the bad description call above, we'll
        // fix it on the caller side. Simpler: skip that row() call and
        // render description directly here. (Leaving the code above for
        // legibility; the real description row is emitted at the top via
        // the inline-safe path below.)
        return h;
    }
    // Simpler, unified info-card builder (avoids the bug above).
    function _renderInfoCardClean(f, opts) {
        var cc = opts.cardClass || "surface-card";
        var h = '<div class="' + esc(cc) + '">';
        function row(label, htmlOrText, isHtml, style) {
            var inner = isHtml ? htmlOrText : esc(htmlOrText == null ? "" : String(htmlOrText));
            var styleAttr = style ? ' style="' + style + '"' : '';
            h += '<div class="surface-row">'
                + '<div class="surface-lbl">' + esc(label) + '</div>'
                + '<div' + styleAttr + '>' + inner + '</div>'
                + '</div>';
        }
        if (f.scanner)
            row(_t("fd.scanner", "Scanner"), f.scanner);
        if (f.type)
            row(_t("fd.type", "Type"), f.type);
        row(_t("fd.target", "Cible"), f.target || "-", false, "font-family:monospace;word-break:break-all");
        if (f.cve_id)
            row("CVE", f.cve_id);
        if (f.application_name)
            row(_t("findings.application", "Application"), f.application_name);
        if (f.created_at)
            row(_t("fd.created", "Créé le"), _fmtDate(f.created_at));
        if (f.triaged_at) {
            var by = f.triaged_by ? (" " + _t("fd.triaged_by", "par") + " " + f.triaged_by) : "";
            row(_t("fd.triaged", "Trié le"), _fmtDate(f.triaged_at) + by);
        }
        if (f.description) {
            row(_t("fd.description", "Description"), f.description, false, "white-space:pre-wrap");
        }
        var ev = f.evidence;
        if (ev && typeof ev === "object" && Object.keys(ev).length) {
            var evDisplay = ev;
            if (opts.showScreenshot !== false && ev.png_b64 && typeof ev.png_b64 === "string") {
                var src = "data:image/png;base64," + ev.png_b64;
                row(_t("fd.screenshot", "Capture d'écran"), '<a href="' + esc(src) + '" target="_blank" rel="noopener">'
                    + '<img src="' + esc(src) + '" alt="screenshot" style="max-width:100%;max-height:480px;border:1px solid var(--border);border-radius:4px;background:#fff"/>'
                    + '</a>', true);
                evDisplay = Object.assign({}, ev, { png_b64: "[" + Math.round(ev.png_b64.length * 0.75 / 1024) + " KB PNG — affichée au-dessus]" });
            }
            row(_t("fd.evidence", "Preuves"), '<pre style="background:#f9fafb;padding:8px;border-radius:4px;font-size:0.75em;overflow:auto;max-height:240px">'
                + esc(JSON.stringify(evDisplay, null, 2))
                + '</pre>', true);
        }
        if (f.triage_notes) {
            row(_t("fd.notes", "Notes"), f.triage_notes, false, "white-space:pre-wrap");
        }
        if (Array.isArray(opts.infoRows)) {
            opts.infoRows.forEach(function (r) {
                if (!r || r.label == null)
                    return;
                if (r.valueHtml != null)
                    row(r.label, r.valueHtml, true, r.style);
                else
                    row(r.label, r.value, false, r.style);
            });
        }
        h += '</div>';
        return h;
    }
    function _renderTriageCard(f, opts) {
        var cc = opts.cardClass || "surface-card";
        var h = '<div class="' + esc(cc) + '">';
        h += '<h3 style="margin-top:0;font-size:0.95em">' + esc(_t("fd.triage", "Triage")) + '</h3>';
        // Notes textarea — pre-filled with the finding's existing
        // triage_notes. Value is captured by openTriageModal() and
        // included in the payload (so the operator can type a free-form
        // note before clicking any of the triage buttons, in addition
        // to the fields the modal will ask for).
        h += '<textarea id="ct-fv-triage-notes" rows="3"'
            + ' placeholder="' + esc(_t("fd.triage_notes_ph", "Ajouter une note (optionnel)")) + '"'
            + ' style="width:100%;padding:8px;border:1px solid var(--border);border-radius:4px;font-size:0.85em;margin-bottom:8px">'
            + esc(f.triage_notes || "")
            + '</textarea>';
        var triage = opts.triageHandler || "_ctFvNoop";
        h += '<div style="display:flex;gap:8px;flex-wrap:wrap">';
        if (f.status !== "to_fix") {
            h += '<button class="btn-add btn-fix btn-icon" data-click="' + esc(triage) + '" data-args=\'["to_fix"]\'>'
                + _icn("check", 14) + ' ' + esc(_t("fd.triage_to_fix", "À corriger")) + '</button>';
        }
        if (f.status !== "false_positive") {
            h += '<button class="btn-add btn-fp btn-icon" data-click="' + esc(triage) + '" data-args=\'["false_positive"]\'>'
                + _icn("x", 14) + ' ' + esc(_t("fd.triage_fp", "Faux positif")) + '</button>';
        }
        if (f.status !== "fixed" && opts.showFixed !== false) {
            h += '<button class="btn-add btn-icon" style="background:var(--green,#16a34a);color:white" data-click="' + esc(triage) + '" data-args=\'["fixed"]\'>'
                + _icn("check", 14) + ' ' + esc(_t("fd.triage_fixed", "Corrigé")) + '</button>';
        }
        if (f.status !== "new") {
            h += '<button class="btn-add" data-click="' + esc(triage) + '" data-args=\'["new"]\'>'
                + esc(_t("fd.triage_reset", "Réinitialiser")) + '</button>';
        }
        if (opts.aiEnabled && opts.aiHandler) {
            h += '<button class="btn-ai btn-icon" data-click="' + esc(opts.aiHandler) + '">'
                + _icn("zap", 14) + ' ' + esc(_t("fd.ai_triage", "Triage IA")) + '</button>';
        }
        if (opts.deleteHandler) {
            h += '<span style="flex:1"></span>';
            h += '<button class="btn-add" style="background:#dc2626;color:white" data-click="' + esc(opts.deleteHandler) + '">'
                + esc(_t("fd.delete", "Supprimer")) + '</button>';
        }
        h += '</div>';
        h += '<div id="ai-triage-result" style="display:none;margin-top:12px;padding:12px;background:#f5f3ff;border:1px solid #c4b5fd;border-radius:6px;font-size:0.88em"></div>';
        h += '</div>';
        return h;
    }
    function _renderLinkedMeasureCard(m, opts) {
        if (!m)
            return "";
        var cc = opts.cardClass || "surface-card";
        var statusKey = "measures.status." + (m.statut || "");
        var statusLbl = _t(statusKey, _t("measure.status." + (m.statut || ""), m.statut || ""));
        var h = '<div class="' + esc(cc) + '">';
        h += '<h3 style="margin-top:0;font-size:0.95em">' + esc(_t("fd.measure_linked", "Mesure liée")) + '</h3>';
        h += '<div style="font-weight:600">' + esc(m.id || "") + ' &mdash; ' + esc(m.title || "") + '</div>';
        var meta = [];
        if (statusLbl)
            meta.push(esc(_t("fd.measure_status", "Statut")) + ' : ' + esc(statusLbl));
        if (m.responsable)
            meta.push(esc(_t("fd.measure_owner", "Responsable")) + ' : ' + esc(m.responsable));
        if (m.echeance)
            meta.push(esc(_t("fd.measure_due", "Échéance")) + ' : ' + esc(m.echeance));
        if (meta.length) {
            h += '<div style="font-size:0.82em;color:var(--text-muted);margin-top:4px">' + meta.join(' &middot; ') + '</div>';
        }
        h += '</div>';
        return h;
    }
    window._ctFvNoop = window._ctFvNoop || function () { };
    // ──────────────────────────────────────────────────────────────
    // Public render
    // ──────────────────────────────────────────────────────────────
    function render(finding, opts) {
        opts = opts || {};
        var f = finding || {};
        var h = _renderHeader(f, opts);
        if (opts.subheaderHtml)
            h += opts.subheaderHtml;
        h += _renderInfoCardClean(f, opts);
        h += _renderTriageCard(f, opts);
        h += _renderLinkedMeasureCard(opts.linkedMeasure, opts);
        return h;
    }
    // ──────────────────────────────────────────────────────────────
    // Triage dialog opener
    // ──────────────────────────────────────────────────────────────
    //
    // Unified entry point for the 3 triage flows:
    //   to_fix          → ct_measure_modal (title/description/owner/due/notes)
    //   false_positive  → ct_modal with a justification textarea (required)
    //   new (reset)     → ct_modal.confirm
    //
    // Returns Promise<payload|null>. `payload` is ready to POST to the
    // module's triageFinding/bulkTriageFindings API.
    function openTriageModal(finding, status, opts) {
        opts = opts || {};
        var f = finding || {};
        // Capture the free-form notes typed on the triage card (if any)
        // so every payload returned to the caller carries them as
        // `triage_notes`. This survives the sub-modal opening (which
        // tears down the finding detail DOM — we snapshot BEFORE that).
        var cardNotesEl = document.getElementById("ct-fv-triage-notes");
        var cardNotes = cardNotesEl ? (cardNotesEl.value || "").trim() : "";
        if (status === "to_fix") {
            return window.ct_measure_modal.open({
                title: f.title || "",
                description: f.description || ""
            }, {
                title: _t("tm.title_to_fix", "Créer une mesure corrective"),
                saveLabel: _t("tm.confirm_to_fix", "Créer la mesure"),
                hideFields: ["type", "statut"],
                ownerPicker: {
                    pickerId: opts.ownerPickerId || "ct-fv-owner",
                    directoryUrl: opts.directoryUrl || "api/directory",
                    sourceUrl: opts.sourceUrl === null ? null : (opts.sourceUrl || "api/settings/directory-source")
                }
            }).then(function (data) {
                if (!data || data.__deleted)
                    return null;
                return {
                    status: "to_fix",
                    measure_title: data.title,
                    measure_description: data.description,
                    responsable: data.responsable,
                    echeance: data.echeance,
                    triage_notes: cardNotes
                };
            });
        }
        if (status === "false_positive") {
            // Wrapped in ct-measure-form so the textarea inherits the
            // standard form styling (full width, padding, border, min-
            // height) instead of the browser's default narrow textarea.
            var body = ''
                + '<div style="font-size:0.82em;color:var(--text-muted);margin-bottom:12px">'
                + '<strong>' + esc(_t("tm.finding", "Finding")) + '</strong> ' + esc(f.title || "")
                + '</div>'
                + '<div class="ct-measure-form">'
                + '<label>' + esc(_t("tm.fp_justif", "Justification")) + ' *'
                + '<textarea id="ct-fv-fp-notes" rows="6" placeholder="'
                + esc(_t("tm.fp_justif_ph", "Expliquer pourquoi ce finding est un faux positif"))
                + '"></textarea>'
                + '</label>'
                + '</div>';
            return window.ct_modal.open({
                title: _t("tm.title_fp", "Marquer comme faux positif"),
                body: body,
                size: "md",
                onOpen: function () {
                    var el = document.getElementById("ct-fv-fp-notes");
                    if (el) {
                        try {
                            el.focus();
                        }
                        catch (e) { }
                    }
                },
                buttons: [
                    { id: "cancel", label: _t("btn_cancel", "Annuler") },
                    { id: "save", primary: true, label: _t("tm.confirm_fp", "Confirmer"),
                        result: function () {
                            var notes = ((document.getElementById("ct-fv-fp-notes") || {}).value || "").trim();
                            if (!notes) {
                                if (typeof showStatus === "function")
                                    // 2nd arg ignored by the shared showStatus(msg) —
                                    // kept for app forks that accept an isError flag.
                                    showStatus(_t("tm.justif_required", "Justification requise"), true);
                                return false;
                            }
                            // Merge the card's free-form note (if any) with the
                            // justification captured in the modal so nothing
                            // gets lost if the user typed in both places.
                            var merged = cardNotes
                                ? (cardNotes + "\n\n" + notes)
                                : notes;
                            return { status: "false_positive", triage_notes: merged, notes: merged };
                        } }
                ]
            });
        }
        if (status === "new") {
            return window.ct_modal.confirm({
                title: _t("tm.title_reset", "Réinitialiser le statut"),
                message: _t("tm.reset_help", "Le statut sera remis à « nouveau » et la mesure associée sera supprimée.")
            }).then(function (ok) {
                return ok ? { status: "new", triage_notes: cardNotes } : null;
            });
        }
        if (status === "fixed") {
            return window.ct_modal.confirm({
                title: _t("tm.title_fixed", "Marquer comme corrigé"),
                message: _t("tm.fixed_help", "Le finding sera marqué comme corrigé. Il réapparaîtra s'il est détecté au prochain scan.")
            }).then(function (ok) {
                return ok ? { status: "fixed", triage_notes: cardNotes } : null;
            });
        }
        return Promise.resolve(null);
    }
    window.ct_finding_view = {
        render: render,
        openTriageModal: openTriageModal
    };
})();

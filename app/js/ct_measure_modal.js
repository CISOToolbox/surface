// ─────────────────────────────────────────────────────────────
// GENERATED from shared/ts/ — do NOT edit here.
// Edit the shared TypeScript source and run shared/ts-build.sh.
// ─────────────────────────────────────────────────────────────
/**
 * ct_measure_modal — Unified add/edit measure modal for every module.
 *
 * Depends on ct_modal and ct_userpicker. All text goes through t()
 * with inline fallbacks. CSP-safe (data-click). Survives the
 * "+ Créer utilisateur" sub-modal via a deferred Promise that is
 * only resolved by the save/cancel/delete/extra button of the
 * terminal reopened instance.
 *
 * Public API:
 *   ct_measure_modal.open(measure, opts) → Promise<data|null>
 *
 * `measure` — existing measure object (for edit) or null (for create).
 *             Field names inside `measure` can follow either the FR
 *             default (statut, responsable, echeance) or the mapped
 *             names declared in opts.fieldMap (e.g. Pilot uses status /
 *             assignee / due_date).
 *
 * Opts (all optional unless noted):
 *   title              — modal title (default: "Nouvelle mesure" / "Mesure <id>")
 *   saveLabel          — save button label (default: t("btn_save"))
 *   size               — "sm" | "md" | "lg" (default "md")
 *
 *   hideFields         — string[] of core field keys to hide
 *                        (title, description, type, statut, responsable, echeance)
 *
 *   fieldMap           — rename output keys. Example for Pilot:
 *                        { statut: "status", responsable: "assignee",
 *                          echeance: "due_date" }
 *
 *   statusOptions      — [{value,label}] for the status <select>. Required
 *                        if status is not hidden.
 *   defaultStatus      — initial status value when measure has none
 *
 *   typeOptions        — [{value,label}] for the type <select>. Required
 *                        if type is not hidden.
 *
 *   titleRequired      — bool (default true) — block save on empty title
 *   titleReadOnly      — bool — display title as plain text (for cross-
 *                        module measures where the host module doesn't own
 *                        the record)
 *
 *   ownerPicker        — bool | {directoryUrl, sourceUrl, pickerId}
 *                        true → mount ct_userpicker with defaults
 *                        false → plain text input
 *                        object → custom picker opts (see ct_userpicker.mount)
 *                        sourceUrl: null → always full picker (Pilot native)
 *
 *   headerHtml         — raw HTML injected before the form (badges, ids…)
 *   extraContent       — raw HTML injected after the form (finding summary
 *                        for bulk create, etc.). Not read back — for display.
 *   extraFields        — [{key,label,type,value,options?,rows?}] extra
 *                        editable fields read back into the output data
 *   extraButtons       — buttons appended before Save. Each is a regular
 *                        ct_modal button (id, label, result).
 *   onDelete           — if provided, adds a red "Supprimer" button that
 *                        calls this handler then closes the modal with
 *                        { __deleted: true }
 *
 * Returned data object on save (keys respect fieldMap):
 *   { id?, title, description?, type?, <status_key>, <owner_key>,
 *     <due_key>, ...extraFields }
 *
 * Dismissal / Delete / extraButton:
 *   - Cancel / Escape / backdrop → resolves null
 *   - Delete → resolves { __deleted: true } (onDelete already called)
 *   - Custom extraButton → whatever its `result` returns
 */
(function () {
    "use strict";
    var DEFAULT_STATUS_KEYS = ["planifie", "en_cours", "termine", "backlog", "annule"];
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
    function _fieldId(key) { return "ctm-f-" + key; }
    function _val(id) { var el = document.getElementById(id); return el ? el.value : ""; }
    function _defaultStatusOptions() {
        return DEFAULT_STATUS_KEYS.map(function (s) {
            return { value: s, label: _t("measure.status." + s, s) };
        });
    }
    function _hidden(key, hide) {
        return Array.isArray(hide) && hide.indexOf(key) >= 0;
    }
    // Extra field rendering (html / textarea / select / date / text / checkbox)
    function _extraFieldHtml(f) {
        if (f.type === "html")
            return f.value || ""; // raw injection, read-only
        var id = _fieldId(f.key);
        var lbl = esc(f.label || f.key);
        var val = f.value == null ? "" : f.value;
        var h = '<label>' + lbl;
        if (f.type === "textarea") {
            h += '<textarea id="' + id + '" rows="' + (f.rows || 2) + '">' + esc(val) + '</textarea>';
        }
        else if (f.type === "select") {
            h += '<select id="' + id + '">';
            h += '<option value="">—</option>';
            (f.options || []).forEach(function (opt) {
                var o = opt;
                var ov = o.value !== undefined ? o.value : opt;
                var ol = o.label !== undefined ? o.label : ov;
                h += '<option value="' + esc(ov) + '"' + (String(val) === String(ov) ? " selected" : "") + '>' + esc(ol) + '</option>';
            });
            h += '</select>';
        }
        else if (f.type === "date") {
            h += '<input type="date" id="' + id + '" value="' + esc(val) + '">';
        }
        else if (f.type === "checkbox") {
            h += '<input type="checkbox" id="' + id + '"' + (val ? " checked" : "") + '>';
        }
        else {
            h += '<input type="text" id="' + id + '" value="' + esc(val) + '">';
        }
        h += '</label>';
        return h;
    }
    function _readExtra(f) {
        if (f.type === "html")
            return undefined;
        var el = document.getElementById(_fieldId(f.key));
        if (!el)
            return undefined;
        if (f.type === "checkbox")
            return !!el.checked;
        return el.value;
    }
    // ──────────────────────────────────────────────────────────────
    // Public entry point — deferred Promise that survives sub-modals
    // ──────────────────────────────────────────────────────────────
    function open(measure, opts) {
        var ctx = { resolved: false, resolveOuter: null };
        var promise = new Promise(function (resolve) {
            ctx.resolveOuter = function (v) {
                if (ctx.resolved)
                    return;
                ctx.resolved = true;
                resolve(v);
            };
        });
        _openInner(measure, opts || {}, ctx);
        return promise;
    }
    // ──────────────────────────────────────────────────────────────
    // Internal: renders + wires one instance of the modal
    // ──────────────────────────────────────────────────────────────
    function _openInner(measure, opts, ctx) {
        if (!window.ct_modal || typeof window.ct_modal.open !== "function") {
            if (typeof showStatus === "function")
                showStatus("ct_modal not loaded", true);
            ctx.resolveOuter(null);
            return;
        }
        var m = measure || {};
        var prefill = opts._prefill || {};
        var FM = opts.fieldMap || {};
        var hide = opts.hideFields || [];
        // willReopen: set to true when "+ Créer utilisateur" triggers a
        // sub-modal. Prevents the outer deferred from resolving with null
        // when ct_modal closes the current instance to open the sub-modal.
        var willReopen = false;
        // ── Resolve field values (prefill > measure[outKey] > measure[localKey] > "") ──
        function outKey(localKey) { return FM[localKey] || localKey; }
        function initial(localKey) {
            var ok = outKey(localKey);
            if (prefill[ok] != null)
                return prefill[ok];
            if (m[ok] != null)
                return m[ok];
            if (m[localKey] != null)
                return m[localKey];
            return "";
        }
        var v_title = initial("title");
        var v_desc = initial("description");
        var v_type = initial("type");
        var v_stat = initial("statut") || opts.defaultStatus || "";
        var v_resp = initial("responsable");
        var v_due = initial("echeance");
        var _rawLog = initial("progress_log");
        var v_log = Array.isArray(_rawLog) ? _rawLog : [];
        // ── Picker config ────────────────────────────────────────────
        var pickerEnabled = !!opts.ownerPicker;
        var pickerOpts = (opts.ownerPicker && typeof opts.ownerPicker === "object") ? opts.ownerPicker : {};
        var pickerId = pickerOpts.pickerId || "ctm-owner";
        var directoryUrl = pickerOpts.directoryUrl || "api/directory";
        // null means "skip source detection, always full picker" (used by
        // Pilot which owns the directory natively).
        var sourceUrl = pickerOpts.sourceUrl === null
            ? null
            : (pickerOpts.sourceUrl || "api/settings/directory-source");
        // Populated in onOpen by ct_userpicker.mount. All reads of the
        // responsable field go through this handle for a uniform API
        // regardless of picker/plain mode.
        var ownerHandle = null;
        // ── Build body HTML ──────────────────────────────────────────
        var statusOpts = Array.isArray(opts.statusOptions) && opts.statusOptions.length
            ? opts.statusOptions
            : _defaultStatusOptions();
        var typeOpts = Array.isArray(opts.typeOptions) ? opts.typeOptions : [];
        var h = "";
        if (opts.headerHtml)
            h += opts.headerHtml;
        h += '<div class="ct-measure-form">';
        if (!_hidden("title", hide)) {
            h += '<label>' + esc(_t("measure.field.title", "Titre"))
                + (opts.titleRequired !== false && !opts.titleReadOnly ? ' *' : '');
            if (opts.titleReadOnly) {
                h += '<div style="font-weight:600">' + esc(v_title) + '</div>';
            }
            else {
                h += '<input type="text" id="' + _fieldId("title") + '" value="' + esc(v_title) + '">';
            }
            h += '</label>';
        }
        if (!_hidden("description", hide)) {
            h += '<label>' + esc(_t("measure.field.description", "Description"))
                + '<textarea id="' + _fieldId("description") + '" rows="3">' + esc(v_desc) + '</textarea>'
                + '</label>';
        }
        // Progress journal — timestamped notes on where the measure stands,
        // distinct from the discrete status. The form shows only the latest
        // note (one line: date · author · text); the full history opens in a
        // secondary overlay. A note can be added inline without saving the
        // measure (persisted immediately via opts.onAddNote when it exists).
        var journalVisible = !_hidden("progress_log", hide);
        // Author for a new note: explicit opt, else the logged-in user (backend
        // apps set window._currentUser), else empty (opensource).
        function _journalAuthor() {
            var cu = window._currentUser;
            return opts.currentUser || (cu && cu.name) || "";
        }
        // One compact line: "<date> · <author> — <text>".
        function _journalLineHtml(e) {
            var when = (e && e.at ? String(e.at) : "").slice(0, 16).replace("T", " ");
            var meta = [when, (e && e.by) ? String(e.by) : ""].filter(Boolean).join(" · ");
            return '<span class="ct-journal-meta">' + esc(meta) + '</span>'
                + (meta ? '<span class="ct-journal-sep"> — </span>' : '')
                + '<span class="ct-journal-text">' + esc((e && e.text) ? String(e.text) : "") + '</span>';
        }
        // Collapsed body = latest entry + a "history (N)" link when N > 1.
        function _journalBodyHtml() {
            if (!v_log.length)
                return '<div class="ct-journal-empty">' + esc(_t("measure.field.progress_log_empty", "Aucune note pour l'instant.")) + '</div>';
            var last = v_log[v_log.length - 1];
            var out = '<div class="ct-journal-entry">' + _journalLineHtml(last) + '</div>';
            if (v_log.length > 1)
                out += '<button type="button" class="ct-journal-history-link" id="ctm-journal-history">'
                    + esc(_t("measure.field.progress_log_history", "Voir l'historique")) + ' (' + v_log.length + ')</button>';
            return out;
        }
        // Full history in a secondary overlay (ct_modal is a single shared
        // overlay, so the history gets its own lightweight layer on top).
        function _openJournalHistory() {
            var ov = document.createElement("div");
            ov.className = "ct-journal-hist-overlay";
            var rows = v_log.slice().reverse().map(function (e) {
                return '<div class="ct-journal-entry">' + _journalLineHtml(e) + '</div>';
            }).join("");
            ov.innerHTML = '<div class="ct-journal-hist-box">'
                + '<div class="ct-journal-hist-head"><strong>' + esc(_t("measure.field.progress_log", "Journal d'avancement")) + '</strong>'
                + '<button type="button" class="ct-journal-hist-close" aria-label="Close">&times;</button></div>'
                + '<div class="ct-journal-hist-list">' + rows + '</div></div>';
            document.body.appendChild(ov);
            function close() { if (ov.parentNode)
                ov.parentNode.removeChild(ov); }
            ov.addEventListener("click", function (ev) { if (ev.target === ov)
                close(); });
            var cb = ov.querySelector(".ct-journal-hist-close");
            if (cb)
                cb.addEventListener("click", close);
            function onEsc(ev) {
                if (ev.key === "Escape") {
                    close();
                    document.removeEventListener("keydown", onEsc);
                }
            }
            document.addEventListener("keydown", onEsc);
        }
        if (journalVisible) {
            h += '<div class="ct-measure-journal">';
            h += '<label class="ct-journal-lbl">' + esc(_t("measure.field.progress_log", "Journal d'avancement")) + '</label>';
            h += '<div class="ct-journal-body" id="ctm-journal-body">' + _journalBodyHtml() + '</div>';
            if (!opts.journalReadOnly) {
                h += '<div class="ct-journal-add">'
                    + '<textarea id="' + _fieldId("progress_log_new") + '" rows="2" placeholder="' + esc(_t("measure.field.progress_log_ph", "Ajouter une note d'avancement…")) + '"></textarea>'
                    + '<button type="button" class="ct-btn ct-journal-add-btn" id="ctm-journal-add">' + esc(_t("measure.field.progress_log_add", "Ajouter")) + '</button>'
                    + '</div>';
            }
            h += '</div>';
        }
        // Row: type + status (collapsed together if both visible)
        var typeVisible = !_hidden("type", hide) && typeOpts.length > 0;
        var statVisible = !_hidden("statut", hide);
        if (typeVisible || statVisible) {
            h += '<div class="ct-measure-form__row">';
            if (typeVisible) {
                h += '<label>' + esc(_t("measure.field.type", "Type"))
                    + '<select id="' + _fieldId("type") + '">'
                    + '<option value="">—</option>';
                typeOpts.forEach(function (ty) {
                    h += '<option value="' + esc(ty.value) + '"' + (v_type === ty.value ? " selected" : "") + '>' + esc(ty.label) + '</option>';
                });
                h += '</select></label>';
            }
            if (statVisible) {
                h += '<label>' + esc(_t("measure.field.statut", "Statut"))
                    + '<select id="' + _fieldId("statut") + '">';
                if (!opts.defaultStatus)
                    h += '<option value="">—</option>';
                statusOpts.forEach(function (s) {
                    h += '<option value="' + esc(s.value) + '"' + (v_stat === s.value ? " selected" : "") + '>' + esc(s.label) + '</option>';
                });
                h += '</select></label>';
            }
            h += '</div>';
        }
        // Row: responsable + echeance
        var respVisible = !_hidden("responsable", hide);
        var dueVisible = !_hidden("echeance", hide);
        if (respVisible || dueVisible) {
            h += '<div class="ct-measure-form__row">';
            if (respVisible) {
                h += '<label>' + esc(_t("measure.field.responsable", "Responsable"));
                if (pickerEnabled) {
                    // Slot replaced by ct_userpicker.mount() in onOpen
                    h += '<div id="ctm-owner-slot"></div>';
                }
                else {
                    h += '<input type="text" id="' + _fieldId("responsable") + '" value="' + esc(v_resp) + '">';
                }
                h += '</label>';
            }
            if (dueVisible) {
                h += '<label>' + esc(_t("measure.field.echeance", "Échéance"))
                    + '<input type="date" id="' + _fieldId("echeance") + '" value="' + esc(v_due) + '">'
                    + '</label>';
            }
            h += '</div>';
        }
        if (Array.isArray(opts.extraFields)) {
            opts.extraFields.forEach(function (f) { h += _extraFieldHtml(f); });
        }
        h += '</div>';
        if (opts.extraContent)
            h += opts.extraContent;
        // ── Snapshot / collect helpers ───────────────────────────────
        // The full journal = entries collected so far (including any added
        // inline via the "Ajouter" button) plus a trailing one if the author
        // typed text but did not click Add. at/by are stamped client-side.
        function buildLog() {
            var out = v_log.slice();
            var nt = (_val(_fieldId("progress_log_new")) || "").trim();
            if (nt)
                out.push({ at: new Date().toISOString(), by: _journalAuthor(), text: nt });
            return out;
        }
        function snapshot() {
            var snap = {};
            if (!_hidden("title", hide) && !opts.titleReadOnly)
                snap[outKey("title")] = _val(_fieldId("title")) || v_title;
            if (!_hidden("description", hide))
                snap[outKey("description")] = _val(_fieldId("description")) || v_desc;
            if (typeVisible)
                snap[outKey("type")] = _val(_fieldId("type")) || v_type;
            if (statVisible)
                snap[outKey("statut")] = _val(_fieldId("statut")) || v_stat;
            if (respVisible)
                snap[outKey("responsable")] = (ownerHandle ? ownerHandle.getValue() : _val(_fieldId("responsable"))) || v_resp;
            if (dueVisible)
                snap[outKey("echeance")] = _val(_fieldId("echeance")) || v_due;
            if (journalVisible && !opts.journalReadOnly)
                snap[outKey("progress_log")] = buildLog();
            if (Array.isArray(opts.extraFields)) {
                opts.extraFields.forEach(function (f) {
                    var v = _readExtra(f);
                    if (v !== undefined)
                        snap[f.key] = v;
                });
            }
            return snap;
        }
        function collect() {
            var data = {};
            if (m && m.id)
                data.id = m.id;
            if (!_hidden("title", hide)) {
                data[outKey("title")] = opts.titleReadOnly
                    ? v_title
                    : (_val(_fieldId("title")) || "").trim();
            }
            if (!_hidden("description", hide))
                data[outKey("description")] = (_val(_fieldId("description")) || "").trim();
            if (typeVisible)
                data[outKey("type")] = _val(_fieldId("type"));
            if (statVisible)
                data[outKey("statut")] = _val(_fieldId("statut")) || opts.defaultStatus || "";
            if (respVisible) {
                var val = ownerHandle ? ownerHandle.getValue() : _val(_fieldId("responsable"));
                data[outKey("responsable")] = (val || "").trim();
            }
            if (dueVisible)
                data[outKey("echeance")] = _val(_fieldId("echeance"));
            if (journalVisible && !opts.journalReadOnly)
                data[outKey("progress_log")] = buildLog();
            if (Array.isArray(opts.extraFields)) {
                opts.extraFields.forEach(function (f) {
                    var v = _readExtra(f);
                    if (v !== undefined)
                        data[f.key] = typeof v === "string" ? v.trim() : v;
                });
            }
            return data;
        }
        // ── Buttons ──────────────────────────────────────────────────
        var isNew = !m || !m.id;
        var title = opts.title || (isNew
            ? _t("measure.new", "Nouvelle mesure")
            : _t("measure.edit", "Mesure") + (m.id ? " " + m.id : ""));
        var buttons = [];
        if (typeof opts.onDelete === "function") {
            buttons.push({
                id: "delete", label: _t("btn_delete", "Supprimer"), danger: true,
                result: function () {
                    // Defer so the measure modal finishes closing before the
                    // caller opens its own confirm dialog — ct_modal is a
                    // single overlay; calling ct_modal.confirm() inside this
                    // result function would tear itself down immediately.
                    var fn = opts.onDelete;
                    setTimeout(function () { try {
                        fn();
                    }
                    catch (e) { } }, 0);
                    return { __deleted: true };
                }
            });
        }
        buttons.push({ id: "cancel", label: _t("btn_cancel", "Annuler") });
        if (Array.isArray(opts.extraButtons)) {
            opts.extraButtons.forEach(function (b) { buttons.push(b); });
        }
        buttons.push({
            id: "save", primary: true,
            label: opts.saveLabel || _t("btn_save", "Enregistrer"),
            result: function () {
                var data = collect();
                var titleKey = outKey("title");
                if (!_hidden("title", hide) && !opts.titleReadOnly
                    && opts.titleRequired !== false
                    && !(data[titleKey] || "").trim()) {
                    if (typeof showStatus === "function")
                        showStatus(_t("measure.title_required", "Titre requis"), true);
                    var el = document.getElementById(_fieldId("title"));
                    if (el) {
                        try {
                            el.focus();
                        }
                        catch (e) { }
                    }
                    return false;
                }
                return data;
            }
        });
        // ── Open ─────────────────────────────────────────────────────
        window.ct_modal.open({
            title: title,
            body: h,
            size: opts.size || "md",
            buttons: buttons,
            onOpen: function (overlay) {
                if (pickerEnabled && window.ct_userpicker && window.ct_userpicker.mount) {
                    window.ct_userpicker.mount({
                        slotId: "ctm-owner-slot",
                        pickerId: pickerId,
                        value: v_resp,
                        placeholder: _t("ct.userpicker.search_placeholder", "Rechercher..."),
                        directoryUrl: directoryUrl,
                        sourceUrl: sourceUrl,
                        onCreate: function (query) {
                            // Deferred reopen: promptCreateUser opens a
                            // sub-modal that WILL tear down this one.
                            willReopen = true;
                            var snap = snapshot();
                            return window.ct_userpicker.promptCreateUser({
                                query: query, apiUrl: directoryUrl
                            }).then(function (created) {
                                if (created)
                                    snap[outKey("responsable")] = window.ct_userpicker._label(created);
                                _openInner(measure, Object.assign({}, opts, { _prefill: snap }), ctx);
                                return created;
                            });
                        }
                    }).then(function (handle) { ownerHandle = handle; });
                }
                // Auto-grow the description textarea to fit its content
                // (capped at 500px to keep the modal manageable). Applied
                // on mount + on every input. Also applied to any extra
                // textarea in the form for consistency.
                var areas = overlay.querySelectorAll(".ct-measure-form textarea");
                areas.forEach(function (el) {
                    function autoGrow() {
                        el.style.height = "auto";
                        var h = Math.min(el.scrollHeight, 500);
                        el.style.height = h + "px";
                    }
                    autoGrow();
                    el.addEventListener("input", autoGrow);
                });
                // Progress journal — inline "Ajouter" + history overlay.
                if (journalVisible && !opts.journalReadOnly) {
                    var jbody = overlay.querySelector("#ctm-journal-body");
                    var bindHistory = function () {
                        var hl = overlay.querySelector("#ctm-journal-history");
                        if (hl)
                            hl.addEventListener("click", function () { _openJournalHistory(); });
                    };
                    bindHistory();
                    var addBtn = overlay.querySelector("#ctm-journal-add");
                    if (addBtn)
                        addBtn.addEventListener("click", function () {
                            var ta = overlay.querySelector("#" + _fieldId("progress_log_new"));
                            var txt = ((ta && ta.value) || "").trim();
                            if (!txt) {
                                if (ta)
                                    ta.focus();
                                return;
                            }
                            var entry = { at: new Date().toISOString(), by: _journalAuthor(), text: txt };
                            var commit = function () {
                                v_log.push(entry);
                                if (ta) {
                                    ta.value = "";
                                    ta.style.height = "auto";
                                }
                                if (jbody)
                                    jbody.innerHTML = _journalBodyHtml();
                                bindHistory();
                            };
                            if (m && m.id && typeof opts.onAddNote === "function") {
                                addBtn.disabled = true;
                                Promise.resolve(opts.onAddNote(entry, v_log.concat([entry])))
                                    .then(function () { commit(); })
                                    .catch(function () {
                                    if (typeof showStatus === "function")
                                        showStatus(_t("measure.field.progress_log_add_err", "Échec de l'ajout de la note"), true);
                                })
                                    .then(function () { if (addBtn)
                                    addBtn.disabled = false; });
                            }
                            else {
                                commit();
                            }
                        });
                }
                if (!opts.titleReadOnly && !_hidden("title", hide)) {
                    var tf = overlay.querySelector("#" + _fieldId("title"));
                    if (tf) {
                        try {
                            tf.focus();
                            tf.select && tf.select();
                        }
                        catch (e) { }
                    }
                }
            }
        }).then(function (result) {
            // Skip resolution if this instance was torn down by a "+ Créer"
            // → the reopened instance owns the deferred resolution.
            if (willReopen)
                return;
            ctx.resolveOuter(result);
        });
    }
    window.ct_measure_modal = { open: open };
})();

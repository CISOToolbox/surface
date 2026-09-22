// -----------------------------------------------------------------------------
// Generated file - do not edit.
// It is overwritten at every release; a change made here is lost.
// See CONTRIBUTING.md.
// -----------------------------------------------------------------------------
// ct_nonconformity — shared non-conformity and derogation UI (FEAT-45).
//
// One component served from any module: the caller supplies transport
// callbacks against ITS backend (the module's /api/nonconformities and
// /api/derogations routes) and, as associations, the objects of the module a
// record can be linked to (its items, its measures). The component renders:
//   * declare(opts, prefill)           — the non-conformity form (also its edit)
//   * requestDerogation(opts, prefill) — the derogation form
//   * renderPanel(container, opts)     — register panel (both lists, filters,
//                                        detail modal with the role-gated actions)
//   * badge(kind, status)              — status badge shared by the modules
// Every link to another object goes through the same field, the shared
// selector: tags, type-to-filter, "+ create" when the module can create the
// object, single or multiple as the field requires. Business rules
// (transitions, dates, single live derogation per subject) are enforced
// server-side; the component only shapes the requests and surfaces the
// server's message when one is refused.
(function () {
    "use strict";
    var NC_SOURCES = ["observation", "report", "informal_review", "incident"];
    var NC_SEVERITIES = ["low", "medium", "high", "critical"];
    var NC_STATUSES = ["to_qualify", "open", "in_remediation", "derogated", "closed", "rejected"];
    var DER_STATUSES = ["pending_approval", "approved", "rejected", "expired", "revoked"];
    var _NC_TONES = {
        to_qualify: "medium", open: "high", in_remediation: "info", derogated: "neutral",
        closed: "low", rejected: "neutral",
    };
    var _DER_TONES = {
        pending_approval: "medium", approved: "low", rejected: "neutral",
        expired: "high", revoked: "neutral",
    };
    var _SEV_TONES = { critical: "critical", high: "high", medium: "medium", low: "low" };
    // Panel state (one panel at a time; both modules render it full-page).
    var _container = null;
    var _opts = null;
    var _ncRows = [];
    var _derRows = [];
    var _ncFilter = "";
    var _derFilter = "";
    var _moduleFilter = "";
    var _sourceFilter = "";
    var _severityFilter = "";
    var _ageFilter = 0; // minimum age in days since observation (0 = any)
    function _tone(kind, status) {
        var m = kind === "der" ? _DER_TONES : _NC_TONES;
        return m[status] || "neutral";
    }
    function _badge(kind, status) {
        var key = (kind === "der" ? "der.status." : "nc.status.") + status;
        return '<span class="ct-badge" data-tone="' + esc(_tone(kind, status)) + '">' + esc(t(key)) + '</span>';
    }
    function _sevBadge(sev) {
        return '<span class="ct-badge" data-tone="' + esc(_SEV_TONES[sev] || "neutral") + '">' + esc(t("nc.severity." + sev)) + '</span>';
    }
    // What the user may do here, read from the MODULE role (window._moduleRole,
    // filled from /auth/role) — the same role the server's gates test. The
    // account's global role says nothing about this module. Auth disabled
    // answers "admin", so the sentinel keeps full access.
    function _moduleRole() { return window._moduleRole || ""; }
    function _isAdmin() {
        if (_opts && _opts.isAdmin)
            return _opts.isAdmin();
        var r = _moduleRole(); // exactly what require_admin tests
        return r === "admin" || r === "control"; // both admin-equivalent roles
    }
    function _canWrite() {
        if (_opts && _opts.canWrite)
            return _opts.canWrite();
        var r = _moduleRole();
        return !!r && r !== "viewer" && r !== "reader";
    }
    function _modal() {
        return (window.ct_modal && typeof window.ct_modal.open === "function") ? window.ct_modal : null;
    }
    // The API layer prefixes "API <code>: {"detail":"…"}" — surface the detail alone.
    function _detail(e) {
        var msg = (e && e.message) ? String(e.message) : t("nc.error");
        var m = /"detail"\s*:\s*"([^"]+)"/.exec(msg);
        return m ? m[1] : msg;
    }
    function _fail(e) { showStatus(_detail(e), true); }
    // A refusal shown in the form itself (the form reopened with its fields kept).
    function _showServerError(msg) {
        var box = document.getElementById("ct-form-errors");
        if (box) {
            box.innerHTML = esc(msg);
            box.hidden = false;
            box.scrollIntoView({ block: "nearest" });
        }
    }
    function _today() { return new Date().toISOString().slice(0, 10); }
    function _val(id) {
        var el = document.getElementById(id);
        return el ? (el.value || "").trim() : "";
    }
    function _lines(id) {
        return _val(id).split("\n").map(function (x) { return x.trim(); }).filter(function (x) { return !!x; });
    }
    function _field(label, control, required) {
        return '<label class="ct-block ct-mb-2"><span class="fs-xs ct-muted">' + esc(label)
            + (required ? '<span class="ct-req" aria-hidden="true">*</span>' : '') + '</span>' + control + '</label>';
    }
    function _input(id, value, type, attrs) {
        return '<input id="' + id + '" type="' + (type || "text") + '" value="' + esc(value) + '" class="w-full"' + (attrs || "") + ' />';
    }
    function _textarea(id, value, rows) {
        return '<textarea id="' + id + '" rows="' + (rows || 3) + '" class="w-full">' + esc(value) + '</textarea>';
    }
    function _select(id, values, current, keyPrefix, attrs) {
        var h = '<select id="' + id + '" class="w-full"' + (attrs || "") + '>';
        values.forEach(function (v) {
            h += '<option value="' + esc(v) + '"' + (v === current ? ' selected' : '') + '>' + esc(t(keyPrefix + v)) + '</option>';
        });
        return h + '</select>';
    }
    function _row(label, value, raw) {
        if (!value)
            return "";
        return '<div class="ct-flex ct-gap-2 fs-sm ct-mb-1"><span class="ct-muted ct-minw-140">' + esc(label) + '</span><span>' + (raw ? value : esc(value)) + '</span></div>';
    }
    // A translation with a per-kind variant ("nc.f.items.control") and a default.
    function _tk(base, kind) {
        var v = t(base + "." + kind);
        return v === base + "." + kind ? t(base) : v;
    }
    // Inline feedback: the modal lists what is missing and outlines the
    // fields concerned, instead of a status message the user may not see.
    function _errorsBox() { return '<div id="ct-form-errors" class="ct-form-errors" hidden></div>'; }
    function _clearErrors() {
        var box = document.getElementById("ct-form-errors");
        if (box) {
            box.hidden = true;
            box.innerHTML = "";
        }
        var marked = document.querySelectorAll(".ct-field-error");
        for (var i = 0; i < marked.length; i++)
            marked[i].classList.remove("ct-field-error");
    }
    function _fieldEl(id) {
        return document.getElementById(id + "-search") || document.getElementById(id + "-plain") || document.getElementById(id);
    }
    function _showErrors(problems, intro) {
        _clearErrors();
        if (!problems.length)
            return true;
        var box = document.getElementById("ct-form-errors");
        if (box) {
            var h = esc(intro) + '<ul>';
            problems.forEach(function (p) { h += '<li>' + esc(p.label) + '</li>'; });
            box.innerHTML = h + '</ul>';
            box.hidden = false;
            box.scrollIntoView({ block: "nearest" });
        }
        problems.forEach(function (p) { var el = _fieldEl(p.id); if (el)
            el.classList.add("ct-field-error"); });
        var first = _fieldEl(problems[0].id);
        if (first && typeof first.focus === "function")
            first.focus();
        return false;
    }
    // Person fields go through the shared directory picker (mounted on open,
    // read back through the handle: a pick or free text alike).
    var _pickers = {};
    function _pickerSlot(id) { return '<div id="' + id + '-slot"></div>'; }
    function _mountPickers(opts, ids, values) {
        _pickers = {};
        var up = window.ct_userpicker;
        if (!up || typeof up.mount !== "function") {
            ids.forEach(function (id) {
                var slot = document.getElementById(id + "-slot");
                if (slot)
                    slot.outerHTML = _input(id, values[id] || "");
            });
            return;
        }
        ids.forEach(function (id) {
            up.mount({ slotId: id + "-slot", pickerId: id, value: values[id] || "",
                placeholder: t("nc.search_person"), directoryUrl: opts.directoryUrl || "api/directory" })
                .then(function (h) { _pickers[id] = h; });
        });
    }
    function _person(id) {
        var h = _pickers[id];
        if (h)
            return (h.getValue() || "").trim();
        return _val(id);
    }
    // The selection stays visible even when the module no longer lists an
    // object (a fixed finding): the caller's labels name it, else its id.
    function _withSelected(options, selected, labels) {
        var out = options.slice();
        selected.forEach(function (id) {
            if (!out.some(function (o) { return o.id === id; }))
                out.unshift({ id: id, label: (labels && labels[id]) || id });
        });
        return out;
    }
    function _assocField(uid, f) {
        if (!window.ctRefSelect || !window.ctRefRegister)
            return "";
        var options = f.options.map(function (o) { return { id: o.id, label: o.label }; });
        window.ctRefRegister(uid, {
            single: !f.multi, hideId: true, emptyText: t("nc.pick_none"),
            labelFor: function (id) { var o = options.filter(function (x) { return x.id === id; })[0]; return o ? (o.label || id) : id; },
            onCreate: f.onCreate ? function (_uid, query) { f.onCreate(query); } : undefined,
            hrefFor: f.hrefFor,
            onToggle: f.onPick ? function (_uid, ids) { f.onPick(ids); } : undefined,
        });
        return '<div class="ct-ref-field">' + window.ctRefSelect(uid, f.selected.join(","), options, { single: !f.multi, hideId: true, placeholder: t("nc.pick_search"), emptyText: t("nc.pick_none"), createLabel: f.createLabel }) + '</div>';
    }
    function _assocValues(uid) {
        var ids = [];
        document.querySelectorAll("#" + uid + "-dd input:checked").forEach(function (el) { ids.push(el.value); });
        return ids;
    }
    // A linked object on a record: the same look as its tag — a link to its
    // page (new tab), a click into the module, or plain text.
    function _linkedItem(label, href, clickArgs, badge) {
        var text = esc(label);
        if (href)
            text = '<a class="ct-link" href="' + esc(href) + '" target="_blank" rel="noopener">' + text + ' ↗</a>';
        else if (clickArgs)
            text = '<span class="ct-link ct-clickable" data-click="_ctNcOpenItem" data-args=\'' + clickArgs + '\'>' + text + '</span>';
        return '<div class="ct-flex ct-items-center ct-gap-2">' + text + (badge || "") + '</div>';
    }
    function _assocOf(field) {
        if (!_opts)
            return null;
        return (field === "measures" ? _opts.measures : _opts.items) || null;
    }
    function _optionOf(field, id) {
        var a = _assocOf(field);
        var o = a ? a.options().filter(function (x) { return x.id === id; })[0] : null;
        return o || { id: id, label: id };
    }
    // The record's objects and measures, rendered alike.
    function _linkedItems(field, ids) {
        var a = _assocOf(field);
        return ids.map(function (id) {
            var o = _optionOf(field, id);
            var href = a && a.href ? a.href(id) : null;
            var click = !href && a && a.open ? _da(field, id) : undefined;
            var badge = o.statusLabel ? '<span class="ct-badge" data-tone="' + (o.done ? 'low' : 'medium') + '">' + esc(o.statusLabel) + '</span>' : "";
            return _linkedItem(o.label, href, click, badge);
        }).join("");
    }
    window._ctNcOpenItem = function (field, id) {
        var a = _assocOf(field);
        if (!a || !a.open)
            return;
        var ncId = _detailNcId;
        var modal = _modal();
        if (modal)
            modal.close();
        // A measure edited in the module may change the record (its status): back to it, refreshed.
        Promise.resolve(a.open(id)).then(function () { return field === "measures" ? _reload().then(function () { if (ncId)
            _openNc({ id: ncId }); }) : undefined; }).catch(_fail);
    };
    function _subjectsOf(nc) {
        if (nc.subjects && nc.subjects.length)
            return nc.subjects.slice();
        return nc.subject_type && nc.subject_id ? [{ type: nc.subject_type, id: nc.subject_id }] : [];
    }
    // "fw:ref" → "ref" (a control key); any other object keeps its id.
    function _refOf(id) {
        var i = id.indexOf(":");
        return i > 0 ? id.substring(i + 1) : id;
    }
    var _formOpts = null;
    var _formCtx = null;
    var _formSeq = 0;
    function declare(opts, prefill) {
        return new Promise(function (resolve) { _openForm(opts, "create", prefill || {}, null, resolve); });
    }
    function _editNc(opts, nc) {
        var p = { title: nc.title, description: nc.description || "", domain: nc.domain || "", severity: nc.severity, source: nc.source,
            observed_at: nc.observed_at || "", observed_by: nc.observed_by || "", evidence: nc.evidence || [],
            subjects: _subjectsOf(nc), measure_ids: nc.measure_ids || [], requirement_ref: nc.requirement_ref || "" };
        return new Promise(function (resolve) { _openForm(opts, "edit", p, nc, resolve); });
    }
    function _formState() {
        var opts = _formOpts;
        var kind = opts ? (opts.subjectTypes[0] || "") : "";
        var ids = opts && opts.items ? _assocValues("ct-nc-items") : [];
        var labels = {};
        ids.forEach(function (id) { labels[id] = _optionOf("items", id).label; });
        var measureIds = opts && opts.measures ? _assocValues("ct-nc-measures") : [];
        measureIds.forEach(function (id) { labels[id] = _optionOf("measures", id).label; });
        return { title: _val("ct-nc-title"), description: _val("ct-nc-desc"), domain: _val("ct-nc-domain"),
            severity: _val("ct-nc-sev"), source: _val("ct-nc-source"), observed_at: _val("ct-nc-observed"),
            observed_by: _person("ct-nc-observer"), evidence: _lines("ct-nc-evidence"),
            subjects: ids.map(function (id) { return { type: kind, id: id }; }), measure_ids: measureIds, labels: labels,
            module: _val("ct-nc-module") };
    }
    // Edit sends what changed, nothing else (the server refuses a subject
    // change under a live derogation: an unchanged one must not trip it).
    function _changedFields(out, nc) {
        var diff = {};
        var rec = nc;
        var key = function (subs) { return subs.map(function (x) { return x.type + ":" + x.id; }).join(","); };
        Object.keys(out).forEach(function (k) {
            if (k === "subjects" || k === "subject_type" || k === "subject_id")
                return;
            var val = out[k], cur = rec[k];
            var same = Array.isArray(val) ? val.join("\n") === (cur || []).join("\n")
                : String(val == null ? "" : val) === String(cur == null ? "" : cur);
            if (!same)
                diff[k] = val;
        });
        if (key(out.subjects || []) !== key(_subjectsOf(nc))) {
            diff.subjects = out.subjects;
            diff.subject_type = out.subject_type;
            diff.subject_id = out.subject_id;
        }
        return diff;
    }
    function _openForm(opts, mode, p, nc, resolve) {
        var modal = _modal();
        if (!modal || (mode === "create" ? !opts.createNc : (!opts.patchNc || !nc))) {
            resolve(null);
            return;
        }
        var seq = ++_formSeq;
        var lastState = null; // the fields as submitted, kept on a refusal
        _formOpts = opts;
        _formCtx = { mode: mode, nc: nc, resolve: resolve };
        var kind = opts.subjectTypes[0] || "";
        var subjects = (p.subjects || (p.subject_id ? [{ type: p.subject_type || kind, id: p.subject_id }] : []))
            .filter(function (s) { return s.type === kind && !!s.id; });
        var labels = p.labels || {};
        if (p.subject_id && p.subject_label)
            labels[p.subject_id] = p.subject_label;
        var withMeasures = mode === "edit" && !!opts.measures && (nc.status === "open" || nc.status === "in_remediation" || nc.status === "derogated");
        var h = _errorsBox();
        if (mode === "create" && opts.modules && opts.modules.length) {
            var ms = '<select id="ct-nc-module" class="w-full">';
            opts.modules.forEach(function (m) { ms += '<option value="' + esc(m.id) + '"' + (p.module === m.id ? ' selected' : '') + '>' + esc(m.label) + '</option>'; });
            h += _field(t("nc.f.module"), ms + '</select>', true);
        }
        h += _field(t("nc.f.title"), _input("ct-nc-title", p.title || "", "text", ' maxlength="500"'), true);
        h += _field(t("nc.f.description"), _textarea("ct-nc-desc", p.description || "", 4));
        if (opts.items && kind) {
            // Several objects may be concerned (requirements overlap across frameworks).
            h += _field(_tk("nc.f.items", kind), _assocField("ct-nc-items", {
                options: _withSelected(opts.items.options(), subjects.map(function (s) { return s.id; }), labels),
                selected: subjects.map(function (s) { return s.id; }), multi: true, hrefFor: opts.items.href,
                createLabel: opts.items.create ? _tk("nc.create", kind) : undefined,
                onCreate: opts.items.create ? function (q) { window._ctNcCreate("items", q); } : undefined,
            }));
        }
        h += '<div class="ct-grid-2 ct-gap-2">';
        h += _field(t("nc.f.source"), _select("ct-nc-source", NC_SOURCES, p.source || "observation", "nc.source."));
        h += _field(t("nc.f.severity"), _select("ct-nc-sev", NC_SEVERITIES, p.severity || "medium", "nc.severity."));
        h += _field(t("nc.f.observed_at"), _input("ct-nc-observed", p.observed_at || _today(), "date"));
        h += _field(t("nc.f.observed_by"), _pickerSlot("ct-nc-observer"));
        h += _field(t("nc.f.domain"), _input("ct-nc-domain", p.domain || ""));
        h += '</div>';
        if (withMeasures) {
            // The corrective measures: the first one moves the record to remediation.
            h += _field(t("nc.f.measures"), _assocField("ct-nc-measures", {
                options: _withSelected(opts.measures.options(), p.measure_ids || [], labels),
                selected: p.measure_ids || [], multi: true,
                createLabel: opts.measures.create ? _tk("nc.create", "measure") : undefined,
                onCreate: opts.measures.create ? function (q) { window._ctNcCreate("measures", q); } : undefined,
            }));
        }
        h += _field(t("nc.f.evidence"), _textarea("ct-nc-evidence", (p.evidence || []).join("\n"), 2));
        h += '<div class="fs-xs ct-muted">' + (mode === "create" ? esc(t("nc.declare_help")) + ' ' : '') + esc(t("nc.required_hint")) + '</div>';
        modal.open({
            title: mode === "create" ? t("nc.declare_title") : t("nc.edit_title") + " — " + nc.reference, body: h, size: "md",
            onOpen: function () {
                _mountPickers(opts, ["ct-nc-observer"], { "ct-nc-observer": p.observed_by || "" });
                if (p.error)
                    _showServerError(p.error);
            },
            buttons: [
                { id: "cancel", label: t("nc.cancel") },
                { id: "save", label: mode === "create" ? t("nc.declare_submit") : t("nc.save"), primary: true, result: function () {
                        var title = _val("ct-nc-title");
                        if (title.length < 3)
                            return _showErrors([{ id: "ct-nc-title", label: t("nc.err_title") }], t("nc.errors_intro"));
                        var st = _formState();
                        lastState = st;
                        var subs = st.subjects || [];
                        var out = {
                            title: title, description: st.description, source: st.source, severity: st.severity,
                            observed_at: st.observed_at || null, observed_by: st.observed_by, domain: st.domain, evidence: st.evidence,
                            subjects: subs, subject_type: subs.length ? kind : "", subject_id: subs.length ? subs[0].id : "",
                        };
                        // The reference follows the objects (the controls' refs); elsewhere it is whatever the caller passed.
                        if (kind === "control")
                            out.requirement_ref = subs.map(function (s) { return _refOf(s.id); }).join(", ").substring(0, 200);
                        else if (!opts.items && p.requirement_ref)
                            out.requirement_ref = p.requirement_ref;
                        if (withMeasures)
                            out.measure_ids = st.measure_ids || [];
                        if (mode === "create" && opts.modules && opts.modules.length)
                            out.module = _val("ct-nc-module");
                        return mode === "edit" ? _changedFields(out, nc) : out;
                    } },
            ],
        }).then(function (body) {
            if (seq !== _formSeq)
                return; // a sub-modal took over: the reopened form answers
            if (!body) {
                resolve(null);
                return;
            }
            var run = mode === "create" ? opts.createNc(body)
                : (Object.keys(body).length ? opts.patchNc(nc.id, body) : Promise.resolve(nc));
            run.then(function (rec) {
                showStatus(t(mode === "create" ? "nc.declared" : "nc.updated", { ref: rec.reference }));
                if (opts.onChange)
                    opts.onChange();
                resolve(rec);
            }).catch(function (e) {
                // Refused: the same form again, fields kept, the server's reason inline.
                var keep = lastState || {};
                keep.error = _detail(e);
                keep.requirement_ref = p.requirement_ref;
                _openForm(opts, mode, keep, nc, resolve);
            });
        });
    }
    // "+ create" in a field of the form: the module's modal, then the same
    // form again with the created object selected.
    window._ctNcCreate = function (field, query) {
        var ctx = _formCtx, opts = _formOpts;
        var a = ctx && opts ? (field === "measures" ? opts.measures : opts.items) : null;
        if (!ctx || !opts || !a || !a.create)
            return;
        var keep = _formState();
        _formSeq++; // this instance no longer answers
        var modal = _modal();
        if (modal)
            modal.close();
        var back = function (created) {
            if (created) {
                keep.labels = keep.labels || {};
                keep.labels[created.id] = created.label;
                if (field === "measures") {
                    if ((keep.measure_ids || []).indexOf(created.id) < 0)
                        keep.measure_ids = (keep.measure_ids || []).concat([created.id]);
                }
                else if (!(keep.subjects || []).some(function (s) { return s.id === created.id; }))
                    keep.subjects = (keep.subjects || []).concat([{ type: opts.subjectTypes[0] || "", id: created.id }]);
            }
            _openForm(opts, ctx.mode, keep, ctx.nc, ctx.resolve);
        };
        a.create({ title: keep.title || query || "", description: keep.description || "", domain: keep.domain || "" }).then(back)
            .catch(function (e) { _fail(e); back(null); });
    };
    // ── The derogation form ──────────────────────────────────────────
    // Its subject is a field of the form: the kind (an item of the module, a
    // non-conformity, none) and the object in the same selector as
    // everywhere else — with "+ declare" when no open non-conformity fits.
    var _derOpts = null;
    var _derResolve = null;
    var _derSeq = 0;
    var _derKind = "";
    function requestDerogation(opts, prefill) {
        var p = prefill || {};
        return new Promise(function (resolve) {
            // An item already covered (requested or approved) says so instead
            // of opening a form the server would refuse.
            var subjectType = p.nonconformity ? "nonconformity" : (p.subject_type || "");
            var subjectId = p.nonconformity ? p.nonconformity.id : (p.subject_id || "");
            if (!subjectId || subjectType === "none") {
                _openDerForm(opts, p, resolve);
                return;
            }
            opts.listDer({ subject_type: subjectType, subject_id: subjectId }).then(function (res) {
                var live = ((res && res.items) || []).filter(function (d) { return d.status === "pending_approval" || d.status === "approved"; })[0];
                if (live) {
                    // The button opens the derogation that exists: in place when the
                    // register is on screen, through its deep link otherwise.
                    showStatus(t("der.already", { ref: live.reference, status: t("der.status." + live.status) }));
                    if (_container && _opts && _derRows.some(function (d) { return d.id === live.id; }))
                        _openDer({ id: live.id });
                    else
                        location.assign("?der=" + encodeURIComponent(live.id) + "#nonconformities");
                    resolve(null);
                    return;
                }
                _openDerForm(opts, p, resolve);
            }).catch(function () { _openDerForm(opts, p, resolve); });
        });
    }
    function _derKinds(opts) {
        var kinds = [];
        if (opts.items && opts.subjectTypes[0])
            kinds.push(opts.subjectTypes[0]);
        kinds.push("nonconformity");
        kinds.push("none");
        return kinds;
    }
    function _openNcOptions() {
        return _ncRows.filter(function (r) { return r.status === "to_qualify" || r.status === "open" || r.status === "in_remediation"; })
            .map(function (r) { return { id: r.id, label: r.reference + " — " + r.title + (r.status === "to_qualify" ? " (" + t("nc.status.to_qualify").toLowerCase() + ")" : "") }; });
    }
    function _derSubjectField(kind, selected, labels) {
        var opts = _derOpts;
        if (kind === "none")
            return '<div class="fs-xs ct-muted ct-mb-2">' + esc(t("der.free_help")) + '</div>';
        var isNc = kind === "nonconformity";
        var options = isNc ? _openNcOptions() : opts.items.options();
        var canCreate = _canWrite() && (isNc ? !!opts.createNc : !!(opts.items && opts.items.create));
        var pickTitle = function (ids) {
            var title = document.getElementById("ct-der-title");
            if (title && !title.value && ids[0])
                title.value = _derSubjectLabel(kind, ids[0]).substring(0, 200);
        };
        return _field(_tk("nc.f.subject", kind), _assocField("ct-der-subject", {
            options: _withSelected(options, selected ? [selected] : [], labels), selected: selected ? [selected] : [], multi: false,
            hrefFor: !isNc && opts.items ? opts.items.href : undefined,
            createLabel: canCreate ? _tk("nc.create", kind) : undefined,
            onCreate: canCreate ? function (q) { isNc ? window._ctDerDeclareNc() : _derCreateItem(q); } : undefined,
            onPick: pickTitle,
        }));
    }
    function _derSubjectLabel(kind, id) {
        if (kind === "nonconformity") {
            var nc = _ncRows.filter(function (r) { return r.id === id; })[0];
            return nc ? nc.reference + " — " + nc.title : id;
        }
        var items = _derOpts && _derOpts.items ? _derOpts.items.options() : [];
        var o = items.filter(function (x) { return x.id === id; })[0];
        return o ? o.label : id;
    }
    function _derState() {
        var kind = _derKind;
        var id = kind === "none" ? "" : _assocValues("ct-der-subject")[0] || "";
        var labels = {};
        if (id)
            labels[id] = _derSubjectLabel(kind, id);
        return { subject_type: kind, subject_id: id, labels: labels,
            title: _val("ct-der-title"), justification: _val("ct-der-just"),
            risk_owner: _person("ct-der-owner"), approver: _person("ct-der-approver"),
            valid_from: _val("ct-der-from"), valid_until: _val("ct-der-until"), review_at: _val("ct-der-review") };
    }
    function _openDerForm(opts, p, resolve) {
        var modal = _modal();
        if (!modal || !opts.createDer) {
            resolve(null);
            return;
        }
        var seq = ++_derSeq;
        var lastState = null; // the fields as submitted, kept on a refusal
        _derOpts = opts;
        _derResolve = resolve;
        var kinds = _derKinds(opts);
        var nc = p.nonconformity || null;
        var kind = nc ? "nonconformity" : (p.subject_type && kinds.indexOf(p.subject_type) >= 0 ? p.subject_type : kinds[0]);
        var selected = nc ? nc.id : (kind === "none" ? "" : (p.subject_id || ""));
        var labels = p.labels || {};
        if (p.subject_id && p.subject_label)
            labels[p.subject_id] = p.subject_label;
        _derKind = kind;
        var h = _errorsBox();
        h += _field(t("der.f.subject_kind"), _select("ct-der-kind", kinds, kind, "nc.subject_type.", ' data-change="_ctDerKind" data-pass-value'));
        h += '<div id="ct-der-subject-wrap">' + _derSubjectField(kind, selected, labels) + '</div>';
        h += _field(t("der.f.title"), _input("ct-der-title", p.title || (nc ? nc.title : (selected ? _derSubjectLabel(kind, selected).substring(0, 200) : "")), "text", ' maxlength="500"'), true);
        h += _field(t("der.f.justification"), _textarea("ct-der-just", p.justification || "", 4), true);
        h += '<div class="ct-grid-2 ct-gap-2">';
        h += _field(t("der.f.risk_owner"), _pickerSlot("ct-der-owner"), true);
        h += _field(t("der.f.approver"), _pickerSlot("ct-der-approver"), true);
        h += _field(t("der.f.valid_from"), _input("ct-der-from", p.valid_from || _today(), "date"));
        h += _field(t("der.f.valid_until"), _input("ct-der-until", p.valid_until || "", "date"), true);
        h += _field(t("der.f.review_at"), _input("ct-der-review", p.review_at || "", "date"));
        h += '</div>';
        h += '<div class="fs-xs ct-muted">' + esc(t("der.request_help")) + ' ' + esc(t("nc.required_hint")) + '</div>';
        modal.open({
            title: t("der.request_title"), body: h, size: "md",
            onOpen: function () {
                _mountPickers(opts, ["ct-der-owner", "ct-der-approver"], { "ct-der-owner": p.risk_owner || "", "ct-der-approver": p.approver || "" });
                if (p.error)
                    _showServerError(p.error);
            },
            buttons: [
                { id: "cancel", label: t("nc.cancel") },
                { id: "save", label: t("der.request_submit"), primary: true, result: function () {
                        var st = _derState();
                        lastState = st;
                        var problems = [];
                        if (st.subject_type !== "none" && !st.subject_id)
                            problems.push({ id: "ct-der-subject", label: t("der.err_subject") });
                        if (!st.title)
                            problems.push({ id: "ct-der-title", label: t("der.f.title") });
                        if ((st.justification || "").length < 3)
                            problems.push({ id: "ct-der-just", label: t("der.f.justification") });
                        if (!st.risk_owner)
                            problems.push({ id: "ct-der-owner", label: t("der.f.risk_owner") });
                        if (!st.approver)
                            problems.push({ id: "ct-der-approver", label: t("der.f.approver") });
                        if (!st.valid_until)
                            problems.push({ id: "ct-der-until", label: t("der.f.valid_until") });
                        else if (st.valid_from && st.valid_until <= st.valid_from)
                            problems.push({ id: "ct-der-until", label: t("der.err_until_order") });
                        if (!_showErrors(problems, t("nc.errors_intro")))
                            return false;
                        return {
                            subject_type: st.subject_type, subject_id: st.subject_id,
                            title: st.title, justification: st.justification,
                            risk_owner: st.risk_owner, approver: st.approver,
                            valid_from: st.valid_from || null, valid_until: st.valid_until || null, review_at: st.review_at || null,
                        };
                    } },
            ],
        }).then(function (body) {
            if (seq !== _derSeq)
                return; // a "+ declare" detour: the reopened form answers
            if (!body) {
                resolve(null);
                return;
            }
            opts.createDer(body).then(function (d) {
                showStatus(t("der.requested", { ref: d.reference }));
                if (opts.onChange)
                    opts.onChange();
                resolve(d);
            }).catch(function (e) {
                // Refused: the same form again, fields kept, the server's reason inline.
                var keep = lastState || {};
                keep.error = _detail(e);
                if (keep.subject_type === "nonconformity" && keep.subject_id)
                    keep.nonconformity = _ncRows.filter(function (r) { return r.id === keep.subject_id; })[0] || null;
                _openDerForm(opts, keep, resolve);
            });
        });
    }
    window._ctDerKind = function (kind) {
        _derKind = kind;
        var box = document.getElementById("ct-der-subject-wrap");
        if (box && _derOpts)
            box.innerHTML = _derSubjectField(kind, "", {});
    };
    // "+ declare" in the subject field: the non-conformity form, then back to
    // the request with the new record as its subject and the fields kept.
    window._ctDerDeclareNc = function () {
        var opts = _derOpts, resolve = _derResolve;
        if (!opts || !resolve)
            return;
        var keep = _derState();
        _derSeq++;
        var modal = _modal();
        if (modal)
            modal.close();
        declare(opts).then(function (nc) {
            if (nc) {
                _ncRows.push(nc);
                keep.nonconformity = nc;
                keep.title = keep.title || nc.title;
            }
            _openDerForm(opts, keep, resolve);
        });
    };
    function _derCreateItem(query) {
        var opts = _derOpts, resolve = _derResolve;
        if (!opts || !resolve || !opts.items || !opts.items.create)
            return;
        var keep = _derState();
        _derSeq++;
        var modal = _modal();
        if (modal)
            modal.close();
        opts.items.create({ title: keep.title || query || "", description: "", domain: "" }).then(function (created) {
            if (created) {
                keep.subject_id = created.id;
                keep.labels = keep.labels || {};
                keep.labels[created.id] = created.label;
                keep.title = keep.title || created.label.substring(0, 200);
            }
            _openDerForm(opts, keep, resolve);
        }).catch(function (e) { _fail(e); _openDerForm(opts, keep, resolve); });
    }
    // ── Register panel ───────────────────────────────────────────────
    function _load(container, opts) {
        _container = container;
        _opts = opts;
        container.innerHTML = '<div class="ct-muted">' + esc(t("nc.loading")) + '</div>';
        return Promise.all([opts.listNc(), opts.listDer()]).then(function (res) {
            _ncRows = (res[0] && res[0].items) || [];
            _derRows = (res[1] && res[1].items) || [];
            _draw();
        }).catch(function (e) { _fail(e); container.innerHTML = ""; });
    }
    // A deep link from the console names a record (`?nc=<id>` / `?der=<id>`
    // before `#nonconformities`): its detail opens once the register is
    // loaded, once per page load.
    var _queryConsumed = false;
    function _openFromQuery() {
        if (_queryConsumed)
            return;
        _queryConsumed = true;
        var q;
        try {
            q = new URLSearchParams(location.search);
        }
        catch (e) {
            return;
        }
        var nc = q.get("nc"), der = q.get("der");
        if (nc && _ncRows.some(function (r) { return r.id === nc; }))
            _openNc({ id: nc });
        else if (der && _derRows.some(function (r) { return r.id === der; }))
            _openDer({ id: der });
    }
    function renderPanel(container, opts) {
        _load(container, opts).then(_openFromQuery);
    }
    // The module role arrives after a couple of round trips; a register drawn
    // before it must be drawn again, or an administrator sits in front of a
    // read-only page (and a viewer in front of buttons the server refuses).
    document.addEventListener("ct-role-ready", function () { if (_container && _opts)
        _draw(); });
    function _reload() {
        var changed = (_opts && _opts.onChange) ? _opts.onChange() : undefined;
        return Promise.resolve(changed).then(function () {
            return (_container && _opts) ? _load(_container, _opts) : undefined;
        });
    }
    // Days since the observation (the declaration date when unknown).
    function _ageDays(r) {
        var from = r.observed_at || (r.created_at || "").slice(0, 10);
        if (!from)
            return 0;
        var ms = Date.now() - new Date(from + "T00:00:00").getTime();
        return ms > 0 ? Math.floor(ms / 86400000) : 0;
    }
    function _pills(kind, statuses, current, rows) {
        var h = '<div class="ct-filters ct-mb-3">';
        var all = [""].concat(statuses);
        all.forEach(function (s) {
            var n = s ? rows.filter(function (r) { return r.status === s; }).length : rows.length;
            var label = s ? t((kind === "der" ? "der.status." : "nc.status.") + s) : t("nc.all");
            h += '<button class="ct-btn" data-size="xs"' + (current === s ? ' data-variant="primary"' : '') + ' data-click="_ctNcFilter" data-args=\'' + _da(kind, s) + '\'>'
                + esc(label) + ' (' + n + ')</button>';
        });
        return h + '</div>';
    }
    function _draw() {
        if (!_container || !_opts)
            return;
        var admin = _isAdmin();
        var h = '<div class="ct-flex ct-items-center ct-gap-2 ct-mb-3">';
        h += '<h2 class="ct-ink ct-flex-1 ct-m-0">' + esc(t("nc.panel_title")) + '</h2>';
        // Write actions appear only for an account the server would let write.
        var canWrite = _canWrite();
        if (_opts.createNc && canWrite)
            h += '<button class="ct-btn" data-variant="primary" data-click="_ctNcDeclare">' + _icon("plus", 14) + ' ' + esc(t("nc.declare_btn")) + '</button>';
        if (_opts.createDer && canWrite)
            h += '<button class="ct-btn" data-click="_ctNcRequestDer">' + esc(t("der.request_btn")) + '</button>';
        if (admin && (_opts.getSettings || _opts.openSettings))
            h += '<button class="ct-btn" data-click="_ctNcSettings" title="' + esc(t("nc.settings_title")) + '">' + _icon("settings", 14) + '</button>';
        var withModule = !!(_opts.modules && _opts.modules.length);
        if (withModule) {
            var sel = '<select class="ct-filter" data-change="_ctNcModuleFilter" data-pass-value><option value="">' + esc(t("nc.all_modules")) + '</option>';
            _opts.modules.forEach(function (m) { sel += '<option value="' + esc(m.id) + '"' + (m.id === _moduleFilter ? ' selected' : '') + '>' + esc(m.label) + '</option>'; });
            h += sel + '</select>';
        }
        var moduleCol = { key: "module", label: t("nc.col_module"), width: "110px", render: function (r) { return esc(r.module_name || r.module || ""); } };
        h += '</div>';
        // Non-conformities
        h += '<h3 class="ct-mt-4">' + esc(t("nc.list_title")) + '</h3>';
        h += _pills("nc", NC_STATUSES, _ncFilter, _ncRows);
        // Reading by source: where the gaps come from, as a second row of pills.
        h += '<div class="ct-filters ct-mb-3"><span class="fs-xs ct-muted">' + esc(t("nc.by_source")) + '</span>';
        [""].concat(NC_SOURCES).forEach(function (src) {
            var n = src ? _ncRows.filter(function (r) { return r.source === src; }).length : _ncRows.length;
            h += '<button class="ct-btn" data-size="xs"' + (_sourceFilter === src ? ' data-variant="primary"' : '') + ' data-click="_ctNcSourceFilter" data-args=\'' + _da(src) + '\'>'
                + esc(src ? t("nc.source." + src) : t("nc.all")) + ' (' + n + ')</button>';
        });
        h += '</div>';
        // Criticality and age: the second and third readings of the register.
        h += '<div class="ct-filters ct-mb-3"><span class="fs-xs ct-muted">' + esc(t("nc.by_severity")) + '</span>';
        [""].concat(NC_SEVERITIES.slice().reverse()).forEach(function (sev) {
            var n = sev ? _ncRows.filter(function (r) { return r.severity === sev; }).length : _ncRows.length;
            h += '<button class="ct-btn" data-size="xs"' + (_severityFilter === sev ? ' data-variant="primary"' : '') + ' data-click="_ctNcSeverityFilter" data-args=\'' + _da(sev) + '\'>'
                + esc(sev ? t("nc.severity." + sev) : t("nc.all")) + ' (' + n + ')</button>';
        });
        h += '<span class="fs-xs ct-muted ct-ml-2">' + esc(t("nc.by_age")) + '</span>';
        [0, 30, 90].forEach(function (days) {
            var n = days ? _ncRows.filter(function (r) { return _ageDays(r) >= days; }).length : _ncRows.length;
            h += '<button class="ct-btn" data-size="xs"' + (_ageFilter === days ? ' data-variant="primary"' : '') + ' data-click="_ctNcAgeFilter" data-args=\'' + _da(String(days)) + '\'>'
                + esc(days ? t("nc.age_over", { n: days }) : t("nc.all")) + ' (' + n + ')</button>';
        });
        h += '</div>';
        var ncRows = _ncRows.filter(function (r) {
            return (!_ncFilter || r.status === _ncFilter) && (!_moduleFilter || r.module === _moduleFilter) && (!_sourceFilter || r.source === _sourceFilter)
                && (!_severityFilter || r.severity === _severityFilter) && (!_ageFilter || _ageDays(r) >= _ageFilter);
        });
        h += window.ct_table.render({
            rows: ncRows, rowKey: "id", onRowClick: "_ctNcOpen",
            emptyHtml: '<div class="ct-muted">' + esc(t("nc.empty")) + '</div>',
            columns: (withModule ? [moduleCol] : []).concat([
                { key: "reference", label: t("nc.col_ref"), width: "110px", render: function (r) { return '<strong>' + esc(r.reference) + '</strong>'; } },
                { key: "title", label: t("nc.col_title"), render: function (r) {
                        var sub = r.subject_type ? '<div class="fs-xs ct-muted">' + esc(t("nc.subject_type." + r.subject_type)) + (r.requirement_ref ? ' · ' + esc(r.requirement_ref) : '') + '</div>' : '';
                        return esc(r.title) + sub;
                    } },
                { key: "severity", label: t("nc.col_severity"), width: "100px", render: function (r) { return _sevBadge(r.severity); } },
                { key: "source", label: t("nc.col_source"), width: "130px", render: function (r) { return esc(t("nc.source." + r.source)); } },
                { key: "observed_at", label: t("nc.col_observed"), width: "110px", render: function (r) { return esc(r.observed_at || ""); } },
                { key: "status", label: t("nc.col_status"), width: "130px", render: function (r) { return _badge("nc", r.status); } },
                { key: "treatment", label: t("nc.col_treatment"), width: "110px", render: function (r) {
                        var tr = r.treatment || (r.status === "derogated" ? "derogation" : (r.status === "in_remediation" && (r.measure_ids || []).length ? "measure" : "none"));
                        return '<span class="ct-badge" data-tone="' + (tr === "none" ? "neutral" : "info") + '">' + esc(t("nc.treatment." + tr)) + '</span>';
                    } },
            ]),
        });
        // Derogations
        h += '<h3 class="ct-mt-4">' + esc(t("der.list_title")) + '</h3>';
        h += _pills("der", DER_STATUSES, _derFilter, _derRows);
        var derRows = _derRows.filter(function (r) { return (!_derFilter || r.status === _derFilter) && (!_moduleFilter || r.module === _moduleFilter); });
        h += window.ct_table.render({
            rows: derRows, rowKey: "id", onRowClick: "_ctDerOpen",
            emptyHtml: '<div class="ct-muted">' + esc(t("der.empty")) + '</div>',
            columns: (withModule ? [moduleCol] : []).concat([
                { key: "reference", label: t("der.col_ref"), width: "120px", render: function (r) { return '<strong>' + esc(r.reference) + '</strong>'; } },
                { key: "subject", label: t("der.col_subject"), render: function (r) {
                        return '<div>' + esc(r.title || r.subject_label || r.subject_id) + '</div>'
                            + '<div class="fs-xs ct-muted">' + esc(t("nc.subject_type." + r.subject_type)) + (r.title && r.subject_label ? ' · ' + esc(r.subject_label) : '') + '</div>';
                    } },
                { key: "risk_owner", label: t("der.col_owner"), width: "140px", render: function (r) { return esc(r.risk_owner || ""); } },
                { key: "valid_until", label: t("der.col_until"), width: "150px", render: function (r) {
                        var left = (r.status === "approved" && r.days_left != null) ? ' <span class="fs-xs ct-muted">(' + esc(t("der.days_left", { n: r.days_left })) + ')</span>' : '';
                        return esc(r.valid_until || "") + left;
                    } },
                { key: "status", label: t("der.col_status"), width: "150px", render: function (r) { return _badge("der", r.status); } },
            ]),
        });
        _container.innerHTML = h;
    }
    // ── Detail modals ────────────────────────────────────────────────
    var _detailNcId = "";
    function _openNc(row) {
        var modal = _modal();
        if (!modal || !_opts)
            return;
        var nc = _ncRows.filter(function (r) { return r.id === row.id; })[0];
        if (!nc)
            return;
        _detailNcId = nc.id;
        var admin = _isAdmin();
        var s = nc.status;
        var subs = _subjectsOf(nc);
        var kind = _opts.subjectTypes[0] || "";
        var h = '<div class="ct-mb-3">' + _badge("nc", nc.status) + ' ' + _sevBadge(nc.severity) + '</div>';
        h += _row(t("nc.f.title"), nc.title);
        h += _row(t("nc.f.description"), nc.description || "");
        h += _row(t("nc.f.source"), t("nc.source." + nc.source));
        if (subs.length)
            h += _row(_tk("nc.f.items", subs[0].type || kind), _linkedItems("items", subs.map(function (x) { return x.id; })), true);
        else if (nc.requirement_ref)
            h += _row(t("nc.f.requirement_ref"), nc.requirement_ref);
        h += _row(t("nc.f.domain"), nc.domain || "");
        h += _row(t("nc.f.observed_at"), (nc.observed_at || "") + (nc.observed_by ? " · " + nc.observed_by : ""));
        h += _row(t("nc.declared_by"), nc.declared_by || "");
        if (nc.evidence && nc.evidence.length)
            h += _row(t("nc.f.evidence"), nc.evidence.join("\n"));
        if (nc.qualified_by)
            h += _row(t("nc.qualified_by"), nc.qualified_by + (nc.qualified_at ? " · " + String(nc.qualified_at).slice(0, 10) : ""));
        if (nc.rejection_note)
            h += _row(t("nc.rejection_note"), nc.rejection_note);
        if (nc.derogation_id) {
            var der = _derRows.filter(function (r) { return r.id === nc.derogation_id; })[0];
            h += _row(t("nc.derogation"), der ? der.reference + " · " + t("der.status." + der.status) : String(nc.derogation_id));
        }
        if (nc.closure_evidence)
            h += _row(t("nc.closure_evidence"), nc.closure_evidence);
        var measureIds = nc.measure_ids || [];
        var pending = measureIds.filter(function (id) { return !_optionOf("measures", id).done; });
        if (measureIds.length) {
            h += _row(t("nc.f.measures"), _linkedItems("measures", measureIds), true);
            if (pending.length && (s === "in_remediation" || s === "open" || s === "derogated")) {
                h += '<div class="fs-xs ct-muted ct-mb-2">' + esc(t("nc.close_blocked", { n: pending.length })) + '</div>';
            }
        }
        if (nc.module_url)
            h = '<div class="ct-mb-2 fs-sm"><a href="' + esc(nc.module_url) + '">' + esc(t("nc.open_in_module", { module: nc.module_name || nc.module || "" })) + ' ↗</a></div>' + h;
        var buttons = [{ id: "close", label: t("nc.close") }];
        // The record is edited in the declaration form — its measures too — by
        // an administrator, or by its declarant before qualification (the server's rule).
        var me = _opts.actor ? _opts.actor() : "";
        var mine = s === "to_qualify" && (!me || !nc.declared_by || nc.declared_by === me);
        if (_opts.patchNc && _canWrite() && s !== "closed" && s !== "rejected" && (admin || mine))
            buttons.push({ id: "edit", label: t("nc.edit_btn"), result: "edit" });
        if (s === "to_qualify" && admin && _opts.qualifyNc) {
            if (_opts.rejectNc)
                buttons.push({ id: "reject", label: t("nc.act_reject"), danger: true, result: "reject" });
            buttons.push({ id: "qualify", label: t("nc.act_qualify"), primary: true, result: "qualify" });
        }
        if ((s === "open" || s === "in_remediation") && _opts.createDer && _canWrite())
            buttons.push({ id: "derog", label: t("der.request_btn"), result: "derog" });
        if ((s === "open" || s === "in_remediation" || s === "derogated") && admin && _opts.closeNc && !pending.length)
            buttons.push({ id: "closeNc", label: t("nc.act_close"), primary: true, result: "closeNc" });
        modal.open({ title: nc.reference, body: h, size: "md", buttons: buttons }).then(function (r) {
            if (!r || !_opts)
                return;
            if (r === "edit") {
                _editNc(_opts, nc).then(function (rec) { (rec ? _reload() : Promise.resolve()).then(function () { _openNc({ id: nc.id }); }); });
                return;
            }
            if (r === "derog") {
                requestDerogation(_opts, { nonconformity: nc }).then(function (d) { if (d)
                    _reload(); });
                return;
            }
            if (r === "qualify") {
                _qualifyNc(nc);
                return;
            }
            if (r === "reject") {
                _noteModal(t("nc.act_reject"), t("nc.reject_note_label"), function (note) { return _opts.rejectNc(nc.id, note); });
                return;
            }
            if (r === "closeNc") {
                _noteModal(t("nc.act_close"), t("nc.closure_evidence"), function (ev) { return _opts.closeNc(nc.id, ev); });
                return;
            }
        });
    }
    function _qualifyNc(nc) {
        var modal = _modal();
        if (!modal)
            return;
        var h = '<div class="ct-grid-2 ct-gap-2">';
        h += _field(t("nc.f.severity"), _select("ct-nc-q-sev", NC_SEVERITIES, nc.severity, "nc.severity."));
        h += _field(t("nc.f.domain"), _input("ct-nc-q-domain", nc.domain || ""));
        h += '</div><div class="fs-xs ct-muted">' + esc(t("nc.qualify_help")) + '</div>';
        modal.open({ title: t("nc.act_qualify") + " — " + nc.reference, body: h, size: "sm", buttons: [
                { id: "cancel", label: t("nc.cancel") },
                { id: "ok", label: t("nc.act_qualify"), primary: true, result: function () {
                        return { severity: _val("ct-nc-q-sev"), domain: _val("ct-nc-q-domain") };
                    } },
            ] }).then(function (body) {
            if (!body || !_opts)
                return;
            _opts.qualifyNc(nc.id, body).then(_reload).catch(_fail);
        });
    }
    function _noteModal(title, label, run, optional) {
        var modal = _modal();
        if (!modal)
            return;
        var h = _field(label, _textarea("ct-nc-note", "", 4));
        modal.open({ title: title, body: h, size: "sm", buttons: [
                { id: "cancel", label: t("nc.cancel") },
                { id: "ok", label: t("nc.confirm"), primary: true, result: function () {
                        var v = _val("ct-nc-note");
                        if (!optional && v.length < 3) {
                            showStatus(t("nc.err_note"), true);
                            return false;
                        }
                        return { note: v };
                    } },
            ] }).then(function (r) {
            if (!r)
                return;
            run(String(r.note || "")).then(_reload).catch(_fail);
        });
    }
    // The subject of a derogation, rendered like any linked object.
    function _derSubjectHtml(d) {
        if (d.subject_type === "none")
            return esc(t("nc.subject_type.none"));
        if (d.subject_type === "nonconformity") {
            var nc = _ncRows.filter(function (r) { return r.id === d.subject_id; })[0];
            return esc(t("nc.subject_type.nonconformity")) + ' · ' + esc(nc ? nc.reference + " — " + nc.title : (d.subject_label || d.subject_id));
        }
        var a = _opts && _opts.items;
        var o = _optionOf("items", d.subject_id);
        var href = a && a.href ? a.href(d.subject_id) : null;
        return esc(t("nc.subject_type." + d.subject_type)) + ' · ' + _linkedItem(o.label !== d.subject_id ? o.label : (d.subject_label || d.subject_id), href, !href && a && a.open ? _da("items", d.subject_id) : undefined);
    }
    function _openDer(row) {
        var modal = _modal();
        if (!modal || !_opts)
            return;
        var d = _derRows.filter(function (r) { return r.id === row.id; })[0];
        if (!d)
            return;
        var admin = _isAdmin();
        var h = '<div class="ct-mb-3">' + _badge("der", d.status) + '</div>';
        h += _row(t("der.f.title"), d.title || "");
        h += _row(t("nc.f.subject"), _derSubjectHtml(d), true);
        h += _row(t("der.f.justification"), d.justification || "");
        h += _row(t("der.f.risk_owner"), d.risk_owner || "");
        h += _row(t("der.f.approver"), d.approver || "");
        h += _row(t("der.f.validity"), (d.valid_from || "") + " → " + (d.valid_until || "") + (d.status === "approved" && d.days_left != null ? " · " + t("der.days_left", { n: d.days_left }) : ""));
        h += _row(t("der.f.review_at"), d.review_at || "");
        h += _row(t("der.requested_by"), (d.requested_by || "") + (d.requested_at ? " · " + String(d.requested_at).slice(0, 10) : ""));
        if (d.decided_by)
            h += _row(t("der.decided_by"), d.decided_by + (d.decided_at ? " · " + String(d.decided_at).slice(0, 10) : ""));
        if (d.decision_note)
            h += _row(t("der.decision_note"), d.decision_note);
        if (d.revoked_reason)
            h += _row(t("der.revoked_reason"), d.revoked_reason);
        if (d.renews_id) {
            var prev = _derRows.filter(function (r) { return r.id === d.renews_id; })[0];
            h += _row(t("der.renews"), prev ? prev.reference : String(d.renews_id));
        }
        if (d.module_url)
            h = '<div class="ct-mb-2 fs-sm"><a href="' + esc(d.module_url) + '">' + esc(t("nc.open_in_module", { module: d.module_name || d.module || "" })) + ' ↗</a></div>' + h;
        var buttons = [{ id: "close", label: t("nc.close") }];
        if (d.status === "pending_approval" && admin && _opts.decideDer) {
            buttons.push({ id: "reject", label: t("der.act_reject"), danger: true, result: "reject" });
            buttons.push({ id: "approve", label: t("der.act_approve"), primary: true, result: "approve" });
        }
        if (d.status === "approved" && admin && _opts.revokeDer)
            buttons.push({ id: "revoke", label: t("der.act_revoke"), danger: true, result: "revoke" });
        if ((d.status === "expired" || d.status === "revoked") && _opts.createDer)
            buttons.push({ id: "renew", label: t("der.act_renew"), result: "renew" });
        modal.open({ title: d.reference, body: h, size: "md", buttons: buttons }).then(function (r) {
            if (!r || !_opts)
                return;
            if (r === "approve") {
                _noteModal(t("der.act_approve"), t("der.decision_note_opt"), function (note) { return _opts.decideDer(d.id, true, note); }, true);
                return;
            }
            if (r === "reject") {
                _noteModal(t("der.act_reject"), t("der.decision_note"), function (note) { return _opts.decideDer(d.id, false, note); });
                return;
            }
            if (r === "revoke") {
                _noteModal(t("der.act_revoke"), t("der.revoked_reason"), function (reason) { return _opts.revokeDer(d.id, reason); });
                return;
            }
            if (r === "renew") {
                var nc = d.subject_type === "nonconformity" ? _ncRows.filter(function (x) { return x.id === d.subject_id; })[0] : null;
                requestDerogation(_opts, { subject_type: d.subject_type, subject_id: d.subject_id, subject_label: d.subject_label, title: d.title, nonconformity: nc || null })
                    .then(function (nd) { if (nd)
                    _reload(); });
                return;
            }
        });
    }
    function _settings() {
        if (_opts && _opts.openSettings) {
            _opts.openSettings();
            return;
        }
        var modal = _modal();
        if (!modal || !_opts || !_opts.getSettings || !_opts.saveSettings)
            return;
        _opts.getSettings().then(function (s) {
            var h = _field(t("nc.settings_max_days"), _input("ct-nc-max-days", String(s.max_derogation_days || 365), "number", ' min="1" max="3650"'));
            h += '<div class="fs-xs ct-muted">' + esc(t("nc.settings_help")) + '</div>';
            return modal.open({ title: t("nc.settings_title"), body: h, size: "sm", buttons: [
                    { id: "cancel", label: t("nc.cancel") },
                    { id: "ok", label: t("nc.save"), primary: true, result: function () {
                            var n = parseInt(_val("ct-nc-max-days"), 10);
                            if (!(n >= 1 && n <= 3650)) {
                                showStatus(t("nc.err_max_days"), true);
                                return false;
                            }
                            return n;
                        } },
                ] });
        }).then(function (n) {
            if (!n || !_opts || !_opts.saveSettings)
                return;
            _opts.saveSettings(Number(n)).then(function () { showStatus(t("nc.settings_saved")); }).catch(_fail);
        }).catch(_fail);
    }
    window._ctNcFilter = function (kind, status) {
        if (kind === "der")
            _derFilter = status;
        else
            _ncFilter = status;
        _draw();
    };
    window._ctNcModuleFilter = function (module) { _moduleFilter = module || ""; _draw(); };
    window._ctNcSourceFilter = function (source) { _sourceFilter = source || ""; _draw(); };
    window._ctNcSeverityFilter = function (severity) { _severityFilter = severity || ""; _draw(); };
    window._ctNcAgeFilter = function (days) { _ageFilter = parseInt(days, 10) || 0; _draw(); };
    window._ctNcOpen = _openNc;
    window._ctDerOpen = _openDer;
    window._ctNcDeclare = function () { if (_opts)
        declare(_opts).then(function (nc) { if (nc)
            _reload(); }); };
    window._ctNcRequestDer = function () { if (_opts)
        requestDerogation(_opts).then(function (d) { if (d)
            _reload(); }); };
    window._ctNcSettings = _settings;
    window.ct_nonconformity = {
        declare: declare,
        requestDerogation: requestDerogation,
        renderPanel: renderPanel,
        canWrite: function () { return _canWrite(); },
        isAdmin: function () { return _isAdmin(); },
        badge: function (kind, status) { return _badge(kind, status); },
        tone: function (kind, status) { return _tone(kind, status); },
    };
})();
_registerTranslations("fr", {
    "nc.pick_none": "Aucun — cliquer pour choisir",
    "nc.pick_search": "Rechercher…",
    "nc.f.items": "Objets concernés",
    "nc.f.items.control": "Exigences concernées",
    "nc.f.items.finding": "Constats concernés",
    "nc.f.items.review_entry": "Anomalies concernées",
    "nc.f.subject": "Objet",
    "nc.f.subject.control": "Exigence",
    "nc.f.subject.finding": "Constat",
    "nc.f.subject.review_entry": "Anomalie d'habilitation",
    "nc.f.subject.nonconformity": "Non-conformité",
    "nc.create": "Créer",
    "nc.create.control": "Créer un contrôle",
    "nc.create.finding": "Créer un constat",
    "nc.create.measure": "Créer une mesure",
    "nc.create.nonconformity": "Déclarer une non-conformité",
    "der.f.subject_kind": "Objet de la dérogation",
    "nav.nonconformities": "Non-conformités",
    "nc.cancel": "Annuler",
    "nc.close": "Retour",
    "nc.confirm": "Confirmer",
    "nc.save": "Enregistrer",
    "nc.loading": "Chargement...",
    "nc.error": "Erreur",
    "nc.all": "Toutes",
    "nc.panel_title": "Non-conformités et dérogations",
    "nc.list_title": "Non-conformités",
    "nc.declare_btn": "Déclarer une non-conformité",
    "nc.declare_title": "Déclarer une non-conformité",
    "nc.declare_submit": "Déclarer",
    "nc.declare_help": "La déclaration est enregistrée « à qualifier » : un administrateur la qualifie (ou la rejette) avant tout suivi.",
    "nc.declared": "Non-conformité {ref} déclarée",
    "nc.empty": "Aucune non-conformité.",
    "nc.subject_type.finding": "Constat",
    "nc.subject_type.control": "Exigence",
    "nc.subject_type.review_entry": "Anomalie d'habilitation",
    "nc.subject_type.nonconformity": "Non-conformité",
    "nc.subject_type.none": "Aucun objet (dérogation libre)",
    "nc.f.title": "Titre",
    "nc.f.description": "Description",
    "nc.f.source": "Source",
    "nc.f.severity": "Gravité",
    "nc.f.observed_at": "Observée le",
    "nc.f.observed_by": "Observée par",
    "nc.f.domain": "Domaine",
    "nc.f.requirement_ref": "Exigence / référence",
    "nc.f.evidence": "Preuves (une par ligne : lien, ticket, fichier)",
    "nc.source.observation": "Constat fortuit",
    "nc.source.report": "Signalement",
    "nc.source.informal_review": "Revue informelle",
    "nc.source.incident": "Incident",
    "nc.severity.low": "Faible",
    "nc.severity.medium": "Moyenne",
    "nc.severity.high": "Élevée",
    "nc.severity.critical": "Critique",
    "nc.status.to_qualify": "À qualifier",
    "nc.status.open": "Ouverte",
    "nc.status.in_remediation": "En remédiation",
    "nc.status.derogated": "Sous dérogation",
    "nc.status.closed": "Clôturée",
    "nc.status.rejected": "Rejetée",
    "nc.col_ref": "Réf.",
    "nc.col_title": "Titre",
    "nc.col_severity": "Gravité",
    "nc.col_source": "Source",
    "nc.col_observed": "Observée le",
    "nc.col_status": "Statut",
    "nc.col_module": "Module",
    "nc.all_modules": "Tous les modules",
    "nc.by_source": "Par source :",
    "nc.by_severity": "Par criticité :",
    "nc.by_age": "Ancienneté :",
    "nc.age_over": "> {n} j",
    "nc.edit_btn": "Modifier",
    "nc.edit_title": "Modifier la non-conformité",
    "nc.updated": "Non-conformité {ref} mise à jour",
    "nc.col_treatment": "Traitement",
    "nc.treatment.measure": "Mesure",
    "nc.treatment.derogation": "Dérogation",
    "nc.treatment.none": "Aucun",
    "nc.f.module": "Module de rattachement",
    "nc.open_in_module": "Ouvrir dans {module}",
    "nc.declared_by": "Déclarée par",
    "nc.qualified_by": "Qualifiée par",
    "nc.rejection_note": "Motif de rejet",
    "nc.derogation": "Dérogation",
    "nc.closure_evidence": "Preuve de clôture",
    "nc.act_qualify": "Qualifier",
    "nc.act_reject": "Rejeter",
    "nc.act_close": "Clôturer",
    "nc.qualify_help": "La qualification confirme la non-conformité et fixe sa gravité ; elle passe alors « ouverte ».",
    "nc.reject_note_label": "Motif du rejet (obligatoire)",
    "nc.err_title": "Le titre doit faire au moins 3 caractères.",
    "nc.errors_intro": "Avant de valider, compléter :",
    "nc.required_hint": "Les champs marqués * sont obligatoires.",
    "nc.close_blocked": "Clôture possible quand toutes les mesures sont terminées ({n} restante(s)).",
    "nc.err_note": "Le texte doit faire au moins 3 caractères.",
    "nc.search_person": "Rechercher une personne...",
    "nc.f.measures": "Mesures correctives",
    "nc.settings_title": "Paramètres des dérogations",
    "nc.settings_max_days": "Durée maximale d'une dérogation (jours)",
    "nc.settings_help": "Toute demande dont la validité dépasse cette durée est refusée à la saisie.",
    "nc.settings_saved": "Paramètres enregistrés",
    "nc.err_max_days": "Saisir un nombre de jours entre 1 et 3650.",
    "der.list_title": "Dérogations",
    "der.request_btn": "Demander une dérogation",
    "der.request_title": "Demander une dérogation",
    "der.request_submit": "Soumettre la demande",
    "der.request_help": "La demande est soumise à approbation. Une seule dérogation en attente ou approuvée par objet.",
    "der.requested": "Dérogation {ref} demandée",
    "der.empty": "Aucune dérogation.",
    "der.free_help": "Dérogation libre, sans objet rattaché : le titre et la justification décrivent l'écart accepté.",
    "der.err_subject": "Choisir l'objet de la dérogation.",
    "der.already": "Une dérogation couvre déjà cet objet : {ref} ({status}).",
    "der.f.title": "Titre",
    "der.f.justification": "Justification (contexte, risque accepté)",
    "der.f.risk_owner": "Porteur du risque",
    "der.f.approver": "Approbateur attendu",
    "der.f.valid_from": "Début de validité",
    "der.f.valid_until": "Fin de validité",
    "der.f.review_at": "Date de revue",
    "der.f.validity": "Validité",
    "der.status.pending_approval": "En attente d'approbation",
    "der.status.approved": "Approuvée",
    "der.status.rejected": "Refusée",
    "der.status.expired": "Expirée",
    "der.status.revoked": "Révoquée",
    "der.col_ref": "Réf.",
    "der.col_subject": "Objet",
    "der.col_owner": "Porteur du risque",
    "der.col_until": "Fin de validité",
    "der.col_status": "Statut",
    "der.days_left": "{n} j restants",
    "der.requested_by": "Demandée par",
    "der.decided_by": "Décidée par",
    "der.decision_note": "Motif de la décision (obligatoire)",
    "der.decision_note_opt": "Note (optionnel)",
    "der.revoked_reason": "Motif de révocation",
    "der.renews": "Renouvelle",
    "der.act_approve": "Approuver",
    "der.act_reject": "Refuser",
    "der.act_revoke": "Révoquer",
    "der.act_renew": "Renouveler",
    "der.err_until_order": "Fin de validité postérieure au début",
});
_registerTranslations("en", {
    "nc.pick_none": "None — click to choose",
    "nc.pick_search": "Search…",
    "nc.f.items": "Items concerned",
    "nc.f.items.control": "Requirements concerned",
    "nc.f.items.finding": "Findings concerned",
    "nc.f.items.review_entry": "Anomalies concerned",
    "nc.f.subject": "Subject",
    "nc.f.subject.control": "Requirement",
    "nc.f.subject.finding": "Finding",
    "nc.f.subject.review_entry": "Entitlement anomaly",
    "nc.f.subject.nonconformity": "Non-conformity",
    "nc.create": "Create",
    "nc.create.control": "Create a control",
    "nc.create.finding": "Create a finding",
    "nc.create.measure": "Create a measure",
    "nc.create.nonconformity": "Declare a non-conformity",
    "der.f.subject_kind": "Subject of the derogation",
    "nav.nonconformities": "Non-conformities",
    "nc.cancel": "Cancel",
    "nc.close": "Back",
    "nc.confirm": "Confirm",
    "nc.save": "Save",
    "nc.loading": "Loading...",
    "nc.error": "Error",
    "nc.all": "All",
    "nc.panel_title": "Non-conformities and derogations",
    "nc.list_title": "Non-conformities",
    "nc.declare_btn": "Declare a non-conformity",
    "nc.declare_title": "Declare a non-conformity",
    "nc.declare_submit": "Declare",
    "nc.declare_help": "The declaration is recorded \"to qualify\": an administrator qualifies (or rejects) it before any follow-up.",
    "nc.declared": "Non-conformity {ref} declared",
    "nc.empty": "No non-conformity.",
    "nc.subject_type.finding": "Finding",
    "nc.subject_type.control": "Requirement",
    "nc.subject_type.review_entry": "Entitlement anomaly",
    "nc.subject_type.nonconformity": "Non-conformity",
    "nc.subject_type.none": "No subject (free derogation)",
    "nc.f.title": "Title",
    "nc.f.description": "Description",
    "nc.f.source": "Source",
    "nc.f.severity": "Severity",
    "nc.f.observed_at": "Observed on",
    "nc.f.observed_by": "Observed by",
    "nc.f.domain": "Domain",
    "nc.f.requirement_ref": "Requirement / reference",
    "nc.f.evidence": "Evidence (one per line: link, ticket, file)",
    "nc.source.observation": "Incidental observation",
    "nc.source.report": "Report",
    "nc.source.informal_review": "Informal review",
    "nc.source.incident": "Incident",
    "nc.severity.low": "Low",
    "nc.severity.medium": "Medium",
    "nc.severity.high": "High",
    "nc.severity.critical": "Critical",
    "nc.status.to_qualify": "To qualify",
    "nc.status.open": "Open",
    "nc.status.in_remediation": "In remediation",
    "nc.status.derogated": "Under derogation",
    "nc.status.closed": "Closed",
    "nc.status.rejected": "Rejected",
    "nc.col_ref": "Ref.",
    "nc.col_title": "Title",
    "nc.col_severity": "Severity",
    "nc.col_source": "Source",
    "nc.col_observed": "Observed on",
    "nc.col_status": "Status",
    "nc.col_module": "Module",
    "nc.all_modules": "All modules",
    "nc.by_source": "By source:",
    "nc.by_severity": "By criticality:",
    "nc.by_age": "Age:",
    "nc.age_over": "> {n} d",
    "nc.edit_btn": "Edit",
    "nc.edit_title": "Edit the non-conformity",
    "nc.updated": "Non-conformity {ref} updated",
    "nc.col_treatment": "Treatment",
    "nc.treatment.measure": "Measure",
    "nc.treatment.derogation": "Derogation",
    "nc.treatment.none": "None",
    "nc.f.module": "Owning module",
    "nc.open_in_module": "Open in {module}",
    "nc.declared_by": "Declared by",
    "nc.qualified_by": "Qualified by",
    "nc.rejection_note": "Rejection reason",
    "nc.derogation": "Derogation",
    "nc.closure_evidence": "Closure evidence",
    "nc.act_qualify": "Qualify",
    "nc.act_reject": "Reject",
    "nc.act_close": "Close the non-conformity",
    "nc.qualify_help": "Qualifying confirms the non-conformity and sets its severity; it then becomes \"open\".",
    "nc.reject_note_label": "Rejection reason (required)",
    "nc.err_title": "The title needs at least 3 characters.",
    "nc.errors_intro": "Before submitting, complete:",
    "nc.required_hint": "Fields marked * are required.",
    "nc.close_blocked": "Closing is possible once every measure is done ({n} left).",
    "nc.err_note": "The text needs at least 3 characters.",
    "nc.search_person": "Search a person...",
    "nc.f.measures": "Corrective measures",
    "nc.settings_title": "Derogation settings",
    "nc.settings_max_days": "Maximum derogation duration (days)",
    "nc.settings_help": "Any request whose validity exceeds this duration is refused at entry.",
    "nc.settings_saved": "Settings saved",
    "nc.err_max_days": "Enter a number of days between 1 and 3650.",
    "der.list_title": "Derogations",
    "der.request_btn": "Request a derogation",
    "der.request_title": "Request a derogation",
    "der.request_submit": "Submit request",
    "der.request_help": "The request awaits approval. One pending or approved derogation per subject.",
    "der.requested": "Derogation {ref} requested",
    "der.empty": "No derogation.",
    "der.free_help": "Free derogation, attached to nothing: the title and the justification describe the accepted deviation.",
    "der.err_subject": "Choose the subject of the derogation.",
    "der.already": "A derogation already covers this item: {ref} ({status}).",
    "der.f.title": "Title",
    "der.f.justification": "Justification (context, accepted risk)",
    "der.f.risk_owner": "Risk owner",
    "der.f.approver": "Expected approver",
    "der.f.valid_from": "Valid from",
    "der.f.valid_until": "Valid until",
    "der.f.review_at": "Review date",
    "der.f.validity": "Validity",
    "der.status.pending_approval": "Pending approval",
    "der.status.approved": "Approved",
    "der.status.rejected": "Rejected",
    "der.status.expired": "Expired",
    "der.status.revoked": "Revoked",
    "der.col_ref": "Ref.",
    "der.col_subject": "Subject",
    "der.col_owner": "Risk owner",
    "der.col_until": "Valid until",
    "der.col_status": "Status",
    "der.days_left": "{n} days left",
    "der.requested_by": "Requested by",
    "der.decided_by": "Decided by",
    "der.decision_note": "Decision reason (required)",
    "der.decision_note_opt": "Note (optional)",
    "der.revoked_reason": "Revocation reason",
    "der.renews": "Renews",
    "der.act_approve": "Approve",
    "der.act_reject": "Reject",
    "der.act_revoke": "Revoke",
    "der.act_renew": "Renew",
    "der.err_until_order": "End of validity after the start",
});

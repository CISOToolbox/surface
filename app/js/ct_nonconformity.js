// -----------------------------------------------------------------------------
// Generated file - do not edit.
// It is overwritten at every release; a change made here is lost.
// See CONTRIBUTING.md.
// -----------------------------------------------------------------------------
// ct_nonconformity — shared non-conformity and derogation UI (FEAT-45).
//
// One component served from any module: the caller supplies transport
// callbacks against ITS backend (the module's /api/nonconformities and
// /api/derogations routes) plus the subject types it knows how to name.
// The component renders:
//   * declare(opts, prefill)          — "Declare a non-conformity" modal
//   * requestDerogation(opts, prefill) — "Request a derogation" modal
//   * renderPanel(container, opts)    — register panel (both lists, filters,
//                                       detail modal with the role-gated actions)
//   * badge(kind, status)             — status badge shared by the modules
// Business rules (transitions, dates, single live derogation per subject) are
// enforced server-side; the component only shapes the requests and surfaces
// the server's message when one is refused.
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
    function _modal() {
        return (window.ct_modal && typeof window.ct_modal.open === "function") ? window.ct_modal : null;
    }
    function _fail(e) {
        var msg = (e && e.message) ? String(e.message) : t("nc.error");
        // The API layer prefixes "API <code>: {"detail":"…"}" — surface the detail alone.
        var m = /"detail"\s*:\s*"([^"]+)"/.exec(msg);
        showStatus(m ? m[1] : msg, true);
    }
    function _today() { return new Date().toISOString().slice(0, 10); }
    function _val(id) {
        var el = document.getElementById(id);
        return el ? (el.value || "").trim() : "";
    }
    function _multi(id) {
        var out = [];
        var boxes = document.querySelectorAll('#' + id + ' input[type="checkbox"]');
        for (var i = 0; i < boxes.length; i++)
            if (boxes[i].checked)
                out.push(boxes[i].value);
        return out;
    }
    function _field(label, control, required) {
        return '<label class="ct-block ct-mb-2"><span class="fs-xs ct-muted">' + esc(label)
            + (required ? '<span class="ct-req" aria-hidden="true">*</span>' : '') + '</span>' + control + '</label>';
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
    function _input(id, value, type, attrs) {
        return '<input id="' + id + '" type="' + (type || "text") + '" value="' + esc(value) + '" class="w-full"' + (attrs || "") + ' />';
    }
    function _textarea(id, value, rows) {
        return '<textarea id="' + id + '" rows="' + (rows || 3) + '" class="w-full">' + esc(value) + '</textarea>';
    }
    function _select(id, values, current, keyPrefix) {
        var h = '<select id="' + id + '" class="w-full">';
        values.forEach(function (v) {
            h += '<option value="' + esc(v) + '"' + (v === current ? ' selected' : '') + '>' + esc(t(keyPrefix + v)) + '</option>';
        });
        return h + '</select>';
    }
    // A checklist, not a multi-select: ticking a second measure must not
    // need a modifier key.
    function _measureSelect(id, opts, selected) {
        var options = opts.measureOptions ? opts.measureOptions() : [];
        if (!options.length)
            return '<span class="fs-xs ct-muted">' + esc(t("nc.no_measures")) + '</span>';
        var h = '<div id="' + id + '" class="ct-checklist">';
        options.forEach(function (o) {
            h += '<label class="ct-block ct-mb-1 fs-sm"><input type="checkbox" name="' + id + '" value="' + esc(o.value) + '"'
                + (selected.indexOf(o.value) >= 0 ? ' checked' : '') + ' /> ' + esc(o.label)
                + (o.statusLabel ? ' <span class="ct-badge" data-size="sm" data-tone="' + (o.done ? 'low' : 'medium') + '">' + esc(o.statusLabel) + '</span>' : '')
                + '</label>';
        });
        return h + '</div>';
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
    function _subjectLine(subjectType, subjectId, label) {
        if (subjectType === "none")
            return '<div class="ct-mb-3 fs-sm ct-muted">' + esc(t("der.free_help")) + '</div>';
        if (!subjectType || !subjectId)
            return "";
        var text = (label || subjectId);
        return '<div class="ct-mb-3 fs-sm"><span class="ct-muted">' + esc(t("nc.subject")) + '</span> '
            + esc(t("nc.subject_type." + subjectType)) + ' · <strong>' + esc(text) + '</strong></div>';
    }
    // ── Declare a non-conformity ─────────────────────────────────────
    function declare(opts, prefill) {
        var modal = _modal();
        if (!modal || !opts.createNc)
            return Promise.resolve(null);
        var p = prefill || {};
        var h = _errorsBox() + _subjectLine(p.subject_type, p.subject_id, p.subject_label);
        if (opts.modules && opts.modules.length) {
            var ms = '<select id="ct-nc-module" class="w-full">';
            opts.modules.forEach(function (m) { ms += '<option value="' + esc(m.value) + '">' + esc(m.label) + '</option>'; });
            h += _field(t("nc.f.module"), ms + '</select>', true);
        }
        h += _field(t("nc.f.title"), _input("ct-nc-title", p.title || "", "text", ' maxlength="500"'), true);
        h += _field(t("nc.f.description"), _textarea("ct-nc-desc", p.description || "", 4));
        h += '<div class="ct-grid-2 ct-gap-2">';
        h += _field(t("nc.f.source"), _select("ct-nc-source", NC_SOURCES, "observation", "nc.source."));
        h += _field(t("nc.f.severity"), _select("ct-nc-sev", NC_SEVERITIES, p.severity || "medium", "nc.severity."));
        h += _field(t("nc.f.observed_at"), _input("ct-nc-observed", _today(), "date"));
        h += _field(t("nc.f.observed_by"), _pickerSlot("ct-nc-observer"));
        h += _field(t("nc.f.domain"), _input("ct-nc-domain", p.domain || ""));
        h += _field(t("nc.f.requirement_ref"), _input("ct-nc-req", p.requirement_ref || ""));
        h += '</div>';
        h += _field(t("nc.f.evidence"), _textarea("ct-nc-evidence", "", 2));
        h += '<div class="fs-xs ct-muted">' + esc(t("nc.declare_help")) + ' ' + esc(t("nc.required_hint")) + '</div>';
        return modal.open({
            title: t("nc.declare_title"), body: h, size: "md",
            onOpen: function () { _mountPickers(opts, ["ct-nc-observer"], {}); },
            buttons: [
                { id: "cancel", label: t("nc.cancel") },
                { id: "save", label: t("nc.declare_submit"), primary: true, result: function () {
                        var title = _val("ct-nc-title");
                        if (title.length < 3)
                            return _showErrors([{ id: "ct-nc-title", label: t("nc.err_title") }], t("nc.errors_intro"));
                        var evidence = _val("ct-nc-evidence").split("\n").map(function (s) { return s.trim(); }).filter(function (s) { return !!s; });
                        var out = {
                            title: title, description: _val("ct-nc-desc"), source: _val("ct-nc-source"),
                            severity: _val("ct-nc-sev"), observed_at: _val("ct-nc-observed") || null,
                            observed_by: _person("ct-nc-observer"), domain: _val("ct-nc-domain"),
                            requirement_ref: _val("ct-nc-req"), evidence: evidence,
                            subject_type: p.subject_type || "", subject_id: p.subject_id || "",
                        };
                        if (opts.modules && opts.modules.length)
                            out.module = _val("ct-nc-module");
                        return out;
                    } },
            ],
        }).then(function (body) {
            if (!body)
                return null;
            return opts.createNc(body).then(function (nc) {
                showStatus(t("nc.declared", { ref: nc.reference }));
                if (opts.onChange)
                    opts.onChange();
                return nc;
            }).catch(function (e) { _fail(e); return null; });
        });
    }
    // ── Request a derogation ─────────────────────────────────────────
    function requestDerogation(opts, prefill) {
        var modal = _modal();
        if (!modal || !opts.createDer)
            return Promise.resolve(null);
        var p = prefill || {};
        var nc = p.nonconformity || null;
        var subjectType = p.subject_type || (nc ? "nonconformity" : "none");
        var subjectId = p.subject_id || (nc ? nc.id : "");
        var subjectLabel = p.subject_label || (nc ? (nc.reference + " — " + nc.title) : "");
        var h = _errorsBox() + _subjectLine(subjectType, subjectId, subjectLabel);
        h += _field(t("der.f.title"), _input("ct-der-title", p.title || (nc ? nc.title : ""), "text", ' maxlength="500"'), true);
        h += _field(t("der.f.justification"), _textarea("ct-der-just", "", 4), true);
        h += '<div class="ct-grid-2 ct-gap-2">';
        h += _field(t("der.f.risk_owner"), _pickerSlot("ct-der-owner"), true);
        h += _field(t("der.f.approver"), _pickerSlot("ct-der-approver"), true);
        h += _field(t("der.f.valid_from"), _input("ct-der-from", _today(), "date"));
        h += _field(t("der.f.valid_until"), _input("ct-der-until", "", "date"), true);
        h += _field(t("der.f.review_at"), _input("ct-der-review", "", "date"));
        h += '</div>';
        h += '<div class="fs-xs ct-muted">' + esc(t("der.request_help")) + ' ' + esc(t("nc.required_hint")) + '</div>';
        return modal.open({
            title: t("der.request_title"), body: h, size: "md",
            onOpen: function () { _mountPickers(opts, ["ct-der-owner", "ct-der-approver"], {}); },
            buttons: [
                { id: "cancel", label: t("nc.cancel") },
                { id: "save", label: t("der.request_submit"), primary: true, result: function () {
                        var problems = [];
                        if (!_val("ct-der-title"))
                            problems.push({ id: "ct-der-title", label: t("der.f.title") });
                        if (_val("ct-der-just").length < 3)
                            problems.push({ id: "ct-der-just", label: t("der.f.justification") });
                        if (!_person("ct-der-owner"))
                            problems.push({ id: "ct-der-owner", label: t("der.f.risk_owner") });
                        if (!_person("ct-der-approver"))
                            problems.push({ id: "ct-der-approver", label: t("der.f.approver") });
                        if (!_val("ct-der-until"))
                            problems.push({ id: "ct-der-until", label: t("der.f.valid_until") });
                        else if (_val("ct-der-from") && _val("ct-der-until") <= _val("ct-der-from"))
                            problems.push({ id: "ct-der-until", label: t("der.err_until_order") });
                        if (!_showErrors(problems, t("nc.errors_intro")))
                            return false;
                        return {
                            subject_type: subjectType, subject_id: subjectId,
                            title: _val("ct-der-title"), justification: _val("ct-der-just"),
                            risk_owner: _person("ct-der-owner"), approver: _person("ct-der-approver"),
                            valid_from: _val("ct-der-from") || null, valid_until: _val("ct-der-until") || null,
                            review_at: _val("ct-der-review") || null,
                        };
                    } },
            ],
        }).then(function (body) {
            if (!body)
                return null;
            return opts.createDer(body).then(function (d) {
                showStatus(t("der.requested", { ref: d.reference }));
                if (opts.onChange)
                    opts.onChange();
                return d;
            }).catch(function (e) { _fail(e); return null; });
        });
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
    function _reload() {
        var changed = (_opts && _opts.onChange) ? _opts.onChange() : undefined;
        return Promise.resolve(changed).then(function () {
            return (_container && _opts) ? _load(_container, _opts) : undefined;
        });
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
        var admin = _opts.isAdmin();
        var h = '<div class="ct-flex ct-items-center ct-gap-2 ct-mb-3">';
        h += '<h2 class="ct-ink ct-flex-1 ct-m-0">' + esc(t("nc.panel_title")) + '</h2>';
        if (_opts.createNc)
            h += '<button class="ct-btn" data-write data-variant="primary" data-click="_ctNcDeclare">' + _icon("plus", 14) + ' ' + esc(t("nc.declare_btn")) + '</button>';
        if (_opts.createDer)
            h += '<button class="ct-btn" data-write data-click="_ctNcRequestDer">' + esc(t("der.request_btn")) + '</button>';
        if (admin && (_opts.getSettings || _opts.openSettings))
            h += '<button class="ct-btn" data-click="_ctNcSettings" title="' + esc(t("nc.settings_title")) + '">' + _icon("settings", 14) + '</button>';
        var withModule = !!(_opts.modules && _opts.modules.length);
        if (withModule) {
            var sel = '<select class="ct-filter" data-change="_ctNcModuleFilter" data-pass-value><option value="">' + esc(t("nc.all_modules")) + '</option>';
            _opts.modules.forEach(function (m) { sel += '<option value="' + esc(m.value) + '"' + (m.value === _moduleFilter ? ' selected' : '') + '>' + esc(m.label) + '</option>'; });
            h += sel + '</select>';
        }
        var moduleCol = { key: "module", label: t("nc.col_module"), width: "110px", render: function (r) { return esc(r.module_name || r.module || ""); } };
        h += '</div>';
        // Non-conformities
        h += '<h3 class="ct-mt-4">' + esc(t("nc.list_title")) + '</h3>';
        h += _pills("nc", NC_STATUSES, _ncFilter, _ncRows);
        var ncRows = _ncRows.filter(function (r) { return (!_ncFilter || r.status === _ncFilter) && (!_moduleFilter || r.module === _moduleFilter); });
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
    function _row(label, value, raw) {
        if (!value)
            return "";
        return '<div class="ct-flex ct-gap-2 fs-sm ct-mb-1"><span class="ct-muted ct-minw-140">' + esc(label) + '</span><span>' + (raw ? value : esc(value)) + '</span></div>';
    }
    function _subjectLink(subjectType, subjectId, label) {
        if (subjectType === "none")
            return esc(t("nc.subject_type.none"));
        if (!subjectType || !subjectId)
            return "";
        var text = esc(t("nc.subject_type." + subjectType)) + ' · ' + esc(label || subjectId);
        if (subjectType === "nonconformity") {
            var nc = _ncRows.filter(function (r) { return r.id === subjectId; })[0];
            if (nc)
                text = esc(t("nc.subject_type.nonconformity")) + ' · ' + esc(nc.reference + " — " + nc.title);
        }
        return text;
    }
    function _openNc(row) {
        var modal = _modal();
        if (!modal || !_opts)
            return;
        var nc = _ncRows.filter(function (r) { return r.id === row.id; })[0];
        if (!nc)
            return;
        _detailNcId = nc.id;
        var admin = _opts.isAdmin();
        var s = nc.status;
        var h = '<div class="ct-mb-3">' + _badge("nc", nc.status) + ' ' + _sevBadge(nc.severity) + '</div>';
        h += _row(t("nc.f.title"), nc.title);
        h += _row(t("nc.f.description"), nc.description || "");
        h += _row(t("nc.f.source"), t("nc.source." + nc.source));
        h += _row(t("nc.subject"), _subjectLink(nc.subject_type, nc.subject_id), true);
        h += _row(t("nc.f.domain"), nc.domain || "");
        h += _row(t("nc.f.requirement_ref"), nc.requirement_ref || "");
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
        // A closed or rejected non-conformity is a record: its measures are
        // read here, edited from the action plan if ever needed.
        var canEdit = !!_opts.openMeasure && s !== "closed" && s !== "rejected";
        var measures = _measureOptionsOf(nc.measure_ids || []);
        var pendingMeasures = measures.filter(function (o) { return !o.done; });
        var canLink = !!_opts.remediationNc && (s === "open" || s === "in_remediation");
        var unlinked = (_opts.measureOptions ? _opts.measureOptions() : []).filter(function (o) { return (nc.measure_ids || []).indexOf(o.value) < 0; });
        if (measures.length || canLink) {
            var mh = '';
            measures.forEach(function (o) {
                // The measure itself is the link to its modal (when the record still moves).
                var open = canEdit ? ' data-click="_ctNcEditMeasure" data-args=\'' + _da(o.value) + '\' title="' + esc(t("nc.edit_measure")) + '"' : '';
                mh += '<div class="ct-flex ct-items-center ct-gap-2 ct-mb-1' + (canEdit ? ' ct-clickable' : '') + '"' + open + '>'
                    + '<span class="ct-flex-1' + (canEdit ? ' ct-link' : '') + '">' + esc(o.label) + '</span>'
                    + (o.statusLabel ? '<span class="ct-badge" data-tone="' + (o.done ? 'low' : 'medium') + '">' + esc(o.statusLabel) + '</span>' : '')
                    + '</div>';
            });
            if (canLink) {
                // The corrective measures are added from here: + creates one in
                // the module's own modal and comes back to this record.
                mh += '<div class="ct-flex ct-gap-2 ct-mt-1">';
                if (_opts.createMeasure)
                    mh += '<button class="ct-btn" data-size="xs" data-variant="primary" data-write data-click="_ctNcAddMeasure" title="' + esc(t("nc.new_measure")) + '">' + _icon("plus", 12) + ' ' + esc(t("nc.new_measure")) + '</button>';
                if (unlinked.length)
                    mh += '<button class="ct-btn" data-size="xs" data-write data-click="_ctNcAttachMeasures">' + esc(t("nc.attach_measures")) + '</button>';
                mh += '</div>';
            }
            if (!measures.length && canLink)
                mh = '<div class="fs-xs ct-muted ct-mb-1">' + esc(t("nc.no_measure_yet")) + '</div>' + mh;
            h += _row(t("nc.f.measures"), mh, true);
            if (pendingMeasures.length && (s === "in_remediation" || s === "open" || s === "derogated")) {
                h += '<div class="fs-xs ct-muted ct-mb-2">' + esc(t("nc.close_blocked", { n: pendingMeasures.length })) + '</div>';
            }
        }
        if (nc.module_url)
            h = '<div class="ct-mb-2 fs-sm"><a href="' + esc(nc.module_url) + '">' + esc(t("nc.open_in_module", { module: nc.module_name || nc.module || "" })) + ' ↗</a></div>' + h;
        var buttons = [{ id: "close", label: t("nc.close") }];
        if (nc.subject_type && nc.subject_id && nc.subject_type !== "nonconformity" && _opts.openSubject) {
            buttons.push({ id: "open_subject", label: _openLabel(nc.subject_type), result: "open_subject" });
        }
        if (s === "to_qualify" && admin && _opts.qualifyNc) {
            if (_opts.rejectNc)
                buttons.push({ id: "reject", label: t("nc.act_reject"), danger: true, result: "reject" });
            buttons.push({ id: "qualify", label: t("nc.act_qualify"), primary: true, result: "qualify" });
        }
        if (s === "open" || s === "in_remediation") {
            if (_opts.createDer)
                buttons.push({ id: "derog", label: t("der.request_btn"), result: "derog" });
            if (admin && _opts.closeNc && !pendingMeasures.length)
                buttons.push({ id: "closeNc", label: t("nc.act_close"), primary: true, result: "closeNc" });
        }
        if (s === "derogated" && admin && _opts.closeNc && !pendingMeasures.length)
            buttons.push({ id: "closeNc", label: t("nc.act_close"), primary: true, result: "closeNc" });
        modal.open({ title: nc.reference, body: h, size: "md", buttons: buttons }).then(function (r) {
            if (!r || !_opts)
                return;
            if (r === "open_subject") {
                _opts.openSubject(nc.subject_type, nc.subject_id);
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
    // "See the requirement" / "See the finding": named after what it opens.
    function _openLabel(subjectType) {
        var k = "nc.open_subject." + subjectType;
        var v = t(k);
        return v === k ? t("nc.open_subject") : v;
    }
    function _measureOptionsOf(ids) {
        var options = (_opts && _opts.measureOptions) ? _opts.measureOptions() : [];
        return ids.map(function (id) {
            var o = options.filter(function (x) { return x.value === id; })[0];
            return o || { value: id, label: id, done: false };
        });
    }
    // Edit a linked measure in the module's own modal, then come back to the
    // non-conformity with fresh data (its status may have changed).
    var _detailNcId = "";
    window._ctNcEditMeasure = function (id) {
        if (!_opts || !_opts.openMeasure)
            return;
        var ncId = _detailNcId;
        var modal = _modal();
        if (modal)
            modal.close();
        Promise.resolve(_opts.openMeasure(id)).then(function () { return _reload(); }).catch(_fail).then(function () {
            if (ncId)
                _openNc({ id: ncId });
        });
    };
    // Corrective measures are added from the record itself. + opens the
    // module's own measure modal (ct_modal is a single overlay, so the record
    // closes and reopens afterwards); "attach" offers the existing measures.
    // Linking the first measure moves the record to in_remediation.
    function _linkMeasures(nc, ids) {
        if (!_opts || !_opts.remediationNc)
            return;
        _opts.remediationNc(nc.id, ids).then(function () { return _reload(); })
            .then(function () { _openNc({ id: nc.id }); })
            .catch(function (e) { _fail(e); _openNc({ id: nc.id }); });
    }
    window._ctNcAddMeasure = function () {
        if (!_opts || !_opts.createMeasure || !_detailNcId)
            return;
        var nc = _ncRows.filter(function (r) { return r.id === _detailNcId; })[0];
        if (!nc)
            return;
        var modal = _modal();
        if (modal)
            modal.close();
        _opts.createMeasure({ title: nc.title, description: nc.description || "" }).then(function (created) {
            if (!created) {
                _openNc({ id: nc.id });
                return;
            }
            _linkMeasures(nc, (nc.measure_ids || []).concat([created.value]));
        });
    };
    window._ctNcAttachMeasures = function () {
        var modal = _modal();
        if (!modal || !_opts || !_detailNcId)
            return;
        var nc = _ncRows.filter(function (r) { return r.id === _detailNcId; })[0];
        if (!nc)
            return;
        var linked = nc.measure_ids || [];
        var options = (_opts.measureOptions ? _opts.measureOptions() : []).filter(function (o) { return linked.indexOf(o.value) < 0; });
        var h = '<div class="fs-sm ct-mb-3"><strong>' + esc(nc.reference) + '</strong> — ' + esc(nc.title) + '</div>';
        h += '<div id="ct-nc-measures" class="ct-checklist">';
        options.forEach(function (o) {
            h += '<label class="ct-block ct-mb-1 fs-sm"><input type="checkbox" name="ct-nc-measures" value="' + esc(o.value) + '" /> ' + esc(o.label)
                + (o.statusLabel ? ' <span class="ct-badge" data-size="sm" data-tone="' + (o.done ? 'low' : 'medium') + '">' + esc(o.statusLabel) + '</span>' : '')
                + '</label>';
        });
        h += '</div>';
        modal.open({ title: t("nc.attach_measures"), body: h, size: "md", buttons: [
                { id: "cancel", label: t("nc.cancel") },
                { id: "ok", label: t("nc.attach_submit"), primary: true, result: function () {
                        var ids = _multi("ct-nc-measures");
                        if (!ids.length) {
                            showStatus(t("nc.err_measures"), true);
                            return false;
                        }
                        return { ids: ids };
                    } },
            ] }).then(function (r) {
            if (!r) {
                _openNc({ id: nc.id });
                return;
            }
            _linkMeasures(nc, linked.concat(r.ids));
        });
    };
    function _qualifyNc(nc) {
        var modal = _modal();
        if (!modal)
            return;
        var h = '<div class="ct-grid-2 ct-gap-2">';
        h += _field(t("nc.f.severity"), _select("ct-nc-q-sev", NC_SEVERITIES, nc.severity, "nc.severity."));
        h += _field(t("nc.f.domain"), _input("ct-nc-q-domain", nc.domain || ""));
        h += _field(t("nc.f.requirement_ref"), _input("ct-nc-q-req", nc.requirement_ref || ""));
        h += '</div><div class="fs-xs ct-muted">' + esc(t("nc.qualify_help")) + '</div>';
        modal.open({ title: t("nc.act_qualify") + " — " + nc.reference, body: h, size: "sm", buttons: [
                { id: "cancel", label: t("nc.cancel") },
                { id: "ok", label: t("nc.act_qualify"), primary: true, result: function () {
                        return { severity: _val("ct-nc-q-sev"), domain: _val("ct-nc-q-domain"), requirement_ref: _val("ct-nc-q-req") };
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
    function _openDer(row) {
        var modal = _modal();
        if (!modal || !_opts)
            return;
        var d = _derRows.filter(function (r) { return r.id === row.id; })[0];
        if (!d)
            return;
        var admin = _opts.isAdmin();
        var h = '<div class="ct-mb-3">' + _badge("der", d.status) + '</div>';
        h += _row(t("der.f.title"), d.title || "");
        h += _row(t("nc.subject"), _subjectLink(d.subject_type, d.subject_id, d.subject_label), true);
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
        if (d.subject_type !== "nonconformity" && d.subject_type !== "none" && _opts.openSubject)
            buttons.push({ id: "open_subject", label: _openLabel(d.subject_type), result: "open_subject" });
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
            if (r === "open_subject") {
                _opts.openSubject(d.subject_type, d.subject_id);
                return;
            }
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
    window._ctNcOpen = _openNc;
    window._ctDerOpen = _openDer;
    window._ctNcDeclare = function () { if (_opts)
        declare(_opts).then(function (nc) { if (nc)
            _reload(); }); };
    window._ctNcRequestDer = function () { if (_opts)
        _pickSubjectThenRequest(); };
    window._ctNcSettings = _settings;
    // "Request a derogation" from the register: on an open non-conformity, or
    // directly on a module item — the a-priori case, when one knows a
    // requirement will not be met and asks for the agreement first.
    var _derKind = "";
    function _derResults(kind, q) {
        q = (q || "").toLowerCase();
        if (kind === "nonconformity") {
            return _ncRows.filter(function (r) { return r.status === "to_qualify" || r.status === "open" || r.status === "in_remediation"; })
                .map(function (r) { return { value: r.id, label: r.reference + " — " + r.title + (r.status === "to_qualify" ? " (" + t("nc.status.to_qualify").toLowerCase() + ")" : "") }; })
                .filter(function (o) { return !q || o.label.toLowerCase().indexOf(q) >= 0; });
        }
        return (_opts && _opts.subjectSearch) ? _opts.subjectSearch(q).slice(0, 100) : [];
    }
    function _derResultsHtml(kind, q) {
        if (kind === "none")
            return '<div class="fs-sm ct-muted">' + esc(t("der.free_help")) + '</div>';
        var rows = _derResults(kind, q);
        if (kind === "nonconformity" && !rows.length && !q) {
            // No open non-conformity: say so, and offer to declare one right here.
            var msg = _ncRows.length ? t("der.no_open_nc") : t("der.no_nc");
            return '<div class="fs-sm ct-muted ct-mb-2">' + esc(msg) + '</div>'
                + '<button class="ct-btn" data-size="xs" data-write data-click="_ctDerDeclareNc">' + _icon("plus", 12) + ' ' + esc(t("nc.declare_btn")) + '</button>';
        }
        if (!rows.length)
            return '<div class="fs-xs ct-muted">' + esc(t("der.no_match")) + '</div>';
        var h = '<select id="ct-der-pick" size="8" class="w-full">';
        rows.forEach(function (o) { h += '<option value="' + esc(o.value) + '">' + esc(o.label) + '</option>'; });
        return h + '</select>';
    }
    window._ctDerSearch = function (q) {
        var box = document.getElementById("ct-der-results");
        if (box)
            box.innerHTML = _derResultsHtml(_derKind, q);
    };
    window._ctDerKind = function (kind) {
        _derKind = kind;
        var wrap = document.getElementById("ct-der-search");
        if (wrap)
            wrap.hidden = kind === "none"; // nothing to search for a free derogation
        window._ctDerSearch(_val("ct-der-q"));
    };
    window._ctDerDeclareNc = function () {
        var modal = _modal();
        if (!modal || !_opts)
            return;
        modal.close();
        declare(_opts).then(function (nc) {
            if (!nc || !_opts) {
                _pickSubjectThenRequest();
                return;
            }
            // Straight back to the request, on the non-conformity just declared.
            requestDerogation(_opts, { nonconformity: nc }).then(function (d) { _reload(); });
        });
    };
    function _pickSubjectThenRequest() {
        var modal = _modal();
        if (!modal || !_opts)
            return;
        var itemType = _opts.subjectSearch ? (_opts.subjectTypes[0] || "") : "";
        var kinds = [];
        if (itemType)
            kinds.push(itemType);
        kinds.push("nonconformity");
        kinds.push("none");
        _derKind = kinds[0];
        var h = '<div class="fs-xs ct-muted ct-mb-2">' + esc(t("der.pick_help")) + '</div>';
        if (kinds.length > 1) {
            var sel = '<select id="ct-der-kind" class="w-full" data-change="_ctDerKind" data-pass-value>';
            kinds.forEach(function (k) { sel += '<option value="' + esc(k) + '">' + esc(t("nc.subject_type." + k)) + '</option>'; });
            h += _field(t("der.subject_kind"), sel + '</select>');
        }
        h += '<div id="ct-der-search">' + _field(t("der.search"), '<input id="ct-der-q" type="text" class="w-full" data-input="_ctDerSearch" data-pass-value autocomplete="off" />') + '</div>';
        h += '<div id="ct-der-results">' + _derResultsHtml(_derKind, "") + '</div>';
        modal.open({ title: t("der.request_btn"), body: h, size: "md", buttons: [
                { id: "cancel", label: t("nc.cancel") },
                { id: "ok", label: t("nc.next"), primary: true, result: function () {
                        if (_derKind === "none")
                            return { kind: "none", id: "", label: "" };
                        var id = _val("ct-der-pick");
                        if (!id) {
                            showStatus(t("der.err_subject"), true);
                            return false;
                        }
                        var o = _derResults(_derKind, _val("ct-der-q")).filter(function (x) { return x.value === id; })[0];
                        return { kind: _derKind, id: id, label: o ? o.label : id };
                    } },
            ] }).then(function (r) {
            if (!r || !_opts)
                return;
            if (r.kind === "nonconformity") {
                var nc = _ncRows.filter(function (x) { return x.id === r.id; })[0];
                requestDerogation(_opts, { nonconformity: nc }).then(function (d) { if (d)
                    _reload(); });
            }
            else if (r.kind === "none") {
                requestDerogation(_opts, { subject_type: "none", subject_id: "" }).then(function (d) { if (d)
                    _reload(); });
            }
            else {
                requestDerogation(_opts, { subject_type: r.kind, subject_id: r.id, subject_label: r.label, title: r.label.substring(0, 200) })
                    .then(function (d) { if (d)
                    _reload(); });
            }
        });
    }
    window.ct_nonconformity = {
        declare: declare,
        requestDerogation: requestDerogation,
        renderPanel: renderPanel,
        badge: function (kind, status) { return _badge(kind, status); },
        tone: function (kind, status) { return _tone(kind, status); },
    };
})();
_registerTranslations("fr", {
    "nav.nonconformities": "Non-conformités",
    "nc.cancel": "Annuler",
    "nc.close": "Retour",
    "nc.confirm": "Confirmer",
    "nc.save": "Enregistrer",
    "nc.next": "Suivant",
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
    "nc.subject": "Objet",
    "nc.subject_type.finding": "Constat de surface",
    "nc.subject_type.control": "Exigence",
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
    "nc.open_subject": "Voir l'élément",
    "nc.open_subject.finding": "Voir le constat de surface",
    "nc.open_subject.control": "Voir l'exigence dans le référentiel",
    "nc.act_qualify": "Qualifier",
    "nc.act_reject": "Rejeter",
    "nc.act_close": "Clôturer",
    "nc.qualify_help": "La qualification confirme la non-conformité et fixe sa gravité ; elle passe alors « ouverte ».",
    "nc.reject_note_label": "Motif du rejet (obligatoire)",
    "nc.err_title": "Le titre doit faire au moins 3 caractères.",
    "nc.errors_intro": "Avant de valider, compléter :",
    "nc.required_hint": "Les champs marqués * sont obligatoires.",
    "nc.edit_measure": "Modifier",
    "nc.close_blocked": "Clôture possible quand toutes les mesures sont terminées ({n} restante(s)).",
    "nc.err_note": "Le texte doit faire au moins 3 caractères.",
    "nc.no_measures": "Aucune mesure disponible dans ce module.",
    "nc.search_person": "Rechercher une personne...",
    "nc.f.measures": "Mesures correctives",
    "nc.attach_measures": "Rattacher des mesures existantes",
    "nc.attach_submit": "Rattacher",
    "nc.no_measure_yet": "Aucune mesure corrective : la non-conformité passe en remédiation dès la première.",
    "nc.new_measure": "Nouvelle mesure",
    "nc.err_measures": "Au moins une mesure corrective est requise.",
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
    "der.pick_help": "Une dérogation se demande de préférence avant l'écart : sur l'élément concerné (exigence, constat), ou sur une non-conformité ouverte.",
    "der.subject_kind": "Objet de la dérogation",
    "der.search": "Rechercher",
    "der.no_match": "Aucun élément ne correspond.",
    "der.no_nc": "Aucune non-conformité déclarée.",
    "der.no_open_nc": "Aucune non-conformité en cours (toutes clôturées, rejetées ou déjà sous dérogation).",
    "der.free_help": "Dérogation libre, sans objet rattaché : le titre et la justification décrivent l'écart accepté.",
    "der.err_subject": "Choisir l'objet de la dérogation.",
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
    "nav.nonconformities": "Non-conformities",
    "nc.cancel": "Cancel",
    "nc.close": "Back",
    "nc.confirm": "Confirm",
    "nc.save": "Save",
    "nc.next": "Next",
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
    "nc.subject": "Subject",
    "nc.subject_type.finding": "Surface finding",
    "nc.subject_type.control": "Requirement",
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
    "nc.open_subject": "See the item",
    "nc.open_subject.finding": "See the finding",
    "nc.open_subject.control": "See the requirement in its framework",
    "nc.act_qualify": "Qualify",
    "nc.act_reject": "Reject",
    "nc.act_close": "Close the non-conformity",
    "nc.qualify_help": "Qualifying confirms the non-conformity and sets its severity; it then becomes \"open\".",
    "nc.reject_note_label": "Rejection reason (required)",
    "nc.err_title": "The title needs at least 3 characters.",
    "nc.errors_intro": "Before submitting, complete:",
    "nc.required_hint": "Fields marked * are required.",
    "nc.edit_measure": "Edit",
    "nc.close_blocked": "Closing is possible once every measure is done ({n} left).",
    "nc.err_note": "The text needs at least 3 characters.",
    "nc.no_measures": "No measure available in this module.",
    "nc.search_person": "Search a person...",
    "nc.f.measures": "Corrective measures",
    "nc.attach_measures": "Attach existing measures",
    "nc.attach_submit": "Attach",
    "nc.no_measure_yet": "No corrective measure yet: the non-conformity enters remediation with the first one.",
    "nc.new_measure": "New measure",
    "nc.err_measures": "At least one corrective measure is required.",
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
    "der.pick_help": "A derogation is best requested before the gap: on the item concerned (requirement, finding), or on an open non-conformity.",
    "der.subject_kind": "Subject of the derogation",
    "der.search": "Search",
    "der.no_match": "Nothing matches.",
    "der.no_nc": "No non-conformity declared.",
    "der.no_open_nc": "No non-conformity in progress (all closed, rejected or already under derogation).",
    "der.free_help": "Free derogation, attached to nothing: the title and the justification describe the accepted deviation.",
    "der.err_subject": "Choose the subject of the derogation.",
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

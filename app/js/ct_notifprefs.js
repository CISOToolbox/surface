// -----------------------------------------------------------------------------
// REPLICATED from the private shared repository (shared/js/ct_notifprefs.js).
// DO NOT EDIT HERE - changes will be overwritten by the next propagation run.
// Fix the master in the shared repository and re-propagate. See CONTRIBUTING.md.
// -----------------------------------------------------------------------------
// ct_notifprefs — shared Notifications-preferences modal (FEAT-34 / FEAT-35).
//
// One modal, served from any module: the caller supplies transport callbacks
// (fetch/save/test against ITS backend — Pilot directly, AppSec through its
// proxy) and the modal adapts to the payload shape:
//   * Pilot deadline-digest section — shown when the payload carries the
//     FEAT-34 fields (`enabled`, `day_of_week`, …), i.e. suite mode or Pilot.
//   * AppSec findings section — shown when `module_prefs` is present.
// Saving always round-trips the FETCHED payload with only the edited fields
// overridden, so a module that doesn't display a section never clobbers it.
var _NP_DAYS = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"];
var _NP_SEVS = ["low", "medium", "high", "critical"];
function _npDaySelect(id, current) {
    var h = '<select id="' + id + '">';
    _NP_DAYS.forEach(function (d, i) {
        h += '<option value="' + i + '"' + (current === i ? " selected" : "") + '>'
            + esc(t("notif.day." + d)) + '</option>';
    });
    return h + '</select>';
}
function _npSevSelect(id, current) {
    var h = '<select id="' + id + '">';
    _NP_SEVS.forEach(function (sv) {
        h += '<option value="' + sv + '"' + (current === sv ? " selected" : "") + '>'
            + esc(t("notif.sev." + sv)) + '</option>';
    });
    return h + '</select>';
}
function _npVal(id) {
    var el = document.getElementById(id);
    return el ? el.value : "";
}
function _npChecked(id) {
    var el = document.getElementById(id);
    return !!(el && el.checked);
}
function _npHas(id) { return !!document.getElementById(id); }
var ct_notifprefs = {
    open: function (opts) {
        opts.fetchPrefs().then(function (p) {
            var hasPilot = typeof p.enabled === "boolean" && typeof p.day_of_week === "number";
            var appsec = (p.module_prefs || {}).appsec || null;
            var h = '<div class="ct-notifprefs-form">';
            h += '<div class="ct-notifprefs-group"><h3 class="ct-notifprefs-section">' + esc(t("notif.section.general")) + '</h3>';
            h += '<div class="ct-form-row"><label for="np-lang">' + esc(t("notif.lang_global")) + '</label><select id="np-lang">'
                + '<option value="fr"' + (p.lang !== "en" ? " selected" : "") + '>Français</option>'
                + '<option value="en"' + (p.lang === "en" ? " selected" : "") + '>English</option>'
                + '</select>'
                + '<div class="ct-notifprefs-help">' + esc(t("notif.lang_global_hint")) + '</div></div>';
            h += '<div class="ct-notifprefs-help">' + esc(t("notif.hint.general")) + '</div>';
            h += '</div>';
            if (hasPilot) {
                h += '<details class="ct-notifprefs-group" name="ct-notifprefs-acc"><summary class="ct-notifprefs-section">' + esc(t("notif.section.pilot")) + '</summary>';
                h += '<div class="ct-notifprefs-help ct-notifprefs-modhint">' + esc(t("notif.hint.pilot")) + '</div>';
                h += '<div class="ct-form-row"><label class="ct-flex ct-items-center ct-gap-2">'
                    + '<input type="checkbox" id="np-enabled"' + (p.enabled ? " checked" : "") + '> '
                    + esc(t("notif.enabled")) + '</label></div>';
                h += '<div class="ct-form-row"><label for="np-day">' + esc(t("notif.day_label")) + '</label>'
                    + _npDaySelect("np-day", p.day_of_week) + '</div>';
                h += '<div class="ct-form-row"><label for="np-window">' + esc(t("notif.window")) + '</label><select id="np-window">';
                [7, 14, 30].forEach(function (n) {
                    h += '<option value="' + n + '"' + (p.upcoming_days === n ? " selected" : "") + '>' + n + ' ' + esc(t("notif.days_unit")) + '</option>';
                });
                h += '</select></div>';
                h += '<div class="ct-form-row"><label class="ct-flex ct-items-center ct-gap-2">'
                    + '<input type="checkbox" id="np-overdue"' + (p.include_overdue ? " checked" : "") + '> '
                    + esc(t("notif.include_overdue")) + '</label></div>';
                if (opts.isAdmin) {
                    h += '<div class="ct-form-row"><label for="np-scope">' + esc(t("notif.scope")) + '</label><select id="np-scope">'
                        + '<option value="mine"' + (p.scope !== "all" ? " selected" : "") + '>' + esc(t("notif.scope.mine")) + '</option>'
                        + '<option value="all"' + (p.scope === "all" ? " selected" : "") + '>' + esc(t("notif.scope.all")) + '</option>'
                        + '</select></div>';
                }
                if (opts.modules && opts.modules.length) {
                    h += '<div class="ct-form-row"><label class="ct-notifprefs-label">' + esc(t("notif.modules")) + '</label><div class="ct-flex ct-gap-2" style="flex-wrap:wrap">';
                    opts.modules.forEach(function (mid) {
                        var on = !(p.modules || []).length || (p.modules || []).indexOf(mid) >= 0;
                        h += '<label class="ct-text-meta ct-flex ct-items-center ct-gap-1">'
                            + '<input type="checkbox" class="ct-notifprefs-mod" value="' + esc(mid) + '"' + (on ? " checked" : "") + '> ' + esc(mid) + '</label>';
                    });
                    h += '</div></div>';
                }
                h += '<div class="ct-form-row"><label for="np-prefix">' + esc(t("notif.prefix")) + '</label>'
                    + '<input type="text" id="np-prefix" maxlength="60" value="' + esc(p.subject_prefix || "[CISO Toolbox]") + '" placeholder="[CISO Toolbox]"></div>';
                h += '</details>';
            }
            if (appsec) {
                h += '<details class="ct-notifprefs-group" name="ct-notifprefs-acc"><summary class="ct-notifprefs-section">' + esc(t("notif.section.appsec")) + '</summary>';
                h += '<div class="ct-notifprefs-help ct-notifprefs-modhint">' + esc(t("notif.hint.appsec")) + '</div>';
                h += '<div class="ct-form-row"><label class="ct-flex ct-items-center ct-gap-2">'
                    + '<input type="checkbox" id="np-as-alert"' + (appsec.alert_enabled ? " checked" : "") + '> '
                    + esc(t("notif.appsec.alert_enabled")) + '</label></div>';
                h += '<div class="ct-form-row"><label for="np-as-alert-sev">' + esc(t("notif.appsec.alert_threshold")) + '</label>'
                    + _npSevSelect("np-as-alert-sev", appsec.alert_min_severity || "low") + '</div>';
                h += '<div class="ct-form-row"><label class="ct-flex ct-items-center ct-gap-2">'
                    + '<input type="checkbox" id="np-as-weekly"' + (appsec.weekly_enabled ? " checked" : "") + '> '
                    + esc(t("notif.appsec.weekly_enabled")) + '</label></div>';
                h += '<div class="ct-form-row"><label for="np-as-weekly-day">' + esc(t("notif.appsec.weekly_day")) + '</label>'
                    + _npDaySelect("np-as-weekly-day", typeof appsec.weekly_day === "number" ? appsec.weekly_day : 0) + '</div>';
                h += '<div class="ct-form-row"><label for="np-as-weekly-sev">' + esc(t("notif.appsec.weekly_threshold")) + '</label>'
                    + _npSevSelect("np-as-weekly-sev", appsec.weekly_min_severity || "low") + '</div>';
                h += '<div class="ct-form-row"><label for="np-as-prefix">' + esc(t("notif.prefix")) + '</label>'
                    + '<input type="text" id="np-as-prefix" maxlength="60" value="' + esc(appsec.subject_prefix || "[AppSec]") + '" placeholder="[AppSec]"></div>';
                h += '</details>';
            }
            var surface = (p.module_prefs || {}).surface || null;
            if (surface) {
                h += '<details class="ct-notifprefs-group" name="ct-notifprefs-acc"><summary class="ct-notifprefs-section">' + esc(t("notif.section.surface")) + '</summary>';
                h += '<div class="ct-notifprefs-help ct-notifprefs-modhint">' + esc(t("notif.hint.surface")) + '</div>';
                h += '<div class="ct-form-row"><label class="ct-flex ct-items-center ct-gap-2">'
                    + '<input type="checkbox" id="np-sf-alert"' + (surface.alert_enabled ? " checked" : "") + '> '
                    + esc(t("notif.surface.alert_enabled")) + '</label></div>';
                h += '<div class="ct-form-row"><label for="np-sf-alert-sev">' + esc(t("notif.surface.alert_threshold")) + '</label>'
                    + _npSevSelect("np-sf-alert-sev", surface.alert_min_severity || "low") + '</div>';
                h += '<div class="ct-form-row"><label for="np-sf-prefix">' + esc(t("notif.prefix")) + '</label>'
                    + '<input type="text" id="np-sf-prefix" maxlength="60" value="' + esc(surface.subject_prefix || "[Surface]") + '" placeholder="[Surface]"></div>';
                h += '</details>';
            }
            h += '</div>';
            function collect() {
                var out = {};
                Object.keys(p).forEach(function (k) { out[k] = p[k]; });
                if (hasPilot) {
                    out.enabled = _npChecked("np-enabled");
                    out.day_of_week = parseInt(_npVal("np-day"), 10);
                    out.upcoming_days = parseInt(_npVal("np-window"), 10);
                    out.include_overdue = _npChecked("np-overdue");
                    if (_npHas("np-scope"))
                        out.scope = _npVal("np-scope");
                    if (document.querySelectorAll(".ct-notifprefs-mod").length) {
                        var mods = [];
                        var checks = document.querySelectorAll(".ct-notifprefs-mod");
                        for (var i = 0; i < checks.length; i++) {
                            if (checks[i].checked)
                                mods.push(checks[i].value);
                        }
                        out.modules = mods.length === checks.length ? [] : mods;
                    }
                    out.subject_prefix = (_npVal("np-prefix") || "").trim() || "[CISO Toolbox]";
                }
                if (appsec || surface) {
                    var mp = {};
                    Object.keys(p.module_prefs || {}).forEach(function (k) { mp[k] = (p.module_prefs || {})[k]; });
                    out.module_prefs = mp;
                }
                if (appsec) {
                    var mp2 = out.module_prefs;
                    mp2.appsec = {
                        alert_enabled: _npChecked("np-as-alert"),
                        alert_min_severity: _npVal("np-as-alert-sev") || "low",
                        weekly_enabled: _npChecked("np-as-weekly"),
                        weekly_day: parseInt(_npVal("np-as-weekly-day"), 10) || 0,
                        weekly_min_severity: _npVal("np-as-weekly-sev") || "low",
                        subject_prefix: (_npVal("np-as-prefix") || "").trim() || "[AppSec]"
                    };
                }
                if (surface) {
                    var mp3 = out.module_prefs;
                    mp3.surface = {
                        alert_enabled: _npChecked("np-sf-alert"),
                        alert_min_severity: _npVal("np-sf-alert-sev") || "low",
                        subject_prefix: (_npVal("np-sf-prefix") || "").trim() || "[Surface]"
                    };
                }
                out.lang = _npVal("np-lang") || "fr";
                return out;
            }
            var buttons = [{ id: "cancel", label: t("notif.cancel") }];
            if (opts.sendTest) {
                buttons.push({ id: "test", label: t("notif.run_test"),
                    result: function () { return { __test: true, prefs: collect() }; } });
            }
            buttons.push({ id: "save", label: t("notif.save"), primary: true,
                result: function () { return { prefs: collect() }; } });
            if (!window.ct_modal || typeof window.ct_modal.open !== "function")
                return;
            window.ct_modal.open({ title: t("notif.title"), body: h, size: "md", buttons: buttons })
                .then(function (result) {
                if (!result)
                    return;
                opts.savePrefs(result.prefs).then(function () {
                    if (result.__test && opts.sendTest) {
                        return opts.sendTest().then(function (r) {
                            var res = (r && r.results) || {};
                            var parts = [];
                            Object.keys(res).forEach(function (k) {
                                var v = String(res[k]);
                                var lbl = v === "sent" ? t("notif.test_res.sent")
                                    : (v.indexOf("skipped") === 0 ? t("notif.test_res.skipped") : t("notif.test_res.failed"));
                                parts.push(k + " : " + lbl);
                            });
                            showStatus(t("notif.test_launched") + " — " + parts.join(" · "));
                        });
                    }
                    showStatus(t("notif.saved"));
                }).catch(function (e) { showStatus((e && e.message) || String(e), true); });
            });
        }).catch(function (e) { showStatus((e && e.message) || String(e), true); });
    }
};
if (typeof window !== "undefined")
    window.ct_notifprefs = ct_notifprefs;

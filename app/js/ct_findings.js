// -----------------------------------------------------------------------------
// REPLICATED from the private shared repository (shared/js/ct_findings.js).
// DO NOT EDIT HERE - changes will be overwritten by the next propagation run.
// Fix the master in the shared repository and re-propagate. See CONTRIBUTING.md.
// -----------------------------------------------------------------------------
/**
 * CISO Toolbox — localized finding labels (FR/EN)
 *
 * Findings are generated server-side (scanners) with a title/description
 * frozen in one language. This module rebuilds a TRANSLATED label at display
 * time, from the structured fields the finding already carries:
 *   - f.type      : template identifier (open_port, host_summary, sast, cve…)
 *   - f.evidence  : structured data (address, port, service, cve_id…)
 *   - f.severity  : severity (for an optional note)
 *
 * Each module declares its templates in its i18n dictionaries:
 *   "finding.<type>.title"   → "Port {port}/{protocol} ({service}) ouvert sur {address}"
 *   "finding.<type>.desc"    → "Le service {service} écoute sur {address}:{port}/{protocol}."
 *   "finding.<type>.sev.<s>" → note appended to desc for severity <s> (optional)
 *
 * Generic and reusable (Surface, AppSec, …). When the template does not exist
 * (technical parse_error/exception type, legacy finding), it falls back to the
 * backend text (f.title / f.description) — never a blank on screen.
 *
 * Load AFTER i18n.js (uses t()).
 */
// Builds the interpolation parameters from a finding: every scalar in
// evidence + the severity + a <field>_count for each array (e.g.
// open_ports → open_ports_count). Generic, with no module-specific knowledge.
function _findingParams(f) {
    var ev = (f && f.evidence) || {};
    // severity + target live outside evidence but are often used in labels.
    // original = the backend text (pivot language, English): a template can
    // re-inject it through {original} to keep rich external prose (NVD, a SAST
    // rule message…) underneath a short translation.
    var p = {
        severity: (f && f.severity) || "",
        target: (f && f.target) || "",
        original: (f && f.description) || "",
    };
    for (var k in ev) {
        if (!Object.prototype.hasOwnProperty.call(ev, k))
            continue;
        var v = ev[k];
        if (Array.isArray(v)) {
            p[k + "_count"] = v.length;
            // {field}_list: scalar items joined (protocols, subdomains…)
            var scalars = v.filter(function (x) { return x != null && typeof x !== "object"; });
            if (scalars.length)
                p[k + "_list"] = scalars.join(", ");
        }
        else if (v != null && typeof v !== "object") {
            p[k] = v;
        }
    }
    return p;
}
// Applies an i18n template IF the key exists AND ALL its {…} placeholders are
// provided. Returns null otherwise — which avoids labels with holes and stops
// a finding missing the right fields (e.g. an smb_status without
// {rule}/{file}) from inheriting a generic scanner template. Placeholders are
// tested on the TEMPLATE (not the values), so data containing "{x}" is
// harmless.
function _findingApply(key, params) {
    var tmpl = t(key);
    if (tmpl === key)
        return null; // t() returns the key when missing
    var ph = tmpl.match(/\{[a-z0-9_]+\}/gi) || [];
    for (var i = 0; i < ph.length; i++) {
        if (!(ph[i].slice(1, -1) in params))
            return null; // placeholder not provided
    }
    return t(key, params);
}
// Rebuilds a localized title ("title") or description ("desc"). Cascade:
//   1. "finding.<type>.<kind>"     — precise template
//   2. "finding.<scanner>.<kind>"  — generic scanner template (dynamic types)
//   3. backend text (f.title / f.description)
function _findingText(f, kind) {
    var backend = kind === "title" ? ((f && f.title) || "") : ((f && f.description) || "");
    var type = f && f.type;
    if (!type)
        return backend;
    var params = _findingParams(f);
    var out = _findingApply("finding." + type + "." + kind, params);
    if (out == null && f && f.scanner)
        out = _findingApply("finding." + f.scanner + "." + kind, params);
    if (out == null)
        return backend;
    if (kind === "desc") {
        // Optional severity note, appended when the module declared one.
        var sn = _findingApply("finding." + type + ".sev." + (params.severity || ""), params);
        if (sn != null)
            out += " " + sn;
    }
    return out;
}
function _findingTitle(f) { return _findingText(f, "title"); }
function _findingDesc(f) { return _findingText(f, "desc"); }

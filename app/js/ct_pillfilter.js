// -----------------------------------------------------------------------------
// Generated file - do not edit.
// It is overwritten at every release; a change made here is lost.
// See CONTRIBUTING.md.
// -----------------------------------------------------------------------------
/**
 * ct_pillfilter — three-state filter pills (include / exclude).
 *
 * A row of filter pills keeps one state per row: the values included and the
 * values excluded. A click on a pill cycles it: neutral → included (✓) →
 * excluded (✕, struck through) → neutral.
 *
 * A value passes the row when it is one of the included values (or nothing is
 * included) and none of the excluded ones. Rows combine with AND; that part
 * is the caller's.
 *
 * Public API (window.ct_pillfilter):
 *   make(inc?, exc?)        → a new state {inc, exc}
 *   state(f, v)             → "inc" | "exc" | ""
 *   cycle(f, v)             — next state for v, in place
 *   clear(f)                — empty the row, in place
 *   isEmpty(f)              → true when nothing is included nor excluded
 *   isExactly(f, inc)       → true when f includes exactly inc and excludes nothing
 *   match(f, value)         → true when value passes the row
 *   pill(f, v, label, opts) → the pill's HTML; opts {click, cls?, title?}.
 *     An included pill carries .active (module colours apply), an excluded
 *     one .is-excluded. The label is escaped here.
 *
 * Depends on esc(), _da() and t() from cisotoolbox.js / i18n.js.
 */
var ct_pillfilter = (function () {
    function make(inc, exc) {
        return { inc: (inc || []).slice(), exc: (exc || []).slice() };
    }
    function state(f, v) {
        if (f.inc.indexOf(v) >= 0)
            return "inc";
        if (f.exc.indexOf(v) >= 0)
            return "exc";
        return "";
    }
    function _drop(list, v) {
        var i = list.indexOf(v);
        if (i >= 0)
            list.splice(i, 1);
    }
    function cycle(f, v) {
        var s = state(f, v);
        if (s === "inc") {
            _drop(f.inc, v);
            f.exc.push(v);
        }
        else if (s === "exc")
            _drop(f.exc, v);
        else
            f.inc.push(v);
    }
    function clear(f) { f.inc.length = 0; f.exc.length = 0; }
    function isEmpty(f) { return !f.inc.length && !f.exc.length; }
    function isExactly(f, inc) {
        if (f.exc.length || f.inc.length !== inc.length)
            return false;
        return inc.every(function (v) { return f.inc.indexOf(v) >= 0; });
    }
    function match(f, value) {
        var v = value || "";
        if (f.inc.length && f.inc.indexOf(v) < 0)
            return false;
        return f.exc.indexOf(v) < 0;
    }
    function pill(f, v, label, opts) {
        var s = state(f, v);
        var cls = "filter-pill" + (opts.cls ? " " + opts.cls : "")
            + (s === "inc" ? " active" : "") + (s === "exc" ? " is-excluded" : "");
        var mark = s === "inc" ? "✓" : (s === "exc" ? "✕" : "");
        var aria = label + (s ? " : " + t(s === "inc" ? "ct.pillfilter.included" : "ct.pillfilter.excluded") : "");
        return '<button type="button" class="' + cls + '" aria-label="' + esc(aria) + '"'
            + (opts.title ? ' title="' + esc(opts.title) + '"' : '')
            + ' data-click="' + opts.click + '" data-args=\'' + _da(v) + '\'>'
            + (mark ? '<span class="filter-pill-mark" aria-hidden="true">' + mark + '</span>' : '')
            + esc(label) + '</button>';
    }
    return { make: make, state: state, cycle: cycle, clear: clear, isEmpty: isEmpty,
        isExactly: isExactly, match: match, pill: pill };
})();

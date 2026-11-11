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
interface CtPillFilter {
    inc: string[];
    exc: string[];
}
interface CtPillOpts {
    /** data-click handler, called with the pill's value. */
    click: string;
    /** Extra classes on the button (colour of the value). */
    cls?: string;
    title?: string;
}
declare var ct_pillfilter: {
    make: (inc?: string[], exc?: string[]) => CtPillFilter;
    state: (f: CtPillFilter, v: string) => "inc" | "exc" | "";
    cycle: (f: CtPillFilter, v: string) => void;
    clear: (f: CtPillFilter) => void;
    isEmpty: (f: CtPillFilter) => boolean;
    isExactly: (f: CtPillFilter, inc: string[]) => boolean;
    match: (f: CtPillFilter, value: string | null | undefined) => boolean;
    pill: (f: CtPillFilter, v: string, label: string, opts: CtPillOpts) => string;
};

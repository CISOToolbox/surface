/**
 * ct_table — Declarative HTML table with sort, row click, and optional
 * bulk-selection checkbox column tied to ct_bulkbar.
 *
 * API:
 *   ct_table.render(opts) → HTML string
 *
 * Opts:
 *   columns    — [{ key, label, sortable?, render?(row,i)→HTML,
 *                   width?, className?, headerClassName? }]
 *                Key is also the sort field unless `sortKey` is set.
 *   rows       — array of row objects
 *   rowKey     — column key used as stable id (default "id"). When the
 *                bulk option is set, this key identifies a row in the
 *                ct_bulkbar scope.
 *   onRowClick — global function name (CSP-safe) invoked with the row
 *                object as single arg (via data-args). Omit for no-op.
 *   emptyHtml  — HTML shown when rows is empty (default "Aucun élément")
 *   bulk       — { scope } — enables the first checkbox column.
 *                ct_bulkbar selection is synced via data-bulk-scope /
 *                data-bulk-key attributes + data-bulk-all on the header.
 *   actions    — [{ icon, label, onClick, danger?, show?(row)→bool }]
 *                appended as a trailing column; each button is a
 *                data-click with the row object passed as its arg.
 *   rowClass   — function(row) → extra CSS class for the <tr>
 *   initialSort — { key, direction } — highlight the header state
 *                 (sorting itself is the caller's responsibility —
 *                 ct_table only fires a click event with scope/key)
 *   sortHandler — global function name invoked as fn(key) when a
 *                 sortable header is clicked
 *
 * Depends on esc(), _da() from cisotoolbox.js.
 */
interface CtTableColumn {
    key: string;
    label?: string;
    sortable?: boolean;
    render?: (row: Record<string, any>, i: number) => string;
    width?: string;
    className?: string;
    headerClassName?: string;
}
interface CtTableAction {
    icon?: string;
    label?: string;
    /** Global function name (CSP-safe), invoked with the row object as arg. */
    onClick: string;
    danger?: boolean;
    show?: (row: Record<string, any>) => boolean;
}
interface CtTableOpts {
    columns?: CtTableColumn[];
    rows?: Record<string, any>[];
    rowKey?: string;
    onRowClick?: string;
    emptyHtml?: string;
    bulk?: {
        scope: string;
    };
    actions?: CtTableAction[];
    rowClass?: (row: Record<string, any>) => string;
    initialSort?: {
        key?: string;
        direction?: "asc" | "desc";
    };
    sortHandler?: string;
}
interface CtTableApi {
    render(opts?: CtTableOpts): string;
}
interface Window {
    ct_table?: CtTableApi;
    _ctTableBulkToggle?: (scope: string, key: string) => void;
    _ctTableBulkToggleAll?: (scope: string) => void;
    _ctNoop?: () => void;
}

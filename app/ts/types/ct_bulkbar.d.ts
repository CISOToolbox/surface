/**
 * ct_bulkbar — Fixed bottom bulk-action bar for CISO Toolbox tables.
 *
 * One reusable .ct-bulkbar DOM node. Selection state kept in a
 * module-level Map<scope, Set<key>> that survives table re-renders.
 * CSP-safe (data-click everywhere).
 *
 * Public API:
 *   ct_bulkbar.attach({scope, label, actions, onClear})
 *     Register the actions to display for a given scope. Safe to call
 *     repeatedly — the latest attach() for a scope wins.
 *   ct_bulkbar.update(scope, count?)
 *     Re-render the bar for scope (defaults to getSelection().size).
 *   ct_bulkbar.getSelection(scope) → Set<key>
 *   ct_bulkbar.count(scope) → number
 *   ct_bulkbar.isSelected(scope, key) → bool
 *   ct_bulkbar.toggle(scope, key)     — flip membership + auto-update
 *   ct_bulkbar.select(scope, key)
 *   ct_bulkbar.deselect(scope, key)
 *   ct_bulkbar.setSelection(scope, keys)  — replace selection
 *   ct_bulkbar.clear(scope)               — empty selection, hide bar
 *
 * Action spec:
 *   { id, icon?, label, onClick, variant?, confirm? }
 *     onClick  — global function name, invoked as fn(scope, actionId).
 *     variant  — primary | success | warning | info | muted | danger.
 *                (danger is also the short-hand: `danger:true`)
 *     confirm  — { title, message } opens ct_modal.confirm before firing.
 *                Both strings support "{n}" = selection count.
 *     label    — supports "{n}" too.
 *
 * Depends on esc(), _da(), _icon() from cisotoolbox.js. Optional
 * ct_modal for confirm dialogs (falls back to window.confirm).
 */
interface CtBulkbarAction {
    id: string;
    icon?: string;
    /** Supports "{n}" = selection count. */
    label?: string;
    /** Global function name, invoked as fn(scope, actionId). */
    onClick: string;
    variant?: string;
    danger?: boolean;
    /** Opens ct_modal.confirm before firing; "{n}" interpolated. */
    confirm?: {
        title?: string;
        message?: string;
    };
}
interface CtBulkbarAttachOpts {
    scope?: string;
    label?: string;
    actions?: CtBulkbarAction[];
    /** Global function name invoked as fn(scope) after the × clear button. */
    onClear?: string | null;
}
interface CtBulkbarApi {
    attach(opts?: CtBulkbarAttachOpts): void;
    update(scope: string, countOverride?: number): void;
    getSelection(scope: string): Set<string>;
    count(scope: string): number;
    isSelected(scope: string, key: string): boolean;
    toggle(scope: string, key: string): void;
    select(scope: string, key: string): void;
    deselect(scope: string, key: string): void;
    setSelection(scope: string, keys: string[]): void;
    clear(scope: string): void;
}
interface Window {
    ct_bulkbar?: CtBulkbarApi;
    _ctBulkbarDispatch?: (scope: string, actionId: string) => void;
    _ctBulkbarClear?: (scope: string) => void;
}

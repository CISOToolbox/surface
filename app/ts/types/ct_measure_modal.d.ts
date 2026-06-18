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
interface CtMeasureExtraField {
    key: string;
    label?: string;
    type?: "text" | "textarea" | "select" | "date" | "checkbox" | "html";
    value?: any;
    /** Option list: objects {value,label} or bare primitives. */
    options?: Array<{
        value?: unknown;
        label?: unknown;
    } | string | number>;
    rows?: number;
}
interface CtMeasureOption {
    value: string;
    label: string;
}
interface CtMeasureOwnerPickerOpts {
    directoryUrl?: string;
    sourceUrl?: string | null;
    pickerId?: string;
}
interface CtMeasureModalOpts {
    title?: string;
    saveLabel?: string;
    size?: "sm" | "md" | "lg";
    hideFields?: string[];
    fieldMap?: Record<string, string>;
    statusOptions?: CtMeasureOption[];
    defaultStatus?: string;
    typeOptions?: CtMeasureOption[];
    titleRequired?: boolean;
    titleReadOnly?: boolean;
    ownerPicker?: boolean | CtMeasureOwnerPickerOpts;
    headerHtml?: string;
    extraContent?: string;
    extraFields?: CtMeasureExtraField[];
    extraButtons?: CtModalButton[];
    onDelete?: () => void;
    /** Internal — field snapshot used by the reopen-after-sub-modal flow. */
    _prefill?: Record<string, any>;
}
interface CtMeasureModalApi {
    open(measure: Record<string, any> | null, opts?: CtMeasureModalOpts): Promise<any>;
}
interface Window {
    ct_measure_modal?: CtMeasureModalApi;
}

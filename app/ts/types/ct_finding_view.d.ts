/**
 * ct_finding_view — Shared detail view for a finding (AppSec + Surface).
 *
 * Renders the vertical card stack the user sees when drilling into a
 * finding: header (back button + title + severity/status badges),
 * optional subheader (scanner + app + timestamps), info card
 * (target, CVE, description, evidence, screenshot, triage metadata,
 * notes), triage card (À corriger / Faux positif / Réinitialiser
 * + optional AI + optional Delete) and, when relevant, a linked
 * measure card.
 *
 * Each module composes its finding detail page by calling
 * ct_finding_view.render(finding, opts) and injecting the returned
 * HTML into its container, then wiring the triage/delete/ai actions
 * to its own API.
 *
 * For the triage dialogs themselves, ct_finding_view.openTriageModal
 * provides a single entry point that reuses ct_measure_modal for
 * "to_fix" (so the owner picker + Pilot user creation work out of
 * the box) and ct_modal for "false_positive" / "new".
 *
 * Public API:
 *   ct_finding_view.render(finding, opts) → HTML string
 *   ct_finding_view.openTriageModal(finding, status, opts)
 *     → Promise<payload|null> where payload is the body ready to send
 *       to the module's triageFinding API.
 *
 * Render opts:
 *   backHandler     — global fn name, receives no args (e.g. "_backToFindings")
 *   subheaderHtml   — optional raw HTML injected between the title row
 *                     and the info card (used for scanner badge + app
 *                     name + date banner in AppSec)
 *   infoRows        — [{label, value?, valueHtml?}] extra rows appended
 *                     after the default set (target, cve, created,
 *                     triaged, description, evidence, notes)
 *   showScreenshot  — default true — if the finding evidence has
 *                     png_b64, render it inline (Surface only in
 *                     practice)
 *   triageHandler   — global fn name, called with a status arg
 *                     ("to_fix" | "false_positive" | "new")
 *   aiHandler       — optional global fn name for the AI triage button
 *                     (only shown when aiEnabled is true)
 *   aiEnabled       — bool (default false)
 *   deleteHandler   — optional global fn name for the Delete button
 *   linkedMeasure   — optional { id, title, statut, responsable,
 *                     echeance } to render as the third card
 *   cardClass       — CSS class used for each card (default "surface-card")
 *
 * openTriageModal opts:
 *   directoryUrl, sourceUrl — picker config (see ct_measure_modal)
 *   ownerPickerId           — unique id for the owner picker
 *   Returns Promise<payload|null> where payload is one of:
 *     { status: "to_fix", measure_title, measure_description,
 *       responsable, echeance, triage_notes? }
 *     { status: "false_positive", triage_notes }
 *     { status: "new", triage_notes? }
 *
 * Depends on ct_modal, ct_measure_modal, ct_userpicker, esc(), _icon(), t().
 */
/** Finding object rendered by ct_finding_view (subset actually read). */
interface CtFvFinding {
    title?: string;
    severity?: string;
    status?: string;
    scanner?: string;
    type?: string;
    target?: string;
    cve_id?: string;
    application_name?: string;
    created_at?: string;
    triaged_at?: string;
    triaged_by?: string;
    description?: string;
    evidence?: CtFvEvidence | null;
    triage_notes?: string;
}
/** Free-form evidence blob; png_b64 triggers the inline screenshot. */
interface CtFvEvidence {
    png_b64?: string;
    [key: string]: unknown;
}
/** Extra row appended to the info card. */
interface CtFvInfoRow {
    label: string;
    value?: string | number | null;
    valueHtml?: string;
    style?: string;
}
/** Linked measure rendered as the third card. */
interface CtFvLinkedMeasure {
    id?: string;
    title?: string;
    statut?: string;
    responsable?: string;
    echeance?: string;
}
/** Options for ct_finding_view.render(). */
interface CtFvRenderOpts {
    backHandler?: string;
    subheaderHtml?: string;
    infoRows?: CtFvInfoRow[];
    showScreenshot?: boolean;
    triageHandler?: string;
    aiHandler?: string;
    aiEnabled?: boolean;
    deleteHandler?: string;
    showFixed?: boolean;
    linkedMeasure?: CtFvLinkedMeasure;
    cardClass?: string;
}
/** Options for ct_finding_view.openTriageModal(). */
interface CtFvTriageModalOpts {
    directoryUrl?: string;
    sourceUrl?: string | null;
    ownerPickerId?: string;
}
/** Payload resolved by openTriageModal, ready for the triage API. */
interface CtFvTriagePayload {
    status: string;
    measure_title?: string;
    measure_description?: string;
    responsable?: string;
    echeance?: string;
    triage_notes?: string;
    notes?: string;
}
interface CtFvMeasureModalData {
    __deleted?: boolean;
    title?: string;
    description?: string;
    responsable?: string;
    echeance?: string;
}
interface CtFvMeasureModalApi {
    open(measure: {
        title?: string;
        description?: string;
    }, opts: {
        title?: string;
        saveLabel?: string;
        hideFields?: string[];
        ownerPicker?: {
            pickerId?: string;
            directoryUrl?: string;
            sourceUrl?: string | null;
        };
    }): Promise<CtFvMeasureModalData | null>;
}
interface CtFvModalButton {
    id: string;
    label: string;
    primary?: boolean;
    result?: () => unknown;
}
interface CtFvModalApi {
    open(opts: {
        title?: string;
        body?: string;
        size?: string;
        onOpen?: () => void;
        buttons?: CtFvModalButton[];
    }): Promise<unknown>;
    confirm(opts: {
        title?: string;
        message?: string;
    }): Promise<boolean>;
}
/** Window deps posed by ct_modal.js / ct_measure_modal.js (cast-only). */
interface CtFvWindowDeps {
    ct_modal: CtFvModalApi;
    ct_measure_modal: CtFvMeasureModalApi;
}
/** Public API posed on window by this file. */
interface CtFindingViewApi {
    render(finding: CtFvFinding | null | undefined, opts?: CtFvRenderOpts): string;
    openTriageModal(finding: CtFvFinding | null | undefined, status: string, opts?: CtFvTriageModalOpts): Promise<CtFvTriagePayload | null>;
}
interface Window {
    ct_finding_view?: CtFindingViewApi;
    _ctFvNoop?: () => void;
}

// -----------------------------------------------------------------------------
// Generated file - do not edit.
// It is overwritten at every release; a change made here is lost.
// See CONTRIBUTING.md.
// -----------------------------------------------------------------------------
interface CtNcSubject {
    type: string;
    id: string;
}
interface CtNcRecord {
    id: string;
    reference: string;
    source: string;
    observed_at?: string | null;
    observed_by?: string;
    declared_by?: string;
    title: string;
    description?: string;
    severity: string;
    evidence?: string[];
    domain?: string;
    requirement_ref?: string;
    subject_type?: string;
    subject_id?: string;
    /** Every item the record is about; the pair above is the first one. */
    subjects?: CtNcSubject[];
    status: string;
    qualified_by?: string;
    qualified_at?: string | null;
    rejection_note?: string;
    closed_at?: string | null;
    closure_evidence?: string;
    measure_ids?: string[];
    derogation_id?: string | null;
    created_at?: string;
    updated_at?: string;
    /** Set when the record is read through the console: the module that owns it. */
    module?: string;
    module_name?: string;
    module_url?: string;
    treatment?: string;
}
interface CtDerRecord {
    id: string;
    reference: string;
    subject_type: string;
    subject_id: string;
    subject_label?: string;
    title?: string;
    justification?: string;
    risk_owner?: string;
    approver?: string;
    compensating_measure_ids?: string[];
    valid_from?: string | null;
    valid_until?: string | null;
    review_at?: string | null;
    status: string;
    requested_by?: string;
    requested_at?: string;
    decided_by?: string;
    decided_at?: string | null;
    decision_note?: string;
    revoked_reason?: string;
    renews_id?: string | null;
    days_left?: number | null;
    created_at?: string;
    module?: string;
    module_name?: string;
    module_url?: string;
}
/** An object of the module a record can be linked to. */
interface CtNcItemOption {
    id: string;
    label: string;
    /** Measures: the module's status label, and whether it counts as finished. */
    statusLabel?: string;
    done?: boolean;
}
/** How the module exposes one kind of object to the association field. */
interface CtNcAssoc {
    /** Every object the field may pick. */
    options: () => CtNcItemOption[];
    /** The module's own creation modal; resolves with the created object, null when cancelled. */
    create?: (draft: {
        title: string;
        description: string;
        domain: string;
    }) => Promise<CtNcItemOption | null>;
    /** The object's own page in the module (opened in a new tab). */
    href?: (id: string) => string | null;
    /** Opens the object in the module when it has no page of its own; resolves when done. */
    open?: (id: string) => Promise<unknown> | void;
}
interface CtNcOptions {
    listNc: (status?: string) => Promise<{
        items: CtNcRecord[];
    }>;
    listDer: (filters?: Record<string, string>) => Promise<{
        items: CtDerRecord[];
    }>;
    /** The writes the host can perform; an absent one hides its action. A
     *  module supplies all of them, the console only what it relays
     *  (declaration, decision). */
    createNc?: (body: Record<string, unknown>) => Promise<CtNcRecord>;
    patchNc?: (id: string, body: Record<string, unknown>) => Promise<CtNcRecord>;
    qualifyNc?: (id: string, body: Record<string, unknown>) => Promise<CtNcRecord>;
    rejectNc?: (id: string, note: string) => Promise<CtNcRecord>;
    closeNc?: (id: string, evidence: string) => Promise<CtNcRecord>;
    createDer?: (body: Record<string, unknown>) => Promise<CtDerRecord>;
    decideDer?: (id: string, approve: boolean, note: string) => Promise<CtDerRecord>;
    revokeDer?: (id: string, reason: string) => Promise<CtDerRecord>;
    /** Console mode: the modules a declaration can target, and the records'
     *  module column. A declaration then carries `module`. */
    modules?: CtNcItemOption[];
    /** Replaces the built-in settings modal (the console edits per module). */
    openSettings?: () => void;
    getSettings?: () => Promise<{
        max_derogation_days: number;
    }>;
    saveSettings?: (days: number) => Promise<unknown>;
    /** Overrides the default reading of the module role (Pilot: the console role). */
    isAdmin?: () => boolean;
    canWrite?: () => boolean;
    /** The current user as the records name their declarant (the server's actor). */
    actor?: () => string;
    /** The kind of item the module links records to (["control"], ["finding"]). */
    subjectTypes: string[];
    /** The module's items of that kind (a record's objects, a derogation's subject). */
    items?: CtNcAssoc;
    /** The module's measures (a record's corrective measures). */
    measures?: CtNcAssoc;
    /** Directory endpoint for the person pickers (default "api/directory"). */
    directoryUrl?: string;
    /** Called after every successful write, so the module can refresh; a
     *  returned promise is awaited before the register re-renders. */
    onChange?: () => void | Promise<unknown>;
}
interface CtNcPrefill {
    /** One item, as the module rows pass it; `subjects` is the general form. */
    subject_type?: string;
    subject_id?: string;
    subject_label?: string;
    subjects?: CtNcSubject[];
    measure_ids?: string[];
    /** Labels of objects the module no longer lists (a fixed finding…). */
    labels?: Record<string, string>;
    title?: string;
    description?: string;
    domain?: string;
    requirement_ref?: string;
    severity?: string;
    source?: string;
    observed_at?: string;
    observed_by?: string;
    evidence?: string[];
    /** Console mode: the module a relayed declaration targets. */
    module?: string;
    /** Non-conformity the derogation covers. */
    nonconformity?: CtNcRecord | null;
    /** A server refusal to show inline when the form reopens with its fields kept. */
    error?: string;
    /** Derogation form fields kept across a "+ declare" detour. */
    justification?: string;
    risk_owner?: string;
    approver?: string;
    valid_from?: string;
    valid_until?: string;
    review_at?: string;
}
interface CtNonconformityApi {
    declare(opts: CtNcOptions, prefill?: CtNcPrefill): Promise<CtNcRecord | null>;
    requestDerogation(opts: CtNcOptions, prefill?: CtNcPrefill): Promise<CtDerRecord | null>;
    renderPanel(container: HTMLElement, opts: CtNcOptions): void;
    /** What the module role allows, the rule the register itself applies. */
    canWrite(): boolean;
    isAdmin(): boolean;
    badge(kind: "nc" | "der", status: string): string;
    tone(kind: "nc" | "der", status: string): string;
}
interface Window {
    ct_nonconformity?: CtNonconformityApi;
    _ctNcFilter?: (kind: string, status: string) => void;
    _ctNcOpen?: (row: Record<string, any>) => void;
    _ctDerOpen?: (row: Record<string, any>) => void;
    _ctNcDeclare?: () => void;
    _ctNcRequestDer?: () => void;
    _ctNcSettings?: () => void;
    _ctNcModuleFilter?: (module: string) => void;
    _ctNcSourceFilter?: (source: string) => void;
    _ctNcSeverityFilter?: (severity: string) => void;
    _ctNcAgeFilter?: (days: string) => void;
    _ctNcCreate?: (field: string, query: string) => void;
    _ctNcOpenItem?: (field: string, id: string) => void;
    _ctDerKind?: (kind: string) => void;
    _ctDerDeclareNc?: () => void;
}

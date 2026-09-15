// -----------------------------------------------------------------------------
// Generated file - do not edit.
// It is overwritten at every release; a change made here is lost.
// See CONTRIBUTING.md.
// -----------------------------------------------------------------------------
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
}
interface CtNcMeasureOption {
    value: string;
    label: string;
    /** Module status value and its display label; `done` when the measure counts as finished. */
    status?: string;
    statusLabel?: string;
    done?: boolean;
}
interface CtNcOptions {
    listNc: (status?: string) => Promise<{
        items: CtNcRecord[];
    }>;
    createNc: (body: Record<string, unknown>) => Promise<CtNcRecord>;
    qualifyNc: (id: string, body: Record<string, unknown>) => Promise<CtNcRecord>;
    rejectNc: (id: string, note: string) => Promise<CtNcRecord>;
    /** Links the corrective measures (at least one) and moves to in_remediation. */
    remediationNc: (id: string, measureIds: string[]) => Promise<CtNcRecord>;
    closeNc: (id: string, evidence: string) => Promise<CtNcRecord>;
    listDer: (filters?: Record<string, string>) => Promise<{
        items: CtDerRecord[];
    }>;
    createDer: (body: Record<string, unknown>) => Promise<CtDerRecord>;
    decideDer: (id: string, approve: boolean, note: string) => Promise<CtDerRecord>;
    revokeDer: (id: string, reason: string) => Promise<CtDerRecord>;
    getSettings?: () => Promise<{
        max_derogation_days: number;
    }>;
    saveSettings?: (days: number) => Promise<unknown>;
    isAdmin: () => boolean;
    /** Subject types the module can attach a record to (e.g. ["finding"]). */
    subjectTypes: string[];
    /** Measures of the module (ids + labels): compensating or corrective. */
    measureOptions?: () => CtNcMeasureOption[];
    /** Opens the module's measure modal and creates the measure; resolves with
     *  its option (or null when cancelled). Enables "+ New measure". */
    createMeasure?: (prefill: {
        title: string;
        description: string;
    }) => Promise<CtNcMeasureOption | null>;
    /** Opens the module's own edit modal for a measure; resolves when it closes. */
    openMeasure?: (id: string) => Promise<unknown> | void;
    /** Module items a derogation can be requested on BEFORE any
     *  non-conformity (a requirement one knows will not be met, a finding):
     *  value = subject id, label = what the user recognises. */
    subjectSearch?: (query: string) => CtNcMeasureOption[];
    /** Directory endpoint for the person pickers (default "api/directory"). */
    directoryUrl?: string;
    /** Opens the subject in the module (called with subject_type, subject_id). */
    openSubject?: (subjectType: string, subjectId: string) => void;
    /** Called after every successful write, so the module can refresh; a
     *  returned promise is awaited before the register re-renders. */
    onChange?: () => void | Promise<unknown>;
}
interface CtNcPrefill {
    subject_type?: string;
    subject_id?: string;
    subject_label?: string;
    title?: string;
    description?: string;
    domain?: string;
    requirement_ref?: string;
    severity?: string;
    /** Non-conformity the derogation covers (its subject is reused). */
    nonconformity?: CtNcRecord | null;
}
interface CtNonconformityApi {
    declare(opts: CtNcOptions, prefill?: CtNcPrefill): Promise<CtNcRecord | null>;
    requestDerogation(opts: CtNcOptions, prefill?: CtNcPrefill): Promise<CtDerRecord | null>;
    renderPanel(container: HTMLElement, opts: CtNcOptions): void;
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
    _ctNcNewMeasure?: () => void;
    _ctNcEditMeasure?: (id: string) => void;
    _ctDerSearch?: (q: string) => void;
    _ctDerKind?: (kind: string) => void;
    _ctDerDeclareNc?: () => void;
}

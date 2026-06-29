/**
 * Surface (demo-docker) — types du module.
 *
 * Modèle de données (findings / monitored assets / scan jobs / mesures),
 * payloads de l'API REST (window.SurfaceAPI) et globals posés par
 * surface_api.js / Surface_app.js / Surface_config.js.
 *
 * Convention nullabilité : les champs optionnels venant du backend sont
 * déclarés `?: T` (sans `| null`) pour rester structurellement assignables
 * aux types partagés CtFvFinding / CtFvLinkedMeasure (un null JSON se
 * comporte comme absent dans tout le code — tests `||` / `!x`).
 */

/* ── Modèle de données ─────────────────────────────────────────── */

type SurfaceSeverity = "critical" | "high" | "medium" | "low" | "info";
type SurfaceFindingStatus = "new" | "to_fix" | "false_positive" | "fixed";
type SurfaceAssetKind = "domain" | "host" | "ip_range" | "file_share";
type SurfaceJobStatus = "pending" | "running" | "completed" | "partial" | "failed";

interface SurfaceFinding {
    id: string;
    scanner?: string;
    type?: string;
    severity: SurfaceSeverity;
    status: SurfaceFindingStatus;
    title?: string;
    description?: string;
    target?: string;
    evidence?: CtFvEvidence;
    cve_id?: string;
    measure_id?: string;
    triage_notes?: string;
    triaged_at?: string;
    triaged_by?: string;
    created_at?: string;
}

interface SurfaceMonitoredAsset {
    id: string;
    kind: SurfaceAssetKind;
    value: string;
    label?: string;
    notes?: string;
    enabled?: boolean;
    scan_frequency_hours?: number;
    enabled_scanners?: string[];
    criticality?: "low" | "medium" | "high" | "critical";
    tags?: string[];
    auto_enroll_discoveries?: boolean;
    stealth_mode?: boolean;
    config?: Record<string, any>;
    resolved_ip?: string;
    last_scan_at?: string;
    created_at?: string;
}

interface SurfaceScanJobDiff { added?: number; reopened?: number; refreshed?: number; scanned?: number; partial?: { scanned?: number; limit?: string; inaccessible_dirs?: number }; }

interface SurfaceScanJob {
    id: string;
    target: string;
    scanner?: string;
    profile?: string;
    status: SurfaceJobStatus;
    error?: string;
    findings_count: number;
    diff?: SurfaceScanJobDiff;
    triggered_by?: string;
    created_at?: string;
    started_at?: string;
    completed_at?: string;
}

interface SurfaceMeasure {
    id: string;
    title?: string;
    description?: string;
    statut?: string;            // a_faire | en_cours | termine (| annule)
    responsable?: string;
    echeance?: string;
    finding_id?: string;
    finding_ids?: string[];
    created_at?: string;
    updated_at?: string;
}

interface SurfaceScannerCatalogEntry {
    scanners: { name: string; label: string }[];
    defaults?: string[];
}
type SurfaceScannersCatalog = Record<string, SurfaceScannerCatalogEntry>;

/** In-app help doc contributed by a loaded add-on scanner (GET /addon-docs).
 *  `doc` is bilingual: doc[lang] = { methodo?: html, usage?: html }. */
interface CtAddonDoc {
    scanner: string;
    kinds?: string[];
    doc: Record<string, { methodo?: string; usage?: string }>;
}

/** Point quotidien de la timeline dashboard (cumuls par sévérité + triage du jour). */
interface SurfaceTimelineBucket {
    key: string;
    label: string;
    critical: number; high: number; medium: number; low: number; info: number;
    triaged: number;
}

/** Compteurs par hôte (index signature : agrégation dynamique des alias). */
interface SurfaceHostCounts {
    total: number; active: number; open: number;
    critical: number; high: number; medium: number; low: number; info: number;
    false_positive: number; fixed: number;
    [key: string]: number;
}

/* ── Payloads API ──────────────────────────────────────────────── */

interface SurfaceTriagePayload {
    status: string;
    measure_title?: string;
    measure_description?: string;
    responsable?: string;
    echeance?: string;
    triage_notes?: string;
    notes?: string;
}

interface SurfaceBulkTriagePayload extends SurfaceTriagePayload { ids: string[]; }

interface SurfaceBulkTriageResult { updated: number; measures_created?: number; }

interface SurfaceScanResult {
    target?: string;
    findings_created?: number;
    findings_count?: number;
    job_id?: string;
}

interface SurfaceScanAllResult { scanned: number; findings_created: number; errors?: unknown[]; }

interface SurfaceImportFinding {
    title: string;
    severity?: string;
    scanner?: string;
    type?: string;
    target?: string;
    description?: string;
    evidence?: Record<string, unknown>;
}

interface SurfaceMonitoredPayload {
    kind?: string;
    value?: string;
    label?: string;
    notes?: string;
    enabled?: boolean;
    scan_frequency_hours?: number;
    enabled_scanners?: string[];
    criticality?: string;
    tags?: string[];
    auto_enroll_discoveries?: boolean;
    stealth_mode?: boolean;
    config?: Record<string, any>;
}

interface SurfaceNucleiConfig {
    installed?: boolean;
    version?: string;
    templates_count?: number;
    last_update?: string;
    tuning?: Record<string, number>;
    tuning_limits?: Record<string, { min: number; max: number }>;
    tuning_defaults?: Record<string, number>;
}

interface SurfaceShodanConfig { configured?: boolean; masked?: string; last_check_at?: string; }

interface SurfaceSmtpConfig {
    host?: string;
    port?: number;
    username?: string;
    password?: string;
    password_set?: boolean;
    sender?: string;
    recipients?: string;
    use_tls?: boolean;
}

interface SurfaceExecutiveReport {
    generated_at: string;
    totals: { active_findings: number; new_last_7d: number; by_severity?: Partial<Record<SurfaceSeverity, number>> };
    scope: { hosts: number; domains: number; assets_total: number };
    top_findings?: { severity: string; title: string; target?: string }[];
    top_hosts?: { value: string; counts?: Partial<Record<SurfaceSeverity, number>> }[];
    scans: { last_7d: number; success_rate: number; failed: number };
    measures: { done: number; total: number; burn_down: number };
    period: { days: number };
}

interface SurfaceAuthUser {
    email: string;
    name?: string;
    role?: string;
}

/* ── Client REST ───────────────────────────────────────────────── */

interface SurfaceAPIShape {
    get(url: string): Promise<any>;
    post(url: string, body?: unknown): Promise<any>;
    listFindings(filters?: Record<string, string>): Promise<SurfaceFinding[]>;
    deleteFinding(id: string): Promise<null>;
    triageFinding(id: string, payload: SurfaceTriagePayload): Promise<SurfaceFinding>;
    bulkTriageFindings(payload: SurfaceBulkTriagePayload): Promise<SurfaceBulkTriageResult>;
    bulkDeleteFindings(ids: string[]): Promise<{ deleted: number }>;
    quickScan(targetHost: string): Promise<SurfaceScanResult>;
    bulkImport(findings: SurfaceImportFinding[]): Promise<{ inserted: number; skipped?: number }>;
    listMonitored(): Promise<SurfaceMonitoredAsset[]>;
    scannersCatalog(): Promise<SurfaceScannersCatalog>;
    createMonitored(data: SurfaceMonitoredPayload): Promise<SurfaceMonitoredAsset>;
    updateMonitored(id: string, data: SurfaceMonitoredPayload): Promise<SurfaceMonitoredAsset>;
    deleteMonitored(id: string): Promise<null>;
    scanMonitored(id: string): Promise<SurfaceScanResult>;
    scanAllMonitored(): Promise<SurfaceScanAllResult>;
    nucleiConfig(): Promise<SurfaceNucleiConfig>;
    nucleiUpdateConfig(data: Record<string, number>): Promise<unknown>;
    nucleiUpdateTemplates(): Promise<{ templates_count: number; stdout?: string }>;
    shodanConfig(): Promise<SurfaceShodanConfig>;
    shodanSaveKey(apiKey: string): Promise<unknown>;
    shodanDeleteKey(): Promise<unknown>;
    listJobs(): Promise<SurfaceScanJob[]>;
    createJob(data: { target: string; profile?: string }): Promise<SurfaceScanJob>;
    deleteJob(id: string): Promise<null>;
    listMeasures(): Promise<SurfaceMeasure[]>;
    updateMeasure(id: string, data: Partial<SurfaceMeasure>): Promise<SurfaceMeasure>;
    deleteMeasure(id: string): Promise<null>;
    executiveReport(): Promise<SurfaceExecutiveReport>;
    smtpConfig(): Promise<SurfaceSmtpConfig>;
    smtpSetConfig(data: SurfaceSmtpConfig): Promise<unknown>;
    sendEmailDigest(): Promise<{ recipients?: string[] }>;
}

/* ── Globals script (assignés via window.X, appelés nus) ───────── */
// En scope script global, une propriété window et la variable globale du
// même nom sont la même entité — déclarées ici pour les appels non
// qualifiés (les decls gen/ partagées ne les exposent que sur Window).

declare var SurfaceAPI: SurfaceAPIShape;
declare var ct_modal: CtModalApi;
declare var ct_measure_modal: CtMeasureModalApi;
declare var ct_table: CtTableApi;
declare var ct_bulkbar: CtBulkbarApi;
declare var ct_finding_view: CtFindingViewApi;

declare var selectPanel: (id: string) => void;
declare var renderAll: () => void;
declare var _closeJobModal: () => void;
declare var _closeMonitoredModal: () => void;
declare var _closeBulkImportModal: () => void;
declare var _editScannersDialog: (idOrIds: string | string[]) => void;

/* ── Propriétés Window posées par le module ────────────────────── */

interface Window {
    SurfaceAPI: SurfaceAPIShape;
    _appInitCallback?: () => void;
    _initDataAndRender?: () => void;
    _currentUser?: SurfaceAuthUser;
    _moduleRole?: string;
    _logout?: () => void;

    // Surface_config.js
    _ASSET_BASE?: string;

    // Surface_app.js — navigation / rendu
    selectPanel: (id: string) => void;
    renderPanel: () => void;
    renderAll: () => void;
    _TZ_OPTIONS_GLOBAL?: string[];
    _onTimezoneChange?: (value: string) => void;
    importHosts?: () => void;
    exportReport?: () => void;

    // Audit log
    _setAuditSearch?: (v: string) => void;

    // Scan jobs
    _setJobsScannerFilter?: (v: string) => void;
    _setJobsStatusFilter?: (v: string) => void;
    _deleteJob?: (id: string) => void;
    _rerunJob?: (id: string, el?: HTMLElement) => void;
    _newJobDialog?: () => void;
    _closeJobModal: () => void;
    _pickMonitoredTarget?: (val: string) => void;
    _launchJob?: () => void;

    // Monitored assets
    _toggleMonBulkAll?: () => void;
    _toggleMonBulkOne?: (id: string) => void;
    _clearMonitoredBulk?: () => void;
    _bulkDeleteMonitored?: () => void;
    _bulkConfigureScanners?: () => void;
    _setMonitoredSearch?: (v: string) => void;
    _clearMonitoredSearch?: () => void;
    _newMonitoredDialog?: () => void;
    _editScannersDialog: (idOrIds: string | string[]) => void;
    _closeScannersDialog?: () => void;
    _saveScannersDialog?: () => void;
    _editMonitoredDialog?: (id: string) => void;
    _closeMonitoredModal: () => void;
    _saveMonitored?: () => void;
    _toggleMonitored?: (id: string, el: HTMLInputElement) => void;
    _deleteMonitored?: (id: string) => void;
    _scanMonitored?: (id: string) => void;
    _scanAllMonitored?: () => void;
    _toggleMonitoredScanner?: (s: string) => void;
    _clearMonitoredScannerFilter?: () => void;

    // Dashboard
    _dashGotoSeverity?: (sev: string) => void;
    _dashGotoRecent?: () => void;
    _dashGotoScanner?: (scanner: string) => void;
    _dashGotoHost?: (hostValue: string) => void;
    _dashShowStale?: () => void;

    // Findings
    _openFindingRow?: (row: Record<string, any>) => void;
    _quickTriageRow?: (row: Record<string, any>) => void;
    _quickTriageFpRow?: (row: Record<string, any>) => void;
    _bulkSurfaceToFix?: (scope: string) => void;
    _bulkSurfaceFixed?: (scope: string) => void;
    _bulkSurfaceFP?: (scope: string) => void;
    _bulkSurfaceDelete?: (scope: string) => void;
    _setStatusFilter?: (v: string) => void;
    _setFindingsSearch?: (v: string) => void;
    _clearFindingsSearch?: () => void;
    _toggleSeverity?: (s: string) => void;
    _clearSeverityFilter?: () => void;
    _toggleScanner?: (s: string) => void;
    _clearScannerFilter?: () => void;
    _openFinding: (id: string) => void;
    _backToFindings?: () => void;
    _openExecutiveReport?: () => Promise<void>;
    _aiTriageFinding?: () => Promise<void>;
    _triageDetail?: (status: string) => void;
    _quickTriage: (id: string, status: string) => void;
    _deleteFindingDetail?: () => void;
    _quickScanDialog?: () => void;
    _closeBulkImportModal: () => void;
    _bulkImportDialog?: () => void;

    // Measures
    _editSurfaceMeasureRow?: (row: Record<string, any>) => void;
    _bulkSurfaceMeasuresDone?: (scope: string) => void;
    _bulkSurfaceMeasuresDelete?: (scope: string) => void;

    // Hosts
    _setHostSearch?: (v: string) => void;
    _clearHostSearch?: () => void;
    _openHost?: (id: string) => void;
    _backToHosts?: () => void;
    _openFindingRowFromHost?: (row: Record<string, any>) => void;
    _openFindingFromHost: (id: string) => void;
    _backToHostFromFinding?: () => void;
    _triageHostFindingDetail?: (newStatus: string) => void;
    _triageHostFinding?: (newStatus: string) => void;
    _toggleHostHideFP?: () => void;
    _toggleHostBulkAll?: () => void;
    _scanHost?: (id: string) => void;
    _scanSharesOnHost?: (hostKey: string) => void;
    _deleteHostFromDetail?: (id: string) => void;

    // Settings (nuclei / smtp)
    _nucleiResetTuning?: () => void;
    _nucleiSaveTuning?: () => void;
    _nucleiUpdateTemplates?: () => void;
    _saveSmtpConfig?: () => void;
    _sendSmtpDigestNow?: () => void;
}

// -----------------------------------------------------------------------------
// REPLICATED from the private shared repository (shared/types/gen/ct_audit.d.ts).
// DO NOT EDIT HERE - changes will be overwritten by the next propagation run.
// Fix the master in the shared repository and re-propagate. See CONTRIBUTING.md.
// -----------------------------------------------------------------------------
/**
 * CISO Toolbox — Audit Log Panel (shared)
 *
 * Provides _renderAuditLog(container) for all backend modules.
 * Each module calls this from its panel switch/render logic.
 * Requires: cisotoolbox.js (esc, _icon, t), i18n.js (_registerTranslations).
 */
interface CtAuditEntry {
    logged_at: string;
    user_email?: string;
    action: string;
    target?: string;
    details?: string;
    ip_address?: string;
}
interface Window {
    _setAuditSearch?: (v: string) => void;
}
declare var _auditFilter: {
    q: string;
};
declare function _renderAuditLog(c: HTMLElement): void;
declare function _refreshAuditBody(): Promise<void>;

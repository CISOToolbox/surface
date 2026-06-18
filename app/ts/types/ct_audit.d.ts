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

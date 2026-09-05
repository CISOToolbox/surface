// -----------------------------------------------------------------------------
// REPLICATED from the private shared repository (shared/types/gen/ct_findings.d.ts).
// DO NOT EDIT HERE - changes will be overwritten by the next propagation run.
// Fix the master in the shared repository and re-propagate. See CONTRIBUTING.md.
// -----------------------------------------------------------------------------
/**
 * CISO Toolbox — localized finding labels (FR/EN)
 *
 * Findings are generated server-side (scanners) with a title/description
 * frozen in one language. This module rebuilds a TRANSLATED label at display
 * time, from the structured fields the finding already carries:
 *   - f.type      : template identifier (open_port, host_summary, sast, cve…)
 *   - f.evidence  : structured data (address, port, service, cve_id…)
 *   - f.severity  : severity (for an optional note)
 *
 * Each module declares its templates in its i18n dictionaries:
 *   "finding.<type>.title"   → "Port {port}/{protocol} ({service}) ouvert sur {address}"
 *   "finding.<type>.desc"    → "Le service {service} écoute sur {address}:{port}/{protocol}."
 *   "finding.<type>.sev.<s>" → note appended to desc for severity <s> (optional)
 *
 * Generic and reusable (Surface, AppSec, …). When the template does not exist
 * (technical parse_error/exception type, legacy finding), it falls back to the
 * backend text (f.title / f.description) — never a blank on screen.
 *
 * Load AFTER i18n.js (uses t()).
 */
declare function _findingParams(f: any): Record<string, string | number>;
declare function _findingApply(key: string, params: Record<string, string | number>): string | null;
declare function _findingText(f: any, kind: "title" | "desc"): string;
declare function _findingTitle(f: any): string;
declare function _findingDesc(f: any): string;

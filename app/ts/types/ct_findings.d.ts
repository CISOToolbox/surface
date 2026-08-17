// -----------------------------------------------------------------------------
// REPLICATED from the private shared repository (shared/types/gen/ct_findings.d.ts).
// DO NOT EDIT HERE - changes will be overwritten by the next propagation run.
// Fix the master in the shared repository and re-propagate. See CONTRIBUTING.md.
// -----------------------------------------------------------------------------
/**
 * CISO Toolbox — Libellés de findings localisés (FR/EN)
 *
 * Les findings sont générés côté serveur (scanners) avec un title/description
 * figés dans une langue. Ce module reconstruit un libellé TRADUIT au moment de
 * l'affichage, à partir des champs structurés que le finding porte déjà :
 *   - f.type      : identifiant du gabarit (open_port, host_summary, sast, cve…)
 *   - f.evidence  : données structurées (address, port, service, cve_id…)
 *   - f.severity  : sévérité (pour une note optionnelle)
 *
 * Chaque module déclare ses gabarits dans ses dictionnaires i18n :
 *   "finding.<type>.title"   → "Port {port}/{protocol} ({service}) ouvert sur {address}"
 *   "finding.<type>.desc"    → "Le service {service} écoute sur {address}:{port}/{protocol}."
 *   "finding.<type>.sev.<s>" → note ajoutée au desc pour la sévérité <s> (optionnel)
 *
 * Générique et réutilisable (Surface, AppSec, …). Si le gabarit n'existe pas
 * (type technique parse_error/exception, finding historique), on retombe sur le
 * texte backend (f.title / f.description) — jamais de trou à l'écran.
 *
 * Charger APRÈS i18n.js (utilise t()).
 */
declare function _findingParams(f: any): Record<string, string | number>;
declare function _findingApply(key: string, params: Record<string, string | number>): string | null;
declare function _findingText(f: any, kind: "title" | "desc"): string;
declare function _findingTitle(f: any): string;
declare function _findingDesc(f: any): string;

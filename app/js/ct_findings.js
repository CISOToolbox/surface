// -----------------------------------------------------------------------------
// REPLICATED from the private shared repository (shared/js/ct_findings.js).
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
// Prépare les paramètres d'interpolation depuis un finding : tous les scalaires
// d'evidence + la sévérité + un <champ>_count pour chaque tableau (ex.
// open_ports → open_ports_count). Générique, sans connaissance d'un module.
function _findingParams(f) {
    var ev = (f && f.evidence) || {};
    // severity + target sont hors evidence mais souvent utilisés dans les libellés.
    // original = le texte backend (langue pivot, anglais) : un gabarit peut le
    // réinjecter via {original} pour conserver une prose externe riche (NVD,
    // message d'une règle SAST…) sous une traduction courte.
    var p = {
        severity: (f && f.severity) || "",
        target: (f && f.target) || "",
        original: (f && f.description) || "",
    };
    for (var k in ev) {
        if (!Object.prototype.hasOwnProperty.call(ev, k))
            continue;
        var v = ev[k];
        if (Array.isArray(v)) {
            p[k + "_count"] = v.length;
            // {champ}_list : éléments scalaires joints (protocoles, sous-domaines…)
            var scalars = v.filter(function (x) { return x != null && typeof x !== "object"; });
            if (scalars.length)
                p[k + "_list"] = scalars.join(", ");
        }
        else if (v != null && typeof v !== "object") {
            p[k] = v;
        }
    }
    return p;
}
// Applique un gabarit i18n SI la clé existe ET si TOUS ses placeholders {…} sont
// fournis. Renvoie null sinon — ce qui évite les titres à trous et permet à un
// finding sans les bons champs (ex. un smb_status sans {rule}/{file}) de NE PAS
// hériter d'un gabarit générique de scanner. On teste les placeholders du
// gabarit (pas des valeurs), donc une donnée contenant « {x} » ne fausse rien.
function _findingApply(key, params) {
    var tmpl = t(key);
    if (tmpl === key)
        return null; // t() renvoie la clé si absente
    var ph = tmpl.match(/\{[a-z0-9_]+\}/gi) || [];
    for (var i = 0; i < ph.length; i++) {
        if (!(ph[i].slice(1, -1) in params))
            return null; // placeholder non fourni
    }
    return t(key, params);
}
// Reconstruit titre ("title") ou description ("desc") localisé. Cascade :
//   1. "finding.<type>.<kind>"     — gabarit précis
//   2. "finding.<scanner>.<kind>"  — gabarit générique du scanner (types dynamiques)
//   3. texte backend (f.title / f.description)
function _findingText(f, kind) {
    var backend = kind === "title" ? ((f && f.title) || "") : ((f && f.description) || "");
    var type = f && f.type;
    if (!type)
        return backend;
    var params = _findingParams(f);
    var out = _findingApply("finding." + type + "." + kind, params);
    if (out == null && f && f.scanner)
        out = _findingApply("finding." + f.scanner + "." + kind, params);
    if (out == null)
        return backend;
    if (kind === "desc") {
        // Note de sévérité optionnelle, ajoutée si le module l'a déclarée.
        var sn = _findingApply("finding." + type + ".sev." + (params.severity || ""), params);
        if (sn != null)
            out += " " + sn;
    }
    return out;
}
function _findingTitle(f) { return _findingText(f, "title"); }
function _findingDesc(f) { return _findingText(f, "desc"); }

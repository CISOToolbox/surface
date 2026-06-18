// ─────────────────────────────────────────────────────────────
// GENERATED from shared/ts/ — do NOT edit here.
// Edit the shared TypeScript source and run shared/ts-build.sh.
// ─────────────────────────────────────────────────────────────
/**
 * CISO Toolbox — Backend persistence layer
 *
 * No-op stubs for localStorage autosave (data is in PostgreSQL).
 * File I/O (open/save/import/export) still works for JSON import/export.
 * Snapshots disabled (use database backups instead).
 * Load AFTER cisotoolbox.js. Used by backend apps only.
 *
 * MASTER FACTORISÉ (migration TS) — remplace les 5 variantes historiques
 * (risk=vendor=asset=access ; appsec=watch=shared/js ; pilot ; surface ;
 * compliance) par un seul fichier paramétré par deux flags runtime, lus
 * au moment de l'action (jamais au chargement) :
 *
 *   window._CT_IMPORT_NO_UNWRAP = true
 *       → désactive la détection/dépliage du format de backup Pilot
 *         {"module":...,"data":[{"id":...,"data":{...}}]} à l'import.
 *         À poser par le front du module PILOT (il ne doit pas déplier
 *         ses propres backups). Défaut : unwrap actif (8/9 modules).
 *
 *   window._BACKEND_BACKUPS_VIA_PILOT = true
 *       → les 6 stubs snapshots affichent la notice "snapshots gérés
 *         dans Pilot" (t("snap.backend.notice")) au lieu du message
 *         "Snapshots not available in backend mode" (et les stubs
 *         non-create deviennent parlants au lieu de muets).
 *         À poser par le front du module COMPLIANCE (suite mode).
 *
 * La délégation newAnalysis → window.catalogCreate reste gardée par un
 * typeof à l'exécution : les modules sans catalogue (pilot, appsec,
 * watch) ne définissent pas catalogCreate, comportement inchangé.
 */
// Flag historique posé par les variantes appsec/watch ; aucun lecteur
// connu dans le code (gardé pour les forks clients éventuels).
window._CT_HAS_BACKEND = true;
// ═══════════════════════════════════════════════════════════════════════
// AUTO-SAVE — No-ops (data persisted in PostgreSQL)
// ═══════════════════════════════════════════════════════════════════════
function _autoSave() { }
function _loadAutoSave() { return false; }
function _checkAutoSaveBanner() { }
function _restoreSession() { }
function _discardSession() { }
// ═══════════════════════════════════════════════════════════════════════
// FICHIERS JSON (save / load / new) — for import/export
// ═══════════════════════════════════════════════════════════════════════
var _fileHandle = null;
function newAnalysis() {
    // In backend mode with catalog, delegate to catalogCreate which creates a new DB entry
    if (typeof window.catalogCreate === "function") {
        window.catalogCreate();
        return;
    }
    var lbl = t(_ct().labelKey || "analysis");
    if (!confirm(t("confirm_new", { label: lbl })))
        return;
    _fileHandle = null;
    var initVar = _ct().initDataVar || "CT_INIT_DATA";
    var fresh = JSON.parse(JSON.stringify(window[initVar] || {}));
    Object.keys(D).forEach(function (k) { delete D[k]; });
    Object.assign(D, fresh);
    _initDataAndRender(function () {
        _autoSave();
        showStatus(t("status_new", { label: lbl }));
    });
}
// Mot de passe du fichier courant (en mémoire uniquement)
var _filePwd = null;
// Charger un buffer (chiffré ou non) et retourner l'objet JSON
async function _loadBuffer(buffer, filename) {
    var bytes = new Uint8Array(buffer);
    var jsonStr;
    if (_isEncrypted(bytes)) {
        var pwd = await _promptPassword(t("pwd_title_encrypted_file"), false);
        if (!pwd)
            return null;
        try {
            jsonStr = await _decryptData(bytes, pwd);
            _filePwd = pwd;
        }
        catch (e) {
            alert(t("alert_wrong_password"));
            return null;
        }
    }
    else {
        jsonStr = new TextDecoder().decode(bytes);
        _filePwd = null;
    }
    if (jsonStr.length > 10000000)
        throw new Error("File too large (>10MB)");
    var parsed = JSON.parse(jsonStr);
    delete parsed.__proto__;
    delete parsed.constructor;
    delete parsed.prototype;
    // Detect Pilot backup format: {"module":"...","data":[{"id":"...","data":{...}}]}
    // (désactivable via window._CT_IMPORT_NO_UNWRAP — cf. en-tête)
    if (!window._CT_IMPORT_NO_UNWRAP && parsed.module && Array.isArray(parsed.data) && parsed.data.length > 0 && parsed.data[0].data) {
        parsed = parsed.data[0].data;
    }
    Object.keys(D).forEach(function (k) { delete D[k]; });
    Object.assign(D, parsed);
    return true;
}
function loadJSON(event) {
    var input = event.target;
    var file = input.files[0];
    if (!file)
        return;
    var reader = new FileReader();
    reader.onload = async function (e) {
        try {
            var ok = await _loadBuffer(e.target.result, file.name);
            if (!ok)
                return;
            _fileHandle = null;
            _initDataAndRender(function () {
                _autoSave();
                showStatus(t("status_file_opened", { name: file.name }));
            });
        }
        catch (err) {
            alert(t("alert_load_error", { msg: err.message }));
        }
    };
    reader.readAsArrayBuffer(file);
    input.value = "";
}
async function openFile() {
    if (window.showOpenFilePicker) {
        try {
            var handles = await window.showOpenFilePicker({
                types: [{ description: "JSON", accept: { "application/json": [".json", ".enc"] } }],
                multiple: false
            });
            var handle = handles[0];
            var file = await handle.getFile();
            var ok = await _loadBuffer(await file.arrayBuffer(), file.name);
            if (!ok)
                return;
            _fileHandle = handle;
            _initDataAndRender(function () {
                _autoSave();
                showStatus(t("status_file_opened", { name: file.name }));
            });
        }
        catch (e) {
            if (e.name !== "AbortError")
                alert(t("alert_open_error", { msg: e.message }));
        }
    }
    else {
        document.getElementById("file-input").click();
    }
}
// Sérialiser D en contenu fichier (chiffré ou non)
async function _serializeForSave() {
    var jsonStr = JSON.stringify(D, null, 2);
    if (_filePwd) {
        var encrypted = await _encryptData(jsonStr, _filePwd);
        return new Blob([encrypted], { type: "application/octet-stream" });
    }
    return new Blob([jsonStr], { type: "application/json" });
}
async function quickSaveJSON() {
    if (_fileHandle) {
        try {
            var blob = await _serializeForSave();
            var writable = await _fileHandle.createWritable();
            await writable.write(blob);
            await writable.close();
            showStatus(t("status_saved") + (_filePwd ? t("status_saved_encrypted") : ""));
            return;
        }
        catch (e) { }
    }
    await saveJSON();
}
async function saveJSON() {
    // Ask whether to encrypt
    var wantEncrypt = await _confirmDialog(t("save_encrypt_prompt"));
    if (wantEncrypt) {
        var pwd = await _promptPassword(t("pwd_title_choose_file"), true);
        if (!pwd)
            return; // user cancelled
        _filePwd = pwd;
    }
    else {
        _filePwd = null;
    }
    var prefix = _ct().filePrefix || "Export";
    var societe = (_ct().getSociete ? _ct().getSociete.call(null, D) : D.meta && D.meta.societe) || prefix;
    var scope = _ct().getScope ? _ct().getScope.call(null, D) : "";
    if (scope)
        societe = societe + "-" + scope;
    societe = societe.replace(/[\/\\:*?"<>|]/g, "_").trim();
    var ext = _filePwd ? ".enc" : ".json";
    var blob = await _serializeForSave();
    if (window.showSaveFilePicker) {
        try {
            var handle = await window.showSaveFilePicker({
                suggestedName: societe + ext,
                types: [{ description: "JSON", accept: { "application/json": [".json", ".enc"] } }]
            });
            var writable = await handle.createWritable();
            await writable.write(blob);
            await writable.close();
            _fileHandle = handle;
            showStatus(t("status_saved_name", { name: handle.name }) + (_filePwd ? t("status_saved_encrypted") : ""));
        }
        catch (e) {
            if (e.name !== "AbortError")
                alert(t("alert_save_error", { msg: e.message }));
        }
    }
    else {
        var a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = societe + ext;
        a.click();
        URL.revokeObjectURL(a.href);
        showStatus(t("status_downloaded") + (_filePwd ? t("status_saved_encrypted") : ""));
    }
}
// Activer/désactiver le chiffrement du fichier
async function enableFileEncryption() {
    var pwd = await _promptPassword(t("pwd_title_choose_file"), true);
    if (!pwd)
        return;
    _filePwd = pwd;
    showStatus(t("status_encryption_on"));
}
function disableFileEncryption() {
    _filePwd = null;
    showStatus(t("status_encryption_off"));
}
// Ctrl+S
document.addEventListener("keydown", function (e) {
    if ((e.ctrlKey || e.metaKey) && e.key === "s") {
        e.preventDefault();
        if (typeof quickSaveJSON === "function")
            quickSaveJSON();
    }
});
// ═══════════════════════════════════════════════════════════════════════
// SNAPSHOTS — No-ops (use database backups instead)
//
// In suite mode, point-in-time backups are centralized in Pilot:
//   * Pilot /api/backups/* drives module export/restore via service token
//   * Snapshots stored in the browser would not survive a redeploy of
//     the module container, so we explicitly disable that path.
//
// Modules in that situation set `window._BACKEND_BACKUPS_VIA_PILOT`
// (compliance) so their `renderHistory()` can render a clear redirect
// notice instead of an empty panel with non-functional buttons.
// ═══════════════════════════════════════════════════════════════════════
function _snapBackendNotice() {
    if (window._BACKEND_BACKUPS_VIA_PILOT) {
        showStatus(typeof t === "function" ? t("snap.backend.notice") : "Snapshots are managed in Pilot in suite mode.");
    }
    else {
        showStatus("Snapshots not available in backend mode");
    }
}
function createSnapshot() { _snapBackendNotice(); }
function restoreSnapshot() { if (window._BACKEND_BACKUPS_VIA_PILOT)
    _snapBackendNotice(); }
function deleteSnapshot() { if (window._BACKEND_BACKUPS_VIA_PILOT)
    _snapBackendNotice(); }
function exportSnapshot() { if (window._BACKEND_BACKUPS_VIA_PILOT)
    _snapBackendNotice(); }
function enableSnapEncryption() { if (window._BACKEND_BACKUPS_VIA_PILOT)
    _snapBackendNotice(); }
function disableSnapEncryption() { if (window._BACKEND_BACKUPS_VIA_PILOT)
    _snapBackendNotice(); }
function _isSnapEncrypted() { return false; }
function _getSnapshots() { return Promise.resolve([]); }
// Libellés par défaut de la notice snapshots-via-Pilot — le module peut
// les surcharger (ses dictionnaires chargent après ce fichier).
if (typeof _registerTranslations === "function") {
    _registerTranslations("fr", { "snap.backend.notice": "Les snapshots sont gérés dans Pilot (sauvegardes centralisées de la suite)." });
    _registerTranslations("en", { "snap.backend.notice": "Snapshots are managed in Pilot (suite-level centralized backups)." });
}

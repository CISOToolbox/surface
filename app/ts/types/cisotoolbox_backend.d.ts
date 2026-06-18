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
declare function _loadAutoSave(): boolean;
declare function _checkAutoSaveBanner(): void;
declare function _restoreSession(): void;
declare function _discardSession(): void;
declare var _fileHandle: FileSystemFileHandle | null;
declare function newAnalysis(): void;
declare var _filePwd: string | null;
declare function _loadBuffer(buffer: ArrayBuffer, filename: string): Promise<true | null>;
declare function loadJSON(event: Event): void;
declare function openFile(): Promise<void>;
declare function _serializeForSave(): Promise<Blob>;
declare function quickSaveJSON(): Promise<void>;
declare function saveJSON(): Promise<void>;
declare function enableFileEncryption(): Promise<void>;
declare function disableFileEncryption(): void;
declare function _snapBackendNotice(): void;
declare function createSnapshot(): void;
declare function restoreSnapshot(): void;
declare function deleteSnapshot(): void;
declare function exportSnapshot(): void;
declare function enableSnapEncryption(): void;
declare function disableSnapEncryption(): void;
declare function _isSnapEncrypted(): boolean;
declare function _getSnapshots(): Promise<unknown[]>;

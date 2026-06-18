// Must be loaded BEFORE i18n.js so that the i18n loader's startup path
// (which lazy-loads EN at script eval time when the saved locale is EN)
// builds the correct asset URL "js/Surface_i18n_en.js".
window._ASSET_BASE = "js/Surface";

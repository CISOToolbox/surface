// -----------------------------------------------------------------------------
// Generated file - do not edit.
// It is overwritten at every release; a change made here is lost.
// See CONTRIBUTING.md.
// -----------------------------------------------------------------------------
interface CtNotifPrefsOptions {
    fetchPrefs: () => Promise<Record<string, any>>;
    savePrefs: (p: Record<string, any>) => Promise<any>;
    sendTest?: () => Promise<any>;
    isAdmin?: boolean;
    modules?: string[] | null;
}
declare var _NP_DAYS: string[];
declare var _NP_SEVS: string[];
declare function _npDaySelect(id: string, current: number): string;
declare function _npSevSelect(id: string, current: string): string;
declare function _npVal(id: string): string;
declare function _npChecked(id: string): boolean;
declare function _npHas(id: string): boolean;
declare var ct_notifprefs: {
    open: (opts: CtNotifPrefsOptions) => void;
};

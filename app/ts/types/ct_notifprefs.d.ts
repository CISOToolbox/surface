// -----------------------------------------------------------------------------
// REPLICATED from the private shared repository (shared/types/gen/ct_notifprefs.d.ts).
// DO NOT EDIT HERE - changes will be overwritten by the next propagation run.
// Fix the master in the shared repository and re-propagate. See CONTRIBUTING.md.
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

// Handlers this page renders in data-click / data-change / data-input: the
// event dispatcher calls no other name (see _ctDeclareHandlers in
// cisotoolbox.js). tests/test_dispatch_allowlist.py fails on a missing one.
_ctDeclareHandlers([
    "_addConnector", "_addExclusionManual", "_aiTriageFinding", "_backToFindings",
    "_backToHostFromFinding", "_backToHosts", "_bulkConfigureScanners", "_bulkDeleteMonitored",
    "_bulkImportDialog", "_bulkScanMonitored", "_bulkSurfaceDelete", "_bulkSurfaceFP",
    "_bulkSurfaceFixed", "_bulkSurfaceMeasuresDelete", "_bulkSurfaceMeasuresDone", "_bulkSurfaceToFix",
    "_clearFindingsSearch", "_clearHostSearch", "_clearMonitoredBulk", "_clearMonitoredScannerFilter",
    "_clearMonitoredSearch", "_clearScannerFilter", "_clearSeverityFilter", "_closeBulkImportModal",
    "_closeMonitoredModal", "_closeScannersDialog", "_configureConnector", "_dashGotoHost",
    "_dashGotoRecent", "_dashGotoScanner", "_dashGotoSeverity", "_deleteConnectorInstance",
    "_deleteFindingDetail", "_deleteHostFromDetail", "_deleteJob", "_deleteMonitored",
    "_editMonitoredDialog", "_editSurfaceMeasureRow", "_hostsSetView", "_logout", "_newMonitoredDialog",
    "_nucleiResetTuning", "_nucleiUpdateTemplates", "_onTimezoneChange", "_openFindingFromHost",
    "_openFindingRow", "_openFindingRowFromHost", "_openHost", "_openMonitoredDetail",
    "_openNotifPrefs", "_quickTriageFpRow", "_quickTriageRow", "_removeExclusion",
    "_requestDerogationDetail", "_rerunJob", "_runConnector", "_saveMonitored", "_saveScannersDialog",
    "_scanAllMonitored", "_scanHost", "_scanMonitored", "_scanSharesOnHost", "_sendSmtpDigestNow",
    "_setAuditSearch", "_setFindingsSearch", "_setHostSearch", "_setJobsScannerFilter",
    "_setJobsStatusFilter", "_setMonitoredSearch", "_setStatusFilter", "_showAllFindings", "_toggleConnector",
    "_toggleHostFromDetail", "_toggleHostHideFP", "_toggleHostsInactive", "_toggleMonBulkAll", "_toggleMonBulkOne",
    "_toggleMonitored", "_toggleMonitoredScanner", "_toggleScanner", "_toggleSeverity", "_triageDetail",
    "_triageHostFindingDetail", "exportReport", "importHosts", "openSettings", "selectPanel"
]);

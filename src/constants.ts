export const SOOS_DAST_CONSTANTS = {
  AuthDelayTime: 5,
  Tool: "zap",
  ToolVersion: "2.12",
  Files: {
    ReportScanResultFile: "/zap/wrk/report.zap.json",
    ReportScanResultFilename: "report.zap.json",
    SarifResultsFilename: "results.sarif",
    SpideredUrlsFile: "./spidered_urls.txt",
    ZapHookFile: "src/zap_hooks/soos_zap_hook.py",
  },
  StatusCheck: {
    DelayTime: 5000,
    MaxAttempts: 10,
  },
};

export const SOOS_DAST_CONSTANTS = {
  AuthDelayTime: 5,
  Tool: "zap",
  ToolVersion: "2.15", // NOTE: this should match the zap-stable version in the Docker file
  Files: {
    DiscoveredUrlsFile: "./core_urls.txt",
    ReportScanResultFile: "/zap/wrk/report.zap.json",
    ReportScanResultFilename: "report.zap.json",
    ZapHookFile: "src/zap_hooks/soos_zap_hook.py",
  },
};

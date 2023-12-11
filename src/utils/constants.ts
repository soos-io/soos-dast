export const CONSTANTS = {
  AUTH: {
    DELAY_TIME: 5,
  },
  DAST: {
    TOOL: "zap",
    TOOL_VERSION: "2.12",
  },
  FILES: {
    REPORT_SCAN_RESULT_FILE: "/zap/wrk/report.zap.json",
    REPORT_SCAN_RESULT_FILENAME: "report.zap.json",
    SARIF: "results.sarif",
    SPIDERED_URLS_FILE_PATH: "./spidered_urls.txt",
    ZAP_CUSTOM_HOOK_SCRIPT: "src/zap_hooks/soos_zap_hook.py",
  },
  SOOS: {
    API_KEY_ENV_VAR: "SOOS_API_KEY",
    CLIENT_ID_ENV_VAR: "SOOS_CLIENT_ID",
    DEFAULT_INTEGRATION_TYPE: "Script",
  },
  STATUS: {
    DELAY_TIME: 5000,
    MAX_ATTEMPTS: 10,
  },
  ZAP: {
    AJAX_SPIDER_OPTION: "-j",
    COMMAND: "python3",
    CONTEXT_FILE_OPTION: "-n",
    DEBUG_OPTION: "-d",
    FORMAT_OPTION: "-f",
    HOOK_OPTION: "--hook",
    JSON_REPORT_OPTION: "-J",
    SCRIPTS: {
      API_SCAN: "/zap/zap-api-scan.py",
      BASE_LINE: "/zap/zap-baseline.py",
      FULL_SCAN: "/zap/zap-full-scan.py",
    },
    SPIDER_MINUTES_OPTION: "-m",
    TARGET_URL_OPTION: "-t",
    UPDATE_ADDONS_OPTION: "--updateAddons",
  },
};

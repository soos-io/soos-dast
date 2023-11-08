export const CONSTANTS = {
  AUTH: {
    DELAY_TIME: 5,
  },
  DAST: {
    TOOL: "zap",
    TOOL_VERSION: "2.12",
  },
  FILES: {
    REPORT_SCAN_RESULT_FILE: "/zap/wrk/report.json",
    REPORT_SCAN_RESULT_FILENAME: "report.json",
    SARIF: "results.sarif",
    SPIDERED_URLS_FILE_PATH: "./spidered_urls.txt",
    ZAP_CUSTOM_HOOK_SCRIPT: "src/zap_hooks/soos_zap_hook.py",
  },
  SOOS: {
    API_KEY_ENV_VAR: "SOOS_API_KEY",
    CLIENT_ID_ENV_VAR: "SOOS_CLIENT_ID",
  },
  STATUS: {
    DELAY_TIME: 5,
    MAX_ATTEMPTS: 10,
  },
  ZAP: {
    ACTIVE_SCAN_POLICY_NAME: "Default Policy",
    AJAX_SPIDER_OPTION: "-j",
    COMMAND: "python3",
    CONFIG_FILE_FOLDER: "/zap/config/",
    CONTEXT_FILE_OPTION: "-n",
    DEBUG_OPTION: "-d",
    FORMAT_OPTION: "-f",
    HOOK_OPTION: "--hook",
    HTTP_SENDER_SCRIPTS_FOLDER_PATH: "/home/zap/.ZAP/scripts/scripts/httpsender/",
    JSON_REPORT_OPTION: "-J",
    OPTIONS: "-z",
    RULES_FILE_OPTION: "-c",
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

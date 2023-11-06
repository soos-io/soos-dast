export const CONSTANTS = {
  SOOS: {
    API_KEY_ENV_VAR: "SOOS_API_KEY",
    CLIENT_ID_ENV_VAR: "SOOS_CLIENT_ID",
  },
  AUTH: {
    DELAY_TIME: 5,
  },
  FILES: {
    SARIF: "results.sarif",
    REPORT_SCAN_RESULT_FILENAME: "report.json",
    REPORT_SCAN_RESULT_FILE: "/zap/wrk/report.json",
    SPIDERED_URLS_FILE_PATH: "./spidered_urls.txt",
    ZAP_CUSTOM_HOOK_SCRIPT: "src/zap_hooks/soos_zap_hook.py",
  },
  ZAP: {
    COMMAND: "python3",
    SCRIPTS: {
      BASE_LINE: "/zap/zap-baseline.py",
      FULL_SCAN: "/zap/zap-full-scan.py",
      API_SCAN: "/zap/zap-api-scan.py",
    },
    CONFIG_FILE_FOLDER: "/zap/config/",
    TARGET_URL_OPTION: "-t",
    RULES_FILE_OPTION: "-c",
    CONTEXT_FILE_OPTION: "-n",
    SPIDER_MINUTES_OPTION: "-m",
    DEBUG_OPTION: "-d",
    AJAX_SPIDER_OPTION: "-j",
    FORMAT_OPTION: "-f",
    JSON_REPORT_OPTION: "-J",
    OPTIONS: "-z",
    HOOK_OPTION: "--hook",
    ACTIVE_SCAN_POLICY_NAME: "Default Policy",
    HTTP_SENDER_SCRIPTS_FOLDER_PATH: "/home/zap/.ZAP/scripts/scripts/httpsender/",
  },
  DAST: {
    TOOL: "zap",
    TOOL_VERSION: "2.12",
  },
};

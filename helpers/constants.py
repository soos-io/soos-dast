DEFAULT_API_URL: str = "https://api.soos.io/api/"
HEADER_SOOS_API_KEY: str = "x-soos-apikey"
HEADER_CONTENT_TYPE: str = "Content-Type"
JSON_HEADER_CONTENT_TYPE: str = "application/json"
MULTIPART_HEADER_CONTENT_TYPE: str = "multipart/form-data"
MAX_RETRY_COUNT: int = 3
SOOS_CLIENT_ID_KEY: str = "SOOS_CLIENT_ID"
SOOS_API_KEY: str = "SOOS_API_KEY"
DEFAULT_INTEGRATION_NAME: str = "None"
DEFAULT_INTEGRATION_TYPE: str = "Script"
DEFAULT_DAST_TOOL: str = "zap"
DEFAULT_DAST_TOOL_VERSION: str = "latest"
SERVER_ERROR_CODES = range(500, 599)
RETRY_DELAY = 3  # seconds
REQUEST_TIMEOUT = 10  # seconds
EMPTY_STRING = ''
FAIL_THE_BUILD = "fail_the_build"
CONTINUE_ON_FAILURE = "continue_on_failure"
AUTH_DELAY_TIME = 5  # seconds

# SCAN MODES
BASELINE = 'baseline'
FULL_SCAN = 'fullscan'
API_SCAN = 'apiscan'

# URL PLACEHOLDERS
BASE_URI_PLACEHOLDER = "{soos_base_uri}"
CLIENT_ID_PLACEHOLDER = "{soos_client_id}"
PROJECT_ID_PLACEHOLDER = "{soos_project_id}"
DAST_TOOL_PLACEHOLDER = "{soos_dast_tool}"
ANALYSIS_ID_PLACEHOLDER = "{soos_analysis_id}"

# FILE PROCESSING
FILE_READ_MODE = "r"
FILE_WRITE_MODE = "x"
UTF_8_ENCODING = "utf-8"

# OWASP ZAP Constants - for command line options, see https://www.zaproxy.org/docs/docker/full-scan/
REPORT_SCAN_RESULT_FILENAME = "report.json"
REPORT_SCAN_RESULT_FILE = "/zap/wrk/" + REPORT_SCAN_RESULT_FILENAME
PY_CMD = "python3"
BASE_LINE_SCRIPT = "/zap/zap-baseline.py"
FULL_SCAN_SCRIPT = "/zap/zap-full-scan.py"
API_SCAN_SCRIPT = "/zap/zap-api-scan.py"
CONFIG_FILE_FOLDER = "/zap/config/"
ZAP_TARGET_URL_OPTION = "-t"
ZAP_MINIMUM_LEVEL_OPTION = "-l"
ZAP_RULES_FILE_OPTION = "-c"
ZAP_CONTEXT_FILE_OPTION = "-n"
ZAP_SPIDER_MINUTES_OPTION = "-m"
ZAP_DEBUG_OPTION = "-d"
ZAP_AJAX_SPIDER_OPTION = "-j"
ZAP_FORMAT_OPTION = "-f"
ZAP_JSON_REPORT_OPTION = "-J"
ZAP_OTHER_OPTIONS = "-z"
ZAP_HOOK_OPTION = "--hook"
# NOTE: ZAP, when performing a 'fullscan', creates a policy called "Default Policy" - it's needed to specify that name in order to change the scan rules.
ZAP_ACTIVE_SCAN_POLICY_NAME = "Default Policy"
URI_START_DAST_ANALYSIS_TEMPLATE = (
    "{soos_base_uri}clients/{soos_client_id}/dast-tools/{soos_dast_tool}/analysis"
)
URI_START_DAST_ANALYSIS_TEMPLATE_v2 = (
    "{soos_base_uri}clients/{soos_client_id}/scan-types/dast/scans"
)
URI_UPLOAD_DAST_RESULTS_TEMPLATE = "{soos_base_uri}clients/{soos_client_id}/projects/{soos_project_id}/dast-tools/{soos_dast_tool}/analysis/{soos_analysis_id}"

URI_UPLOAD_DAST_RESULTS_TEMPLATE_v2 = "{soos_base_uri}clients/{soos_client_id}/projects/{soos_project_id}/branches/{soos_branch_hash}/scan-types/dast/scans/{soos_analysis_id}"

URI_PROJECT_DETAILS_TEMPLATE = "{soos_base_uri}projects/{soos_project_id}/details"

# LOGS
LOG_FORMAT = "%(asctime)s %(message)s"
LOG_DATE_FORMAT = "%m/%d/%Y %I:%M:%S %p %Z"


# ZAP SCRIPTS
ZAP_ACTIVE_SCAN_SCRIPTS_FOLDER_PATH = "/home/zap/.ZAP/scripts/scripts/active/"
ZAP_HTTP_SENDER_SCRIPTS_FOLDER_PATH = "/home/zap/.ZAP/scripts/scripts/httpsender/"

DEFAULT_API_URL: str = 'https://api.soos.io/api/'
HEADER_SOOS_API_KEY: str = 'x-soos-apikey'
HEADER_CONTENT_TYPE: str = 'Content-Type'
JSON_HEADER_CONTENT_TYPE: str = 'application/json'
MULTIPART_HEADER_CONTENT_TYPE: str = 'multipart/form-data'
MAX_RETRY_COUNT: int = 3
SOOS_CLIENT_ID_KEY: str = 'SOOS_CLIENT_ID'
SOOS_API_KEY: str = 'SOOS_API_KEY'
DEFAULT_INTEGRATION_NAME: str = 'Script'
DEFAULT_INTEGRATION_TYPE: str = 'Script'
DEFAULT_DAST_TOOL: str = 'zap'
SERVER_ERROR_CODES = range(500, 599)
RETRY_DELAY = 3  # seconds


# OWASP ZAP Constants
REPORT_SCAN_RESULT_FILENAME = 'report.json'
REPORT_SCAN_RESULT_FILE = '/zap/wrk/' + REPORT_SCAN_RESULT_FILENAME
PY_CMD = 'python3'
BASE_LINE_SCRIPT = '/zap/zap-baseline.py'
FULL_SCAN_SCRIPT = '/zap/zap-full-scan.py'
API_SCAN_SCRIPT = '/zap/zap-api-scan.py'
CONFIG_FILE_FOLDER = '/zap/config/'
ZAP_TARGET_URL_OPTION = '-t'
ZAP_MINIMUM_LEVEL_OPTION = '-l'
ZAP_RULES_FILE_OPTION = '-c'
ZAP_CONTEXT_FILE_OPTION = '-n'
ZAP_MINUTES_DELAY_OPTION = '-m'
ZAP_DEBUG_OPTION = '-d'
ZAP_AJAX_SPIDER_OPTION = '-j'
ZAP_FORMAT_OPTION = '-f'
ZAP_JSON_REPORT_OPTION = '-J'
URI_START_DAST_ANALYSIS_TEMPLATE = '{soos_base_uri}clients/{soos_client_id}/dast-tools/{soos_dast_tool}/analysis'
URI_UPLOAD_DAST_RESULTS_TEMPLATE = '{soos_base_uri}clients/{soos_client_id}/projects/{soos_project_id}/dast-tools/{soos_dast_tool}/analysis/{soos_analysis_id}'

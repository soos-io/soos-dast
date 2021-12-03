import yaml
import sys
import os
import json
import requests
from datetime import datetime
from helpers.helper import ZAPHelper
from argparse import ArgumentParser
from bleach import clean
from typing import List

DEFAULT_API_URL = 'https://app.soos.io'


def console_log(message: str) -> None:
    time_now = datetime.utcnow().isoformat(timespec="seconds", sep=" ")
    print(time_now + " SOOS: " + str(message))


def print_line_separator() -> None:
    print('----------------------------------------------------------------------------------------------------------')


def exit_app(e) -> None:
    console_log('ERROR: ' + str(e))
    sys.exit(1)


def valid_required(key, value):
    if value is None or len(value) == 0:
        exit_app(key + ' is required')


def has_value(prop) -> bool:
    return prop is not None and len(prop) > 0


def is_true(prop) -> bool:
    return prop is True


class DASTStartAnalysisResponse:
    def __init__(self, dast_analysis_api_response):
        self.analysis_id = dast_analysis_api_response['analysisId']
        if dast_analysis_api_response['projectId'] is not None:
            self.project_id = dast_analysis_api_response['projectId']
        elif dast_analysis_api_response['projectHash'] is not None:
            self.project_id = dast_analysis_api_response['projectHash']


class SOOSDASTAnalysis:
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

    def __init__(self):
        self.client_id = None
        self.api_key = None
        self.project_name = None
        self.base_uri = None
        self.scan_mode = None
        self.fail_on_error = None
        self.target_url = None
        self.rules_file = None
        self.context_file = None
        self.user_context = None
        self.api_scan_format = None
        self.debug_mode = False
        self.ajax_spider_scan = False
        self.spider = False
        self.minutes_delay = None

        # Special Context - loads from script arguments only
        self.commit_hash = None
        self.branch_name = None
        self.branch_uri = None
        self.build_version = None
        self.build_uri = None
        self.operating_environment = None
        self.integration_name = 'Script'
        self.log_level = None

        # INTENTIONALLY HARDCODED
        self.integration_type = 'Script'
        self.dast_analysis_tool = 'zap'

    def parse_configuration(self, configuration: dict, target_url: str):
        console_log('Configuration: ' + str(configuration))
        valid_required('Target URL', target_url)
        self.target_url = target_url

        for key, value in configuration.items():
            if key == 'clientId':
                if value is None:
                    try:
                        self.api_key = os.environ.get('SOOS_CLIENT_ID')
                        valid_required(key, self.api_key)
                    except Exception as e:
                        exit_app(e)
                else:
                    valid_required(key, value)
                    self.client_id = value
            elif key == 'apiKey':
                if value is None:
                    try:
                        self.api_key = os.environ.get('SOOS_API_KEY')
                        valid_required(key, self.api_key)
                    except Exception as e:
                        exit_app(e)
                else:
                    valid_required(key, value)
                    self.api_key = value
            elif key == 'apiURL':
                if value is None:
                    self.base_uri = DEFAULT_API_URL
                else:
                    self.base_uri = value
            elif key == 'projectName':
                valid_required(key, value)
                self.project_name = value
            elif key == 'scanMode':
                valid_required(key, value)
                self.scan_mode = value
            elif key == 'failOnError':
                valid_required(key, value)
                self.fail_on_error = value
            elif key == 'rules':
                self.rules_file = value
            elif key == 'debug':
                self.debug_mode = True
            elif key == 'ajaxSpider':
                self.ajax_spider_scan = True
            elif key == 'context':
                self.context_file = value['file']
                self.user_context = value['user']
            elif key == 'contextFile':
                self.context_file = value
            elif key == 'contextUser':
                self.user_context = value
            elif key == 'fullScan':
                self.minutes_delay = value['minutes']
            elif key == 'fullScanMinutes':
                self.minutes_delay = value
            elif key == 'apiScan':
                self.api_scan_format = value['format']
            elif key == 'apiScanFormat':
                self.api_scan_format = value
            elif key == 'commitHash':
                self.commit_hash = value
            elif key == 'branchName':
                self.branch_name = value
            elif key == 'buildVersion':
                self.build_version = value
            elif key == 'branchURI':
                self.branch_uri = value
            elif key == 'buildURI':
                self.build_uri = value
            elif key == 'operatingEnvironment':
                self.operating_environment = value
            elif key == 'integrationName':
                self.integration_name = value
            elif key == 'level':
                self.log_level = value

    def __add_target_url_option__(self, args: List[str]) -> None:
        if has_value(self.target_url):
            args.append(self.ZAP_TARGET_URL_OPTION)
            args.append(self.target_url)
        else:
            exit_app('Target url is required.')

    def __add_rules_file_option__(self, args: List[str]) -> None:
        if has_value(self.rules_file):
            args.append(self.ZAP_RULES_FILE_OPTION)
            args.append(self.rules_file)

    def __add_context_file_option__(self, args: List[str]) -> None:
        if has_value(self.context_file):
            args.append(self.ZAP_CONTEXT_FILE_OPTION)
            args.append(self.context_file)

    def __add_debug_option__(self, args: List[str]) -> None:
        if is_true(self.debug_mode):
            args.append(self.ZAP_DEBUG_OPTION)

    def __add_ajax_spider_scan_option__(self, args: List[str]) -> None:
        if is_true(self.ajax_spider_scan):
            args.append(self.ZAP_AJAX_SPIDER_OPTION)

    def __add_minutes_delay_option__(self, args: List[str]) -> None:
        if has_value(self.minutes_delay):
            args.append(self.ZAP_MINUTES_DELAY_OPTION)
            args.append(self.minutes_delay)

    def __add_format_option__(self, args: List[str]) -> None:
        if has_value(self.api_scan_format):
            args.append(self.ZAP_FORMAT_OPTION)
            args.append(self.api_scan_format)
        elif self.scan_mode == 'apiscan':
            exit_app('Format is required for apiscan mode.')

    def __add_log_level_option__(self, args: List[str]) -> None:
        if has_value(self.log_level):
            args.append(self.ZAP_MINIMUM_LEVEL_OPTION)
            args.append(self.log_level)

    def __add_report_file__(self, args: List[str]) -> None:
        args.append(self.ZAP_JSON_REPORT_OPTION)
        args.append(self.REPORT_SCAN_RESULT_FILENAME)

    def __generate_command__(self, args: List[str]) -> str:
        self.__add_debug_option__(args)
        self.__add_rules_file_option__(args)
        self.__add_context_file_option__(args)
        self.__add_ajax_spider_scan_option__(args)
        self.__add_minutes_delay_option__(args)

        self.__add_report_file__(args)

        return ' '.join(args)

    def baseline_scan(self) -> str:
        args: List[str] = [self.PY_CMD,
                           self.BASE_LINE_SCRIPT]

        self.__add_target_url_option__(args)

        return self.__generate_command__(args)

    def full_scan(self) -> str:
        args: List[str] = [self.PY_CMD,
                           self.BASE_LINE_SCRIPT]

        self.__add_target_url_option__(args)

        return self.__generate_command__(args)

    def api_scan(self) -> str:
        valid_required('api_scan_format', self.api_scan_format)
        args: List[str] = [self.PY_CMD,
                           self.API_SCAN_SCRIPT]

        self.__add_target_url_option__(args)
        self.__add_format_option__(args)

        return self.__generate_command__(args)

    def active_scan(self):
        """
        Run an Active Scan against a URL.

        The URL to be scanned must be in ZAP's site tree, i.e. it should have already
        been opened using the open-url command or found by running the spider command.
        """

        zap = ZAPHelper()
        options = dict(recursive=True,
                       ajax_spider=self.ajax_spider_scan,
                       spider=True,
                       context=self.context_file,
                       user=self.user_context)

        console_log('Ajax Spider: ' + str(self.ajax_spider_scan))

        zap.scan(target_url=self.target_url, options=options)

    def passive_scan(self):
        valid_required('api_scan_format', self.api_scan_format)
        args = [self.PY_CMD,
                self.API_SCAN_SCRIPT]

        self.__add_target_url_option__(args)
        self.__add_format_option__(args)

        return self.__generate_command__(args)

    def open_zap_results_file(self):
        with open(self.REPORT_SCAN_RESULT_FILE, mode='r') as file:
            return file.read()

    def __generate_start_dast_analysis_url__(self) -> str:
        url = self.URI_START_DAST_ANALYSIS_TEMPLATE
        url = url.replace("{soos_base_uri}", self.base_uri)
        url = url.replace("{soos_client_id}", self.client_id)
        url = url.replace("{soos_dast_tool}", self.dast_analysis_tool)

        return url

    def __generate_upload_results_url__(self, project_id: str, analysis_id: str) -> str:
        url = self.URI_UPLOAD_DAST_RESULTS_TEMPLATE
        url = url.replace("{soos_base_uri}", self.base_uri)
        url = url.replace("{soos_client_id}", self.client_id)
        url = url.replace("{soos_project_id}", project_id)
        url = url.replace("{soos_dast_tool}", self.dast_analysis_tool)
        url = url.replace("{soos_analysis_id}", analysis_id)

        return url

    def __make_soos_start_analysis_request__(self) -> DASTStartAnalysisResponse:
        console_log('Making request to SOOS')
        api_url = self.__generate_start_dast_analysis_url__()
        console_log('SOOS URL Endpoint: ' + api_url)

        # Validate required fields
        if self.project_name is None or len(self.project_name) == 0 or self.scan_mode is None or len(
                self.scan_mode) == 0:
            console_log('ERROR: projectName and scanMode are required')
            sys.exit(1)

        param_values: dict = dict(projectName=self.project_name,
                                  commitHast=self.commit_hash,
                                  branch=self.branch_name,
                                  buildVersion=self.build_version,
                                  buildUri=self.build_uri,
                                  branchUri=self.branch_uri,
                                  operationEnvironment=self.operating_environment,
                                  integrationName=self.integration_name,
                                  integrationType=self.integration_type,
                                  mode=self.scan_mode)

        # Clean up None values
        request_body = {k: v for k, v in param_values.items() if v is not None}

        api_response = requests.post(
            url=api_url,
            data=json.dumps(request_body),
            headers={'x-soos-apikey': self.api_key, 'Content-Type': 'application/json'})

        if api_response.status_code >= 400:
            try:
                error_response = api_response.json()
                message = error_response['message']
            except Exception as e:
                message = "An error has occurred Starting the Analysis"

            exit_app(message)

        elif api_response.status_code == 201:
            return DASTStartAnalysisResponse(api_response.json())

    def __make_upload_dast_results_request__(self, project_id: str, analysis_id: str) -> bool:
        console_log('Starting report results processing')
        zap_report = self.open_zap_results_file()
        console_log('File read')
        console_log('Get The json')
        console_log('Making request to SOOS')
        api_url: str = self.__generate_upload_results_url__(project_id, analysis_id)
        console_log('SOOS URL Upload Results Endpoint: ' + api_url)
        results_json = json.loads(zap_report)
        files = {"manifest": clean(str(results_json)
                                   .replace('<script ', '_script ')
                                   .replace('<script>', '_script_')
                                   .replace('</script>', '_script_'))}

        api_response: requests.Response = requests.put(
            url=api_url,
            data=dict(resultVersion=results_json["@version"]),
            files=files,
            headers={"x-soos-apikey": self.api_key, "Content_type": "multipart/form-data"})

        if api_response.status_code >= 400:
            try:
                error_response = api_response.json()
                message = error_response['message']
            except Exception as e:
                message = 'An error has occurred uploading the report'

            exit_app(message)

        elif api_response.status_code >= 200:
            console_log('SOOS Upload Success')
            return True

    def publish_results_to_soos(self, project_id: str, analysis_id: str) -> None:
        try:
            self.__make_upload_dast_results_request__(project_id, analysis_id)

            print_line_separator()
            console_log('Report processed successfully')
            console_log('Project Id: ' + project_id)
            console_log('Analysis Id: ' + analysis_id)
            print_line_separator()
            console_log('SOOS DAST Analysis successful')
            print_line_separator()
            sys.exit(0)

        except Exception as e:
            exit_app(e)

    def parse_args(self) -> None:
        parser = ArgumentParser(description='SOOS DAST Analysis Script')
        parser.add_argument('targetURL',
                            help='target URL including the protocol, eg https://www.example.com', )
        parser.add_argument('--configFile',
                            help='SOOS yaml file with all the configuration for the DAST Analysis',
                            required=False)
        parser.add_argument('--clientId',
                            help='SOOS Client Id',
                            required=False)
        parser.add_argument('--apiKey',
                            help='SOOS API Key',
                            required=False)
        parser.add_argument('--projectName',
                            help='SOOS project name',
                            required=False)
        parser.add_argument('--scanMode',
                            help='SOOS DAST scan mode. Values available: baseline, fullscan, apiscan, and activescan',
                            default='baseline',
                            required=False)
        parser.add_argument('--apiURL',
                            help='SOOS API URL',
                            default='https://app.soos.io/api/',
                            required=False)
        parser.add_argument('--debug',
                            help='show debug messages',
                            default=False,
                            type=bool,
                            required=False)
        parser.add_argument('--ajaxSpider',
                            help='use the Ajax spider in addition to the traditional one',
                            type=bool,
                            required=False)
        parser.add_argument('--rules',
                            help='rules file to use to INFO, IGNORE or FAIL warnings',
                            required=False)
        parser.add_argument('--contextFile',
                            help='context file which will be loaded prior to scanning the target',
                            required=False)
        parser.add_argument('--contextUser',
                            help='username to use for authenticated scans - must be defined in the given context file',
                            required=False)
        parser.add_argument('--fullScanMinutes',
                            help='Project Name to be displayed in the SOOS Application',
                            required=False)
        parser.add_argument('--apiScanFormat',
                            help='target API format: openapi, soap, or graphql',
                            required=False)
        parser.add_argument('--level',
                            help='minimum level to show: PASS, IGNORE, INFO, WARN or FAIL',
                            required=False)

        args: Namespace = parser.parse_args()
        if args.configFile is not None:
            console_log('Reading config file: ' + args.configFile)
            with open(self.CONFIG_FILE_FOLDER + args.configFile, mode='r') as file:
                # The FullLoader parameter handles the conversion from YAML
                # scalar values to Python the dictionary format
                configuration = yaml.load(file, Loader=yaml.FullLoader)
                self.parse_configuration(configuration['config'], args.targetURL)
        else:
            self.parse_configuration(vars(args), args.targetURL)

    def run_analysis(self) -> None:
        try:
            console_log('Starting SOOS DAST Analysis')
            print_line_separator()

            self.parse_args()

            console_log('Configuration read')
            print_line_separator()

            console_log('Project Name: ' + self.project_name)
            console_log('Scan Mode: ' + self.scan_mode)
            console_log('API URL: ' + self.base_uri)
            console_log('Target URL: ' + self.target_url)
            print_line_separator()

            console_log('Executing ' + self.scan_mode + ' scan')
            soos_dast_start_response = self.__make_soos_start_analysis_request__()
            # execute test
            command = ''
            if self.scan_mode == 'baseline':
                command = self.baseline_scan()
            elif self.scan_mode == 'fullscan':
                command = self.full_scan()
            elif self.scan_mode == 'apiscan':
                command = self.api_scan()
            elif self.scan_mode == 'activescan':
                self.active_scan()
                sys.exit(0)

            if len(command) == 0:
                exit_app('Invalid scan mode')
                print_line_separator()

            os.system(command)
            print_line_separator()

            self.publish_results_to_soos(project_id=soos_dast_start_response.project_id,
                                         analysis_id=soos_dast_start_response.analysis_id)
        except Exception as e:
            exit_app(e)


if __name__ == "__main__":
    dastAnalysis = SOOSDASTAnalysis()
    dastAnalysis.run_analysis()

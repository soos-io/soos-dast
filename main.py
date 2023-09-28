import base64
import gzip
import json
import logging
import os
import platform
import sys
from argparse import ArgumentParser, Namespace
from datetime import datetime
import time
from typing import List, Optional, Any, Dict, NoReturn
from collections import OrderedDict

import requests
import yaml
from requests import Response, put, post, patch

import helpers.constants as Constants
from helpers.utils import log, valid_required, has_value, exit_app, is_true, print_line_separator, \
    check_site_is_available, log_error, unescape_string, read_file, convert_string_to_b64, generate_header, \
    handle_response, ErrorAPIResponse, array_to_str
from model.log_level import LogLevel

ANALYSIS_START_TIME = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
OPERATING_ENVIRONMENT = f'{platform.system()} {platform.release()} {platform.architecture()[0]}'
ANALYSIS_RESULT_POLLING_INTERVAL = 10 # 10 seconds
ANALYSIS_RESULT_MAX_WAIT = 300 # 5 minutes

with open(os.path.join(os.path.dirname(__file__), "VERSION.txt"), encoding='UTF-8') as version_file:
    SCRIPT_VERSION = version_file.read().strip()

class DASTStartAnalysisResponse:
    def __init__(self, dast_analysis_api_response):
        self.analysis_id = dast_analysis_api_response[
            "analysisId"] if "analysisId" in dast_analysis_api_response else None
        self.branch_hash = dast_analysis_api_response[
            "branchHash"] if "branchHash" in dast_analysis_api_response else None
        self.scan_type = dast_analysis_api_response["scanType"] if "scanType" in dast_analysis_api_response else None
        self.scan_url = dast_analysis_api_response["scanUrl"] if "scanUrl" in dast_analysis_api_response else None
        self.scan_status_url = dast_analysis_api_response[
            "scanStatusUrl"] if "scanStatusUrl" in dast_analysis_api_response else None
        self.errors = dast_analysis_api_response["errors"] if "errors" in dast_analysis_api_response else None
        self.project_id = dast_analysis_api_response["projectId"] if "projectId" in dast_analysis_api_response else None
        if self.project_id is None:
            self.project_id = dast_analysis_api_response[
                "projectHash"] if "projectHash" in dast_analysis_api_response else None


class SOOSDASTAnalysis:

    def __init__(self):
        self.client_id: Optional[str] = None
        self.api_key: Optional[str] = None
        self.project_name: Optional[str] = None
        self.base_uri: Optional[str] = None
        self.scan_mode: Optional[str] = None
        self.fail_on_error: Optional[str] = None
        self.target_url: Optional[str] = None
        self.rules_file: Optional[str] = None
        self.context_file: Optional[str] = None
        self.user_context: Optional[str] = None
        self.api_scan_format: Optional[str] = None
        self.debug_mode: bool = False
        self.app_version: Optional[str] = None
        self.ajax_spider_scan: bool = False
        self.spider_minutes: Optional[int] = 120
        self.report_request_headers: bool = False
        self.on_failure: Optional[str] = None
        self.update_addons: bool = False

        # Special Context - loads from script arguments only
        self.commit_hash: Optional[str] = None
        self.branch_name: Optional[str] = None
        self.branch_uri: Optional[str] = None
        self.build_version: Optional[str] = None
        self.build_uri: Optional[str] = None
        self.operating_environment: Optional[str] = None
        self.log_level: Optional[str] = None
        self.zap_options: Optional[str] = None
        self.request_cookies: Optional[str] = None
        self.request_header: Optional[str] = None

        # Hardcoded values, used for analysis metadata
        self.dast_analysis_tool: str = Constants.DEFAULT_DAST_TOOL
        self.dast_analysis_tool_version: str = Constants.DEFAULT_DAST_TOOL_VERSION
        self.integration_name: str = Constants.DEFAULT_INTEGRATION_NAME
        self.integration_type: str = Constants.DEFAULT_INTEGRATION_TYPE

        # Auth Options
        self.auth_auto: Optional[str] = '0'
        self.auth_login_url: Optional[str] = None
        self.auth_username: Optional[str] = None
        self.auth_password: Optional[str] = None
        self.auth_username_field_name: Optional[str] = None
        self.auth_password_field_name: Optional[str] = None
        self.auth_submit_field_name: Optional[str] = None
        self.auth_submit_second_field_name: Optional[str] = None
        self.auth_submit_action: Optional[str] = None
        self.auth_form_type: Optional[str] = None
        self.auth_delay_time: Optional[int] = None
        self.auth_exclude_urls: Optional[str] = None
        self.auth_display: bool = False
        self.auth_bearer_token: Optional[str] = None
        self.oauth_token_url: Optional[str] = None
        self.oauth_parameters: Optional[str] = None

        self.output_format: Optional[str] = None
        self.github_pat: Optional[str] = None
        self.checkout_dir: Optional[str] = None
        self.sarif_destination: Optional[str] = None
        self.disable_rules: Optional[str] = None

        self.scan_mode_map: Dict = {
            Constants.BASELINE: self.baseline_scan,
            Constants.FULL_SCAN: self.full_scan,
            Constants.API_SCAN: self.api_scan
        }

    def parse_configuration(self, configuration: Dict, target_url: str):
        valid_required("Target URL", target_url)
        self.target_url = target_url
        self.log_level = configuration.get("level", LogLevel.INFO)
        logging.getLogger("SOOS DAST").setLevel(self.log_level)
        log(json.dumps(configuration, indent=2), log_level=LogLevel.DEBUG)
        for key, value in configuration.items():
            if key == "clientId":
                if value is None:
                    try:
                        self.client_id = os.environ.get(Constants.SOOS_CLIENT_ID_KEY)
                        valid_required(key, self.client_id)
                    except Exception as error:
                        exit_app(error)
                else:
                    valid_required(key, value)
                    self.client_id = value
            elif key == "apiKey":
                if value is None:
                    try:
                        self.api_key = os.environ.get(Constants.SOOS_API_KEY)
                        valid_required(key, self.api_key)
                    except Exception as error:
                        exit_app(error)
                else:
                    valid_required(key, value)
                    self.api_key = value
            elif key == "apiURL":
                if value is None:
                    self.base_uri = Constants.DEFAULT_API_URL
                else:
                    self.base_uri = value
            elif key == "projectName":
                valid_required(key, value)
                value = array_to_str(value)
                self.project_name = unescape_string(value)
            elif key == "scanMode":
                valid_required(key, value)
                self.scan_mode = value
            elif key == "failOnError":
                valid_required(key, value)
                self.fail_on_error = value
            elif key == "rules":
                self.rules_file = value
            elif key == "debug":
                self.debug_mode = True
            elif key == "ajaxSpider":
                self.ajax_spider_scan = True
            elif key == "context":
                self.context_file = value["file"]
                self.user_context = value["user"]
            elif key == "contextFile":
                self.context_file = value
            elif key == "contextUser":
                self.user_context = value
            elif key == "fullScanMinutes":
                self.spider_minutes = value
            elif key == "apiScan":
                self.api_scan_format = value["format"]
            elif key == "apiScanFormat":
                self.api_scan_format = value
            elif key == "commitHash":
                self.commit_hash = value
            elif key == "branchName":
                value = array_to_str(value)
                self.branch_name = value
            elif key == "buildVersion":
                self.build_version = value
            elif key == "branchURI":
                self.branch_uri = value
            elif key == "buildURI":
                self.build_uri = value
            elif key == "operatingEnvironment":
                value = array_to_str(value)
                self.operating_environment = value
            elif key == "integrationName":
                if value is None:
                    self.integration_name = Constants.DEFAULT_INTEGRATION_NAME
                else:
                    value = array_to_str(value)
                    self.integration_name = value
            elif key == "integrationType":
                if value is None:
                    self.integration_type = Constants.DEFAULT_INTEGRATION_TYPE
                else:
                    value = array_to_str(value)
                    self.integration_type = value
            elif key == "appVersion":
                value = array_to_str(value)
                self.app_version = value
            elif key == 'authAuto':
                self.auth_auto = '1'
            elif key == 'authDisplay':
                self.auth_display = value
            elif key == 'authUsername':
                self.auth_username = value
            elif key == 'authPassword':
                self.auth_password = value
            elif key == 'authLoginURL':
                self.auth_login_url = value
            elif key == 'authUsernameField':
                self.auth_username_field_name = value
            elif key == 'authPasswordField':
                self.auth_password_field_name = value
            elif key == 'authSubmitField':
                self.auth_submit_field_name = value
            elif key == 'authSecondSubmitField':
                self.auth_submit_second_field_name = value
            elif key == 'authSubmitAction':
                self.auth_submit_action = value
            elif key == 'authFormType':
                self.auth_form_type = value
            elif key == 'authDelayTime':
                self.auth_delay_time = value
            elif key == "zapOptions":
                value = array_to_str(value)
                self.zap_options = value
            elif key == "requestCookies":
                value = array_to_str(value)
                self.request_cookies = value
            elif key == "requestHeaders":
                value = array_to_str(value)
                self.request_header = value
            elif key == "outputFormat":
                self.output_format = value
            elif key == "gpat":
                self.github_pat = value
            elif key =="bearerToken":
                self.auth_bearer_token = value
            elif key == "reportRequestHeaders":
                self.report_request_headers = True if str.lower(value) == "true" else False
            elif key == "onFailure":
                self.on_failure = value
            elif key == "checkoutDir":
                self.checkout_dir = value
            elif key == "sarifDestination":
                self.sarif_destination = value
            elif key == "oauthTokenUrl":
                self.oauth_token_url = value
            elif key == "oauthParameters":
                value = array_to_str(value)
                self.oauth_parameters = value
            elif key == "sarif" and value is not None:
                log("Argument 'sarif' is deprecated. Please use --outputFormat='sarif' instead.")
                sys.exit(1)
            elif key == "updateAddons":
                self.update_addons = True if str.lower(value) == "true" else False
            elif key == "disableRules":
                self.disable_rules = array_to_str(value)

    def __add_target_url_option__(self, args: List[str]) -> NoReturn:
        if has_value(self.target_url):
            args.append(Constants.ZAP_TARGET_URL_OPTION)
            args.append(self.target_url)
        else:
            exit_app("Target url is required.")

    def __add_rules_file_option__(self, args: List[str]) -> None:
        if has_value(self.rules_file):
            args.append(Constants.ZAP_RULES_FILE_OPTION)
            args.append(self.rules_file)

    def __add_context_file_option__(self, args: List[str]) -> None:
        if has_value(self.context_file):
            args.append(Constants.ZAP_CONTEXT_FILE_OPTION)
            args.append(self.context_file)

    def __add_debug_option__(self, args: List[str]) -> None:
        if is_true(self.debug_mode):
            args.append(Constants.ZAP_DEBUG_OPTION)

    def __add_ajax_spider_scan_option__(self, args: List[str]) -> None:
        if is_true(self.ajax_spider_scan):
            args.append(Constants.ZAP_AJAX_SPIDER_OPTION)

    def __add_spider_minutes_option__(self, args: List[str]) -> None:
        if has_value(self.spider_minutes):
            args.append(Constants.ZAP_SPIDER_MINUTES_OPTION)
            args.append(self.spider_minutes)

    def __add_format_option__(self, args: List[str]) -> NoReturn:
        if has_value(self.api_scan_format):
            args.append(Constants.ZAP_FORMAT_OPTION)
            args.append(self.api_scan_format)
        elif self.scan_mode == Constants.API_SCAN:
            exit_app("Format is required for apiscan mode.")

    def __add_log_level_option__(self, args: List[str]) -> None:
        if has_value(self.log_level):
            args.append(Constants.ZAP_MINIMUM_LEVEL_OPTION)
            args.append(self.log_level)

    def __add_report_file__(self, args: List[str]) -> None:
        args.append(Constants.ZAP_JSON_REPORT_OPTION)
        args.append(Constants.REPORT_SCAN_RESULT_FILENAME)

    def __add_hook_params__(self) -> None:
        log("Adding hook params", LogLevel.DEBUG)
        if self.auth_login_url is not None:
            os.environ['AUTH_LOGIN_URL'] = self.auth_login_url
        if self.auth_username is not None:
            os.environ['AUTH_USERNAME'] = self.auth_username
        if self.auth_password is not None:
            os.environ['AUTH_PASSWORD'] = self.auth_password
        if self.request_cookies is not None:
            os.environ['CUSTOM_COOKIES'] = self.request_cookies
        if self.request_header is not None:
            os.environ['CUSTOM_HEADER'] = self.request_header
        if self.auth_bearer_token is not None:
            os.environ['AUTH_BEARER_TOKEN'] = self.auth_bearer_token
        if self.auth_display is not None:
            os.environ['AUTH_DISPLAY'] = str(self.auth_display)
        if self.auth_submit_field_name is not None:
            os.environ['AUTH_SUBMIT_FIELD'] = self.auth_submit_field_name
        if self.auth_submit_second_field_name is not None:
            os.environ['AUTH_SECOND_SUBMIT_FIELD'] = self.auth_submit_second_field_name
        if self.auth_submit_action is not None:
            os.environ['AUTH_SUBMIT_ACTION'] = self.auth_submit_action
        if self.auth_form_type is not None:
            os.environ['AUTH_FORM_TYPE'] = self.auth_form_type
        if self.auth_delay_time is not None:
            os.environ['AUTH_DELAY_TIME'] = str(self.auth_delay_time)
        if self.auth_username_field_name is not None:
            os.environ['AUTH_USERNAME_FIELD'] = self.auth_username_field_name
        if self.auth_password_field_name is not None:
            os.environ['AUTH_PASSWORD_FIELD'] = self.auth_password_field_name
        if self.oauth_token_url is not None:
            os.environ['OAUTH_TOKEN_URL'] = self.oauth_token_url
        if self.oauth_parameters is not None:
            os.environ['OAUTH_PARAMETERS'] = self.oauth_parameters
        if self.disable_rules is not None:
            os.environ['DISABLE_RULES'] = self.disable_rules

    def __add_hook_option__(self, args: List[str]) -> None:
        args.append(Constants.ZAP_HOOK_OPTION)
        args.append('/zap/hooks/soos_dast_hook.py')

    def __generate_command__(self, args: List[str]) -> str:
        self.__add_debug_option__(args)
        self.__add_rules_file_option__(args)
        self.__add_context_file_option__(args)
        self.__add_ajax_spider_scan_option__(args)
        self.__add_spider_minutes_option__(args)
        log("Add ZAP Options?")
        log(f"Auth Login: {str(self.auth_login_url)}")
        log(f"Zap Options: {str(self.zap_options)}")
        log(f"Cookies: {str(self.request_cookies)}")
        log(f"Github PAT: {str(self.github_pat)}")
        if (self.auth_login_url or self.request_cookies is not None or
            self.request_header is not None or self.auth_bearer_token is not None or
            self.oauth_token_url is not None or self.disable_rules is not None):
            self.__add_hook_params__()

        self.__add_hook_option__(args)

        self.__add_report_file__(args)
       
        return " ".join(args)

    def baseline_scan(self) -> str:
        args: List[str] = [Constants.PY_CMD, Constants.BASE_LINE_SCRIPT]

        self.__add_target_url_option__(args)

        return self.__generate_command__(args)

    def full_scan(self) -> str:
        args: List[str] = [Constants.PY_CMD, Constants.FULL_SCAN_SCRIPT]

        self.__add_target_url_option__(args)

        return self.__generate_command__(args)

    def api_scan(self) -> str:
        valid_required("api_scan_format", self.api_scan_format)
        args: List[str] = [Constants.PY_CMD, Constants.API_SCAN_SCRIPT]

        self.__add_target_url_option__(args)
        self.__add_format_option__(args)

        return self.__generate_command__(args)

    def open_zap_results_file(self):
        return read_file(file_path=Constants.REPORT_SCAN_RESULT_FILE)

    def __generate_start_dast_analysis_url__(self) -> str:
        url = Constants.URI_START_DAST_ANALYSIS_TEMPLATE_v2.format(soos_base_uri=self.base_uri,
                                                                   soos_client_id=self.client_id)

        return url

    def __generate_upload_results_url__(self, project_id: str, branch_hash: str, analysis_id: str) -> str:
        url = Constants.URI_UPLOAD_DAST_RESULTS_TEMPLATE_v2.format(soos_base_uri=self.base_uri,
                                                                   soos_client_id=self.client_id,
                                                                   soos_project_id=project_id,
                                                                   soos_branch_hash=branch_hash,
                                                                   soos_analysis_id=analysis_id)
        return url

    def __generate_project_details_url__(self, project_id: str) -> str:
        url = Constants.URI_PROJECT_DETAILS_TEMPLATE.format(soos_base_uri=self.base_uri,
                                                            soos_project_id=project_id)
        return url

    def __make_soos_start_analysis_request__(self, command: str) -> DASTStartAnalysisResponse:
        message: str = "An error has occurred Starting the Analysis"
        try:
            log("Making request to SOOS")
            api_url: str = self.__generate_start_dast_analysis_url__()
            log(f"SOOS URL Endpoint: {api_url}")

            # Validate required fields
            if self.project_name is None or len(self.project_name) == 0:
                log("projectName is required", LogLevel.ERROR)
                sys.exit(1)

            if self.scan_mode is None or len(self.scan_mode) == 0:
                log("scanMode is required", LogLevel.ERROR)
                sys.exit(1)

            # Obfuscate sensitive data
            obfuscated_command = command
            if self.auth_bearer_token is not None:
                obfuscated_command = obfuscated_command.replace(self.auth_bearer_token, "********")
            if self.auth_password is not None:
                obfuscated_command = obfuscated_command.replace(self.auth_password, "********")
            if self.auth_username is not None:
                obfuscated_command = obfuscated_command.replace(self.auth_username, "********")
            if self.oauth_token_url is not None:
                obfuscated_command = obfuscated_command.replace(self.oauth_token_url, "********")
            
            param_values: dict = dict(
                projectName=self.project_name,
                name=datetime.now().strftime("%m/%d/%Y, %H:%M:%S"),
                integrationType=self.integration_type,
                scriptVersion=SCRIPT_VERSION,
                appVersion=self.app_version,
                toolName=self.dast_analysis_tool,
                toolVersion=self.dast_analysis_tool_version,
                commandLine=obfuscated_command,
                scanMode=self.scan_mode,
                commitHash=self.commit_hash,
                branch=self.branch_name,
                branchUri=self.branch_uri,
                buildVersion=self.build_version,
                buildUri=self.build_uri,
                operationEnvironment=self.operating_environment or OPERATING_ENVIRONMENT,
                integrationName=self.integration_name,
            )

            # Clean up None values
            request_body = {k: v for k, v in param_values.items() if v is not None}

            error_response: Optional[Any] = None

            data = json.dumps(request_body)

            api_response: Response = post(
                url=api_url,
                data=data,
                headers={"x-soos-apikey": self.api_key, "Content-Type": Constants.JSON_HEADER_CONTENT_TYPE}
            )

            if api_response.ok:
                return DASTStartAnalysisResponse(api_response.json())
            else:
                log_error(api_response)
                error_response = api_response
                log(
                    "An error has occurred performing the request."
                )

            if error_response is not None:
                error_response = error_response.json()
                message = error_response["message"]

        except Exception as error:
            log(f"Error: {error}")
            message = message if message is not None else "An error has occurred Starting the Analysis"

        exit_app(message)

    def __make_soos_scan_status_request__(self, project_id: str, branch_hash: str,
                                          analysis_id: str, status: str,
                                          status_message: Optional[str]) -> bool:
        message: str = "An error has occurred Starting the Analysis"
        try:
            log("Making request to SOOS")
            api_url: str = self.__generate_upload_results_url__(project_id, branch_hash, analysis_id)
            log(f"SOOS URL Endpoint: {api_url}")

            param_values: dict = dict(
                status=status,
                message=status_message
            )

            # Clean up None values
            request_body = {k: v for k, v in param_values.items() if v is not None}

            error_response: Optional[Any] = None

            data = json.dumps(request_body)

            api_response: Response = patch(
                url=api_url,
                data=data,
                headers={"x-soos-apikey": self.api_key, "Content-Type": Constants.JSON_HEADER_CONTENT_TYPE}
            )

            if api_response.ok:
                return True
            else:
                log_error(api_response)
                error_response = api_response
                log(
                    "An error has occurred performing the request"
                )

            if  error_response is not None:
                error_response = error_response.json()
                message = error_response["message"]

        except Exception as error:
            log(f"Error: {error}")
            message = message if message is not None else "An error has occurred setting the scan status"
            self.__make_soos_scan_status_request__(project_id=project_id,
                                                   branch_hash=branch_hash,
                                                   analysis_id=analysis_id,
                                                   status="Error",
                                                   status_message=message
                                                   )

        exit_app(message)

    def __make_upload_dast_results_request__(
            self, project_id: str, branch_hash: str, analysis_id: str
    ) -> bool:
        error_response = None
        error_message: Optional[str] = None
        try:
            log("Starting report results processing")
            zap_report = self.open_zap_results_file()
            log("Making request to SOOS")
            api_url: str = self.__generate_upload_results_url__(project_id, branch_hash, analysis_id)
            log("SOOS URL Upload Results Endpoint: " + api_url)
            results_json = json.loads(zap_report)
            log(json.dumps(results_json, indent=2), log_level=LogLevel.DEBUG)

            zap_report_encoded = convert_string_to_b64(json.dumps(results_json))
            files = {"base64Manifest": zap_report_encoded}

            api_response: Response = put(
                url=api_url,
                data=dict(resultVersion=results_json["@version"]),
                files=files,
                headers={
                    "x-soos-apikey": self.api_key,
                    "Content_type": Constants.MULTIPART_HEADER_CONTENT_TYPE,
                },
            )

            if api_response.ok:
                log("SOOS Upload Success")
                return True
            else:
                error_response = api_response
                log_error(error_response)
                log("An error has occurred performing the request")

            if  error_response is not None:
                error_response = error_response.json()
                error_message = error_response["message"]

        except Exception as error:
            log(f"Error: {error}")

        self.__make_soos_scan_status_request__(project_id=project_id,
                                               branch_hash=branch_hash,
                                               analysis_id=analysis_id,
                                               status="Error",
                                               status_message=error_message
                                               )
        exit_app(error_message)

    def publish_results_to_soos(self, project_id: str, branch_hash: str, analysis_id: str, report_url: str) -> None:
        try:
            self.__make_upload_dast_results_request__(project_id=project_id, branch_hash=branch_hash,
                                                      analysis_id=analysis_id)

            print_line_separator()
            log("Report processed successfully")
            log(f"Project Id: {project_id}")
            log(f"Branch Hash: {branch_hash}")
            log(f"Analysis Id: {analysis_id}")
            print_line_separator()
            log("SOOS DAST Analysis successful")
            log(f"Project URL: {report_url}")
            print_line_separator()

        except Exception as error:
            self.__make_soos_scan_status_request__(project_id=project_id,
                                                   branch_hash=branch_hash,
                                                   analysis_id=analysis_id,
                                                   status="Error",
                                                   status_message="An Unexpected error has occurred uploading ZAP Report Results"
                                                   )
            exit_app(error)

    def get_analysis_status_soos(self, result_uri):

        analysis_result_response = None
        try:
            analysis_result_response = requests.get(
                url=result_uri,
                headers={'x-soos-apikey': self.api_key, 'Content-Type': 'application/json'}
            )

        except Exception as error:
            log(f"Analysis Result API Exception Occurred: {error}")

        return analysis_result_response

    def parse_args(self) -> None:
        parser = ArgumentParser(description="SOOS DAST")

        # DOCUMENTATION

        parser.add_argument('-hf', "--helpFormatted", dest="help_formatted",
                            help="Print the --help command in markdown table format",
                            action="store_false",
                            default=False,
                            required=False)

        # SCRIPT PARAMETERS

        parser.add_argument(
            "targetURL",
            help="Target URL - URL of the site or api to scan. The URL should include the protocol. Ex: https://www.example.com",
        )
        parser.add_argument(
            "--configFile",
            help="Config File - SOOS yaml file with all the configuration for the DAST Analysis (See https://github.com/soos-io/soos-dast#config-file-definition)",
            required=False,
        )
        parser.add_argument("--clientId", help="SOOS Client ID - get yours from https://app.soos.io/integrate/sca", required=False)
        parser.add_argument("--apiKey", help="SOOS API Key - get yours from https://app.soos.io/integrate/sca", required=False)
        parser.add_argument("--projectName", help="Project Name - this is what will be displayed in the SOOS app", nargs="+", required=False)
        parser.add_argument(
            "--scanMode",
            help="Scan Mode - Available modes: baseline, fullscan, and apiscan (for more information about scan modes visit https://github.com/soos-io/soos-dast#scan-modes)",
            default="baseline",
            required=False,
        )
        parser.add_argument(
            "--apiURL",
            help="SOOS API URL - Intended for internal use only, do not modify.",
            default="https://api.soos.io/api/",
            required=False,
        )
        parser.add_argument(
            "--debug",
            help="Enable to show debug messages.",
            default=False,
            type=bool,
            required=False,
        )
        parser.add_argument(
            "--ajaxSpider",
            help="Ajax Spider - Use the ajax spider in addition to the traditional one. Additional information: https://www.zaproxy.org/docs/desktop/addons/ajax-spider/",
            type=bool,
            required=False,
        )
        parser.add_argument(
            "--rules",
            help="Rules file to use to INFO, IGNORE or FAIL warnings",
            nargs="*",
            required=False,
        )
        parser.add_argument(
            "--contextFile",
            help="Context file which will be loaded prior to scanning the target",
            nargs="*",
            required=False,
        )
        parser.add_argument(
            "--contextUser",
            help="Username to use for authenticated scans - must be defined in the given context file",
            nargs="*",
            required=False,
        )
        parser.add_argument(
            "--fullScanMinutes",
            help="Number of minutes for the spider to run",
            required=False,
        )
        parser.add_argument(
            "--apiScanFormat",
            help="Target API format: OpenAPI, SOAP, or GraphQL",
            required=False,
        )
        parser.add_argument(
            "--level",
            help="Log level to show: DEBUG, INFO, WARN, ERROR, CRITICAL",
            default="INFO",
            required=False,
        )
        parser.add_argument(
            "--integrationName",
            help="Integration Name - Intended for internal use only.",
            type=str,
            nargs="*",
            required=False,
        )
        parser.add_argument(
            "--integrationType",
            help="Integration Type - Intended for internal use only.",
            type=str,
            nargs="*",
            required=False,
        )
        parser.add_argument(
            "--scriptVersion",
            help="Script Version - Intended for internal use only.",
            type=str,
            nargs="*",
            required=False,
        )
        parser.add_argument(
            "--appVersion",
            help="App Version - Intended for internal use only.",
            type=str,
            nargs="*",
            required=False,
        )
        parser.add_argument(
            "--authDisplay",
            help="Minimum level to show: PASS, IGNORE, INFO, WARN or FAIL",
            required=False,
        )
        parser.add_argument(
            "--authUsername",
            help="Username to use in auth apps",
            required=False,
        )
        parser.add_argument(
            "--authPassword",
            help="Password to use in auth apps",
            required=False,
        )
        parser.add_argument(
            "--authLoginURL",
            help="Login url to use in auth apps",
            required=False,
        )
        parser.add_argument(
            "--authUsernameField",
            help="Username input id to use in auth apps",
            required=False,
        )
        parser.add_argument(
            "--authPasswordField",
            help="Password input id to use in auth apps",
            required=False,
        )
        parser.add_argument(
            "--authSubmitField",
            help="Submit button id to use in auth apps",
            required=False,
        )
        parser.add_argument(
            "--authSecondSubmitField",
            help="Second submit button id to use in auth apps (for multi-page forms)",
            required=False,
        )
        parser.add_argument(
            "--authSubmitAction",
            help="Submit action to perform on form filled. Options: click or submit",
            type=str,
            required=False,
        )
        parser.add_argument(
            "--authFormType",
            help="simple (all fields are displayed at once), wait_for_password (Password field is displayed only after username is filled), or multi_page (Password field is displayed only after username is filled and submit is clicked)",
            type=str,
            default="simple",
            required=False,
        )
        parser.add_argument(
            "--authDelayTime",
            help="Delay time in seconds to wait for the page to load after performing actions in the form. (Used only on authFormType: wait_for_password and multi_page)",
            default=Constants.AUTH_DELAY_TIME,
            required=False,
        )
        parser.add_argument(
            "--zapOptions",
            help="Additional ZAP Options",
            type=str,
            nargs="*",
            required=False,
        )
        parser.add_argument(
            "--requestCookies",
            help="Set Cookie values for the requests to the target URL",
            type=str,
            nargs="*",
            default=None,
            required=False,
        )
        parser.add_argument(
            "--requestHeaders",
            help="Set extra Header requests",
            type=str,
            nargs="*",
            default=None,
            required=False,
        )
        parser.add_argument(
            "--onFailure",
            help="Action to perform when the scan fails. Options: fail_the_build, continue_on_failure",
            type=str,
            default="continue_on_failure",
            required=False,
        )
        parser.add_argument(
            "--commitHash",
            help="The commit hash value from the SCM System",
            type=str,
            default=None,
            required=False,
        )
        parser.add_argument(
            "--branchName",
            help="The name of the branch from the SCM System",
            type=str,
            default=None,
            nargs="*",
            required=False,
        )
        parser.add_argument(
            "--branchURI",
            help="The URI to the branch from the SCM System",
            default=None,
            required=False,
        )
        parser.add_argument(
            "--buildVersion",
            help="Version of application build artifacts",
            type=str,
            default=None,
            required=False,
        )
        parser.add_argument(
            "--buildURI",
            help="URI to CI build info",
            type=str,
            default=None,
            required=False,
        )
        parser.add_argument(
            "--operatingEnvironment",
            help="Set Operating environment for information purposes only",
            type=str,
            default=None,
            nargs="*",
            required=False,
        )
        parser.add_argument(
            "--reportRequestHeaders",
            help="Include request/response headers data in report",
            type=str,
            default="True",
            required=False
        )
        parser.add_argument(
            "--outputFormat",
            help="Output format for vulnerabilities: only the value SARIF is available at the moment",
            type=str,
            default=None,
            required=False
        )
        parser.add_argument(
            "--gpat",
            help="GitHub Personal Authorization Token",
            type=str,
            default=None,
            required=False
        )
        parser.add_argument(
            "--bearerToken",
            help="Bearer token to authenticate",
            type=str,
            default=None,
            required=False
        )
        parser.add_argument(
            "--checkoutDir",
            help="Checkout directory to locate SARIF report",
            type=str,
            default=None,
            required=False
        )
        parser.add_argument(
            "--sarifDestination",
            help="SARIF destination to upload report in the form of <repo_owner>/<repo_name>",
            type=str,
            default=None,
            required=False
        )
        parser.add_argument(
            "--sarif",
            help="DEPRECATED - SARIF parameter is currently deprecated, please use --outputFormat='sarif' instead",
            type=bool,
            default=None,
            required=False
        )
        parser.add_argument(
            "--oauthTokenUrl",
            help="The authentication URL that grants the access_token.",
            type=str,
            default=None,
            required=False
        )
        parser.add_argument(
            "--oauthParameters",
            help="Parameters to be added to the oauth token request. (eg --oauthParameters=\"client_id:clientID, client_secret:clientSecret, grant_type:client_credentials\")",
            type=str,
            nargs="*",
            default=None,
            required=False,
        )
        parser.add_argument(
            "--updateAddons",
            help="Internal use only. Update addons of the zap image.",
            type=str,
            default="False",
            required=False
        )
        parser.add_argument(
            "--disableRules",
            help="Comma separated list of ZAP rules IDs to disable. List for reference https://www.zaproxy.org/docs/alerts/",
            nargs="*",
            default=None,
            required=False
        )

        # parse help argument
        if "-hf" in sys.argv or "--helpFormatted" in sys.argv:
            self.print_help_formatted(parser)
            sys.exit(0)
        log("Parsing Arguments")
        args: Namespace = parser.parse_args()
        if args.configFile is not None:
            log(f"Reading config file: {args.configFile}", log_level=LogLevel.DEBUG)
            file = read_file(file_path=Constants.CONFIG_FILE_FOLDER + args.configFile)
            configuration = yaml.load(file, Loader=yaml.FullLoader)
            self.parse_configuration(configuration["config"], args.targetURL)
        else:
            self.parse_configuration(vars(args), args.targetURL)

    def print_help_formatted(self, parser: ArgumentParser):
        print("| Argument | Default | Description |")
        print("| --- | --- | --- |")
        all_rows = []
        for arg, options in parser._option_string_actions.items():
            default_value = options.default
            description_text = options.help
            all_rows.append(f"| `{'`, `'.join(options.option_strings)}` | {default_value} | {description_text} |")
        # remove duplicates
        for row in list(OrderedDict.fromkeys(all_rows)):
            print(row)

    def run_analysis(self) -> None:
        try:
            log("Starting SOOS DAST Analysis")
            print_line_separator()

            self.parse_args()

            log("Configuration read")
            print_line_separator()

            log(f"Project Name: {self.project_name}")
            log(f"Scan Mode: {self.scan_mode}")
            log(f"API URL: {self.base_uri}")
            log(f"Target URL: {self.target_url}")
            print_line_separator()

            if self.scan_mode != Constants.API_SCAN:
                check: bool = check_site_is_available(self.target_url)

                if check is False:
                    exit_app(f"The URL {self.target_url} is not available")
                    return None


            scan_function = self.scan_mode_map.get(self.scan_mode, None)

            if scan_function is None:
                exit_app(f"The scan mode {self.scan_mode} is invalid.")
                return None

            log(f"Copying report templates. Include request headers: {self.report_request_headers}", log_level=LogLevel.DEBUG)
            os.system("mkdir -p ~/.ZAP/reports")
            os.system("mkdir -p /root/.ZAP/reports")
            if self.report_request_headers is True:
               os.system("cp -R /zap/reports/traditional-json-headers ~/.ZAP/reports/traditional-json")
               os.system("cp -R /zap/reports/traditional-json-headers /root/.ZAP/reports/traditional-json")
            else:
               os.system("cp -R /zap/reports/traditional-json ~/.ZAP/reports/traditional-json")
               os.system("cp -R /zap/reports/traditional-json /root/.ZAP/reports/traditional-json")

            command: str = scan_function()
                            
            if self.update_addons:
                command = f"{command} --updateAddons"

            if self.zap_options:
                command = f"{command} {Constants.ZAP_OPTIONS} \"{self.zap_options}\""

            log(f"Executing {self.scan_mode} scan")
            soos_dast_start_response = self.__make_soos_start_analysis_request__(command)

            self.__make_soos_scan_status_request__(project_id=soos_dast_start_response.project_id,
                                                   branch_hash=soos_dast_start_response.branch_hash,
                                                   analysis_id=soos_dast_start_response.analysis_id,
                                                   status="Running",
                                                   status_message=None
                                                   )           
            
            log(f"Command to be executed: {command}", log_level=LogLevel.DEBUG)
            os.system(command)

            run_success = os.path.exists(Constants.REPORT_SCAN_RESULT_FILE)

            print_line_separator()
            if run_success is False:
                self.__make_soos_scan_status_request__(project_id=soos_dast_start_response.project_id,
                                                       branch_hash=soos_dast_start_response.branch_hash,
                                                       analysis_id=soos_dast_start_response.analysis_id,
                                                       status="Error",
                                                       status_message=f"An Unexpected error has occurred running the {self.scan_mode} scan"
                                                       )
                raise Exception(f"An Unexpected error has occurred running the {self.scan_mode} scan")

            # Add the discovered urls to the report
            discoveredUrls = open('./spidered_urls.txt', 'r').read().splitlines()
            data = json.load(open(Constants.REPORT_SCAN_RESULT_FILE, 'r'))
            data['discoveredUrls'] = discoveredUrls
            json.dump(data, open(Constants.REPORT_SCAN_RESULT_FILE, 'w'))

            self.publish_results_to_soos(
                project_id=soos_dast_start_response.project_id,
                branch_hash=soos_dast_start_response.branch_hash,
                analysis_id=soos_dast_start_response.analysis_id,
                report_url=soos_dast_start_response.scan_url,
            )

            if self.output_format == "sarif":
                SOOSSARIFReport.exec(analysis=self,
                                     project_hash=soos_dast_start_response.project_id,
                                     branch_hash=soos_dast_start_response.branch_hash,
                                     scan_id=soos_dast_start_response.analysis_id)


            while True and self.on_failure == Constants.FAIL_THE_BUILD:
                if (datetime.utcnow() - datetime.strptime(ANALYSIS_START_TIME, "%Y-%m-%dT%H:%M:%SZ")).seconds > ANALYSIS_RESULT_MAX_WAIT:
                    log(f"Analysis Result Max Wait Time Reached ({str(ANALYSIS_RESULT_MAX_WAIT)})")
                    sys.exit(1)

                analysis_result_api_response = self.get_analysis_status_soos(result_uri=soos_dast_start_response.scan_status_url)

                content_object = analysis_result_api_response.json()

                if analysis_result_api_response.status_code < 299:
                    analysis_status = str(content_object["status"]) if content_object and "status" in content_object else None

                    if analysis_status.lower().startswith("failed") and self.on_failure:
                        log("Analysis complete - Failures reported")
                        log("Failing the build.")
                        sys.exit(1)
                    elif analysis_status.lower() == "incomplete":
                        log("Analysis Incomplete. It may have been cancelled or superseded by another scan.")
                        log("Failing the build.")
                        sys.exit(1)
                    elif analysis_status.lower() == "error":
                        log("Analysis Error.")
                        log("Failing the build.")
                        sys.exit(1)
                    elif analysis_status.lower() == "finished":
                        return
                    else:
                    # Status code that is not pertinent to the result
                        log(f"Analysis Ongoing. Will retry in {str(ANALYSIS_RESULT_POLLING_INTERVAL)} seconds.")
                        time.sleep(ANALYSIS_RESULT_POLLING_INTERVAL)
                        continue
                else:
                    if "message" in analysis_result_api_response.json():
                        results_error_code = analysis_result_api_response.json()["code"]
                        results_error_message = analysis_result_api_response.json()["message"]
                        log(f"Analysis Results API Status Code: {str(results_error_code)},{results_error_message}")
                        sys.exit(1)



            sys.exit(0)

        except Exception as error:
            exit_app(error)


class SOOSSARIFReport:

    URL_TEMPLATE = '{soos_base_uri}clients/{clientHash}/projects/{projectHash}/branches/{branchHash}/scan-types/dast/scans/{scanId}/formats/sarif'
    GITHUB_URL_TEMPLATE = 'https://api.github.com/repos/{sarif_destination}/code-scanning/sarifs'

    errors_dict = {
        400: "Github: The sarif report is invalid",
        403: "Github: The repository is archived or if github advanced security is not enabled for this repository",
        404: "Github: Resource not found",
        413: "Github: The sarif report is too large",
        503: "Github: Service Unavailable"
    }

    def __init__(self):
        pass

    @staticmethod
    def generate_soos_sarif_url(base_uri: str, client_id: str, project_hash: str, branch_hash: str,
                                scan_id: str) -> str:
        return SOOSSARIFReport.URL_TEMPLATE.format(soos_base_uri=base_uri,
                                                   clientHash=client_id,
                                                   projectHash=project_hash,
                                                   branchHash=branch_hash,
                                                   scanId=scan_id)

    @staticmethod
    def generate_github_sarif_url(sarif_destination: str) -> str:
        return SOOSSARIFReport.GITHUB_URL_TEMPLATE.format(sarif_destination=sarif_destination)

    @staticmethod
    def exec(analysis: SOOSDASTAnalysis, project_hash: str, branch_hash: str,
             scan_id: str) -> NoReturn:
        try:
            url = SOOSSARIFReport.generate_soos_sarif_url(base_uri=analysis.base_uri,
                                                          client_id=analysis.client_id,
                                                          project_hash=project_hash,
                                                          branch_hash=branch_hash,
                                                          scan_id=scan_id)

            headers = generate_header(api_key=analysis.api_key, content_type="application/json")
            sarif_json_response = None

            api_response: requests.Response = requests.get(url=url, headers=headers)
            sarif_json_response = handle_response(api_response)
            if type(sarif_json_response) is ErrorAPIResponse:
                error_message = "A Generate SARIF Report API Exception Occurred."
                log(f"{error_message}\n{sarif_json_response.code}-{sarif_json_response.message}")
            else:
                log("SARIF Report")
                log(json.dumps(sarif_json_response, indent=2))

            if sarif_json_response is None:
                log("This project contains no issues. There will be no SARIF upload.")
                return
            if analysis.github_pat is not None:
                sarif_report_str = json.dumps(sarif_json_response)
                compressed_sarif_response = base64.b64encode(gzip.compress(bytes(sarif_report_str, 'UTF-8')))

                github_body_request = {
                    "commit_sha": analysis.commit_hash,
                    "ref": analysis.branch_name,
                    "sarif": compressed_sarif_response.decode(encoding='UTF-8'),
                    "started_at": ANALYSIS_START_TIME,
                    "tool_name": "SOOS DAST"
                }

                github_sarif_url = SOOSSARIFReport.generate_github_sarif_url(sarif_destination=analysis.sarif_destination)
                headers = {"Accept": "application/vnd.github.v3+json", "Authorization": f"token {analysis.github_pat}"}

                log(f"GitHub SARIF URL: {github_sarif_url}")
                log(f"GitHub SARIF Header: {str(headers)}")
                log(f"GitHub SARIF Body Request")
                log(str(json.dumps(github_body_request)))
                log("Uploading SARIF Response")
                sarif_github_response = requests.post(url=github_sarif_url, data=json.dumps(github_body_request),
                                                      headers=headers)

                if sarif_github_response.status_code >= 400:
                    SOOSSARIFReport.handle_github_sarif_error(status=sarif_github_response.status_code,
                                                              json_response=sarif_github_response.json())
                else:
                    sarif_github_json_response = sarif_github_response.json()
                    sarif_url = sarif_github_json_response["url"]
                    sarif_github_status_response = requests.get(url=sarif_url,
                                                                headers=headers)

                    if sarif_github_status_response.status_code >= 400:
                        SOOSSARIFReport.handle_github_sarif_error(status=sarif_github_status_response.status_code,
                                                                  json_response=sarif_github_status_response.json())
                    else:
                        status_json_response = sarif_github_status_response.json()
                        processing_status = status_json_response["processing_status"]
                        log("SARIF Report uploaded to GitHub")
                        log(f"Processing Status: {processing_status}")
            if analysis.checkout_dir is not None:
                log("Writing sarif file")
                sarif_file = open(os.path.join(analysis.checkout_dir, "results.sarif"), "w")
                sarif_file.write(json.dumps(sarif_json_response))
                sarif_file.close()


        except Exception as sarif_exception:
            log(f"ERROR: {str(sarif_exception)}")

    @staticmethod
    def handle_github_sarif_error(status, json_response):

        error_message = json_response["message"] if json_response is not None and json_response[
            "message"] is not None else SOOSSARIFReport.errors_dict[status]
        if error_message is None:
            error_message = "An unexpected error has occurred uploading the sarif report to GitHub"

        log(f"ERROR: {error_message}")


if __name__ == "__main__":
    dastAnalysis = SOOSDASTAnalysis()
    dastAnalysis.run_analysis()

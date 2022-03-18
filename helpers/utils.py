from base64 import b64encode
from datetime import datetime, timedelta
from html import unescape
from sys import exit
from time import sleep
from typing import Optional, Any, NoReturn, Dict
from urllib.parse import unquote

from requests import Response, get
from requests.exceptions import (
    HTTPError,
)

import helpers.constants as Constants
from helpers.constants import RETRY_DELAY, REQUEST_TIMEOUT
from model.log_level import LogLevel, loggerFunc
from model.target_availability_check import TargetAvailabilityCheck

UTF_8: str = 'utf-8'


class ErrorAPIResponse:
    code: Optional[str] = None
    message: Optional[str] = None

    def __init__(self, api_response):
        for key in api_response:
            self.__setattr__(key, api_response[key])

        self.code = api_response["code"] if "code" in api_response else None
        self.message = api_response["message"] if "message" in api_response else None


def log(message: str, log_level: LogLevel = LogLevel.INFO) -> NoReturn:
    logFunc = loggerFunc.get(log_level)
    logFunc(str(message))


def print_line_separator() -> NoReturn:
    print(
        "----------------------------------------------------------------------------------------------------------"
    )


def exit_app(e) -> NoReturn:
    log(str(e), LogLevel.ERROR)
    exit(1)


def valid_required(key, value):
    if value is None or len(value) == 0:
        exit_app(key + " is required")


def has_value(prop) -> bool:
    return prop is not None and len(prop) > 0


def is_true(prop) -> bool:
    return prop is True


def check_site_is_available(url: str) -> bool:
    log(f"Waiting for {url} to be available")

    check = False
    max_time = datetime.utcnow() + timedelta(days=0, minutes=0, seconds=30)
    attempt = 1

    while datetime.utcnow() < max_time:
        log(f"Attempt {attempt} to connect to {url}")
        try:
            check = __send_ping__(url)

            if check is True:
                break

            if datetime.utcnow() + timedelta(0, RETRY_DELAY) > max_time:
                break
        except Exception as e:
            pass

        sleep(RETRY_DELAY)
        attempt = attempt + 1

    return check


def __send_ping__(target: str) -> bool:
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36'
    }
    response: Response = get(
        url=target,
        headers=headers,
        timeout=REQUEST_TIMEOUT,
        verify=False,  # nosec
        allow_redirects=True,  # nosec
    )

    return _check_status(response).is_available()


def _check_status(response: Response) -> TargetAvailabilityCheck:
    try:
        response.raise_for_status()
    except HTTPError as error:
        log(f"{type(error).__name__}: {response.status_code}")
        log(response.text, log_level=LogLevel.DEBUG)

        # 401 status indicates the host is available but may be behind basic auth
        if response.status_code == 401:
            return TargetAvailabilityCheck(True, response=response)

        return TargetAvailabilityCheck(
            False,
            response=response,
            unavailable_reason=error,
        )
    else:
        return TargetAvailabilityCheck(True, response=response)


def make_call(request) -> Response:
    attempt: int = 1
    error_response: Optional[Any] = None
    error_message: str = "An error has occurred"
    try:
        while attempt <= Constants.MAX_RETRY_COUNT:
            api_response: Response = request()

            if api_response.ok:
                return api_response
            else:
                error_response = api_response
                log(
                    f"An error has occurred performing the request. Retrying Request: {str(attempt)} attempts"
                )
                attempt = attempt + 1

        if attempt > Constants.MAX_RETRY_COUNT and error_response is not None:
            error_response = error_response.json()
            error_message = error_response["message"]

    except Exception as e:
        log(str(e))

    exit_app(error_message)


def set_generic_value(self, object_key: str, param_key: str, param_value: Optional[Any], is_required=False) -> NoReturn:
    if is_required:
        valid_required(param_key, param_value)

    if self[object_key]:
        self[object_key] = param_value


def log_error(api_response: Response) -> NoReturn:
    log(f"Status Code: {api_response.status_code}", log_level=LogLevel.ERROR)
    if api_response.text is not None:
        log(f"Response Text: {api_response.text}", log_level=LogLevel.ERROR)


def unescape_string(value: str) -> str or None:
    if value is None:
        return value

    return unescape(unquote(value))


def encode_report(report_json) -> NoReturn:
    if report_json['site'] is not None:
        for site in report_json['site']:
            if site['alerts'] is not None:
                for alert in site['alerts']:
                    if alert['instances'] is not None:
                        for instance in alert['instances']:
                            instance['base64Uri'] = convert_string_to_b64(instance['uri'])
                            instance['uri'] = Constants.EMPTY_STRING


def convert_string_to_b64(content: str) -> str:
    message_bytes = content.encode(UTF_8)
    base64_bytes = b64encode(message_bytes)
    base64_message = base64_bytes.decode(UTF_8)
    return base64_message


def process_custom_cookie_header_data(data: str) -> Dict:
    values: Dict = dict()

    if data is not None:
        dataModified = data.replace('[', Constants.EMPTY_STRING).replace(']', Constants.EMPTY_STRING)
        for value in dataModified.split(','):
            dict_key, dict_value = value.split(':')
            values[dict_key] = dict_value

    return values


def read_file(file_path):
    with open(file=file_path, mode=Constants.FILE_READ_MODE, encoding=Constants.UTF_8_ENCODING) as file:
        return file.read()


def write_file(file_path, file_content):
    with open(file=file_path, mode=Constants.FILE_WRITE_MODE, encoding=Constants.UTF_8_ENCODING) as file:
        file.write(file_content)
        file.close()


def handle_response(api_response):
    if api_response.status_code in range(400, 600):
        return ErrorAPIResponse(api_response.json())
    else:
        return api_response.json()


def handle_error(error: ErrorAPIResponse, api: str, attempt: int, max_retry: int):
    error_message = f"{api} has an error. Attempt {str(attempt)} of {str(max_retry)}"
    raise Exception(f"{error_message}\n{error.code}-{error.message}")


def generate_header(api_key: str, content_type: str):
    return {'x-soos-apikey': api_key, 'Content-Type': content_type}


def raise_max_retry_exception(attempt: int, retry_count: int):
    if attempt >= retry_count:
        raise Exception("The maximum retries allowed were reached")

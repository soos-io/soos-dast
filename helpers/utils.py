import sys
from datetime import datetime, timedelta
from time import sleep
import helpers.constants as Constants
from typing import Optional, Any, NoReturn
from urllib.parse import unquote
from html import unescape
import base64

from requests import Response, get
from requests.exceptions import (
    HTTPError,
)

from helpers.constants import RETRY_DELAY, REQUEST_TIMEOUT
from model.log_level import LogLevel, loggerFunc
from model.target_availability_check import TargetAvailabilityCheck


def log(message: str, log_level: LogLevel = LogLevel.INFO) -> None:
    logFunc = loggerFunc.get(log_level)
    logFunc(str(message))


def print_line_separator() -> None:
    print(
        "----------------------------------------------------------------------------------------------------------"
    )


def exit_app(e) -> None:
    log(str(e), LogLevel.ERROR)
    sys.exit(1)


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

    while datetime.utcnow() < max_time:
        check = __send_ping__(url)

        if check is True:
            break

        if datetime.utcnow() + timedelta(0, RETRY_DELAY) > max_time:
            break

        sleep(RETRY_DELAY)

    return check


def __send_ping__(target: str) -> bool:
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36'}
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
                            instance['uri'] = ''


def convert_string_to_b64(content: str) -> str:
    message_bytes = content.encode('utf-8')
    base64_bytes = base64.b64encode(message_bytes)
    base64_message = base64_bytes.decode('utf-8')
    return base64_message

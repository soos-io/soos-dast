from sys import exit
from typing import Dict, Iterable, NoReturn

from requests import Response
from requests.exceptions import HTTPError

import src.hooks.helpers.constants as Constants
from src.hooks.model.log_level import LogLevel, loggerFunc
from src.hooks.model.target_availability_check import TargetAvailabilityCheck


UTF_8: str = 'utf-8'

def log(message: str, log_level: LogLevel = LogLevel.INFO) -> None:
    logFunc = loggerFunc.get(log_level)
    logFunc(str(message))


def print_line_separator() -> None:
    print(
        "----------------------------------------------------------------------------------------------------------"
    )


def exit_app(e) -> NoReturn:
    log(str(e), LogLevel.ERROR)
    exit(1)


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

def array_to_dict(array: Iterable[str]):
    body = []
    for key_value in array:
        print(key_value)
        key, value = key_value.split(':', 1)
        body.append((key, value))
    return body
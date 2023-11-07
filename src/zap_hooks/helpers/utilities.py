from sys import exit
from typing import Dict, Iterable, NoReturn

import src.zap_hooks.helpers.constants as Constants
from src.zap_hooks.model.log_level import LogLevel, loggerFunc


def log(message: str, log_level: LogLevel = LogLevel.INFO) -> None:
    logFunc = loggerFunc.get(log_level)
    logFunc(str(message))


def exit_app(e) -> NoReturn:
    log(str(e), LogLevel.ERROR)
    exit(1)


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
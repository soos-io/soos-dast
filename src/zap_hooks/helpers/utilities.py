import json
from sys import exit
from typing import NoReturn

from src.zap_hooks.helpers.log_level import LogLevel, loggerFunc


def log(message: str, log_level: LogLevel = LogLevel.INFO) -> None:
    logFunc = loggerFunc.get(log_level)
    logFunc(str(message))


def exit_app(e) -> NoReturn:
    log(str(e), LogLevel.ERROR)
    exit(1)


def serialize_and_save(obj, filename):
    serialized_data = serialize_object(obj)
    with open(filename, 'w') as file:
        json.dump(serialized_data, file, indent=4)


def serialize_object(obj):
    serialized_data = {}
    for attr in dir(obj):
        value = getattr(obj, attr)
        if is_serializable(value):
            serialized_data[attr] = value
        else:
            pass
    return serialized_data


def is_serializable(value):
    try:
        json.dumps(value)
        return True
    except (TypeError, OverflowError):
        return False

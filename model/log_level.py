from enum import Enum

from helpers.log import console


class LogLevel(Enum):
    DEBUG = 0
    INFO = 1
    WARN = 2
    ERROR = 3
    CRITICAL = 4


loggerFunc = {
    LogLevel.INFO: console.info,
    LogLevel.WARN: console.warn,
    LogLevel.ERROR: console.error,
    LogLevel.CRITICAL: console.critical
}

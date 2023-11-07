from enum import Enum
from logging import DEBUG, INFO, WARN, ERROR, CRITICAL

from src.zap_hooks.helpers.logging import console


class LogLevel(Enum):
    DEBUG = DEBUG
    INFO = INFO
    WARN = WARN
    ERROR = ERROR
    CRITICAL = CRITICAL


loggerFunc = {
    LogLevel.DEBUG: console.debug,
    LogLevel.INFO: console.info,
    LogLevel.WARN: console.warn,
    LogLevel.ERROR: console.error,
    LogLevel.CRITICAL: console.critical
}

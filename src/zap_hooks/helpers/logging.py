"""
Logger classes for the ZAP CLI.
"""
import logging
import sys

from termcolor import colored
from datetime import datetime

from src.zap_hooks.helpers import constants as Constants


class ColorStreamHandler(logging.StreamHandler):
    """
    StreamHandler that prints color. This is used by the console client.
    """

    level_map = {
        logging.DEBUG: ("magenta", ["bold"]),
        logging.INFO: ("cyan", ["bold"]),
        logging.WARNING: ("yellow", ["bold"]),
        logging.ERROR: ("red", ["bold"]),
        logging.CRITICAL: ("red", ["bold", "reverse"]),
    }

    @property
    def is_tty(self):
        """is the stream a tty?"""
        isatty = getattr(self.stream, "isatty", None)
        return isatty and isatty()

    def emit(self, record):
        colorize = "console" in globals() and getattr(console, "colorize", False)

        if self.is_tty and colorize:
            color, attr = self.level_map[record.levelno]
            prefix = colored(
                str("[" + record.levelname + "]"), color, attrs=attr
            )
            if hasattr(record, "highlight") and record.highlight:
                record.msg = colored(record.msg, color, attrs=["bold", "reverse"])
        else:
            prefix = str("[" + record.levelname + "]")

        record.msg = f"{prefix} {record.msg}"

        logging.StreamHandler.emit(self, record)
class CustomFormatter(logging.Formatter):
    """Custom Formatter to match the TypeScript timestamp style."""

    def formatTime(self, record, datefmt=None):
        utc_time = datetime.utcfromtimestamp(record.created)
        t = utc_time.strftime("%Y-%m-%d %I:%M:%S %p")
        return f"{t} UTC"


class ConsoleLogger(logging.Logger):
    """Log to the console with some color decorations."""

    def __init__(self, name):
        super(ConsoleLogger, self).__init__(name)
        self.setLevel(logging.DEBUG)
        handler = ColorStreamHandler(sys.stdout)
        formatter = CustomFormatter(fmt=Constants.LOG_FORMAT)
        handler.setFormatter(formatter)
        self.addHandler(handler)
        self.propagate = False

class LoggingFilter(logging.Filter):
    """Filter out logs from the console logger."""

    def filter(self, record):
        return record.name not in Constants.FILTER_LOGS
    
default_logger_class = logging.getLoggerClass()

logging.setLoggerClass(ConsoleLogger)
console = logging.getLogger("SOOS DAST")
console.setLevel(logging.INFO)

logging.setLoggerClass(default_logger_class)

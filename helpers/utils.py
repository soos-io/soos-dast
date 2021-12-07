import logging
import sys
from datetime import datetime, timedelta
from time import sleep

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


def _check_site_is_available(url: str) -> bool:
    logging.info(f"Waiting for {url} to be available")

    check = False
    max_time = datetime.utcnow() + timedelta(0, self._config.availability_timeout)

    while datetime.utcnow() < max_time:
        check = send_ping(url)

        if check is True:
            break

        if datetime.utcnow() + timedelta(0, RETRY_DELAY) > max_time:
            break

        sleep(RETRY_DELAY)

    return check


def send_ping(target: str) -> bool:
    response: Response = get(
        url=target,
        timeout=REQUEST_TIMEOUT,
        verify=False,  # nosec
        allow_redirects=True,  # nosec
    )


def _check_status(self, response: Response) -> TargetAvailabilityCheck:
    try:
        response.raise_for_status()
    except HTTPError as error:
        logging.info(f"{type(error).__name__}: {response.status_code}")
        logging.debug(response.text)

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

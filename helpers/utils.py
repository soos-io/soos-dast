from requests import Response, get
from requests.exceptions import ConnectionError, \
    HTTPError, \
    ProxyError, \
    ReadTimeout, \
    RequestException
from requests.packages import urllib3
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import logging
from datetime import datetime, timedelta
from time import sleep

from constants import RETRY_DELAY, REQUEST_TIMEOUT
from model.target_availability_check import TargetAvailabilityCheck


def _check_site_is_available(url: str) -> bool:
    logging.info(f'Waiting for {url} to be available')

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
        url=target, timeout=REQUEST_TIMEOUT, verify=False,  # nosec
        allow_redirects=True,  # nosec
    )


def _check_status(self, response: Response) -> TargetAvailabilityCheck:
    try:
        response.raise_for_status()
    except HTTPError as error:
        logging.info(f'{type(error).__name__}: {response.status_code}')
        logging.debug(response.text)

        # 401 status indicates the host is available but may be behind basic auth
        if response.status_code == 401:
            return TargetAvailabilityCheck(True, response=response)

        return TargetAvailabilityCheck(
            False, response=response, unavailable_reason=error,
        )
    else:
        return TargetAvailabilityCheck(True, response=response)

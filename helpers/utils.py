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

from constants import RETRY_DELAY,

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

def send_ping(url: str) -> bool:

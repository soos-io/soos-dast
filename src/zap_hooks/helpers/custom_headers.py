import sys
import traceback
from typing import Dict

from src.zap_hooks.helpers.configuration import DASTConfig
from src.zap_hooks.helpers.utilities import log
import src.zap_hooks.helpers.constants as Constants


def load(config: DASTConfig, zap):
    if config.header:
        log(f"loading custom headers...")
        script_name: str = 'request_headers'

        header_data = process_custom_header_data(config.header)

        try:
            for key, value in header_data.items():
                zap.replacer.add_rule(
                    description=f"ReqHeader {key}",
                    enabled=True,
                    matchtype='REQ_HEADER',
                    matchregex=False,
                    matchstring=key,
                    replacement=value,
                )
        except Exception as error:
            log(f"error in zap_{script_name}.load loading custom script:\n{traceback.format_exc()}")
            log(f"Error: {error}")
            sys.exit(1)


def process_custom_header_data(data: str) -> Dict:
    values: Dict = dict()

    if data is not None:
        dataModified = data.replace('[', Constants.EMPTY_STRING).replace(']', Constants.EMPTY_STRING)
        for value in dataModified.split(','):
            dict_key, dict_value = value.split(':')
            values[dict_key] = dict_value

    return values

import sys
import traceback

from src.zap_hooks.helpers.configuration import DASTConfig
from src.zap_hooks.helpers.utilities import log, process_custom_header_data


def load(config: DASTConfig, zap):
    if config.header:
        log(f"loading custom headers...")
        script_name: str = 'request_headers'

        header_data = process_custom_header_data(config.header)

        try:
            for key, value in header_data.items():
                zap.replacer.add_rule(description=f"ReqHeader {key}", enabled=True, matchtype='REQ_HEADER',
                                      matchregex=False, matchstring=key, replacement=value)
        except Exception as error:
            log(f"error in zap_{script_name}.load loading custom script: {traceback.print_exc()}")
            log(f"Error: {error}")
            sys.exit(1)

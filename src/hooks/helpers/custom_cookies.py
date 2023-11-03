import sys
import traceback
import json

from src.hooks.helpers.configuration import DASTConfig
from src.hooks.helpers.constants import ZAP_HTTP_SENDER_SCRIPTS_FOLDER_PATH
from src.hooks.helpers.utils import log, process_custom_cookie_header_data


def load(config: DASTConfig, zap):
    log(f"loading cookies: {config.cookies}")
    if config.cookies:
        script_name: str = 'request_cookies'
        request_cookies_script_path = f"{ZAP_HTTP_SENDER_SCRIPTS_FOLDER_PATH}{script_name}.js"

        cookies_data = process_custom_cookie_header_data(config.cookies)

        try:
            log(f"Loading custom script: {request_cookies_script_path}")
            zap.script.load(script_name, 'httpsender', 'Oracle Nashorn', request_cookies_script_path)
            zap.script.enable(script_name)
            zap.script.set_global_var(varkey='custom_cookies', varvalue=json.dumps(cookies_data, sort_keys=True))
        except Exception as error:
            log(f"error in zap_{script_name}.load loading custom script: {traceback.print_exc()}")
            log(f"Error: {error}")
            sys.exit(1)

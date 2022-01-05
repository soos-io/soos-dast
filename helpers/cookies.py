import os
import traceback

from helpers.configuration import DASTConfig
from helpers.constants import ZAP_SCRIPTS_FOLDER_PATH
from helpers.utils import log


def load(config: DASTConfig, zap):
    if config.cookies:
        script_name: str = 'request_cookies'
        request_cookies_script_path = f"{ZAP_SCRIPTS_FOLDER_PATH}{script_name}.js"

        try:
            log(f"Loading custom script: {request_cookies_script_path}")
            zap.script.load(script_name, 'active', 'Alfredo Benassi', request_cookies_script_path)
            zap.script.set_script_var(script_name=script_name, varkey='cookies', varvalue=config.cookies)
            zap.script.enable(script_name)
            zap.ascan.set_option_target_params_injectable(31)
        except Exception as e:
            log(f"error in zap_{script_name}.load loading custom script: {traceback.print_exc()}")
            os.exit(1)

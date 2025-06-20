import os
import sys
import traceback
from typing import Optional, List

from src.zap_hooks.helpers.constants import EMPTY_STRING
from src.zap_hooks.helpers.utilities import log
from src.zap_hooks.model.log_level import LogLevel

class DASTConfig:
    extra_zap_params = None
    auth_login_url: Optional[str] = None
    auth_username: Optional[str] = None
    auth_password: Optional[str] = None
    auth_submit_action: Optional[str] = None
    auth_form_type: Optional[str] = None
    auth_delay_time: Optional[int] = None
    auth_bearer_token: Optional[str] = None
    auth_username_field_name: Optional[str] = None
    auth_password_field_name: Optional[str] = None
    auth_submit_field_name: Optional[str] = None
    auth_submit_second_field_name: Optional[str] = None
    auth_check_delay: Optional[float] = None
    auth_check_element: Optional[str] = None
    auth_verification_url: Optional[str] = None
    auth_exclude_urls: Optional[List[str]] = None
    auth_include_urls: Optional[List[str]] = None
    debug_mode: Optional[bool] = False
    disable_rules: Optional[str] = None
    exclude_urls_file: Optional[str] = None
    header: Optional[str] = None

    def __init__(self):
        self.extra_zap_params = None

    def load_config(self, extra_zap_params):
        log(f"load_config: {extra_zap_params}")
        try:
            self.auth_login_url = os.environ.get('AUTH_LOGIN_URL') or EMPTY_STRING
            self.auth_username = os.environ.get('AUTH_USERNAME') or EMPTY_STRING
            self.auth_password = os.environ.get('AUTH_PASSWORD') or EMPTY_STRING
            self.auth_submit_action = os.environ.get('AUTH_SUBMIT_ACTION') or 'click'
            self.auth_form_type = os.environ.get('AUTH_FORM_TYPE') or 'simple'
            self.auth_bearer_token = os.environ.get('AUTH_BEARER_TOKEN') or EMPTY_STRING
            self.auth_username_field_name = os.environ.get('AUTH_USERNAME_FIELD') or 'username'
            self.auth_password_field_name = os.environ.get('AUTH_PASSWORD_FIELD') or 'password'
            self.auth_submit_field_name = os.environ.get('AUTH_SUBMIT_FIELD') or 'login'
            self.auth_submit_second_field_name =  os.environ.get('AUTH_SECOND_SUBMIT_FIELD') or 'login'
            self.auth_delay_time = float(os.environ.get('AUTH_DELAY_TIME') or 1)
            self.auth_check_delay = float(os.environ.get('AUTH_CHECK_DELAY') or 5)
            self.auth_check_element = os.environ.get('AUTH_CHECK_ELEMENT') or EMPTY_STRING
            self.auth_verification_url = os.environ.get('AUTH_VERIFICATION_URL') or EMPTY_STRING
            self.debug_mode = os.environ.get('DEBUG_MODE') or False
            self.disable_rules = self._get_hook_param_list(os.environ.get('DISABLE_RULES')) or None
            self.exclude_urls_file = os.environ.get('EXCLUDE_URLS_FILE') or None
            self.header = os.environ.get('CUSTOM_HEADER') or EMPTY_STRING

            self.extra_zap_params = extra_zap_params
            log(f"Extra params passed by ZAP: {self.extra_zap_params}")

        except Exception as error:
            log(f"error in start_docker_zap:\n{traceback.format_exc()}", log_level=LogLevel.ERROR)
            sys.exit(1)

    def _get_hook_param_list(self, value):
            if value is None:
                return []
            value = list(filter(None, value.split(',')))
            return [s.strip() for s in value]
from helpers.constants import EMPTY_STRING
from helpers.utils import log
import sys
import traceback
from typing import Optional, List

from model.log_level import LogLevel


class DASTConfig:
    extra_zap_params = None
    auth_login_url: Optional[str] = None
    auth_username: Optional[str] = None
    auth_password: Optional[str] = None
    auth_otp_secret: Optional[str] = None
    auth_submit_action: Optional[str] = None
    auth_form_type: Optional[str] = None
    auth_token_endpoint: Optional[str] = None
    auth_bearer_token: Optional[str] = None
    auth_username_field_name: Optional[str] = None
    auth_password_field_name: Optional[str] = None
    auth_otp_field_name: Optional[str] = None
    auth_submit_field_name: Optional[str] = None
    auth_first_submit_field_name: Optional[str] = None
    auth_check_delay: Optional[float] = None
    auth_check_element: Optional[str] = None
    auth_exclude_urls: Optional[List[str]] = None
    auth_include_urls: Optional[List[str]] = None
    xss_collector: Optional[str] = None
    cookies: Optional[str] = None
    header: Optional[str] = None
    oauth_token_url: Optional[str] = None
    oauth_parameters: Optional[str] = None

    def __init__(self):
        self.extra_zap_params = None

    def load_config(self, extra_zap_params):
        log(f"load_config: {extra_zap_params}")
        try:
            self.extra_zap_params = extra_zap_params
            log(f"Extra params passed by ZAP: {self.extra_zap_params}")

            self.auth_login_url = self._get_zap_param('auth.loginurl') or EMPTY_STRING
            self.auth_username = self._get_zap_param('auth.username') or EMPTY_STRING
            self.auth_password = self._get_zap_param('auth.password') or EMPTY_STRING
            self.auth_otp_secret = self._get_zap_param('auth.otpsecret') or EMPTY_STRING
            self.auth_submit_action = self._get_zap_param('auth.submit_action') or 'click'
            self.auth_form_type = self._get_zap_param('auth.form_type') or 'SIMPLE'
            self.auth_token_endpoint = self._get_zap_param('auth.token_endpoint') or EMPTY_STRING
            self.auth_bearer_token = self._get_zap_param('auth.bearer_token') or EMPTY_STRING
            self.auth_username_field_name = self._get_zap_param('auth.username_field') or 'username'
            self.auth_password_field_name = self._get_zap_param('auth.password_field') or 'password'
            self.auth_display = self._get_zap_param('auth.display') or EMPTY_STRING
            self.auth_otp_field_name = self._get_zap_param('auth.otp_field') or 'otp'
            self.auth_submit_field_name = self._get_zap_param('auth.submit_field') or 'login'
            self.auth_first_submit_field_name = self._get_zap_param('auth.first_submit_field') or 'next'
            self.auth_check_delay = self._get_zap_param_float('auth.check_delay') or 5
            self.auth_check_element = self._get_zap_param('auth.check_element') or EMPTY_STRING
            self.auth_exclude_urls = self._get_zap_param_list('auth.exclude') or list()
            self.auth_include_urls = self._get_zap_param_list('auth.include') or list()
            self.xss_collector = self._get_zap_param('xss.collector') or EMPTY_STRING
            self.cookies = self._get_zap_param('request.custom_cookies') or EMPTY_STRING
            self.header = self._get_zap_param('request.custom_header') or EMPTY_STRING
            self.oauth_token_url = self._get_zap_param('oauth.token_url') or EMPTY_STRING   
            self.oauth_parameters = self._get_zap_param_list('oauth.parameters') or EMPTY_STRING

        except Exception as error:
            log(f"error in start_docker_zap: {traceback.print_exc()}", log_level=LogLevel.ERROR)
            sys.exit(1)

    def _get_zap_param(self, key):
        for param in self.extra_zap_params:
            if param.find(key) > -1:
                value = param[len(key) + 1:]
                log(f"_get_zap_param {key}: {value}")
                return value

    def _get_zap_param_list(self, key):
        for param in self.extra_zap_params:
            if param.find(key) > -1:
                value = list(filter(None, param[len(key) + 1:].split(',')))
                log(f"_get_zap_param_list {key}: {value}")
                return [s.strip() for s in value]

    def _get_zap_param_boolean(self, key):
        for param in self.extra_zap_params:
            if param.find(key) > -1:
                value = param[len(key) + 1:] in ['1', 'True', 'true']
                log(f"_get_zap_param_boolean {key}: {value}")
                return value

    def _get_zap_param_float(self, key):
        for param in self.extra_zap_params:
            if param.find(key) > -1:
                value = float(param[len(key) + 1:])
                log(f"_get_zap_param_float {key}: {value}")
                return value

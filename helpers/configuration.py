from helpers.utils import log
import os
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

    def __init__(self):
        self.extra_zap_params = None

    def load_config(self, extra_zap_params):
        try:
            self.extra_zap_params = extra_zap_params
            log(f"Extra params passed by ZAP: {self.extra_zap_params}")

            self.auth_login_url = self._get_zap_param('auth.loginurl') or ''
            self.auth_username = self._get_zap_param('auth.username') or ''
            self.auth_password = self._get_zap_param('auth.password') or ''
            self.auth_otp_secret = self._get_zap_param('auth.otpsecret') or ''
            self.auth_submit_action = self._get_zap_param('auth.submitaction') or 'click'
            self.auth_token_endpoint = self._get_zap_param('auth.token_endpoint') or ''
            self.auth_bearer_token = self._get_zap_param('auth.bearer_token') or ''
            self.auth_username_field_name = self._get_zap_param('auth.username_field') or 'username'
            self.auth_password_field_name = self._get_zap_param('auth.password_field') or 'password'
            self.auth_otp_field_name = self._get_zap_param('auth.otp_field') or 'otp'
            self.auth_submit_field_name = self._get_zap_param('auth.submit_field') or 'login'
            self.auth_first_submit_field_name = self._get_zap_param('auth.first_submit_field') or 'next'
            self.auth_check_delay = self._get_zap_param_float('auth.check_delay') or 5
            self.auth_check_element = self._get_zap_param('auth.check_element') or ''
            self.auth_exclude_urls = self._get_zap_param_list('auth.exclude') or list()
            self.auth_include_urls = self._get_zap_param_list('auth.include') or list()
            self.xss_collector = self._get_zap_param('xss.collector') or ''
        except Exception:
            log(f"error in start_docker_zap: {traceback.print_exc()}", log_level=LogLevel.ERROR)
            os.exit(1)

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
                return value

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

import traceback
from typing import List
import os

from src.zap_hooks.helpers.auth import authenticate
from src.zap_hooks.helpers.configuration import DASTConfig
from src.zap_hooks.helpers.utilities import log, exit_app, LogLevel, serialize_and_save
from src.zap_hooks.helpers import custom_headers as headers
from src.zap_hooks.helpers import constants as Constants

config = DASTConfig()


# Triggered when running a script directly (ex. python zap-baseline.py ...)
def start_docker_zap(docker_image, port, extra_zap_params, mount_dir):
    config.load_config(extra_zap_params)

# Triggered when running from the Docker image
def start_zap(port, extra_zap_params):
    config.load_config(extra_zap_params)


def zap_started(zap, target):
    log("zap_started_hook is running")
    os.system("cp -R /zap/reports/traditional-json/report.json /root/.ZAP/reports/traditional-json/report.json")
    try:
        # ZAP Docker scripts reset the target to the root URL
        if target.count('/') > 2:
            # The url can include a valid path, but always reset to spider the host
            target = target[0:target.index('/', 8) + 1]

        zap.ascan.update_scan_policy(scanpolicyname=Constants.ZAP_ACTIVE_SCAN_POLICY_NAME, attackstrength="LOW")

        if config.disable_rules:
            pscan_disabled_rules = set(config.disable_rules).intersection(set(_all_passive_scanner_rules(zap)))
            ascan_disabled_rules = set(config.disable_rules).intersection(set(_all_active_scanner_rules(zap, Constants.ZAP_ACTIVE_SCAN_POLICY_NAME)))
            zap.pscan.disable_scanners(','.join(pscan_disabled_rules))
            zap.ascan.disable_scanners(','.join(ascan_disabled_rules), Constants.ZAP_ACTIVE_SCAN_POLICY_NAME)
            log(f"disabled rules: {config.disable_rules}")
        if config.auth_login_url or config.auth_bearer_token or config.auth_token_endpoint or config.oauth_token_url:
            authenticate(zap, target, config)
        else:
            log(
                'No login URL, Token Endpoint or Bearer token provided - skipping authentication',
                log_level=LogLevel.WARN
            )
        headers.load(config, zap)
        if config.debug_mode:
            serialize_and_save(zap.ascan, 'wrk/ascan_data_started.json')
            serialize_and_save(zap.spider, 'wrk/spider_data_started.json')
            serialize_and_save(zap.core, 'wrk/core_data_started.json')
            serialize_and_save(zap.context, 'wrk/context_data_started.json')
        if config.exclude_urls_file:
            exclude_urls_file_path = f"wrk/{config.exclude_urls_file}"
            with open(exclude_urls_file_path) as f:
                for line in f:
                    url = line.strip()
                    log(f"Excluding url on spider: {url}")
                    zap.spider.exclude_from_scan(url)
            
    except Exception:
        exit_app(f"error in zap_started: {traceback.print_exc()}")

    return zap, target

def zap_import_context(zap, context_file):
    log("zap_import_context_hook is running")
    log(f"importing context from file: {context_file}")

def zap_pre_shutdown(zap):
    if config.debug_mode:
        serialize_and_save(zap.ascan, 'wrk/ascan_data_pre_shutdown.json')
        serialize_and_save(zap.spider, 'wrk/spider_data_pre_shutdown.json')
        serialize_and_save(zap.core, 'wrk/core_data_pre_shutdown.json')
        serialize_and_save(zap.context, 'wrk/context_data_pre_shutdown.json')
    log("URLs Discovered:")
    with open('core_urls.txt', 'w') as f:
        for url in zap.core.urls():
            f.write(f"{url}\n")
            log(f"-- {url}")

def _all_active_scanner_rules(zap, policy_name) -> List[str]: return [scanner['id'] for scanner in zap.ascan.scanners(policy_name)]

def _all_passive_scanner_rules(zap) -> List[str]: return [scanner['id'] for scanner in zap.pscan.scanners]

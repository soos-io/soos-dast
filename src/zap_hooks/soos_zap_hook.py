import sys
import traceback
from typing import List

from src.zap_hooks.helpers.auth_context import authenticate
from src.zap_hooks.helpers.configuration import DASTConfig
from src.zap_hooks.helpers.utilities import log, exit_app
from src.zap_hooks.helpers import custom_cookies as cookies
from src.zap_hooks.helpers import custom_headers as headers
from src.zap_hooks.helpers import constants as Constants
import src.zap_hooks.helpers.globals as globals

config = DASTConfig()


# Triggered when running a script directly (ex. python zap-baseline.py ...)
def start_docker_zap(docker_image, port, extra_zap_params, mount_dir):
    config.load_config(extra_zap_params)

# Triggered when running from the Docker image
def start_zap(port, extra_zap_params):
    config.load_config(extra_zap_params)


def zap_started(zap, target):
    log("zap_started_hook is running")
    globals.initialize()
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

        authenticate(zap, target, config)
        cookies.load(config, zap)
        headers.load(config, zap)
    except Exception:
        exit_app(f"error in zap_started: {traceback.print_exc()}")
        sys.exit(1)

    return zap, target

def zap_import_context(zap, context_file):
    log("zap_import_context_hook is running")
    log(f"importing context from file: {context_file}")
    zap.context.remove_context(globals.context_name)

def zap_pre_shutdown(zap):
    log("Overview of spidered URL's:")
    with open('spidered_urls.txt', 'w') as f:
        for url in zap.spider.all_urls:
            f.write(f"{url}\n")
            log(f"found: {url}")

def _all_active_scanner_rules(zap, policy_name) -> List[str]: return [scanner['id'] for scanner in zap.ascan.scanners(policy_name)]

def _all_passive_scanner_rules(zap) -> List[str]: return [scanner['id'] for scanner in zap.pscan.scanners]

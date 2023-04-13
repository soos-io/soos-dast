from helpers.auth import DASTAuth
from helpers.configuration import DASTConfig
import helpers.custom_cookies as cookies
import helpers.custom_headers as headers
import helpers.constants as Constants
import sys
import traceback
from helpers.utils import log, exit_app

config = DASTConfig()


# Triggered when running a script directly (ex. python zap-baseline.py ...)
def start_docker_zap(docker_image, port, extra_zap_params, mount_dir):
    config.load_config(extra_zap_params)


# Triggered when running from the Docker image
def start_zap(port, extra_zap_params):
    config.load_config(extra_zap_params)


def zap_started(zap, target):
    log(f"zap_started_hook is running")
    try:
        # ZAP Docker scripts reset the target to the root URL
        if target.count('/') > 2:
            # The url can include a valid path, but always reset to spider the host
            target = target[0:target.index('/', 8) + 1]

        zap.ascan.update_scan_policy(scanpolicyname=Constants.ZAP_ACTIVE_SCAN_POLICY_NAME, attackstrength="LOW")
        log(f"disabled rules: {config.disable_rules}")
        zap.pscan.disable_scanners(','.join(config.disable_rules))
        zap.ascan.disable_scanners(','.join(config.disable_rules), Constants.ZAP_ACTIVE_SCAN_POLICY_NAME)

        auth = DASTAuth(config)
        auth.authenticate(zap, target)
        cookies.load(config, zap)
        headers.load(config, zap)
    except Exception:
        exit_app(f"error in zap_started: {traceback.print_exc()}")
        sys.exit(1)

    return zap, target


def zap_pre_shutdown(zap):
    log("Overview of spidered URL's:")
    with open('spidered_urls.txt', 'w') as f:
        for url in zap.spider.all_urls:
            f.write(f"{url}\n")
            log(f"found: {url}")
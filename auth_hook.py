from helpers.auth import DASTAuth
from helpers.configuration import DASTConfig
import helpers.blindxss as blindxss
import os
import traceback
from helpers.utils import log
from model.log_level import LogLevel

config = DASTConfig()


# Triggered when running a script directly (ex. python zap-baseline.py ...)
def start_docker_zap(docker_image, port, extra_zap_params, mount_dir):
    config.load_config(extra_zap_params)


# Triggered when running from the Docker image
def start_zap(port, extra_zap_params):
    config.load_config(extra_zap_params)


def zap_started(zap, target):
    try:
        # ZAP Docker scripts reset the target to the root URL
        if target.count('/') > 2:
            # The url can include a valid path, but always reset to spider the host
            target = target[0:target.index('/', 8) + 1]

        scan_policy = 'Default Policy'
        zap.ascan.update_scan_policy(scanpolicyname=scan_policy, attackstrength="LOW")

        auth = DASTAuth(config)
        auth.authenticate(zap, target)

        blindxss.load(config, zap)
    except Exception:
        log(f"error in zap_started: {traceback.print_exc()}", log_level=LogLevel.ERROR)
        os.exit(1)

    return zap, target


def zap_pre_shutdown(zap):
    log("Overview of spidered URL's:")
    for url in zap.spider.all_urls:
        log(f"found: {url}")

import os
import traceback
import logging
from helpers.configuration import DASTConfig
from helpers.utils import log
import random


def load(config: DASTConfig, zap):
    # Load Custom Blind XSS scripts if a collector URI was provided
    if config.xss_collector:
        xss_script_path = replace_collector_uri(config.xss_collector)

        try:
            logging.info(f"Loading custom script: {xss_script_path}")
            zap.script.load('blindxss', 'active', 'Oracle Nashorn', xss_script_path)
            zap.script.enable('blindxss')
            zap.ascan.set_option_target_params_injectable(31)
        except Exception as e:
            log(f"error in zap_blindxss.load loading custom script: {traceback.print_exc()}")
            os.exit(1)


def replace_collector_uri(uri):
    template_script_path = '/home/zap/.ZAP_D/scripts/scripts/active/blindxss.js'

    with open(template_script_path, 'r') as file:
        file_data = file.read()

    file_data = file_data.replace('callbackdomain.com', uri)

    random_suffix = random.randint(1000, 9999)
    script_path = f'/home/zap/.ZAP_D/scripts/scripts/active/bxxs_{random_suffix}.js'
    with open(script_path, 'w') as file:
        file.write(file_data)
    return script_path

from traceback import print_exc
from helpers.configuration import DASTConfig
from helpers.utils import log, read_file
from random import randint
from sys import exit


def load(config: DASTConfig, zap):
    # Load Custom Blind XSS scripts if a collector URI was provided
    if config.xss_collector:
        xss_script_path = replace_collector_uri(config.xss_collector)

        try:
            log(f"Loading custom script: {xss_script_path}")
            zap.script.load('blindxss', 'active', 'Oracle Nashorn', xss_script_path)
            zap.script.enable('blindxss')
            zap.ascan.set_option_target_params_injectable(31)
        except Exception as error:
            log(f"error in zap_blindxss.load loading custom script: {print_exc()}")
            exit(1)


def replace_collector_uri(uri):
    template_script_path = '/home/zap/.ZAP/scripts/scripts/active/blindxss.js'

    file_data = read_file(file_path=template_script_path)

    file_data = file_data.replace('callbackdomain.com', uri)

    random_suffix = randint(1000, 9999)
    script_path = f'/home/zap/.ZAP/scripts/scripts/active/bxxs_{random_suffix}.js'
    with open(script_path, 'w') as file:
        file.write(file_data)
    return script_path

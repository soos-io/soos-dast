from src.zap_hooks.helpers.constants import ZAP_AUTH_CONTEXT
def initialize(): 
    global context_name
    global context_id
    context_name = ZAP_AUTH_CONTEXT
    context_id = None
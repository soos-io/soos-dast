from re import search
from time import sleep
import sys

from selenium import webdriver
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.by import By
from selenium.common.exceptions import NoSuchElementException, TimeoutException
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
import zap_common
import logging
import json

from src.zap_hooks.helpers.browser_storage import BrowserStorage
from src.zap_hooks.helpers.utilities import log
from src.zap_hooks.helpers.log_level import LogLevel
from src.zap_hooks.helpers.logging import LoggingFilter


def setup_webdriver() -> webdriver.Chrome:
    log('Start webdriver')
    options = webdriver.ChromeOptions()
    options.add_experimental_option('excludeSwitches', ['enable-logging'])
    options.add_argument('--headless')
    options.add_argument('--ignore-certificate-errors')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    options.set_capability("goog:loggingPrefs", {"performance": "ALL"})
    options.binary_location = '/opt/google/chrome/google-chrome'

    driver = webdriver.Chrome(options=options)
    driver.implicitly_wait(30)
    driver.set_page_load_timeout(30)
    driver.set_script_timeout(30)
    driver.set_window_size(1920, 1080)
    driver.maximize_window()

    loggingFilter = LoggingFilter()
    for handler in logging.getLogger().handlers:
        handler.addFilter(loggingFilter)

    return driver


def authenticate(zap, target, config):
    driver_instance = setup_webdriver()

    if config.auth_login_url:
        login(driver_instance, config)
        set_authentication(zap, target, driver_instance)
    elif config.auth_bearer_token:
        add_authorization_header(zap, f"Bearer {config.auth_bearer_token}")

    if config.auth_verification_url:
        validate_authentication_url(driver_instance, config.auth_verification_url)

    log(f"Cleaning up web driver...")
    driver_instance.quit()


def set_authentication(zap, target, driver):
    log('Finding authentication cookies')
    # Create an empty session for session cookies
    if zap is not None:
        zap.httpsessions.add_session_token(target, 'session_token')
        zap.httpsessions.create_empty_session(target, 'auth-session')

    # add all found cookies as session cookies
    for cookie in driver.get_cookies():
        if zap is not None:
            zap.httpsessions.set_session_token_value(target, 'auth-session', cookie['name'], cookie['value'])
        log(f"Cookie added: {cookie['name']}={cookie['value']}")

    # add token from cookies if exists
    add_token_from_cookie(zap, driver.get_cookies())

    # Mark the session as active
    if zap is not None:
        zap.httpsessions.set_active_session(target, 'auth-session')
        log(f"Active session: {zap.httpsessions.active_session(target)}")

    # try to find JWT tokens in Local Storage and Session Storage and add them as Authorization header
    localStorage = BrowserStorage(driver, 'localStorage')
    sessionStorage = BrowserStorage(driver, 'sessionStorage')
    add_token_from_browser_storage(zap, localStorage)
    add_token_from_browser_storage(zap, sessionStorage)


def validate_authentication_url(driver, url):
    """Validate that the authentication URL is called during the authentication process and returns a 200/302 status code."""
    log(f"Validating authentication url: {url}")
    log_entries = driver.get_log("performance")

    status = 0
    for entry in log_entries:
        obj_serialized: str = entry.get("message")
        obj = json.loads(obj_serialized)
        message = obj.get("message")
        method = message.get("method")
        if method == "Network.responseReceived":
            response = message.get("params", {}).get("response", {})
            response_url = response.get("url")
            response_status = response.get("status")
            if response_url.startswith("http"):
                log(f"Comparing {response_url} {response_status}")
            if response_url == url:
                status = response_status
                break

    if status in (200, 302):
        log(f"Status code is {status} for {url}, authentication was successful")
    elif status == 0:
        log(f"Authentication url {url} was not found, authentication failed.")
        sys.exit(1)
    else:
        log(f"Status code is not 200/302 for {url}, it is {status}")
        sys.exit(1)


def add_token_from_browser_storage(zap, browserStorage):
    """Add JWT token from browser storage as Authorization header"""
    for key in browserStorage:
        log(f"Found key: {key}")
        match = search('(eyJ[^"]*)', browserStorage.get(key))
        if match:
            auth_header = "Bearer " + match.group()
            add_authorization_header(zap, auth_header)


def add_token_from_cookie(zap, cookies):
    """Add JWT token from cookies as Authorization header"""
    for cookie in cookies:
        if cookie['name'] == 'token':
            auth_header = "Bearer " + cookie['value']
            add_authorization_header(zap, auth_header)


def add_authorization_header(zap, auth_token):
    """Add an authorization header to all requests using the zap replacer"""
    if zap is not None:
        zap.replacer.add_rule(
            description='AuthHeader',
            enabled=True,
            matchtype='REQ_HEADER',
            matchregex=False,
            matchstring='Authorization',
            replacement=auth_token,
        )
        log("Authorization header added")


def login(driver, config):
    """Main function to perform login via form"""
    log(f"authenticate using webdriver against URL: {config.auth_login_url}")

    driver.get(config.auth_login_url)
    sleep(config.auth_delay_time)
    log('automatically finding login elements')

    if config.auth_username:
        element = find_element(
            config.auth_username_field_name,
            "input",
            "(//input[contains(@name,'User') or contains(@name,'user') or @type='email'])[1]",
            driver,
        )
        if element is not None:
            element.clear()
            element.send_keys(config.auth_username)
            log(f"Filled the {config.auth_username_field_name} element")

    if config.auth_form_type == 'wait_for_password':
        log(f"Waiting for {config.auth_password_field_name} element to load")
        sleep(config.auth_delay_time)
    elif config.auth_form_type == 'multi_page':
        element = find_element(config.auth_submit_field_name, "submit", "//*[@type='submit' or @type='button']", driver)
        if element is not None:
            actions = ActionChains(driver)
            actions.move_to_element(element).click().perform()
            log("Clicked the first submit element for multi page")
            sleep(config.auth_delay_time)

    if config.auth_password:
        element = find_element(
            config.auth_password_field_name,
            "password",
            "//input[@type='password' or contains(@name,'Pass') or contains(@name,'pass')]",
            driver,
        )
        if element is not None:
            element.clear()
            element.send_keys(config.auth_password)
            log(f"Filled the {config.auth_password_field_name} element")

    if config.auth_form_type == 'multi_page':
        submit_button = config.auth_submit_second_field_name
    else:
        submit_button = config.auth_submit_field_name
    submit_form(config.auth_submit_action, submit_button, config.auth_password_field_name, driver)
    sleep(config.auth_delay_time)


def submit_form(submit_action, submit_field_name, password_field_name, driver):
    """Submit the form using the submit action can either be click or submit"""
    if submit_action == "click":
        element = find_element(submit_field_name, "submit", "//*[@type='submit' or @type='button']", driver)
        if element is not None:
            actions = ActionChains(driver)
            actions.move_to_element(element).click().perform()
            log(f"Clicked the {submit_field_name} element")
        else:
            log(f"Didn't find the {submit_field_name} element")
    else:
        element = find_element(
            password_field_name,
            "password",
            "//input[@type='password' or contains(@name,'Pass') or contains(@name,'pass')]",
            driver,
        )
        if element is not None:
            element.submit()
            log('Submitted the form')
        else:
            log(f"Didn't find the {password_field_name} element")


def find_element(id_name_or_xpath, element_type, default_xpath, driver):
    # Find by ID then Name attribute if not provided Xpath else find by Xpath
    # If not found, use a default XPath to try to find the most likely option
    element = None

    if id_name_or_xpath:
        log(f"Trying to find element {id_name_or_xpath}")
        is_xpath = id_name_or_xpath.strip().startswith(('/', '//'))
        if not is_xpath:
            element = try_find_element(
                build_xpath(id_name_or_xpath, "id", element_type), id_name_or_xpath, "id", driver
            )
            if element is None:
                element = try_find_element(
                    build_xpath(id_name_or_xpath, "name", element_type), id_name_or_xpath, "name", driver
                )
        else:
            element = try_find_element(id_name_or_xpath, id_name_or_xpath, "xpath", driver)

        if element is None:
            element = try_find_element(default_xpath, default_xpath, "default xpath", driver)
            if element is None:
                log(f"Failed to find the element {id_name_or_xpath}")

    return element


def try_find_element(xpath, id_name_or_xpath, by, driver):
    element = None

    try:
        element = WebDriverWait(driver, 30).until(EC.presence_of_element_located((By.XPATH, xpath)))
    except TimeoutException:
        element = None
    if element is not None:
        log(f"Found element {id_name_or_xpath} by {by}")

    return element


def build_xpath(name, find_by, element_type):
    xpath = f"translate(@{find_by}, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz')='{name.lower()}'"

    if element_type == 'input':
        xpath = f"//input[({xpath}) and (@type='text' or @type='email' or @type='number' or not(@type))]"
    elif element_type == 'password':
        xpath = f"//input[({xpath}) and (@type='text' or @type='password' or not(@type))]"
    elif element_type == 'submit':
        xpath = f"//*[({xpath}) and (@type='submit' or @type='button')]"
    else:
        xpath = f"//*[{xpath}]"

    log(f"Built xpath: {xpath}")
    return xpath

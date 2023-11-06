from os import environ, pathsep
from re import search
from time import sleep
from traceback import print_exc
import sys

from pyotp import TOTP
from requests import post
from selenium import webdriver
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.by import By
from selenium.common.exceptions import NoSuchElementException, TimeoutException
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from seleniumwire import webdriver
import zap_common
import logging

from src.zap_hooks.helpers.browserstorage import BrowserStorage
from src.zap_hooks.helpers.utilities import array_to_dict, log
from src.zap_hooks.model.log_level import LogLevel
from src.zap_hooks.helpers.logging import LoggingFilter
import src.zap_hooks.helpers.globals as globals


def setup_context(zap, target, config):
    # Set an X-Scanner header so requests can be identified in logs
    zap.replacer.add_rule(description='Scanner', enabled=True, matchtype='REQ_HEADER',
                            matchregex=False, matchstring='X-Scanner', replacement="ZAP")
    globals.context_id = zap.context.new_context(globals.context_name)

    zap_common.context_name = globals.context_name
    zap_common.context_id = globals.context_id

    # include everything below the target
    config.auth_include_urls.append(target + '.*')

    # include additional url's
    for include in config.auth_include_urls:
        zap.context.include_in_context(globals.context_name, include)
        log(f"Included {include}")

    # exclude all urls that end the authenticated session
    if len(config.auth_exclude_urls) == 0:
        config.auth_exclude_urls.append('.*logout.*')
        config.auth_exclude_urls.append('.*uitloggen.*')
        config.auth_exclude_urls.append('.*afmelden.*')
        config.auth_exclude_urls.append('.*signout.*')

    for exclude in config.auth_exclude_urls:
        zap.context.exclude_from_context(globals.context_name, exclude)
        log(f"Excluded {exclude}")


def setup_webdriver() -> webdriver.Chrome:
    log('Start webdriver')
    options = webdriver.ChromeOptions()
    options.add_experimental_option('excludeSwitches', ['enable-logging'])
    options.add_argument('--headless')
    options.add_argument('--ignore-certificate-errors')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')

    # NOTE this is needed for the chromedriver path to be found on github actions, where the path is overridden before execution
    if environ['CHROMEDRIVER_DIR'] not in environ['PATH']:
        log(f"adding {environ['CHROMEDRIVER_DIR']} to path {environ['PATH']}")
        environ["PATH"] += pathsep + environ['CHROMEDRIVER_DIR']	

    driver = webdriver.Chrome(options=options)
    driver.set_window_size(1920, 1080)
    driver.maximize_window()

    loggingFilter = LoggingFilter()

    # Add the custom filter to all handlers of the root logger
    for handler in logging.getLogger().handlers:
        handler.addFilter(loggingFilter)

    return driver

def authenticate(zap, target, config):
    skip_cleanup = False
    try:
        if zap is not None:
            setup_context(zap, target, config)

        if config.auth_login_url:
            driver_instance = setup_webdriver()

            login(driver_instance, config)

            set_authentication(zap, target, driver_instance, config)
        elif config.auth_bearer_token:
            add_authorization_header(
                zap, f"Bearer {config.auth_bearer_token}")
        elif config.auth_token_endpoint:
            login_from_token_endpoint(zap, config)
        elif config.oauth_token_url:
            login_from_oauth_token_url(zap, config)
        else:
            skip_cleanup = True
            log(
                'No login URL, Token Endpoint or Bearer token provided - skipping authentication',
                log_level=LogLevel.WARN
            )

    except Exception:
        log(f"error in authenticate: {print_exc()}", log_level=LogLevel.ERROR)
    finally:
        if config.auth_verification_url:
            validate_authentication_url(driver_instance, config.auth_verification_url)
        if not skip_cleanup:            
            cleanup(driver_instance)

def set_authentication(zap, target, driver, config):
    log('Finding authentication cookies')
    # Create an empty session for session cookies
    if zap is not None:
        zap.httpsessions.add_session_token(target, 'session_token')
        zap.httpsessions.create_empty_session(target, 'auth-session')

    # add all found cookies as session cookies
    for cookie in driver.get_cookies():
        if zap is not None:
            zap.httpsessions.set_session_token_value(
                target, 'auth-session', cookie['name'], cookie['value'])
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
    add_token_from_browser_storage(zap, localStorage, config)
    add_token_from_browser_storage(zap, sessionStorage, config)

def validate_authentication_url(driver, url):
    """Validate that the authentication url is called and returns a 200 status code"""
    log(f"Validating authentication url: {url}")
    url_found = False
    for request in driver.requests:
        if request.response and url in request.url:
            url_found = True
            log(f"Checking response status code {request.response}")
            if request.response.status_code != 200:
                log(f"Status code is not 200 for {request.url}, it is {request.response.status_code}")
                sys.exit(1)
            else: 
                log(f"Status code is 200 for {request.url}, authentication was successful")
    if not url_found:
        log(f"Authentication url {url} was not found, authentication failed.")
        sys.exit(1)

def add_token_from_browser_storage(zap, browserStorage, config):
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
        

def login_from_token_endpoint(zap, config):
    """Login using a token endpoint"""
    log('Fetching authentication token from endpoint')
    response = post(config.auth_token_endpoint, data={
        'username': config.auth_username, 'password': config.auth_password})
    data = response.json()
    auth_header = None

    if "token" in data:
        auth_header = f"Bearer {data['token']}"
    elif "token_type" in data:
        auth_header = f"{data['token_type']} {data['token_type']}"

    if auth_header:
        add_authorization_header(zap, auth_header)

def login_from_oauth_token_url(zap, config):
    """Login using an oauth token url"""
    log('Making request to oauth token url')
    body = array_to_dict(config.oauth_parameters)
    response = post(config.oauth_token_url, data=body)
    data = response.json()
    auth_header = None
    if "token" in data:
        auth_header = f"Bearer {data['token']}"
    elif "access_token" in data:
        log("setting access_token from oauth response")
        auth_header = f"Bearer {data['access_token']}"

def add_authorization_header(zap, auth_token):
    """Add an authorization header to all requests using the zap replacer"""
    if zap is not None:
        zap.replacer.add_rule(description='AuthHeader', enabled=True, matchtype='REQ_HEADER',
                               matchregex=False, matchstring='Authorization', replacement=auth_token)
        log(f"Authorization header added: {auth_token}")

def login(driver, config):
    """Main function to perform logging using selenium webdriver"""
    log(f"authenticate using webdriver against URL: {config.auth_login_url}")

    driver.get(config.auth_login_url)
    final_submit_button = config.auth_submit_field_name
    sleep(5)
    log('automatically finding login elements')

    username_element = None

    if config.auth_username:
        username_element = fill_username(config, driver)

    if config.auth_form_type == 'wait_for_password':
        log(f"Waiting for {config.auth_password_field_name} element to load")
        sleep(config.auth_delay_time)
        
    if config.auth_form_type == 'multi_page':
        continue_button = find_element(config.auth_submit_field_name, "submit", "//*[@type='submit' or @type='button' or button]", driver)
        actions = ActionChains(driver)
        actions.move_to_element(continue_button).click().perform()
        final_submit_button = config.auth_submit_second_field_name
        log("Clicked the first submit element for multi page")
        sleep(config.auth_delay_time)

    if config.auth_password:
        try:
            fill_password(config, driver)
        except Exception:
            log(
                'Did not find the password field - clicking Next button and trying again', log_level=LogLevel.WARN)

            fill_password(config, driver)

    if config.auth_otp_secret:
        try:
            fill_otp(config, driver)
        except Exception:
            log(
                'Did not find the OTP field - clicking Next button and trying again', log_level=LogLevel.WARN)

            submit_form(config.auth_submit_action,
                                final_submit_button, config.auth_password_field_name, driver)
            fill_otp(config, driver)

    submit_form(config.auth_submit_action,
                    final_submit_button, config.auth_password_field_name, driver)
    
    if config.auth_check_element:
        try:
            log('Check element')
            WebDriverWait(driver, config.auth_check_delay).until(
                EC.presence_of_element_located((By.XPATH, config.auth_check_element)))
        except TimeoutException:
            log('Check element timeout')
    else:
        sleep(config.auth_check_delay)

def submit_form(submit_action, submit_field_name, password_field_name, driver):
    """Submit the form using the submit action can either be click or submit"""
    if submit_action == "click":
        element = find_element(
            submit_field_name, "submit", "//*[@type='submit' or @type='button' or button]", driver)
        actions = ActionChains(driver)
        actions.move_to_element(element).click().perform()
        log(f"Clicked the {submit_field_name} element")
    else:
        find_element(password_field_name,"password","//input[@type='password' or contains(@name,'ass')]", driver).submit()
        log('Submitted the form')

def fill_username(config, driver):
    """Finds and fills username field"""
    return find_and_fill_element(config.auth_username,
                                        config.auth_username_field_name,
                                        "input",
                                        "(//input[((@type='text' or @type='email') and contains(@name,'ser')) or (@type='text' or @type='email')])[1]",
                                        driver)

def fill_password(config, driver):
    """Find and fills password field"""
    return find_and_fill_element(config.auth_password,
                                        config.auth_password_field_name,
                                        "password",
                                        "//input[@type='password' or contains(@name,'ass')]",
                                        driver)

def fill_otp(config, driver):
    """fills """
    totp = TOTP(config.auth_otp_secret)
    otp = totp.now()

    log(f"Generated OTP: {otp}")

    return find_and_fill_element(otp,
                                        config.auth_otp_field_name,
                                        "input",
                                        "//input[@type='text' and (contains(@id,'otp') or contains(@name,'otp'))]",
                                        driver)

def find_and_fill_element( value, name, element_type, xpath, driver):
    element = find_element(name, element_type, xpath, driver)
    element.clear()
    element.send_keys(value)
    log(f"Filled the {name} element")

    return element

    # 1. Find by ID attribute (case insensitive)
    # 2. Find by Name attribute (case insensitive)
    # 3. Find by xpath
    # 4. Find by the default xpath if all above fail
def find_element(name_or_id_or_xpath, element_type, default_xpath, driver):
    element = None
    log(f"Trying to find element {name_or_id_or_xpath}")

    if name_or_id_or_xpath:
        try:
            path = build_xpath(
                name_or_id_or_xpath, "id", element_type)
            element = driver.find_element(By.XPATH, path)
            log(f"Found element {name_or_id_or_xpath} by id")
        except NoSuchElementException:
            try:
                path = build_xpath(
                    name_or_id_or_xpath, "name", element_type)
                element = driver.find_element(By.XPATH, path)
                log(f"Found element {name_or_id_or_xpath} by name")
            except NoSuchElementException:
                try:
                    element = driver.find_element(By.XPATH,
                        name_or_id_or_xpath)
                    log(
                        f"Found element {name_or_id_or_xpath} by xpath (name)")
                except NoSuchElementException:
                    try:
                        element = driver.find_element(By.XPATH,
                            default_xpath)
                        log(
                            f"Found element {default_xpath} by default xpath")
                    except NoSuchElementException:
                        log(
                            f"Failed to find the element {name_or_id_or_xpath}")

    return element

def build_xpath(name, find_by, element_type):
    xpath = "translate(@{0}, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz')='{1}'".format(
        find_by, name.lower())

    if element_type == 'input':
        xpath = "//input[({0}) and ({1})]".format(xpath,
                                                    "@type='text' or @type='email' or @type='number' or not(@type)")
    elif element_type == 'password':
        xpath = "//input[({0}) and ({1})]".format(xpath,
                                                    "@type='text' or @type='password' or not(@type)")
    elif element_type == 'submit':
        xpath = "//*[({0}) and ({1})]".format(xpath,
                                                "@type='submit' or @type='button' or button")
    else:
        xpath = "//*[{0}]".format(xpath)

    log(f"Built xpath: {xpath}")

    return xpath

def cleanup(driver):
    if driver:
        driver.quit()

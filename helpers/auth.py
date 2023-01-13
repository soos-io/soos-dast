from os import environ
from re import search
from time import sleep
from traceback import print_exc

from pyotp import TOTP
from requests import post
from selenium import webdriver
from selenium.webdriver.common.action_chains import ActionChains
from selenium.common.exceptions import NoSuchElementException, TimeoutException
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from helpers.browserstorage import BrowserStorage
from helpers.utils import array_to_dict, log
from model.log_level import LogLevel


class DASTAuth:
    driver = None
    config = None

    def __init__(self, config=None):
        self.config = config

    def setup_context(self, zap, target):
        # Set an X-Scanner header so requests can be identified in logs
        zap.replacer.add_rule(description='Scanner', enabled=True, matchtype='REQ_HEADER',
                              matchregex=False, matchstring='X-Scanner', replacement="ZAP")

        context_name = 'ctx-zap-docker'
        context_id = zap.context.new_context(context_name)

        import zap_common
        zap_common.context_name = context_name
        zap_common.context_id = context_id

        # include everything below the target
        self.config.auth_include_urls.append(target + '.*')

        # include additional url's
        for include in self.config.auth_include_urls:
            zap.context.include_in_context(context_name, include)
            log(f"Included {include}")

        # exclude all urls that end the authenticated session
        if len(self.config.auth_exclude_urls) == 0:
            self.config.auth_exclude_urls.append('.*logout.*')
            self.config.auth_exclude_urls.append('.*uitloggen.*')
            self.config.auth_exclude_urls.append('.*afmelden.*')
            self.config.auth_exclude_urls.append('.*signout.*')

        for exclude in self.config.auth_exclude_urls:
            zap.context.exclude_from_context(context_name, exclude)
            log(f"Excluded {exclude}")

    def setup_webdriver(self):
        log('Start webdriver')

        options = webdriver.ChromeOptions()
        if not self.config.auth_display:
            options.add_argument('--headless')
        options.add_argument('--ignore-certificate-errors')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')

        self.driver = webdriver.Chrome(options=options)
        self.driver.set_window_size(1920, 1080)
        self.driver.maximize_window()

    def authenticate(self, zap, target):
        try:
            # setup the zap context
            if zap is not None:
                self.setup_context(zap, target)

            # perform authentication using selenium
            if self.config.auth_login_url:
                # setup the webdriver
                self.setup_webdriver()

                # login to the application
                self.login()

                # find session cookies or tokens and set them in ZAP
                self.set_authentication(zap, target)
            # perform authentication using a provided Bearer token
            elif self.config.auth_bearer_token:
                self.add_authorization_header(
                    zap, f"Bearer {self.config.auth_bearer_token}")
            # perform authentication using a simple token endpoint
            elif self.config.auth_token_endpoint:
                self.login_from_token_endpoint(zap)
            # perform authentication to url that grant access_token for oauth
            elif self.config.oauth_token_url:
                self.login_from_oauth_token_url(zap)
            else:
                log(
                    'No login URL, Token Endpoint or Bearer token provided - skipping authentication',
                    log_level=LogLevel.WARN
                )

        except Exception:
            log(f"error in authenticate: {print_exc()}", log_level=LogLevel.ERROR)
        finally:
            self.cleanup()

    def set_authentication(self, zap, target):
        log('Finding authentication cookies')
        # Create an empty session for session cookies
        if zap is not None:
            zap.httpsessions.add_session_token(target, 'session_token')
            zap.httpsessions.create_empty_session(target, 'auth-session')

        # add all found cookies as session cookies
        for cookie in self.driver.get_cookies():
            if zap is not None:
                zap.httpsessions.set_session_token_value(
                    target, 'auth-session', cookie['name'], cookie['value'])
            log(f"Cookie added: {cookie['name']}={cookie['value']}")

        # add token from cookies if exists
        self.add_token_from_cookie(zap, self.driver.get_cookies())

        # Mark the session as active
        if zap is not None:
            zap.httpsessions.set_active_session(target, 'auth-session')
            log(f"Active session: {zap.httpsessions.active_session(target)}")

        log('Finding authentication headers')

        # try to find JWT tokens in Local Storage and Session Storage and add them as Authorization header
        localStorage = BrowserStorage(self.driver, 'localStorage')
        sessionStorage = BrowserStorage(self.driver, 'sessionStorage')
        self.add_token_from_browser_storage(zap, localStorage)
        self.add_token_from_browser_storage(zap, sessionStorage)

    def add_token_from_browser_storage(self, zap, browserStorage):
        for key in browserStorage:
            log(f"Found key: {key}")
            match = search('(eyJ[^"]*)', browserStorage.get(key))
            if match:
                auth_header = "Bearer " + match.group()
                self.add_authorization_header(zap, auth_header)

    def add_token_from_cookie(self, zap, cookies):
        for cookie in cookies:
            if cookie['name'] == 'token':
                auth_header = "Bearer " + cookie['value']
                self.add_authorization_header(zap, auth_header)
        

    def login_from_token_endpoint(self, zap):
        log('Fetching authentication token from endpoint')

        response = post(self.config.auth_token_endpoint, data={
            'username': self.config.auth_username, 'password': self.config.auth_password})
        data = response.json()
        auth_header = None

        if "token" in data:
            auth_header = f"Bearer {data['token']}"
        elif "token_type" in data:
            auth_header = f"{data['token_type']} {data['token_type']}"

        if auth_header:
            self.add_authorization_header(zap, auth_header)

    def login_from_oauth_token_url(self, zap):
        log('Making request to oauth token url')
        body = array_to_dict(self.config.oauth_parameters)
        response = post(self.config.oauth_token_url, data=body)
        data = response.json()
        auth_header = None
        if "token" in data:
            auth_header = f"Bearer {data['token']}"
        elif "access_token" in data:
            log("setting access_token from oauth response")
            auth_header = f"Bearer {data['access_token']}"

    def add_authorization_header(self, zap, auth_token):
        if zap is not None:
            zap.replacer.add_rule(description='AuthHeader', enabled=True, matchtype='REQ_HEADER',
                                  matchregex=False, matchstring='Authorization', replacement=auth_token)
        log(f"Authorization header added: {auth_token}")

    def login(self):
        log(f"authenticate using webdriver against URL: {self.config.auth_login_url}")

        self.driver.get(self.config.auth_login_url)
        final_submit_button = self.config.auth_submit_field_name

        # wait for the page to load
        sleep(5)

        log('automatically finding login elements')

        username_element = None

        # fill out the username field
        if self.config.auth_username:
            username_element = self.fill_username()

        if self.config.auth_form_type == 'wait_for_password':
            log(f"Waiting for {self.config.auth_password_field_name} element to load")
            sleep(self.config.auth_delay_time)
        
        if self.config.auth_form_type == 'multi_page':
            continue_button = self.find_element(self.config.auth_submit_field_name, "submit", "//*[@type='submit' or @type='button' or button]" )
            actions = ActionChains(self.driver)
            actions.move_to_element(continue_button).click().perform()
            final_submit_button = self.config.auth_submit_second_field_name
            log(f"Clicked the first submit element for multi page")
            sleep(self.config.auth_delay_time)

        # fill out the password field
        if self.config.auth_password:
            try:
                self.fill_password()
            except Exception:
                log(
                    'Did not find the password field - clicking Next button and trying again', log_level=LogLevel.WARN)

                # if the password field was not found, we probably need to submit to go to the password page
                # login flow: username -> next -> password -> submit
                self.fill_password()

        # fill out the OTP field
        if self.config.auth_otp_secret:
            try:
                self.fill_otp()
            except Exception:
                log(
                    'Did not find the OTP field - clicking Next button and trying again', log_level=LogLevel.WARN)

                # if the OTP field was not found, we probably need to submit to go to the OTP page
                # login flow: username -> next -> password -> next -> otp -> submit
                self.submit_form(self.config.auth_submit_action,
                                 final_submit_button, self.config.auth_password_field_name)
                self.fill_otp()

        # submit
        self.submit_form(self.config.auth_submit_action,
                        final_submit_button, self.config.auth_password_field_name)

        # wait for the page to load
        if self.config.auth_check_element:
            try:
                log('Check element')
                WebDriverWait(self.driver, self.config.auth_check_delay).until(
                    EC.presence_of_element_located((By.XPATH, self.config.auth_check_element)))
            except TimeoutException:
                log('Check element timeout')
        else:
            sleep(self.config.auth_check_delay)

    def submit_form(self, submit_action, submit_field_name, password_field_name):
        if submit_action == "click":
            element = self.find_element(
                submit_field_name, "submit", "//*[@type='submit' or @type='button' or button]")
            actions = ActionChains(self.driver)
            actions.move_to_element(element).click().perform()
            log(f"Clicked the {submit_field_name} element")
        else:
            self.find_element(password_field_name,"password","//input[@type='password' or contains(@name,'ass')]").submit()
            log('Submitted the form')

    def fill_username(self):
        return self.find_and_fill_element(self.config.auth_username,
                                          self.config.auth_username_field_name,
                                          "input",
                                          "(//input[((@type='text' or @type='email') and contains(@name,'ser')) or (@type='text' or @type='email')])[1]")

    def fill_password(self):
        return self.find_and_fill_element(self.config.auth_password,
                                          self.config.auth_password_field_name,
                                          "password",
                                          "//input[@type='password' or contains(@name,'ass')]")

    def fill_otp(self):
        totp = TOTP(self.config.auth_otp_secret)
        otp = totp.now()

        log(f"Generated OTP: {otp}")

        return self.find_and_fill_element(otp,
                                          self.config.auth_otp_field_name,
                                          "input",
                                          "//input[@type='text' and (contains(@id,'otp') or contains(@name,'otp'))]")

    def find_and_fill_element(self, value, name, element_type, xpath):
        element = self.find_element(name, element_type, xpath)
        element.clear()
        element.send_keys(value)
        log(f"Filled the {name} element")

        return element

    # 1. Find by ID attribute (case insensitive)
    # 2. Find by Name attribute (case insensitive)
    # 3. Find by xpath
    # 4. Find by the default xpath if all above fail
    def find_element(self, name_or_id_or_xpath, element_type, default_xpath):
        element = None
        log(f"Trying to find element {name_or_id_or_xpath}")

        if name_or_id_or_xpath:
            try:
                path = self.build_xpath(
                    name_or_id_or_xpath, "id", element_type)
                element = self.driver.find_element_by_xpath(path)
                log(f"Found element {name_or_id_or_xpath} by id")
            except NoSuchElementException:
                try:
                    path = self.build_xpath(
                        name_or_id_or_xpath, "name", element_type)
                    element = self.driver.find_element_by_xpath(path)
                    log(f"Found element {name_or_id_or_xpath} by name")
                except NoSuchElementException:
                    try:
                        element = self.driver.find_element_by_xpath(
                            name_or_id_or_xpath)
                        log(
                            f"Found element {name_or_id_or_xpath} by xpath (name)")
                    except NoSuchElementException:
                        try:
                            element = self.driver.find_element_by_xpath(
                                default_xpath)
                            log(
                                f"Found element {default_xpath} by default xpath")
                        except NoSuchElementException:
                            log(
                                f"Failed to find the element {name_or_id_or_xpath}")

        return element

    def build_xpath(self, name, find_by, element_type):
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

    def cleanup(self):
        if self.driver:
            self.driver.quit()

import random
import string
import sys
import requests
import datetime
from environs import Env

s = requests.session()

def get_random_password():
    random_source = string.ascii_letters + string.digits + string.punctuation
    # select 1 lowercase
    password = random.choice(string.ascii_lowercase)
    # select 1 uppercase
    password += random.choice(string.ascii_uppercase)
    # select 1 digit
    password += random.choice(string.digits)
    # select 1 special symbol
    password += random.choice(string.punctuation)

    # generate other characters
    for i in range(16):
        password += random.choice(random_source)

    password_list = list(password)
    # shuffle all characters
    random.SystemRandom().shuffle(password_list)
    password = ''.join(password_list)
    return password

def __post_request(config, url, json_data):
    api_host = config['API_HOST']
    api_key = config['API_KEY']
    api_url = f"{api_host}/{url}"
    headers = {'X-API-Key': api_key, 'Content-type': 'application/json'}

    req = s.post(api_url, headers=headers, json=json_data, verify=False)
    req.close()

    dt_string = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    try:
        rsp = req.json()
    except:
        ret_msg = f"{dt_string} => API {url}: not a valid JSON response"
        return (False, ret_msg)

    if isinstance(rsp, list):
        rsp = rsp[0]
    else:
        ret_msg = f"{dt_string} => API {url}: Instance rsp is not a list"
        return (False, ret_msg)

    if not "type" in rsp or not "msg" in rsp:
        ret_msg = f"{dt_string} => API {url}: got response without type or msg from Mailcow API"
        return (False, ret_msg)

    if rsp['type'] != 'success':
        ret_msg = f"{dt_string} => API {url}: {rsp['type']} - {rsp['msg']} / Json_data: {json_data} / Url: {url}"
        return (False, ret_msg)

    return (True, None)


def add_user(config, email, name, active, quotum):
    password = get_random_password()

    json_data = {
        'local_part': email.split('@')[0],
        'domain': email.split('@')[1],
        'name': name,
        'quota': str(quotum),
        'password': password,
        'password2': password,
        "active": 1 if active else 0 # Active: 0 = no incoming mail/no login, 1 = allow both, 2 = custom state: allow incoming mail/no login
    }

    retVal = __post_request(config, 'api/v1/add/mailbox', json_data)

    if not retVal[0]:
        ret_msg = retVal[1]
        return (False, ret_msg)

    json_data = {
        'items': [email],
        'attr': {
            'user_acl': [
                "spam_alias",
                # "tls_policy",
                "spam_score",
                "spam_policy",
                # "delimiter_action",
                # "syncjobs",
                # "eas_reset",
                # "quarantine",
                # "sogo_profile_reset",
                # "quarantine_attachments",
                # "quarantine_notification",
                # "app_passwds",
                # "pushover"
            ]
        }
    }

    retVal = __post_request(config, 'api/v1/edit/user-acl', json_data)

    if not retVal[0]:   
        ret_msg = retVal[1]
        return (False, ret_msg)

    return (True, None)

def edit_user(config, email, active=None, name=None, quota=None):
    attr = {}
    if (active is not None):
        attr['active'] = 1 if active else config['MAILCOW_INACTIVE']
        # Active: 0 = no incoming mail/no login, 1 = allow both, 2 = custom state: allow incoming mail/no login
    if (name is not None):
        attr['name'] = name
    if (quota is not None):
        attr['quota'] = quota

    json_data = {
        'items': [email],
        'attr': attr
    }

    retVal = __post_request(config, 'api/v1/edit/mailbox', json_data)

    if not retVal[0]:
        ret_msg = retVal[1]
        return (False, ret_msg)

    return (True, None)

def check_user(config, email):
    api_host = config['API_HOST']
    api_key = config['API_KEY']
    url = f"{api_host}/api/v1/get/mailbox/{email}"
    headers = {'X-API-Key': api_key, 'Content-type': 'application/json'}
    req = s.get(url, headers=headers, verify=False)
    req.close()

    try:
        rsp = req.json()
    except:
        ret_msg = "API get/mailbox: not a valid JSON response"
        return (False, False, None, None, ret_msg)

    if not isinstance(rsp, dict):
        ret_msg = "API get/mailbox: got response of a wrong type"
        return (False, False, None, None, ret_msg)

    if (not rsp):
        return (False, False, None, None, None)

    if 'active_int' not in rsp and rsp['type'] == 'error':
        ret_msg = f"API {url}: {rsp['type']} - {rsp['msg']}"
        return (False, False, None, None, ret_msg)

    quota = rsp['quota']//1024//1024
    active_int = True if rsp['active_int'] == 1 else False

    return (True, active_int, rsp['name'], quota, None)


def check_api(config):
    api_host = config['API_HOST']
    api_key = config['API_KEY']
    api_url = f"{api_host}/api/v1/get/status/containers"
    headers = {'X-API-Key': api_key, 'Content-type': 'application/json'}

    req = s.get(api_url, headers=headers, verify=False)
    req.close()
    if req.status_code == 200:
        return True
    return False

def domain_exists(config, domain):
    api_host = config['API_HOST']
    api_key = config['API_KEY']
    url = f"{api_host}/api/v1/get/domain/{domain}"
    headers = {'X-API-Key': api_key, 'Content-type': 'application/json'}
    rsp = s.get(url, headers=headers).json()

    if (len(rsp) > 0):
        return True
    else:
        return False

def check_mailbox_all(config):
    api_host = config['API_HOST']
    api_key = config['API_KEY']
    url = f"{api_host}/api/v1/get/mailbox/all"
    headers = {'X-API-Key': api_key, 'Content-type': 'application/json'}
    req = s.get(url, headers=headers)
    req.close()

    try:
        rsp = req.json()
    except:
        ret_msg = "API get/mailbox/all: not a valid JSON response"
        return (False, ret_msg)

    if not isinstance(rsp, list):
        ret_msg = "API get/mailbox/all: got response of a wrong type"
        return (False, ret_msg)

    if (not rsp):
        return (False, False)

    return (True, rsp)

import sys
import os
import string
import time
import datetime
import ldap

import filedb
import api
import sendmail

from string import Template
from pathlib import Path

import urllib3
urllib3.disable_warnings()

logging.info( 'Démarrage du cron ldap-mailcow...')

import logging
logging.basicConfig(format='%(asctime)s %(message)s',
                    datefmt='%d.%m.%y %H:%M:%S', level=logging.INFO)

from dotenv import load_dotenv

load_dotenv()

def main():

    passdb_conf = read_dovecot_passdb_conf_template()
    plist_ldap = read_sogo_plist_ldap_template()
    extra_conf = read_dovecot_extra_conf()

    passdb_conf_changed = apply_config('conf/dovecot/ldap/passdb.conf', config_data=passdb_conf)
    extra_conf_changed = apply_config('conf/dovecot/extra.conf', config_data=extra_conf)
    plist_ldap_changed = apply_config('conf/sogo/plist_ldap', config_data=plist_ldap)

    if passdb_conf_changed or extra_conf_changed or plist_ldap_changed:
        logging.info( f"One or more config files have been changed, please make sure to restart dovecot-mailcow and sogo-mailcow!")
        if os.getenv('MAIL_ACTIVE'): sendmail.send_email( f"One or more config files have been changed, please make sure to restart dovecot-mailcow and sogo-mailcow!")

    logging.info(
            f"Sync started")
    while (True):
        sync()
        interval = int(os.getenv('SYNC_INTERVAL'))
        logging.info(
            f"Sync finished, sleeping {interval} seconds before next cycle")
        logging.info( f"Sync finished, sleeping {interval} seconds before next cycle")
        time.sleep(interval)

def str_to_bool(s):
    if str(s) == "b'TRUE'":
         return True
    elif str(s) == "b'FALSE'":
         return False
    else:
         raise ValueError # evil ValueError that doesn't tell you what the wrong value was

def sync():
    api_status = api.check_api()

    if api_status != True:
        logging.info( f"mailcow is not fully up, skipping this sync...")
#        if os.getenv('MAIL_ACTIVE'): sendmail.send_email( f"mailcow is not fully up, skipping this sync...")
#        return

    try:
        if os.getenv('LDAP_URL_TYPE') == 'TLS':
            uri="ldap://" + str(os.getenv('LDAP_SERVER')) + ":" + str(os.getenv('LDAP_URL_PORT')) + "/????!StartTLS"
        elif os.getenv('LDAP_URL_TYPE') == 'SSL':
            uri="ldaps://" + str(os.getenv('LDAP_SERVER')) + ":" + str(os.getenv('LDAP_URL_PORT'))
        else:
            uri="ldap://" + str(os.getenv('LDAP_SERVER')) + ":" + str(os.getenv('LDAP_URL_PORT'))

        ldap_connector = ldap.initialize(f"{uri}")
        logging.info(f"Connected to LDAP server {uri}") 
        ldap.protocol_version = 3
        ldap_connector.set_option(ldap.OPT_REFERRALS, 0)
        logging.info(f"setoption")
        ldap_connector.simple_bind_s(
            str(os.getenv('LDAP_BIND_DN')), str(os.getenv('LDAP_BIND_DN_PASSWORD')))
        logging.info(f"Bind to LDAP server {uri}")
    except Exception as e: # work on python 3.x
        logging.info(f"Can't connect to LDAP server :" + str(e))
        logging.info( f"Can't connect to LDAP server {uri}, skipping this sync...")
        if os.getenv('MAIL_ACTIVE'): sendmail.send_email(f"Can't connect to LDAP server {uri}, skipping this sync...")
        return

    ldap_results = ldap_connector.search_s(str(os.getenv('LDAP_BASE_DN')), ldap.SCOPE_SUBTREE,
                                           str(os.getenv('LDAP_FILTER')),
                                           [str(os.getenv('LDAP_UIDFieldName')), str(os.getenv('LDAP_CNFieldName')), "mail", str(os.getenv('LDAP_active')), str(os.getenv('LDAP_mailQuota'))])

    logging.info(f"LDAP Search Results: ", ldap_results)

    ldap_results = map(lambda x: (
          x[1][os.getenv('LDAP_UIDFieldName')][0].decode(),
          x[1][os.getenv('LDAP_CNFieldName')][0].decode(),
          x[1]['mail'][0].decode(),
          False,
          "100000"),
#          x[1][str(os.getenv('LDAP_mailQuota'))][0].decode()),
          ldap_results)

    # Geet all accounts info from Mailcow in 1 request
    rsp_code, rsp_data = api.check_mailbox_all()
    if not rsp_code:
        if not rsp_data:
            logging.info(
            f"Error retrieving data from Mailcow.")
            logging.info( f"Error retrieving data from Mailcow.")
            if os.getenv('MAIL_ACTIVE'): sendmail.send_email( f"Error retreiving data from Mailcow.")
            return
        else:
            logging.info(rsp_data)
            logging.info( rsp_data)
            if os.getenv('MAIL_ACTIVE'): sendmail.send_email( rsp_data)
            return

    api_data = {}
    for x in rsp_data:
        api_data[x['username']] = (True,x['active_int'],x['name'],x['quota'])

    filedb.session_time = datetime.datetime.now()

    for ldap_item in ldap_results:
        dt_string = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        print(dt_string, ": ", ldap_item)
        #sys.exit()

        try:
            mail=ldap_item[0]
            logging.info( f"Working on {mail}")
        except:
            logging.info( f"An error occurred while iterating through the LDAP users.")
            if os.getenv('MAIL_ACTIVE'): sendmail.send_email( f"An error occurred while iterating through the LDAP users.")
            return

        ldap_uid = ldap_item[0]
        ldap_name = ldap_item[1]
        ldap_email = ldap_item[2]
        ldap_active = ldap_item[3]
        ldap_quota = ldap_item[4]

        (db_user_exists, db_user_active) = filedb.check_user(ldap_email)

        try:
            api_user = api_data[ldap_email]

            quota = api_user[3]//1024//1024
            active_int = True if api_user[1] == 1 else False

            (api_user_exists, api_user_active, api_name, api_quota) = (True, active_int, api_user[2],quota)
        except KeyError:
            # Key is not present -> User only in Ldap, not in Mailcow
            (api_user_exists, api_user_active, api_name, api_quota) = (False, False, None, None)

        unchanged = True

        if not db_user_exists:
            filedb.add_user(ldap_email, ldap_active)
            (db_user_exists, db_user_active) = (True, ldap_active)
            logging.info( f"Added filedb user: {ldap_email} (Active: {ldap_active})")
            unchanged = False

        if not api_user_exists:
            domain = ldap_email.split('@')[1]
            if (not api.domain_exists( domain)):
                logging.info( f"Error: Domain {domain} doesn't exist for email {ldap_email}")
                if os.getenv('MAIL_ACTIVE'): sendmail.send_email( f"Error: Domain {domain} doesn't exist for email {ldap_email}")
                continue
            else:
                rsp_code, rsp_data = api.add_user( ldap_email, ldap_name, ldap_active, ldap_quota)

                if not rsp_code:
                    logging.info( rsp_data)
                    if os.getenv('MAIL_ACTIVE'): sendmail.send_email( rsp_data)
                    continue

                (api_user_exists, api_user_active, api_name, api_quota) = (True, ldap_active, ldap_name, ldap_quota)
                logging.info( f"Added Mailcow user: {ldap_email} (Active: {ldap_active})")
                unchanged = False

        if db_user_active != ldap_active:
            filedb.user_set_active_to(ldap_email, ldap_active)
            logging.info( f"{'Activated' if ldap_active else 'Deactived'} {ldap_email} in filedb")
            unchanged = False

        if api_user_active != ldap_active:
            rsp_code, rsp_data = api.edit_user( ldap_email, active=ldap_active)

            if not rsp_code:
                logging.info( rsp_data)
                if os.getenv('MAIL_ACTIVE'): sendmail.send_email( rsp_data)
                continue

            logging.info( f"{'Activated' if ldap_active else 'Deactived'} {ldap_email} in Mailcow")
            unchanged = False

        if api_name != ldap_name:
            rsp_code, rsp_data = api.edit_user( ldap_email, name=ldap_name)

            if not rsp_code:
                logging.info( rsp_data)
                if os.getenv('MAIL_ACTIVE'): sendmail.send_email( rsp_data)
                continue

            logging.info( f"Changed name of {ldap_email} in Mailcow to {ldap_name}")
            unchanged = False

        if int(api_quota) != int(ldap_quota):
            rsp_code, rsp_data = api.edit_user( ldap_email, quota=ldap_quota)

            if not rsp_code:
                logging.info( rsp_data)
                if os.getenv('MAIL_ACTIVE'): sendmail.send_email( rsp_data)
                continue

            logging.info( f"Changed quota of {ldap_email} in Mailcow to {ldap_quota}Mo")
            unchanged = False

        if unchanged:
            logging.info( f"Checked user {ldap_email}, unchanged")

    for db_email in filedb.get_unchecked_active_users():
        try:
            api_user = api_data[db_email]

            quota = api_user[3]//1024//1024
            active_int = True if api_user[1] == 1 else False

            (api_user_exists, api_user_active, api_name, api_quota) = (True, active_int, api_user[2],quota)
        except KeyError:
            # Key is not present -> User only in Ldap, not in Mailcow (shoudn't arise in this case
            (api_user_exists, api_user_active, api_name, api_quota) = (False, False, None, None)

        if (api_user_active):
            rsp_code, rsp_data = api.edit_user( db_email, active=False)

            if not rsp_code:
                logging.info( rsp_data)
                if os.getenv('MAIL_ACTIVE'): sendmail.send_email( rsp_data)
                continue

            logging.info( f"Deactivated user {db_email} in Mailcow, not found in LDAP")

        filedb.user_set_active_to(db_email, False)
        logging.info( f"Deactivated user {db_email} in filedb, not found in LDAP")


def apply_config(config_file, config_data):
    if os.path.isfile(config_file):
        with open(config_file) as f:
            old_data = f.read()

        if old_data.strip() == config_data.strip():
            logging.info( f"Config file {config_file} unchanged")
            return False

        backup_index = 1
        backup_file = f"{config_file}.ldap_mailcow_bak"
        while os.path.exists(backup_file):
            backup_file = f"{config_file}.ldap_mailcow_bak.{backup_index}"
            backup_index += 1

        os.rename(config_file, backup_file)
        logging.info( f"Backed up {config_file} to {backup_file}")

    Path(os.path.dirname(config_file)).mkdir(parents=True, exist_ok=True)

    print(config_data, file=open(config_file, 'w'))

    logging.info( f"Saved generated config file to {config_file}")
    return True


def read_dovecot_passdb_conf_template():
    with open('templates/dovecot/ldap/passdb.conf') as f:
        data = Template(f.read())

    if os.getenv('LDAP_URL_TYPE') == 'TLS':
        uri="ldap://" + str(os.getenv('LDAP_SERVER')) + ":" + str(os.getenv('LDAP_URL_PORT'))
        tls="tls = yes"
    elif os.getenv('LDAP_URL_TYPE') == 'SSL':
        uri="ldaps://" + str(os.getenv('LDAP_SERVER')) + ":" + str(os.getenv('LDAP_URL_PORT'))
        tls=''
    else:
        uri="ldap://" + str(os.getenv('LDAP_SERVER')) + ":" + str(os.getenv('LDAP_URL_PORT'))
        tls=''

    ldap_filter_tmp = str(os.getenv('LDAP_FILTER'))[1:-1]

    return data.substitute(
        ldap_uri=uri,
        ldap_filter=ldap_filter_tmp,
        ldap_base_dn=str(os.getenv('LDAP_BASE_DN')),
        ldap_bind_dn=str(os.getenv('LDAP_BIND_DN')),
        ldap_bind_dn_password=str(os.getenv('LDAP_BIND_DN_PASSWORD')),
        ldap_uidfieldname=str(os.getenv('LDAP_UIDFieldName')),
        ldap_tls=tls
    )


def read_sogo_plist_ldap_template():
    with open('templates/sogo/plist_ldap') as f:
        data = Template(f.read())

    if os.getenv('LDAP_URL_TYPE') == 'TLS':
        uri="ldap://" + str(os.getenv('LDAP_SERVER')) + ":" + str(os.getenv('LDAP_URL_PORT')) + "/????!StartTLS"
    elif os.getenv('LDAP_URL_TYPE') == 'SSL':
        uri="ldaps://" + str(os.getenv('LDAP_SERVER')) + ":" + str(os.getenv('LDAP_URL_PORT'))
    else:
        uri="ldap://" + str(os.getenv('LDAP_SERVER')) + ":" + str(os.getenv('LDAP_URL_PORT'))

    return data.substitute(
        ldap_uri=uri,
        ldap_base_dn=str(os.getenv('LDAP_BASE_DN')),
        ldap_bind_dn=str(os.getenv('LDAP_BIND_DN')),
        ldap_bind_dn_password=str(os.getenv('LDAP_BIND_DN_PASSWORD')),
        sogo_ldap_filter=str(os.getenv('SOGO_LDAP_FILTER')),
        ldap_cnfieldname=str(os.getenv('LDAP_CNFieldName')),
        ldap_idfieldname=str(os.getenv('LDAP_IDFieldName')),
        ldap_uidfieldname=str(os.getenv('LDAP_UIDFieldName')),
        ldap_bindfields=str(os.getenv('LDAP_bindFields')),
        ldap_passwordpolicy=str(os.getenv('LDAP_passwordPolicy')),
        ldap_isaddressbook=str(os.getenv('LDAP_isAddressBook')),
        ldap_abdisplayname=str(os.getenv('LDAP_abaddressBookName'))
        )
    


def read_dovecot_extra_conf():
    with open('templates/dovecot/extra.conf') as f:
        data = f.read()

    return data

if __name__ == '__main__':
    main()

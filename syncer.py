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

import syslog
syslog.openlog(ident="Ldap-Mailcow",logoption=syslog.LOG_PID, facility=syslog.LOG_LOCAL0)
syslog.syslog(syslog.LOG_INFO, 'Démarrage du cron ldap-mailcow...')

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
        syslog.syslog(syslog.LOG_INFO, f"One or more config files have been changed, please make sure to restart dovecot-mailcow and sogo-mailcow!")
        if os.getenv('MAIL_ACTIVE'): sendmail.send_email( f"One or more config files have been changed, please make sure to restart dovecot-mailcow and sogo-mailcow!")

    while (True):
        sync()
        interval = int(os.getenv('SYNC_INTERVAL'))
        syslog.syslog(syslog.LOG_INFO, f"Sync finished, sleeping {interval} seconds before next cycle")
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
        syslog.syslog(syslog.LOG_INFO, f"mailcow is not fully up, skipping this sync...")
        if os.getenv('MAIL_ACTIVE'): sendmail.send_email( f"mailcow is not fully up, skipping this sync...")
        return

    try:
        if os.getenv('LDAP_URL_TYPE') == 'TLS':
            uri="ldap://" + str(os.getenv('LDAP_URL')) + ":" + str(os.getenv('LDAP_URL_PORT')) + "/????!StartTLS"
        elif os.getenv('LDAP_URL_TYPE') == 'SSL':
            uri="ldaps://" + str(os.getenv('LDAP_URL')) + ":" + str(os.getenv('LDAP_URL_PORT'))
        else:
            uri="ldap://" + str(os.getenv('LDAP_URL')) + ":" + str(os.getenv('LDAP_URL_PORT'))

        ldap_connector = ldap.initialize(f"{uri}")
        ldap_connector.set_option(ldap.OPT_REFERRALS, 0)
        ldap_connector.simple_bind_s(
            os.getenv('LDAP_BIND_DN'), os.getenv('LDAP_BIND_DN_PASSWORD'))
    except:
        syslog.syslog (syslog.LOG_ERR, f"Can't connect to LDAP server {uri}, skipping this sync...")
        if os.getenv('MAIL_ACTIVE'): sendmail.send_email(f"Can't connect to LDAP server {uri}, skipping this sync...")
        return

    ldap_results = ldap_connector.search_s(os.getenv('LDAP_BASE_DN'), ldap.SCOPE_SUBTREE,
                                           os.getenv('LDAP_FILTER'),
                                           [os.getenv('LDAP_UIDFieldName'), os.getenv('LDAP_CNFieldName'), os.getenv('LDAP_active'), os.getenv('LDAP_mailQuota')])

    ldap_results = map(lambda x: (
          x[1][os.getenv('LDAP_UIDFieldName')][0].decode(),
          x[1][os.getenv('LDAP_CNFieldName')][0].decode(),
          False if not str_to_bool(x[1][os.getenv('LDAP_active')][0]) else True,
          x[1][os.getenv('LDAP_mailQuota')][0].decode()),
          ldap_results)

    # Geet all accounts info from Mailcow in 1 request
    rsp_code, rsp_data = api.check_mailbox_all(config)
    if not rsp_code:
        if not rsp_data:
            syslog.syslog (syslog.LOG_ERR, f"Error retreiving data from Mailcow.")
            if os.getenv('MAIL_ACTIVE'): sendmail.send_email( f"Error retreiving data from Mailcow.")
            return
        else:
            syslog.syslog (syslog.LOG_ERR, rsp_data)
            if os.getenv('MAIL_ACTIVE'): sendmail.send_email( rsp_data)
            return

    api_data = {}
    for x in rsp_data:
        api_data[x['username']] = (True,x['active_int'],x['name'],x['quota'])

    filedb.session_time = datetime.datetime.now()

    for ldap_item in ldap_results:
        dt_string = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        #print(dt_string, ": ", ldap_item)
        #sys.exit()

        try:
            mail=ldap_item[0]
            syslog.syslog(syslog.LOG_INFO, f"Working on {mail}")
        except:
            syslog.syslog (syslog.LOG_ERR, f"An error occurred while iterating through the LDAP users.")
            if os.getenv('MAIL_ACTIVE'): sendmail.send_email( f"An error occurred while iterating through the LDAP users.")
            return

        ldap_email = ldap_item[0]
        ldap_name = ldap_item[1]
        ldap_active = ldap_item[2]
        ldap_quota = ldap_item[3]

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
            syslog.syslog(syslog.LOG_INFO, f"Added filedb user: {ldap_email} (Active: {ldap_active})")
            unchanged = False

        if not api_user_exists:
            domain = ldap_email.split('@')[1]
            if (not api.domain_exists( domain)):
                syslog.syslog (syslog.LOG_ERR, f"Error: Domain {domain} doesn't exist for email {ldap_email}")
                if os.getenv('MAIL_ACTIVE'): sendmail.send_email( f"Error: Domain {domain} doesn't exist for email {ldap_email}")
                continue
            else:
                rsp_code, rsp_data = api.add_user( ldap_email, ldap_name, ldap_active, ldap_quota)

                if not rsp_code:
                    syslog.syslog (syslog.LOG_ERR, rsp_data)
                    if os.getenv('MAIL_ACTIVE'): sendmail.send_email( rsp_data)
                    continue

                (api_user_exists, api_user_active, api_name, api_quota) = (True, ldap_active, ldap_name, ldap_quota)
                syslog.syslog(syslog.LOG_INFO, f"Added Mailcow user: {ldap_email} (Active: {ldap_active})")
                unchanged = False

        if db_user_active != ldap_active:
            filedb.user_set_active_to(ldap_email, ldap_active)
            syslog.syslog(syslog.LOG_INFO, f"{'Activated' if ldap_active else 'Deactived'} {ldap_email} in filedb")
            unchanged = False

        if api_user_active != ldap_active:
            rsp_code, rsp_data = api.edit_user( ldap_email, active=ldap_active)

            if not rsp_code:
                syslog.syslog (syslog.LOG_ERR, rsp_data)
                if os.getenv('MAIL_ACTIVE'): sendmail.send_email( rsp_data)
                continue

            syslog.syslog(syslog.LOG_INFO, f"{'Activated' if ldap_active else 'Deactived'} {ldap_email} in Mailcow")
            unchanged = False

        if api_name != ldap_name:
            rsp_code, rsp_data = api.edit_user( ldap_email, name=ldap_name)

            if not rsp_code:
                syslog.syslog (syslog.LOG_ERR, rsp_data)
                if os.getenv('MAIL_ACTIVE'): sendmail.send_email( rsp_data)
                continue

            syslog.syslog(syslog.LOG_INFO, f"Changed name of {ldap_email} in Mailcow to {ldap_name}")
            unchanged = False

        if int(api_quota) != int(ldap_quota):
            rsp_code, rsp_data = api.edit_user( ldap_email, quota=ldap_quota)

            if not rsp_code:
                syslog.syslog (syslog.LOG_ERR, rsp_data)
                if os.getenv('MAIL_ACTIVE'): sendmail.send_email( rsp_data)
                continue

            syslog.syslog(syslog.LOG_INFO, f"Changed quota of {ldap_email} in Mailcow to {ldap_quota}Mo")
            unchanged = False

        if unchanged:
            syslog.syslog(syslog.LOG_INFO, f"Checked user {ldap_email}, unchanged")

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
                syslog.syslog (syslog.LOG_ERR, rsp_data)
                if os.getenv('MAIL_ACTIVE'): sendmail.send_email( rsp_data)
                continue

            syslog.syslog(syslog.LOG_INFO, f"Deactivated user {db_email} in Mailcow, not found in LDAP")

        filedb.user_set_active_to(db_email, False)
        syslog.syslog(syslog.LOG_INFO, f"Deactivated user {db_email} in filedb, not found in LDAP")


def apply_config(config_file, config_data):
    if os.path.isfile(config_file):
        with open(config_file) as f:
            old_data = f.read()

        if old_data.strip() == config_data.strip():
            syslog.syslog(syslog.LOG_INFO, f"Config file {config_file} unchanged")
            return False

        backup_index = 1
        backup_file = f"{config_file}.ldap_mailcow_bak"
        while os.path.exists(backup_file):
            backup_file = f"{config_file}.ldap_mailcow_bak.{backup_index}"
            backup_index += 1

        os.rename(config_file, backup_file)
        syslog.syslog(syslog.LOG_INFO, f"Backed up {config_file} to {backup_file}")

    Path(os.path.dirname(config_file)).mkdir(parents=True, exist_ok=True)

    print(config_data, file=open(config_file, 'w'))

    syslog.syslog(syslog.LOG_INFO, f"Saved generated config file to {config_file}")
    return True


def read_dovecot_passdb_conf_template():
    with open('templates/dovecot/ldap/passdb.conf') as f:
        data = Template(f.read())

    if os.getenv('LDAP_URL_TYPE') == 'TLS':
        uri="ldap://" + str(os.getenv('LDAP_URL')) + ":" + str(os.getenv('LDAP_URL_PORT'))
        tls="tls = yes"
    elif os.getenv('LDAP_URL_TYPE') == 'SSL':
        uri="ldaps://" + str(os.getenv('LDAP_URL')) + ":" + str(os.getenv('LDAP_URL_PORT'))
        tls=''
    else:
        uri="ldap://" + str(os.getenv('LDAP_URL')) + ":" + str(os.getenv('LDAP_URL_PORT'))
        tls=''

    ldap_filter_tmp = str(os.getenv('LDAP_FILTER'))[1:-1]

    return data.substitute(
        ldap_uri=uri,
        ldap_filter=ldap_filter_tmp,
        ldap_base_dn=os.getenv('LDAP_BASE_DN'),
        ldap_bind_dn=os.getenv('LDAP_BIND_DN'),
        ldap_bind_dn_password=os.getenv('LDAP_BIND_DN_PASSWORD'),
        ldap_uidfieldname=os.getenv('LDAP_UIDFieldName'),
        ldap_tls=tls
    )


def read_sogo_plist_ldap_template():
    with open('templates/sogo/plist_ldap') as f:
        data = Template(f.read())

    if os.getenv('LDAP_URL_TYPE') == 'TLS':
        uri="ldap://" + str(os.getenv('LDAP_URL')) + ":" + str(os.getenv('LDAP_URL_PORT')) + "/????!StartTLS"
    elif os.getenv('LDAP_URL_TYPE') == 'SSL':
        uri="ldaps://" + str(os.getenv('LDAP_URL')) + ":" + str(os.getenv('LDAP_URL_PORT'))
    else:
        uri="ldap://" + str(os.getenv('LDAP_URL')) + ":" + str(os.getenv('LDAP_URL_PORT'))

    return data.substitute(
        ldap_uri=uri,
        ldap_base_dn=os.getenv('LDAP_BASE_DN'),
        ldap_bind_dn=os.getenv('LDAP_BIND_DN'),
        ldap_bind_dn_password=os.getenv('LDAP_BIND_DN_PASSWORD'),
        sogo_ldap_filter=os.getenv('SOGO_LDAP_FILTER'),
        ldap_cnfieldname=os.getenv('LDAP_CNFieldName'),
        ldap_idfieldname=os.getenv('LDAP_IDFieldName'),
        ldap_uidfieldname=os.getenv('LDAP_UIDFieldName'),
        ldap_bindfields=os.getenv('LDAP_bindFields'),
        ldap_passwordpolicy=os.getenv('LDAP_passwordPolicy'),
        ldap_isaddressbook=os.getenv('LDAP_isAddressBook'),
        ldap_abdisplayname=os.getenv('LDAP_abaddressBookName')
    )


def read_dovecot_extra_conf():
    with open('templates/dovecot/extra.conf') as f:
        data = f.read()

    return data

if __name__ == '__main__':
    main()

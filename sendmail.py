import smtplib, ssl
from smtplib import SMTPException
from email.message import EmailMessage

import syslog
syslog.openlog(ident="Ldap-Mailcow",logoption=syslog.LOG_PID, facility=syslog.LOG_LOCAL0)

def get_email_server(config):
    """Creates an instance of email server.
    Returns:
        server -- SMTP instance
    """
    try:
        server = (smtplib.SMTP_SSL if config['MAIL_SSL'] else smtplib.SMTP)(config['MAIL_SERVER'],config['MAIL_PORT'])
        server.ehlo()

        if config['MAIL_TLS']:
            #context = ssl._create_unverified_context()
            #context = ssl.create_default_context()
            #server.starttls(context=context)
            server.starttls()

        #server.set_debuglevel(1)

        if config['MAIL_AUTH']:
            server.login(config['MAIL_AUTH_USERNAME'], config['MAIL_AUTH_PASSWD'])

    except Error:
        print(Error)
        server.quit()
        return False

    return server


def send_email(config, text):
    server = get_email_server(config)
    if not server:
        syslog.syslog (syslog.LOG_ERR, f"Can't create mail server instance...")
        return False

    msg = EmailMessage()
    msg["Subject"] = config['MAIL_SUBJECT'] 
    msg["To"] = config['MAIL_TO']
    msg["From"] = config['MAIL_FROM']
    msg.set_content(text)

    server.sendmail(config['MAIL_FROM'],config['MAIL_TO'],msg.as_string())
    server.quit()

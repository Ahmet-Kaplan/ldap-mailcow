import smtplib, ssl
from smtplib import SMTPException
from email.message import EmailMessage
import os

from dotenv import load_dotenv

load_dotenv()

import syslog
syslog.openlog(ident="Ldap-Mailcow",logoption=syslog.LOG_PID, facility=syslog.LOG_LOCAL0)

def get_email_server():
    """Creates an instance of email server.
    Returns:
        server -- SMTP instance
    """
    try:
        server = (smtplib.SMTP_SSL if str(os.getenv('MAIL_SSL')) else smtplib.SMTP)(str(os.getenv('MAIL_SERVER')),str(os.getenv('MAIL_PORT')))
        server.ehlo()

        if str(os.getenv('MAIL_TLS')):
            #context = ssl._create_unverified_context()
            #context = ssl.create_default_context()
            #server.starttls(context=context)
            server.starttls()

        #server.set_debuglevel(1)

        if str(os.getenv('MAIL_AUTH')):
            server.login(str(os.getenv('MAIL_AUTH_USERNAME')), str(os.getenv('MAIL_AUTH_PASSWD')))

    except:
        syslog.syslog (syslog.LOG_ERR, f"An error occurred while sending mail.")
        server.quit()
        return False

    return server


def send_email(text):
    server = get_email_server()
    if not server:
        syslog.syslog (syslog.LOG_ERR, f"Can't create mail server instance...")
        return False

    msg = EmailMessage()
    msg["Subject"] = str(os.getenv('MAIL_SUBJECT')) 
    msg["To"] = str(os.getenv('MAIL_TO'))
    msg["From"] = str(os.getenv('MAIL_FROM'))
    msg.set_content(text)

    server.sendmail(str(os.getenv('MAIL_FROM')),str(os.getenv('MAIL_TO')),msg.as_string())
    server.quit()

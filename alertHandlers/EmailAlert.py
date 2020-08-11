#!/usr/bin/env python3
import smtplib, ssl, os
import yaml
from email.message import EmailMessage


def send_alert(msg, count):

    cfg_file = "config.yaml"
    alert_file = "alert_emails.yaml"
    
    
    if not os.path.isfile(cfg_file) or not os.path.isfile(alert_file):
      print('Email_alerts not configured')
      return(0)

    with open("config.yaml", "r") as ymlfile:
        cfg = yaml.safe_load(ymlfile)

    with open("alert_emails.yaml", "r") as ymlfile:
        all_emails = yaml.safe_load(ymlfile)

        config = cfg['myconn']
        smtp_server = config['smtp_server']
        port = config['port']
        email = config['email']
        password = config['password']

        for receiver in all_emails['receivers']:
            if receiver is not None:
                receiver_email = receiver
                message = EmailMessage()
                message['Subject'] = '** Alert **  ' + str(count) + ' New CVE(s) Found'
                message['From'] = email
                message['To'] = receiver_email
                message.set_content(msg)

                # Create a secure SSL context
                context = ssl.create_default_context()
                server = smtplib.SMTP(smtp_server, port)

                try:
                    server.ehlo()  # Can be omitted
                    if port in (587, 465):
                        server.starttls(context=context)  # Secure the connection
                    server.ehlo()  # Can be omitted
                    if email and password:
                      server.login(email, password)
                    server.send_message(message)
                    print('CVE(s) Sent To Email ' + receiver_email)
                except:
                    print('Error in Sending Email')
                finally:
                    server.quit()
            else:
                print('No Receivers')

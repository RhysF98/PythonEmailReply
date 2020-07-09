import email
import getpass
import imaplib
import smtplib
import re
import ssl
import sys
import time
from email.message import EmailMessage


# Uses IMAP to retrieve emails, uses SMTP to send emails
def start_server():
    # email address for sending the DMARC checks to
    domain = "dmarcpolicycheck@gmail.com"
    # Opens an SSL connection to Gmail's SSL domain
    receive_email = imaplib.IMAP4_SSL('imap.gmail.com')
    # Map that stores domains of senders and the most recent time they were checked
    recent_domain_dict = {"null": time.time()}
    # Retrieves the password for 'dmarcpolicycheck@gmail.com' from Stdin
    password = getpass.getpass("\nDMARC Domain Checker\n© 2019 Global Cyber Alliance. All Rights Reserved.\nEnter '" + domain + "' password: ", stream=None)

    context = ssl.create_default_context()
    try:
        # Opens SMTP connection to Gmail's SMTP domain, uses TLS
        send_email = smtplib.SMTP("smtp.gmail.com", 587)
        send_email.starttls(context=context)
        # Logs in to the SMTP and IMAP server
        send_email.login(domain, password)
        receive_email.login(domain, password)
    except (smtplib.SMTPAuthenticationError, imaplib.IMAP4.error):
        print("\nCould not log in/ incorrect password\n")
        sys.exit()
    print("\nLogged in successful\nAwaiting emails...\n")
    while True:
        receive_email.list()
        receive_email.select("inbox")
        # Fetches all unread emails from the inbox
        result, data = receive_email.search(None, "ALL", "(UNSEEN)")
        ids = data[0]
        id_list = ids.split()
        if len(id_list) != 0:
            for unreadEmail in id_list:
                result, data = receive_email.fetch(unreadEmail, "(RFC822)")
                raw_email = data[0][1]
                email_message = email.message_from_bytes(raw_email)
                # Gets sender address
                parsed_from = email.utils.parseaddr(email_message['From'])
                sender = parsed_from[1]
                sender_domain = re.sub('^.*?@', '', sender)
                # Gets domain from sender address
                sender_address = sender.split("@", 1)[0]
                print("\nAddress: " + sender_address + "\nDomain: " + sender_domain + "\n")
                if sender_domain in recent_domain_dict:
                    # Makes sure that an email address can't be processed less than 5 minutes after it has been previously
                    # Black lists emails to reply to, e.g. mailerdaemon and any account emails
                    if (time.time() - recent_domain_dict[sender_domain]) < 300 or sender == "mailer-daemon@googlemail.com" or ("google.com" in sender):
                        print("Ignore current domain\n")
                        print("---------------------------------------------")
                        continue
                print("-- Processing DMARC status for domain --")
                print(assess_dmarc(email_message))
                msg = EmailMessage()
                msg['Subject'] = "DMARC Results"
                msg['To'] = sender
                msg['From'] = domain
                message = "Your DMARC Results for " + sender + ":\n" + assess_dmarc(email_message) + "\n" \
                                                                                                  "Please wait 5 minutes before testing this domain again...\n" \
                                                                                                  "---------------------------------------------------------------------------------------" \
                                                                                                  "\nHow to improve your company's email security: https://www.dmarc.globalcyberalliance.org" \
                                                                                                  "\nSmall business security Toolkit available for free: https://www.globalcyberalliance.org/gca-cybersecurity-toolkit" \
                                                                                                  "" \
                                                                                                  "\n\nTo report a bug or any queries, please contact lewisoshaughnessy99@gmail.com" \
                msg.set_content(message)
                print("-- Sending DMARC results summary to sender --")
                send_email.send_message(msg)
                print("-- Sent --\n")
                print("---------------------------------------------")
                recent_domain_dict[sender_domain] = time.time()


# Performs the checks on the email address (domain)
def assess_dmarc(email):
    string_to_send = ""
    # Looks for DKIM records in the email header
    if "dkim=" in str(email):
        string_to_send = string_to_send + "\nDKIM: " + str(email)[str(email).find("dkim=") + 5:str(email).find("dkim=") + 9]
    else:
        string_to_send = string_to_send + "\nDKIM: fail (none detected)"
    # Looks for SPF records in the email header
    if "spf=" in str(email):
        string_to_send = string_to_send + "\nSPF: " + str(email)[str(email).find("spf=") + 4:str(email).find("spf=") + 8]
    else:
        string_to_send = string_to_send + "\nSPF: fail (none detected)"
    # Looks for DMARC records in the email header (and the specified policy, e.g. REJECT, NONE)
    # DMARC passes regardless of policy, passes if DMARC is in place, fails if not
    if "dmarc=" in str(email):
        string_to_send = string_to_send + "\nDMARC: " + str(email)[str(email).find("dmarc=") + 6:str(email).find("dmarc=") + 42]
    else:
        string_to_send = string_to_send + "\nDMARC: fail (none detected)"
    # Looks for TLS/ SSL (or STMPS) in the email header
    if "TLS" in str(email):
        # Checks if the TLS version is less than 1.2
        if int(re.sub("_", "", (str(email)[str(email).find("TLS"):str(email).find("TLS") + 6])[3:6])) < 12:
            string_to_send = string_to_send + "\nTLS: fail (" + str(email)[str(email).find("TLS"):str(email).find(
                "TLS") + 6] + "). TLS version should be at least 1.2\n"
        else:
            string_to_send = string_to_send + "\nTLS: pass (" + str(email)[str(email).find("TLS"):str(email).find(
                "TLS") + 6] + ")\n"
    elif "SMTPS" in str(email):
        string_to_send = string_to_send + "\nTLS: pass (SMTPS)\n"
    elif "SSL" in str(email):
        string_to_send = string_to_send + "\nTLS: fail (SSL). Consider upgrading to TLS\n"
    else:
        string_to_send = string_to_send + "\nTLS: fail (none detected)\n"
    return string_to_send


start_server()

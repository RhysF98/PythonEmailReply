import email
import getpass
import imaplib
import re


def start_receiver():
    domain = "dmarcpolicycheck@gmail.com"
    mail = imaplib.IMAP4_SSL('imap.gmail.com')

    password = getpass.getpass("DMARC Policy Checker. Enter '" + domain + "' password: ", stream=None)

    try:
        mail.login('dmarcpolicycheck@gmail.com', password)
    except:
        print("Could not log in/ incorrect password\n")
    else:
        print("Logged in successful\nAwaiting messages...\n")
        while True:
            mail.list()
            mail.select("inbox")
            result, data = mail.search(None, "ALL", "(UNSEEN)")
            ids = data[0]
            id_list = ids.split()
            if len(id_list) != 0:
                for unreadEmail in id_list:
                    result, data = mail.fetch(unreadEmail, "(RFC822)")
                    raw_email = data[0][1]
                    email_message = email.message_from_bytes(raw_email)
                    parsed_from = email.utils.parseaddr(email_message['From'])
                    sender = parsed_from[1]
                    sender_domain = re.sub('^.*?@', '', sender)
                    sender_address = sender.split("@", 1)[0]
                    print("Address: " + sender_address + "\nDomain: " + sender_domain + "\n")
                    # Send senderDomain to PolicyCheck function


start_receiver()

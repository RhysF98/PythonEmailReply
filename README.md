# DMARC EMAIL CHECKER
# (C) 2019 Global Cyber Alliance
-----------------------------------------

Currently using: dmarcpolicycheck@gmail.com
Written in Python 3.6.

The script starts a server that receives any emails sent to a specified domain, or any unopened emails already received by that domain. Checks the DMARC, DKIM, SPF and TLS status of the sender's domain, and responds with a summary email.

IMAP is used to fetch emails, SMTP with TLS is used to send the results email back to the initial sender.

The whole process between sending an email and receiving a response is ~10 seconds.

-----------------------------------------

To use:

1) Run script/ start server
2) Log in to specified domain using the console (password for dmarcpolicycheck@gmail.com is: _dmarc\_check_)
3) Send an email from any account to dmarcpolicycheck@gmail.com; email can contain anything (or nothing)
4) Receipt of the email should appear in the console, no action is needed
5) After the script detects the DMARC, DKIM, SPF and TLS records/ status, it automatically responds with an email
   - If server has unread emails when it's turned on, it will perform those scans first
   - The server enforces a 5 minute wait before processing the same email again (unless server is restarted)

-----------------------------------------

Extensions/ Limitations:
 
- The script will return "pass" if DMARC is detected, regardless of policy
+ Make policy NONE fail or "seek improvement", QUARANTINE and REJECT can pass

- If initial sender uses Outlook, the links in the response from the script will be encapsulated in Outlook's "safelinks" protection, obfuscating the destination of the link
+ Send email response as HTML rather than TXT

- DMARC itself may block the email response, depending on which network the sender is connected to
+ Have a GCA domain to host the service rather than my Gmail one

+ Have a TXT/CSV list of black-listed email addresses, rather than hardcoded in Python

+ Have a configuration (.ini) file to setup the current domain and black-listed email addresses

+ Dockerize the program (Rob's area of expertise)

+ Needs a better name

-----------------------------------------

This program was conceptualised and realised in the space of 24 hours.
Personal email: l.oshaughnessy@gemasecure.com

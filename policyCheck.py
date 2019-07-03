import gs.dmarc
import os

def getPolicy(domain):
    policy = gs.dmarc.receiver_policy(domain)
    if (policy == gs.dmarc.ReceiverPolicy.noDmarc):
        return "NoDmarc"
    elif (policy == gs.dmarc.ReceiverPolicy.none):
        return "None"
    elif (policy == gs.dmarc.ReceiverPolicy.quarantine):
        return "Quarantine"
    elif (policy == gs.dmarc.ReceiverPolicy.reject):
        return "Reject"

def getReportAddresses(domain):
    dmarcContents = os.popen("dig +short TXT _dmarc." + domain).read()
    dmarcContents = dmarcContents[1:-1]
    loc = dmarcContents.find("rua")
    dmarcContents = dmarcContents[loc+4:]
    loc = dmarcContents.find(";")
    dmarcContents = dmarcContents[:loc]
    mailList = dmarcContents.split("mailto")
    del mailList[0]
    for i in range(0, len(mailList)-1):
        mailList[i] = mailList[i][1:-1]
    mailList[len(mailList)-1] = mailList[len(mailList)-1][1:]
    return mailList

def getForensicAddresses(domain):
    dmarcContents = os.popen("dig +short TXT _dmarc." + domain).read()
    dmarcContents = dmarcContents[1:-1]
    loc = dmarcContents.find("ruf")
    dmarcContents = dmarcContents[loc+4:]
    loc = dmarcContents.find(";")
    dmarcContents = dmarcContents[:loc]
    mailList = dmarcContents.split("mailto")
    del mailList[0]
    for i in range(0, len(mailList)-1):
        mailList[i] = mailList[i][1:-1]
    mailList[len(mailList)-1] = mailList[len(mailList)-1][1:]
    return mailList

print(getPolicy("globalcyberalliance.org"))
print(getReportAddresses("globalcyberalliance.org"))
print(getForensicAddresses("globalcyberalliance.org"))

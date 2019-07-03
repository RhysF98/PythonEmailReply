import gs.dmarc
import os

def getMessage(domain):
    message = ""
    message += "Your policy is: " + getPolicy(domain) + os.linesep
    message += "Your subdomain policy is: " + getSubdomainPolicy(domain) + os.linesep
    message += "Aggregate reports are being sent to: "
    reportList = getReportAddresses(domain)
    for email in reportList:
        message += email + ","
    message += os.linesep
    message += "Forensic reports are being sent to: "
    forensicList = getForensicAddresses(domain)
    for email in forensicList:
        message += email + ","
    message += os.linesep
    message += "Reporting interval is: " + getReportFrequency(domain)
    return message

def getPolicy(domain):
    policy = gs.dmarc.receiver_policy(domain)
    if (policy == gs.dmarc.ReceiverPolicy.noDmarc):
        return "noDmarc"
    elif (policy == gs.dmarc.ReceiverPolicy.none):
        return "none"
    elif (policy == gs.dmarc.ReceiverPolicy.quarantine):
        return "quarantine"
    elif (policy == gs.dmarc.ReceiverPolicy.reject):
        return "reject"

def getSubdomainPolicy(domain):
    dmarcContents = os.popen("dig +short TXT _dmarc." + domain).read()
    dmarcContents = dmarcContents[1:-1]
    loc = dmarcContents.find("sp=")
    if loc == -1:
        return getPolicy(domain) #If no subdomain policy found, return normal policy
    dmarcContents = dmarcContents[loc+3:]
    loc = dmarcContents.find(";")
    dmarcContents = dmarcContents[:loc]
    return dmarcContents

def getReportAddresses(domain):
    dmarcContents = os.popen("dig +short TXT _dmarc." + domain).read()
    dmarcContents = dmarcContents[1:-1]
    loc = dmarcContents.find("rua=")
    if loc == -1:
        return list()
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
    loc = dmarcContents.find("ruf=")
    if loc == -1:
        return list()
    dmarcContents = dmarcContents[loc+4:]
    loc = dmarcContents.find(";")
    dmarcContents = dmarcContents[:loc]
    mailList = dmarcContents.split("mailto")
    del mailList[0]
    for i in range(0, len(mailList)-1):
        mailList[i] = mailList[i][1:-1]
    mailList[len(mailList)-1] = mailList[len(mailList)-1][1:]
    return mailList

def getReportFrequency(domain):
    dmarcContents = os.popen("dig +short TXT _dmarc." + domain).read()
    dmarcContents = dmarcContents[1:-1]
    loc = dmarcContents.find("ri=")
    if loc == -1:
        return "86400" #If no reporting frequency, return default of 1 day
    dmarcContents = dmarcContents[loc+3:]
    loc = dmarcContents.find(";")
    dmarcContents = dmarcContents[:loc]
    return dmarcContents

print(getPolicy("globalcyberalliance.org"))
print(getSubdomainPolicy("globalcyberalliance.org"))
print(getReportAddresses("globalcyberalliance.org"))
print(getForensicAddresses("globalcyberalliance.org"))
print(getReportFrequency("globalcyberalliance.org"))
print(getMessage("globalcyberalliance.org"))

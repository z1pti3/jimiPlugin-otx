import csv
import datetime
import os
import re
from pathlib import Path

from core import settings, helpers, auth, db
from core.models import action
from plugins.otx.includes import otx

class _otxLookup(action._action):
    otxType = str()
    indicator = str()

    def run(self,data,persistentData,actionResult):
        indicator = helpers.evalString(self.indicator,{"data" : data})
        otxType = helpers.evalString(self.otxType,{"data" : data})
        if re.search('(\.|\\|\/)',otxType):
            actionResult["result"] = False
            actionResult["rc"] = 255
            return actionResult

        actionResult["data"]["otxIndicators"] = []

        if os.path.isfile(Path("plugins/otx/cache/ioc_{0}.csv".format(otxType))):
            f = csv.reader(open(Path("plugins/otx/cache/ioc_{0}.csv".format(otxType)), "rt", encoding='utf-8'), quoting=csv.QUOTE_ALL, dialect='excel')
            for line in f:
                if indicator == line[12]:
                    actionResult["data"]["otxIndicators"].append(line)

        if len(actionResult["data"]["otxIndicators"]) > 0:
            actionResult["result"] = True
            actionResult["rc"] = 0
        else:
            actionResult["result"] = False
            actionResult["rc"] = 404
        return actionResult

class _otxUpdate(action._action):

    def run(self,data,persistentData,actionResult):
        if "ca" in otxSettings:
            o = otx._otx(otxSettings["otxkey"],otxSettings["ca"],otxSettings["requestTimeout"])
        else:
           o = otx._otx(otxSettings["otxkey"],otxSettings["ca"],otxSettings["requestTimeout"])

        since = (datetime.datetime.now() - datetime.timedelta(days=120))
        if os.path.isfile(Path("plugins/otx/cache/ioc.csv")):
            modTimesinceEpoc = os.path.getmtime(Path("plugins/otx/cache/ioc.csv"))
            since = datetime.datetime.fromtimestamp(modTimesinceEpoc)

        types = { "all" : open(Path("plugins/otx/cache/ioc.csv"), "a", newline="", encoding='utf-8') }
        for pulse in o.getSubscribed(since):
            for indicator in pulse["indicators"]:
                line = [pulse['id'].replace("\r\n","").replace("\n",""), pulse['author_name'].replace("\r\n","").replace("\n",""), pulse['name'].replace("\r\n","").replace("\n",""), pulse['description'].replace("\r\n","").replace("\n",""), pulse['created'].replace("\r\n","").replace("\n",""), pulse['modified'].replace("\r\n","").replace("\n",""), ";".join(pulse['attack_ids']).replace("\r\n","").replace("\n",""), ";".join(pulse['industries']).replace("\r\n","").replace("\n",""), ";".join(pulse['malware_families']).replace("\r\n","").replace("\n",""), ";".join(pulse['targeted_countries']).replace("\r\n","").replace("\n",""), ";".join(pulse['references']).replace("\r\n","").replace("\n",""), pulse['tlp'].replace("\r\n","").replace("\n",""), indicator['indicator'].replace("\r\n","").replace("\n","")]
                if indicator['type'].lower() not in types:
                    if not os.path.isfile(Path("plugins/otx/cache/ioc_{0}.csv".format(indicator['type'].lower()))):
                        types[indicator['type'].lower()] = open(Path("plugins/otx/cache/ioc_{0}.csv".format(indicator['type'].lower())), "w", newline="", encoding='utf-8')
                        header=["otx_id","otx_author_name","otx_name","otx_description","otx_created","otx_modified","otx_attack_ids","otx_industries","otx_malware_families","otx_targeted_countries","otx_references","otx_tlp","otx_indicator"]
                        wr = csv.writer(types[indicator['type'].lower()], quoting=csv.QUOTE_ALL, dialect='excel')
                        wr.writerow(header)
                    types[indicator['type'].lower()] = open(Path("plugins/otx/cache/ioc_{0}.csv".format(indicator['type'].lower())), "a", newline="", encoding='utf-8')
                # Write into seperate file
                wr = csv.writer(types[indicator['type'].lower()], quoting=csv.QUOTE_ALL, dialect='excel')
                wr.writerow(line)
                # Write into all file
                wr = csv.writer(types["all"], quoting=csv.QUOTE_ALL, dialect='excel')
                wr.writerow(line)

        actionResult["data"]["otxFiles"] = {}
        for openfile in types:
            actionResult["data"]["otxFiles"][openfile] = "plugins/otx/cache/ioc_{0}.csv".format(openfile)
            types[openfile].close()

        actionResult["result"] = True
        actionResult["rc"] = 0 
        return actionResult

class _otxLookupIPv4(action._action):
    apiToken = str()
    ip = str()

    def run(self,data,persistentData,actionResult):
        ip = helpers.evalString(self.ip,{"data" : data})
        apiToken = auth.getPasswordFromENC(self.apiToken)

        result = otx._otx(apiToken).lookupIpv4(ip)
        if result:
            actionResult["result"] = True
            actionResult["rc"] = 0
            actionResult["apiResult"] = result
        else:
            actionResult["result"] = False
            actionResult["rc"] = 404
            actionResult["msg"] = "Failed to get a valid response from OTX API"
        return actionResult 

    def setAttribute(self,attr,value,sessionData=None):
        if attr == "apiToken" and not value.startswith("ENC "):
            if db.fieldACLAccess(sessionData,self.acl,attr,accessType="write"):
                self.apiToken = "ENC {0}".format(auth.getENCFromPassword(value))
                return True
            return False
        return super(_otxLookupIPv4, self).setAttribute(attr,value,sessionData=sessionData)

class _otxLookupIPv6(action._action):
    apiToken = str()
    ip = str()

    def run(self,data,persistentData,actionResult):
        ip = helpers.evalString(self.ip,{"data" : data})
        apiToken = auth.getPasswordFromENC(self.apiToken)

        result = otx._otx(apiToken).lookupIpv6(ip)
        if result:
            actionResult["result"] = True
            actionResult["rc"] = 0
            actionResult["apiResult"] = result
        else:
            actionResult["result"] = False
            actionResult["rc"] = 404
            actionResult["msg"] = "Failed to get a valid response from OTX API"
        return actionResult 

    def setAttribute(self,attr,value,sessionData=None):
        if attr == "apiToken" and not value.startswith("ENC "):
            if db.fieldACLAccess(sessionData,self.acl,attr,accessType="write"):
                self.apiToken = "ENC {0}".format(auth.getENCFromPassword(value))
                return True
            return False
        return super(_otxLookupIPv6, self).setAttribute(attr,value,sessionData=sessionData)

class _otxLookupDomain(action._action):
    apiToken = str()
    domain = str()

    def run(self,data,persistentData,actionResult):
        domain = helpers.evalString(self.domain,{"data" : data})
        apiToken = auth.getPasswordFromENC(self.apiToken)

        result = otx._otx(apiToken).lookupDomain(domain)
        if result:
            actionResult["result"] = True
            actionResult["rc"] = 0
            actionResult["apiResult"] = result
        else:
            actionResult["result"] = False
            actionResult["rc"] = 404
            actionResult["msg"] = "Failed to get a valid response from OTX API"
        return actionResult 

    def setAttribute(self,attr,value,sessionData=None):
        if attr == "apiToken" and not value.startswith("ENC "):
            if db.fieldACLAccess(sessionData,self.acl,attr,accessType="write"):
                self.apiToken = "ENC {0}".format(auth.getENCFromPassword(value))
                return True
            return False
        return super(_otxLookupDomain, self).setAttribute(attr,value,sessionData=sessionData)

class _otxLookupHostname(action._action):
    apiToken = str()
    hostname = str()

    def run(self,data,persistentData,actionResult):
        hostname = helpers.evalString(self.hostname,{"data" : data})
        apiToken = auth.getPasswordFromENC(self.apiToken)

        result = otx._otx(apiToken).lookupHostname(hostname)
        if result:
            actionResult["result"] = True
            actionResult["rc"] = 0
            actionResult["apiResult"] = result
        else:
            actionResult["result"] = False
            actionResult["rc"] = 404
            actionResult["msg"] = "Failed to get a valid response from OTX API"
        return actionResult 

    def setAttribute(self,attr,value,sessionData=None):
        if attr == "apiToken" and not value.startswith("ENC "):
            if db.fieldACLAccess(sessionData,self.acl,attr,accessType="write"):
                self.apiToken = "ENC {0}".format(auth.getENCFromPassword(value))
                return True
            return False
        return super(_otxLookupHostname, self).setAttribute(attr,value,sessionData=sessionData)

class _otxLookupUrl(action._action):
    apiToken = str()
    url = str()

    def run(self,data,persistentData,actionResult):
        url = helpers.evalString(self.url,{"data" : data})
        apiToken = auth.getPasswordFromENC(self.apiToken)

        result = otx._otx(apiToken).lookupUrl(url)
        if result:
            actionResult["result"] = True
            actionResult["rc"] = 0
            actionResult["apiResult"] = result
        else:
            actionResult["result"] = False
            actionResult["rc"] = 404
            actionResult["msg"] = "Failed to get a valid response from OTX API"
        return actionResult 

    def setAttribute(self,attr,value,sessionData=None):
        if attr == "apiToken" and not value.startswith("ENC "):
            if db.fieldACLAccess(sessionData,self.acl,attr,accessType="write"):
                self.apiToken = "ENC {0}".format(auth.getENCFromPassword(value))
                return True
            return False
        return super(_otxLookupUrl, self).setAttribute(attr,value,sessionData=sessionData)

class _otxLookupCve(action._action):
    apiToken = str()
    cve = str()

    def run(self,data,persistentData,actionResult):
        cve = helpers.evalString(self.cve,{"data" : data})
        apiToken = auth.getPasswordFromENC(self.apiToken)

        result = otx._otx(apiToken).lookupCve(cve)
        if result:
            actionResult["result"] = True
            actionResult["rc"] = 0
            actionResult["apiResult"] = result
        else:
            actionResult["result"] = False
            actionResult["rc"] = 404
            actionResult["msg"] = "Failed to get a valid response from OTX API"
        return actionResult 

    def setAttribute(self,attr,value,sessionData=None):
        if attr == "apiToken" and not value.startswith("ENC "):
            if db.fieldACLAccess(sessionData,self.acl,attr,accessType="write"):
                self.apiToken = "ENC {0}".format(auth.getENCFromPassword(value))
                return True
            return False
        return super(_otxLookupCve, self).setAttribute(attr,value,sessionData=sessionData)

class _otxLookupFileHash(action._action):
    apiToken = str()
    fileHash = str()

    def run(self,data,persistentData,actionResult):
        fileHash = helpers.evalString(self.fileHash,{"data" : data})
        apiToken = auth.getPasswordFromENC(self.apiToken)

        result = otx._otx(apiToken).lookupFileHash(fileHash)
        if result:
            actionResult["result"] = True
            actionResult["rc"] = 0
            actionResult["apiResult"] = result
        else:
            actionResult["result"] = False
            actionResult["rc"] = 404
            actionResult["msg"] = "Failed to get a valid response from OTX API"
        return actionResult 

    def setAttribute(self,attr,value,sessionData=None):
        if attr == "apiToken" and not value.startswith("ENC "):
            if db.fieldACLAccess(sessionData,self.acl,attr,accessType="write"):
                self.apiToken = "ENC {0}".format(auth.getENCFromPassword(value))
                return True
            return False
        return super(_otxLookupFileHash, self).setAttribute(attr,value,sessionData=sessionData)

otxSettings = settings.config["otx"]
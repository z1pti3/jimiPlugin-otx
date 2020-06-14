import csv
import datetime
import os
import re
from pathlib import Path

from core import settings, helpers
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

otxSettings = settings.config["otx"]
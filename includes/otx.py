import requests
from pathlib import Path
import json
import datetime

class _otx():
    apiURL = "https://otx.alienvault.com/api/v1"

    def __init__(self,otxKey,ca=None,requestTimeout=30):
        self.otxKey = otxKey
        self.requestTimeout = requestTimeout
        if ca:
            self.ca = Path(ca)
        else:
            self.ca = None
        self.buildHeaders()

    def buildHeaders(self):
        self.url = self.apiURL
        self.headers = {
            "X-OTX-API-KEY" : self.otxKey
        }

    def getAPI(self,url):
        try:
            if self.ca:
                response = requests.get(url, headers=self.headers, verify=self.ca, timeout=self.requestTimeout)
            else:
                response = requests.get(url, headers=self.headers, timeout=self.requestTimeout)
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
            return 0, "Connection Timeout"
        if response.status_code == 200:
            return response.text
        return None

    def getSubscribed(self,since=None):
        args = []
        if since:
             args.append('modified_since={}'.format(since.strftime('%Y-%m-%d %H:%M:%S.%f')))
        args.append("limit=1000")
        args.append("page=1")
        requestArgs = "&".join(args)
        requestArgs = "/{0}?{1}".format("/pulses/subscribed",requestArgs)
        url = "{0}{1}".format(self.url,requestArgs)
        response = self.getAPI(url)
        while response != None:
            try:
                responseData = json.loads(response)
                if "results" in responseData:
                    for result in responseData["results"]:
                        yield result
                response = None
                if "next" in responseData:
                    if responseData["next"]:
                        response = self.getAPI(responseData["next"])
            except TypeError as e:
                return None

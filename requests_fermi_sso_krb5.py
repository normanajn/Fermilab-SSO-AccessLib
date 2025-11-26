import requests
from requests_kerberos import HTTPKerberosAuth, OPTIONAL, REQUIRED
import re
import sys
import time

class FermiSSOKrb5Session( requests.Session ):
     def __init__(self, *args, **kwargs):
         if "userpass" in kwargs:
             self.adapterid =  "ad..KrbOrForm"
             self.username, self.passwd = kwargs["userpass"].split(":")
             del kwargs["userpass"]
         requests.Session.__init__(self, *args, **kwargs)
         self.choose_page_re = re.compile('<form.*method="GET".*action="(/idp/[^"]*)">')
         self.login_page_re = re.compile('<form.*method="POST".*action="(/idp/[^"]*)".*>')
         self.base_re = re.compile('<base href="(.*)/"/>')
         # default to kerberos
         self.adapterid =  "ad..KrbOrForm"

     def send(self, req, **send_kwargs):
         res = requests.Session.send(self, req, **send_kwargs)
         m = self.choose_page_re.search(res.text)
         if m:
             print("got Choose page...")
             # got choose_auth page...
             url = self.extract_chose_url(res)
             print(f"trying to choose by calling {url} ")
             res = self.get(url, auth = HTTPKerberosAuth(mutual_authentication=OPTIONAL,force_preemptive=True))

         m = self.login_page_re.search(res.text)
         if m:
             print("got Login page...")
             url = self.extract_login_url(res)
             formdata = {
                "pf.username" : self.username,
                "pf.pass": self.passwd, 
                "pf.ok" : "clicked",
                "pf.cancel" :"",
                "pf.adapterId" :"FormBased",
             }
             res = self.post(url, data=formdata)
         return res
        
     def extract_login_url(self, resp):
         base = "https://pingprod.fnal.gov"
         mb = self.base_re.search(resp.text)
         if mb:
              base = mb.group(1)
         m = self.login_page_re.search(resp.text)
         return base + m.group(1)

     def extract_chose_url(self, resp):
         # form data to send to the Pick Authentication Method form
         formdata = {
            "pfidpadapterid": self.adapterid,    # we want kerberos
            "rememberChoice": "true",            # don't re-ask
         }
         # should find this from the response somewhere, but..
         base = "https://pingprod.fnal.gov"
         mb = self.base_re.search(resp.text)
         if mb:
              base = mb.group(1)
          
         packed_form_data = "&".join([ f"{k}={v}" for k,v in formdata.items()])
         # use a regexp to find the <form> tag in the page
         m = self.choose_page_re.search(resp.text)
         assert(m)
         return base + m.group(1) + "?" + packed_form_data

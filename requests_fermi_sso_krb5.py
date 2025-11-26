import requests
from requests_kerberos import HTTPKerberosAuth, OPTIONAL, REQUIRED
import re
import sys
import time

class FermiSSOKrb5Session( requests.Session ):
     def __init__(self, *args, **kwargs):
         if "userpass" in kwargs:
             self.adapterid =  "ad..KrbOrForm"
             username, passwd = kwargs["userpass"].split(":")
             self.login_form_data = {
                "pf.username" : username,
                "pf.pass": passwd, 
                "pf.ok" : "clicked",
                "pf.cancel" :"",
                "pf.adapterId" :"FormBased",
             }
             del kwargs["userpass"]
         else:
             self.login_form_data = None

         self.choose_page_re = re.compile('<form.*method="GET".*action="(/idp/[^"]*)".*>')
         self.login_page_re = re.compile('<form.*method="POST".*action="(/idp/[^"]*)".*>')
         self.base_re = re.compile('<base href="(.*)/"/>')
         self.postback_form_re = re.compile('<form.*method="post".*action="([^"]*)".*>.*<input.*name="RelayState" *value="([^"]*)".*<input.*name="SAMLResponse" *value="([^"]*)"',flags=re.S)
         self.adapterid =  "ad..KrbOrForm"
         self.logging_in_already = False

         requests.Session.__init__(self, *args, **kwargs)


     def send(self, req, **send_kwargs):
         res = requests.Session.send(self, req, **send_kwargs)
         if self.logging_in_already:
             # recursively called from a get() or post(), below...
             return res

         m = self.choose_page_re.search(res.text)
         if m:
             self.logging_in_already = True
             print("got Choose page...")
             # got choose_auth page...
             url = self.extract_chose_url(res)
             print(f"trying to choose by calling {url} ")
             res = requests.Session.get(self, url, auth = HTTPKerberosAuth(mutual_authentication=OPTIONAL,force_preemptive=False))

         m = self.login_page_re.search(res.text)
         if m and self.login_form_data:
             print("got Login page...")
             url = self.extract_login_url(res)
             res = requests.Session.post(self, url, data=self.login_form_data)
             m = self.login_page_re.search(res.text)

         m = self.postback_form_re.search(res.text)
         if m:
             print("saw Postback form...")
             print(f"cookies: {repr(self.cookies)}")
             print(res.text)
             print("=-=-=-=-=-=-=-=")
             url, formdata = self.extract_post_back_data(res)
             # h = { 'Content-type': 'application/x-www-form-urlencoded' }
             res = requests.Session.post(self,url, data=formdata)

         self.logging_in_already = False
         return res

     def extract_post_back_data(self, resp): 
      
         m = self.postback_form_re.search(resp.text)
         return m.group(1), { "RelayState": m .group(2), "SAMLResponse": m.group(3)}
        
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

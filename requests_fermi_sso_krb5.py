import requests
from requests_kerberos import HTTPKerberosAuth
import re

class FermiSSOKrb5Session( requests.Session )

     def send(self, req, **send_kwargs):
         if not self.cookies.get("_saml_idp"):
             # we haven't done SSO signon yet, so we're going to get a "Pick Authentication form"...
             pick_meth_resp = super().send(req, **send_kwargs)
             req.url = extract_url(pick_method_resp)
         req.auth = HTTPKerberosAuth()
         return  super().send(req, **send_kwargs)

     def extract_url(self, resp):
         m = re.search( '<form.*method="GET".*action="(/idp/[^"]*)">',resp.text)
         if m:
              return m.group(1) + "?pfidpadapterid=ad..KrbOrForm&rememberChoice=true&Continue=Continue"

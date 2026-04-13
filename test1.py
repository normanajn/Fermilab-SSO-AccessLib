import requests
from requests_fermi_sso import FermiSSOSession
# =-=-=- debug logging =-=-=-=-=
import http
import logging
import requests

http.client.HTTPConnection.debuglevel = 1

logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)
requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True
# =-=-=-=-=-=-=-=

s = FermiSSOKrb5Session()
r = s.get("https://cdcvs.fnal.gov/index.html")

if r.text.find("Marc Mengel") > 0:
   print("yay!")
else:
   print("sad:")
   print(r.text)

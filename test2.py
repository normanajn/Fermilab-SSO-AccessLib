import requests, os, sys
from requests_fermi_sso_krb5 import FermiSSOKrb5Session
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

print(f"{os.environ['USER']}passwd:", end="")
sys.stdout.flush()
passtxt = sys.stdin.readline().strip("\n")
s = FermiSSOKrb5Session(userpass=f"{os.environ['USER']}:{passtxt}")
r = s.get("https://cdcvs.fnal.gov/index.html")

print("got: ")
if r.text.find("cdcvs") > 0:
   print(r.text)
   print("yay!")
else:
   print(r.text)
   print("sad :-(")

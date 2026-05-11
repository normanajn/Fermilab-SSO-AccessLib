import requests, os, sys
from requests_fermi_sso import FermiSSOSession

debug=True
if debug:
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
    rfs_log = logging.getLogger("requests_fermi_sso")
    rfs_log.setLevel(logging.DEBUG)
    # =-=-=-=-=-=-=-=

os.system("stty -echo")
print(f"{os.environ['USER']} passwd: ", end="")
sys.stdout.flush()
passtxt = sys.stdin.readline().strip("\n")
os.system("stty echo")
s = FermiSSOSession(userpass=f"{os.environ['USER']}:{passtxt}")
r = s.get("https://cdcvs.fnal.gov/index.html")

print("got: ")
if r.text.find("cdcvs") > 0:
   print(r.text)
   print("yay!")
else:
   print(r.text)
   print("sad :-(")

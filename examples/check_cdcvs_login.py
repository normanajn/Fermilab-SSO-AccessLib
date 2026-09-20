#!/usr/bin/env python3
"""
Smallest end-to-end check: log in to cdcvs.fnal.gov and say whether it worked.

This is a hand-run example, not part of the test suite -- it needs a real
password and real network access. For an automated check with proper exit
codes and cookie reuse, use fermi-sso-probe(1) instead:

    fermi-sso-probe -u "$USER" https://cdcvs.fnal.gov/index.html

Run as:  python examples/check_cdcvs_login.py [--debug]
"""

import getpass
import os
import sys

from requests_fermi_sso import FermiSSOSession

URL = "https://cdcvs.fnal.gov/index.html"


def enable_debug():
    import http.client
    import logging

    http.client.HTTPConnection.debuglevel = 1
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    logging.getLogger("requests.packages.urllib3").setLevel(logging.DEBUG)
    logging.getLogger("requests_fermi_sso").setLevel(logging.DEBUG)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if "--debug" in argv:
        enable_debug()

    user = os.environ.get("FERMI_USER") or getpass.getuser()
    # getpass handles terminal echo itself; the stty dance this script used
    # to do left the terminal broken whenever it exited early
    password = getpass.getpass(f"Fermilab password for {user}: ")

    session = FermiSSOSession(userpass=f"{user}:{password}")
    resp = session.get(URL)

    if session.login_page_re.search(resp.text):
        print("login failed: still on the identity provider's login form")
        return 1
    print(f"login succeeded: {resp.url} ({len(resp.content)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

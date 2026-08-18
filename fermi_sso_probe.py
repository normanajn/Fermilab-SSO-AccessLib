#!/usr/bin/env python3
"""
fermi_sso_probe -- diagnostic helper for requests_fermi_sso.

Fetches an SSO-protected Fermilab URL using FermiSSOSession and reports
whether the login actually succeeded, since FermiSSOSession returns the
login page with a 200 status on bad credentials rather than raising.

Option priority: commandline > environment > default.

  --user      / $FERMI_USER  (default: $USER)
  --url       / $FERMI_SSO_URL
  --password-env NAME        read password from that env var instead of prompting
  --debug     / $FERMI_SSO_DEBUG=1
"""

import argparse
import getpass
import os
import sys

from requests_fermi_sso import FermiSSOSession

DEFAULT_URL = "https://mu2e-docdb.fnal.gov/cgi-bin/sso/DocumentDatabase"

# If the response still looks like any of these, we never got through.
IDP_HOST = "pingprod.fnal.gov"


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="fermi_sso_probe",
        description="Test a Fermilab SSO login through requests_fermi_sso.",
    )
    p.add_argument(
        "-u",
        "--user",
        default=os.environ.get("FERMI_USER", os.environ.get("USER", "")),
        help="Fermilab services account name (default: $FERMI_USER, then $USER)",
    )
    p.add_argument(
        "-U",
        "--url",
        default=os.environ.get("FERMI_SSO_URL", DEFAULT_URL),
        help=f"SSO-protected URL to fetch (default: {DEFAULT_URL})",
    )
    p.add_argument(
        "--password-env",
        metavar="NAME",
        default=None,
        help="Read the password from environment variable NAME instead of prompting. "
        "Never pass a password on the command line; it is visible in ps(1).",
    )
    p.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        default=None,
        help="Write the final response body to FILE for inspection",
    )
    p.add_argument(
        "-d",
        "--debug",
        action="store_true",
        default=os.environ.get("FERMI_SSO_DEBUG", "") == "1",
        help="Enable wire-level and library debug logging",
    )
    return p.parse_args(argv)


def enable_debug():
    import http.client
    import logging

    http.client.HTTPConnection.debuglevel = 1
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    logging.getLogger("requests.packages.urllib3").setLevel(logging.DEBUG)
    logging.getLogger("requests_fermi_sso").setLevel(logging.DEBUG)


def main(argv=None):
    args = parse_args(argv)

    if not args.user:
        print("error: no username; pass --user or set $FERMI_USER", file=sys.stderr)
        return 2

    if args.password_env:
        password = os.environ.get(args.password_env)
        if not password:
            print(
                f"error: ${args.password_env} is unset or empty", file=sys.stderr
            )
            return 2
    else:
        password = getpass.getpass(f"Fermilab services password for {args.user}: ")

    if ":" in password:
        # FermiSSOSession splits "user:pass" on every colon and unpacks into
        # two names, so an embedded colon raises ValueError deep in __init__.
        print(
            "error: password contains ':', which requests_fermi_sso cannot parse",
            file=sys.stderr,
        )
        return 2

    if args.debug:
        enable_debug()

    session = FermiSSOSession(userpass=f"{args.user}:{password}")

    print(f"fetching {args.url}", file=sys.stderr)
    resp = session.get(args.url)

    print("", file=sys.stderr)
    print(f"final url : {resp.url}", file=sys.stderr)
    print(f"status    : {resp.status_code}", file=sys.stderr)
    print(f"bytes     : {len(resp.text)}", file=sys.stderr)
    print(
        f"cookies   : {sorted(c.name for c in session.cookies)}", file=sys.stderr
    )
    print(
        f"redirects : {[h.status_code for h in resp.history]}", file=sys.stderr
    )

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(resp.text)
        print(f"body written to {args.output}", file=sys.stderr)

    # Decide success: we must be off the IdP and past the login form.
    stuck_at_idp = IDP_HOST in resp.url
    still_login = bool(session.login_page_re.search(resp.text))
    still_choose = bool(session.choose_page_re.search(resp.text))

    print("", file=sys.stderr)
    if stuck_at_idp or still_login or still_choose:
        print("RESULT: login FAILED", file=sys.stderr)
        if still_choose:
            print("  still on the choose-authentication page", file=sys.stderr)
        if still_login:
            print(
                "  still on the login form -- bad password, or the account "
                "requires MFA (this package only does password auth)",
                file=sys.stderr,
            )
        if stuck_at_idp and not (still_login or still_choose):
            print(f"  stranded on {IDP_HOST} at an unrecognized page", file=sys.stderr)
        return 1

    print("RESULT: login SUCCEEDED", file=sys.stderr)
    print(f"  landed on {resp.url}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

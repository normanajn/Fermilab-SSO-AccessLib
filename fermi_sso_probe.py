#!/usr/bin/env python3
"""
fermi_sso_probe -- fetch an SSO-protected Fermilab URL and report whether
the login actually worked.

FermiSSOSession returns the login page with HTTP 200 when credentials fail,
so a status check alone cannot distinguish success from failure. This tool
fetches a URL through the session and reports success only when the final
response has left the identity provider and no longer looks like any stage
of the login sequence.

With --cookie-file the session cookies are loaded before the request and
saved after a completed login, so later runs -- and other scripts using the
same jar -- skip the password step. A browser's exported cookies.txt works
as the jar too, which is the only way to use an MFA-enrolled account.

Settings resolve in this order, highest priority first:

    1. commandline options
    2. environment variables
    3. a .env file
    4. built-in defaults

See fermi_sso_probe(1) and docs/HOWTO.md.
"""

import argparse
import getpass
from urllib.parse import urlencode, urlsplit
import os
import stat
import sys
from typing import Dict, List, Optional, Tuple

from requests_fermi_sso import (
    CILOGON_DEVICE_URL,
    CILOGON_HOSTS,
    FERMILAB_CILOGON_IDP,
    FermiSSOSession,
)
from requests_fermi_sso import __version__ as _lib_version

#: single source of truth lives in the library module
__version__ = _lib_version

#: Fetched when no URL is given. The Mu2e DocDB SSO entry point; note that
#: https://mu2e-docdb.fnal.gov/ itself is an unprotected landing page and
#: will not exercise the login flow at all.
DEFAULT_URL = "https://mu2e-docdb.fnal.gov/cgi-bin/sso/DocumentDatabase"

#: Landing on this host means we never made it back to the service provider.
DEFAULT_IDP_HOST = "pingprod.fnal.gov"

#: Searched in order when --env-file is not given.
DEFAULT_ENV_FILES = (".env", "~/.fermi_sso.env")

ENV_USER = "FERMI_USER"
ENV_PASSWORD = "FERMI_PASSWORD"
ENV_URL = "FERMI_SSO_URL"
ENV_IDP_HOST = "FERMI_SSO_IDP_HOST"
ENV_DEBUG = "FERMI_SSO_DEBUG"
ENV_ENV_FILE = "FERMI_SSO_ENV_FILE"
ENV_COOKIE_FILE = "FERMI_SSO_COOKIE_FILE"
ENV_AUTH = "FERMI_SSO_AUTH"
ENV_PIN_SOURCE = "FERMI_SSO_PIN_SOURCE"
ENV_COOKIE_FORMAT = "FERMI_SSO_COOKIE_FORMAT"
ENV_USER_CODE = "FERMI_SSO_USER_CODE"
ENV_CILOGON_IDP = "FERMI_SSO_CILOGON_IDP"


# --------------------------------------------------------------------------
# .env file handling
# --------------------------------------------------------------------------


def parse_env_file(text: str) -> Dict[str, str]:
    """
    Parse .env-style ``KEY=value`` text into a dict.

    Understands blank lines, ``#`` comments, an optional ``export`` prefix,
    and single- or double-quoted values (quotes are stripped; a quoted value
    may contain ``#`` and leading/trailing spaces). Unquoted values have
    surrounding whitespace and trailing inline comments removed.

    Deliberately small: this avoids a python-dotenv dependency for what is
    otherwise a stdlib-only package.
    """
    values: Dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        key, sep, value = line.partition("=")
        if not sep:
            continue
        key = key.strip()
        if not key:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        else:
            # strip an inline comment only on unquoted values
            hash_at = value.find(" #")
            if hash_at != -1:
                value = value[:hash_at].rstrip()
        values[key] = value
    return values


def find_env_file(explicit: Optional[str], environ: Optional[Dict[str, str]] = None):
    """
    Return the path of the .env file to use, or None.

    An explicit path (from --env-file or $FERMI_SSO_ENV_FILE) is returned even
    if missing, so the caller can report the error rather than silently
    falling back. Otherwise DEFAULT_ENV_FILES are probed in order.
    """
    environ = os.environ if environ is None else environ
    candidate = explicit or environ.get(ENV_ENV_FILE)
    if candidate:
        return os.path.expanduser(candidate)
    for name in DEFAULT_ENV_FILES:
        path = os.path.expanduser(name)
        if os.path.isfile(path):
            return path
    return None


def load_env_file(path: Optional[str], warn=None) -> Dict[str, str]:
    """
    Read and parse an env file. Returns {} when path is None or unreadable.

    Warns when the file is group- or world-readable, since it holds a
    password.
    """
    if not path:
        return {}
    try:
        # utf-8-sig, not utf-8: Notepad, VS Code's "UTF-8 with BOM" and
        # PowerShell's Set-Content -Encoding utf8 all write a byte-order mark,
        # which would otherwise become part of the first variable's name and
        # make that one variable silently unreachable.
        with open(path, "r", encoding="utf-8-sig") as handle:
            text = handle.read()
    except OSError as exc:
        if warn:
            warn(f"warning: cannot read env file {path}: {exc}")
        return {}
    # Windows reports 0666 for every file regardless of its real ACL, so the
    # check below would warn every time and ask for something chmod cannot do
    # there.  cookie_permission_warning() in fermi_sso_cookies skips nt too.
    if warn and os.name != "nt":
        try:
            mode = os.stat(path).st_mode
            if mode & (stat.S_IRGRP | stat.S_IROTH):
                warn(
                    f"warning: {path} is readable by group/other "
                    f"({stat.filemode(mode)}); chmod 600 it"
                )
        except OSError:
            pass
    return parse_env_file(text)


# --------------------------------------------------------------------------
# settings resolution
# --------------------------------------------------------------------------


def resolve(
    cli_value: Optional[str],
    env_key: str,
    environ: Dict[str, str],
    dotenv: Dict[str, str],
    default: Optional[str] = None,
) -> Optional[str]:
    """Apply the commandline > environment > .env file > default precedence."""
    if cli_value is not None:
        return cli_value
    if environ.get(env_key):
        return environ[env_key]
    if dotenv.get(env_key):
        return dotenv[env_key]
    return default


def resolve_password(
    args,
    environ: Dict[str, str],
    dotenv: Dict[str, str],
    prompt=None,
) -> Optional[str]:
    """
    Resolve the password across all supported sources.

    --password beats --password-env beats $FERMI_PASSWORD beats the .env
    file. If none supplied and a prompt callable is given, prompt for it.
    """
    if args.password is not None:
        return args.password
    if args.password_env:
        value = environ.get(args.password_env)
        if not value:
            raise ValueError(f"${args.password_env} is unset or empty")
        return value
    if environ.get(ENV_PASSWORD):
        return environ[ENV_PASSWORD]
    if dotenv.get(ENV_PASSWORD):
        return dotenv[ENV_PASSWORD]
    if prompt is not None:
        return prompt()
    return None


# --------------------------------------------------------------------------
# result classification
# --------------------------------------------------------------------------

import re

#: Titles that mark an application's own sign-in page, seen after the IdP
#: pages are all behind us. Deliberately narrow: "Sign in", "Log in",
#: "Login" as a word, not any page mentioning logging in.
SIGNIN_TITLE_RE = re.compile(r"\b(sign[ -]?in|log[ -]?in|login)\b", re.I)
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)

#: PingFederate's RSA SecurID adapter form, served after the password when a
#: connection demands a second factor (seen on the Workday connection).
SECOND_FACTOR_RE = re.compile(
    r'name="SecurIDAuthenticationAdapter:|<title>[^<]*SecurID', re.I
)


def _page_title(text: str) -> str:
    match = _TITLE_RE.search(text)
    return " ".join(match.group(1).split()) if match else ""


def classify(
    session: FermiSSOSession,
    resp,
    idp_host: str,
    expect: Optional[str] = None,
) -> Tuple[bool, List[str]]:
    """
    Decide whether a response represents a completed login.

    Returns (ok, reasons). Success requires that the final URL is off the
    IdP host, that neither the choose-auth nor the login form regex still
    matches, and that --expect text (if given) is present.
    """
    reasons: List[str] = []

    if session.delay_page_re.search(resp.text):
        reasons.append(
            "the identity provider is throttling sign-ons (Multiple Sign-On "
            "Delay page); wait a few minutes and retry"
        )
        return False, reasons
    if session.choose_page_re.search(resp.text):
        reasons.append("still on the choose-authentication page")
    if session.login_page_re.search(resp.text):
        if session.login_form_data is None:
            reasons.append(
                "still on the login form -- the cookie file did not yield a "
                "live session and no password was supplied to log in"
            )
        else:
            reasons.append(
                "still on the login form -- wrong password, or the account "
                "requires MFA (this package only drives password auth)"
            )
    if session.is_postback_page(resp):
        reasons.append("stopped on the SAML postback form; it was not submitted")
    if session.is_shib_storage_page(resp):
        reasons.append(
            f"stopped on a Shibboleth client-storage form at "
            f"{urlsplit(resp.url).hostname}; it was not submitted"
        )
    final_host = (urlsplit(resp.url).hostname or "").lower()
    if final_host in CILOGON_HOSTS:
        # CILogon's pages are neither the IdP nor the application: a device
        # approval ends on CILogon itself, and its errors are alert boxes
        reasons.extend(session.cilogon_problems(resp))
    denied = [h for h in list(resp.history) + [resp] if "error=access_denied" in h.url]
    if denied:
        reasons.append(
            "the identity provider sent the application 'access_denied': the "
            "selected adapter refused to authenticate (for a hardware-token "
            "adapter, the client certificate was not presented or not accepted)"
        )
    if (
        resp.status_code == 401
        and "negotiate" in resp.headers.get("WWW-Authenticate", "").lower()
    ):
        reasons.append(
            "the identity provider's Kerberos (Negotiate) challenge was not "
            "answered: it needs a FERMI.WIN.FNAL.GOV ticket for "
            f"HTTP/{urlsplit(resp.url).hostname}, and an FNAL.GOV ticket "
            "(the kind Vault accepts) is refused; check klist, or use "
            "--auth yubikey"
        )
    if SECOND_FACTOR_RE.search(resp.text):
        reasons.append(
            "the identity provider requires a second factor (RSA SecurID "
            "passcode form); this package cannot supply one"
        )
    if idp_host and final_host == idp_host.lower() and not reasons:
        reasons.append(f"stranded on {idp_host} at an unrecognized page")
    title = _page_title(resp.text)
    if not reasons and title and SIGNIN_TITLE_RE.search(title):
        # Off the IdP and past its forms, but the application itself is still
        # showing a sign-in page: e.g. django-allauth's "Sign In via SSO"
        # confirmation, which needs a POST the library does not perform.
        reasons.append(
            f"landed on an application sign-in page (title {title!r}); the "
            "site's own login step was not completed"
        )
    if expect and expect not in resp.text:
        reasons.append(f"expected text {expect!r} not found in the response body")

    return (not reasons), reasons


# --------------------------------------------------------------------------
# commandline
# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fermi_sso_probe",
        description="Fetch an SSO-protected Fermilab URL and report whether "
        "the login succeeded.",
        epilog="Settings resolve as: commandline > environment > .env file > "
        "defaults. See fermi_sso_probe(1).",
    )
    parser.add_argument(
        "url",
        nargs="?",
        default=None,
        help=f"URL to fetch (default: {DEFAULT_URL})",
    )
    parser.add_argument(
        "-U", "--url", dest="url_opt", default=None, help="same as the positional URL"
    )
    parser.add_argument(
        "-u",
        "--user",
        default=None,
        help=f"services account name (${ENV_USER}, then $USER)",
    )
    parser.add_argument(
        "-p",
        "--password",
        default=None,
        help="password. WARNING: visible to other users in ps(1); prefer "
        "--password-env, a .env file, or the interactive prompt",
    )
    parser.add_argument(
        "--password-env",
        metavar="NAME",
        default=None,
        help=f"read the password from environment variable NAME (default ${ENV_PASSWORD})",
    )
    parser.add_argument(
        "-e",
        "--env-file",
        metavar="FILE",
        default=None,
        help="load settings from FILE (default: ./.env, then ~/.fermi_sso.env)",
    )
    parser.add_argument(
        "--no-env-file",
        action="store_true",
        help="ignore .env files entirely",
    )
    parser.add_argument(
        "-a",
        "--auth",
        choices=("password", "kerberos", "yubikey"),
        default=None,
        help=f"authentication method at the identity provider (${ENV_AUTH}; "
        f"default password). kerberos uses the local ticket cache via "
        f"requests-gssapi; yubikey uses the PIV certificate on the token via "
        f"openssl and the pkcs11 engine (see fermi_sso_yubikey(3)). Neither "
        f"needs a password",
    )
    parser.add_argument(
        "--pin-source",
        metavar="FILE",
        default=None,
        help=f"with --auth yubikey: read the PIV PIN from FILE (mode 600) instead "
        f"of letting openssl prompt on the terminal (${ENV_PIN_SOURCE})",
    )
    parser.add_argument(
        "-c",
        "--cookie-file",
        metavar="FILE",
        default=None,
        help=f"load cookies from FILE before the request and save them after a "
        f"completed login (${ENV_COOKIE_FILE}). A browser cookies.txt export works. "
        f"When FILE exists no password is required",
    )
    parser.add_argument(
        "--cookie-format",
        choices=("netscape", "lwp", "json"),
        default=None,
        help=f"cookie file format (${ENV_COOKIE_FORMAT}; default: detect from the "
        f"extension and contents, write netscape)",
    )
    parser.add_argument(
        "--no-save-cookies",
        action="store_true",
        help="load the cookie file but never rewrite it",
    )
    parser.add_argument(
        "--user-code",
        metavar="CODE",
        default=None,
        help=f"approve this CILogon device-flow user code (${ENV_USER_CODE}); "
        f"with no URL, fetches {CILOGON_DEVICE_URL}?user_code=CODE. Also "
        f"entered if CILogon asks for a code on a URL given explicitly",
    )
    parser.add_argument(
        "--cilogon-idp",
        metavar="ENTITYID",
        default=None,
        help=f"identity provider to select on CILogon's page "
        f"(${ENV_CILOGON_IDP}; default {FERMILAB_CILOGON_IDP})",
    )
    parser.add_argument(
        "--idp-host",
        default=None,
        help=f"identity provider hostname used to detect a stalled login "
        f"(default: {DEFAULT_IDP_HOST})",
    )
    parser.add_argument(
        "-x",
        "--expect",
        metavar="TEXT",
        default=None,
        help="require TEXT to appear in the final page for success",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        default=None,
        help="write the final response body to FILE ('-' for stdout)",
    )
    parser.add_argument(
        "-n",
        "--no-prompt",
        action="store_true",
        help="fail instead of prompting for a missing password (for cron/CI)",
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="only print the final verdict"
    )
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        default=None,
        help=f"wire-level and library debug logging (${ENV_DEBUG}=1)",
    )
    parser.add_argument("-V", "--version", action="version", version=__version__)
    return parser


def enable_debug():
    import http.client
    import logging

    http.client.HTTPConnection.debuglevel = 1
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    logging.getLogger("requests.packages.urllib3").setLevel(logging.DEBUG)
    logging.getLogger("requests_fermi_sso").setLevel(logging.DEBUG)


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    environ = dict(os.environ)

    def warn(message):
        print(message, file=sys.stderr)

    if args.no_env_file:
        dotenv: Dict[str, str] = {}
    else:
        env_path = find_env_file(args.env_file, environ)
        if args.env_file and not os.path.isfile(os.path.expanduser(args.env_file)):
            warn(f"error: env file not found: {args.env_file}")
            return 2
        dotenv = load_env_file(env_path, warn=warn)

    user_code = resolve(args.user_code, ENV_USER_CODE, environ, dotenv)
    cilogon_idp = resolve(
        args.cilogon_idp, ENV_CILOGON_IDP, environ, dotenv, FERMILAB_CILOGON_IDP
    )
    default_url = DEFAULT_URL
    if user_code:
        default_url = CILOGON_DEVICE_URL + "?" + urlencode({"user_code": user_code})
    url = resolve(args.url_opt or args.url, ENV_URL, environ, dotenv, default_url)
    user = resolve(args.user, ENV_USER, environ, dotenv, environ.get("USER"))
    idp_host = resolve(args.idp_host, ENV_IDP_HOST, environ, dotenv, DEFAULT_IDP_HOST)
    debug = args.debug
    if debug is None:
        debug = resolve(None, ENV_DEBUG, environ, dotenv, "") == "1"
    cookie_file = resolve(args.cookie_file, ENV_COOKIE_FILE, environ, dotenv)
    cookie_format = resolve(args.cookie_format, ENV_COOKIE_FORMAT, environ, dotenv)
    if cookie_file:
        cookie_file = os.path.expanduser(cookie_file)
    # An existing jar may carry the whole session, so a password becomes
    # optional. A jar that does not exist yet still needs a password to
    # perform the login that will populate it.
    have_cookies = bool(cookie_file) and os.path.isfile(cookie_file)
    auth_method = resolve(args.auth, ENV_AUTH, environ, dotenv, "password")
    if auth_method not in ("password", "kerberos", "yubikey"):
        warn(
            f"error: ${ENV_AUTH} must be password, kerberos, or yubikey, "
            f"not {auth_method!r}"
        )
        return 2
    pin_source = resolve(args.pin_source, ENV_PIN_SOURCE, environ, dotenv)
    # Kerberos and the YubiKey, like an existing jar, make the password optional
    password_optional = have_cookies or auth_method in ("kerberos", "yubikey")

    if not password_optional and not user:
        warn(f"error: no username; pass --user or set ${ENV_USER}")
        return 2

    prompt = None
    if not args.no_prompt and sys.stdin.isatty() and not password_optional:
        prompt = lambda: getpass.getpass(f"Fermilab password for {user}: ")

    try:
        password = resolve_password(args, environ, dotenv, prompt=prompt)
    except ValueError as exc:
        warn(f"error: {exc}")
        return 2

    if not password and not password_optional:
        warn(
            f"error: no password; use --password, --password-env, "
            f"${ENV_PASSWORD}, a .env file, --cookie-file with a saved jar, "
            f"or --auth kerberos"
        )
        return 2

    if password and not user:
        warn(f"error: no username; pass --user or set ${ENV_USER}")
        return 2

    if debug:
        enable_debug()

    session_kwargs = {"auth_method": auth_method, "cilogon_idp": cilogon_idp}
    if user_code:
        session_kwargs["cilogon_user_code"] = user_code
    if auth_method == "yubikey":
        from fermi_sso_yubikey import YubiKeyCertHop

        hop = YubiKeyCertHop(
            pin_source=os.path.expanduser(pin_source) if pin_source else None
        )
        failed = [(w, d) for w, ok, d in hop.check() if not ok]
        if failed:
            for what, detail in failed:
                warn(f"error: yubikey prerequisite missing: {what}: {detail}")
            warn("run fermi-sso-yubikey for the full readiness report")
            return 2
        session_kwargs["cert_hop"] = hop
    if password:
        session_kwargs["userpass"] = f"{user}:{password}"
    if cookie_file:
        session_kwargs["cookie_file"] = cookie_file
        session_kwargs["cookie_format"] = cookie_format
        session_kwargs["cookie_save"] = not args.no_save_cookies
    try:
        session = FermiSSOSession(**session_kwargs)
    except ImportError as exc:
        warn(f"error: {exc}")
        return 2
    except (OSError, ValueError) as exc:
        warn(f"error: cannot load cookie file {cookie_file}: {exc}")
        return 2

    if not args.quiet:
        if auth_method == "kerberos":
            who = "with Kerberos" + (
                f" (password fallback as {user})" if password else ""
            )
        elif auth_method == "yubikey":
            who = "with the YubiKey certificate" + (
                f" (password fallback as {user})" if password else ""
            )
        else:
            who = f"as {user}" if password else "with cookies only"
        warn(f"fetching {url} {who}")
        if cookie_file:
            warn(
                f"cookie file: {cookie_file} ({session.cookies_loaded} cookies loaded)"
            )

    resp = session.get(url)
    ok, reasons = classify(session, resp, idp_host, args.expect)

    if not args.quiet:
        warn("")
        warn(f"final url : {resp.url}")
        warn(f"status    : {resp.status_code}")
        warn(f"bytes     : {len(resp.content)}")
        warn(f"cookies   : {sorted(c.name for c in session.cookies)}")
        warn(f"redirects : {[h.status_code for h in resp.history]}")
        if session.login_count:
            saved = (
                "saved to " + cookie_file
                if cookie_file and session.cookie_save
                else "not saved"
            )
            warn(f"login     : performed; cookies {saved}")
        elif ok:
            warn("login     : not needed (existing cookies accepted)")
        else:
            warn("login     : not completed")
        warn("")

    if args.output:
        # bytes, not resp.text: the body may be a PDF or any other
        # attachment, and decoding it to text and re-encoding as UTF-8 does
        # not round-trip
        if args.output == "-":
            sys.stdout.buffer.write(resp.content)
            sys.stdout.buffer.flush()
        else:
            with open(args.output, "wb") as handle:
                handle.write(resp.content)
            if not args.quiet:
                warn(f"body written to {args.output} ({len(resp.content)} bytes)")

    if ok:
        warn("RESULT: login SUCCEEDED")
        if not args.quiet:
            warn(f"  landed on {resp.url}")
        return 0

    warn("RESULT: login FAILED")
    for reason in reasons:
        warn(f"  {reason}")
    return 1


if __name__ == "__main__":
    sys.exit(main())

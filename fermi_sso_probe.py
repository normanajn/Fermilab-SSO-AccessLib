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
import os
import stat
import sys
from typing import Dict, List, Optional, Tuple

from requests_fermi_sso import FermiSSOSession

__version__ = "0.2.0"

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
ENV_COOKIE_FORMAT = "FERMI_SSO_COOKIE_FORMAT"


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
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
    except OSError as exc:
        if warn:
            warn(f"warning: cannot read env file {path}: {exc}")
        return {}
    if warn:
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
    if session.postback_form_re.search(resp.text):
        reasons.append("stopped on the SAML postback form; it was not submitted")
    if idp_host and idp_host in resp.url and not reasons:
        reasons.append(f"stranded on {idp_host} at an unrecognized page")
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

    url = resolve(args.url_opt or args.url, ENV_URL, environ, dotenv, DEFAULT_URL)
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

    if not have_cookies and not user:
        warn(f"error: no username; pass --user or set ${ENV_USER}")
        return 2

    prompt = None
    if not args.no_prompt and sys.stdin.isatty() and not have_cookies:
        prompt = lambda: getpass.getpass(f"Fermilab password for {user}: ")

    try:
        password = resolve_password(args, environ, dotenv, prompt=prompt)
    except ValueError as exc:
        warn(f"error: {exc}")
        return 2

    if not password and not have_cookies:
        warn(
            f"error: no password; use --password, --password-env, "
            f"${ENV_PASSWORD}, a .env file, or --cookie-file with a saved jar"
        )
        return 2

    if password and not user:
        warn(f"error: no username; pass --user or set ${ENV_USER}")
        return 2

    if password and ":" in password:
        # FermiSSOSession splits "user:pass" on every colon and unpacks the
        # result into two names, so an embedded colon raises ValueError in
        # its __init__. Report it here rather than as a traceback.
        warn("error: password contains ':', which requests_fermi_sso cannot parse")
        return 2

    if debug:
        enable_debug()

    session_kwargs = {}
    if password:
        session_kwargs["userpass"] = f"{user}:{password}"
    if cookie_file:
        session_kwargs["cookie_file"] = cookie_file
        session_kwargs["cookie_format"] = cookie_format
        session_kwargs["cookie_save"] = not args.no_save_cookies
    try:
        session = FermiSSOSession(**session_kwargs)
    except (OSError, ValueError) as exc:
        warn(f"error: cannot load cookie file {cookie_file}: {exc}")
        return 2

    if not args.quiet:
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
        warn(f"bytes     : {len(resp.text)}")
        warn(f"cookies   : {sorted(c.name for c in session.cookies)}")
        warn(f"redirects : {[h.status_code for h in resp.history]}")
        if session.login_count:
            saved = (
                "saved to " + cookie_file
                if cookie_file and session.cookie_save
                else "not saved"
            )
            warn(f"login     : performed; cookies {saved}")
        else:
            warn("login     : not needed (existing cookies accepted)")
        warn("")

    if args.output:
        if args.output == "-":
            sys.stdout.write(resp.text)
        else:
            with open(args.output, "w", encoding="utf-8") as handle:
                handle.write(resp.text)
            if not args.quiet:
                warn(f"body written to {args.output}")

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

#!/usr/bin/env python3
"""
fermi_sso_cookies -- list the cookies in a saved jar, with their details.

A jar written by FermiSSOSession (or exported from a browser) is the only
state a cookies-only run has, so when such a run fails the first question is
what the file actually holds: which hosts, which cookies, and whether any of
them have expired. This tool answers that without a network round trip.

Every cookie is shown, including expired ones, which FermiSSOSession.load_cookies
would skip. Values are masked by default because session cookies are bearer
credentials; --show-values prints them in full.

Settings resolve in this order, highest priority first:

    1. commandline options
    2. environment variables
    3. a .env file
    4. built-in defaults

See fermi_sso_cookies(1).
"""

import argparse
import fnmatch
import json
import os
import stat
import sys
import time
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional

from fermi_sso_probe import (
    ENV_COOKIE_FILE,
    ENV_COOKIE_FORMAT,
    find_env_file,
    load_env_file,
    resolve,
)
from requests_fermi_sso import (
    COOKIE_FORMATS,
    _is_httponly,
    detect_cookie_format,
    parse_json_cookies,
    parse_lwp_cookies,
    parse_netscape_cookies,
)

__version__ = "0.2.0"

#: Session cookies and cookies expiring within this many seconds are marked
#: "soon" in the table view.
SOON_SECONDS = 15 * 60

#: Characters of a masked value shown in the clear.
MASK_PREFIX = 4


# --------------------------------------------------------------------------
# reading the jar
# --------------------------------------------------------------------------


def read_jar(path: str, fmt: Optional[str] = None):
    """
    Parse every cookie in the file at path.

    Returns (fmt, cookies). Unlike FermiSSOSession.load_cookies this keeps
    expired cookies, so the caller can report them. fmt None means detect
    from the extension and first line, as the library does.
    """
    path = os.path.expanduser(path)
    with open(path, "r", encoding="utf-8") as handle:
        text = handle.read()
    fmt = fmt or detect_cookie_format(path, text)
    if fmt == "netscape":
        cookies = parse_netscape_cookies(text)
    elif fmt == "lwp":
        cookies = parse_lwp_cookies(text)
    elif fmt == "json":
        cookies = parse_json_cookies(text)
    else:
        raise ValueError(
            f"unknown cookie format {fmt!r}; expected one of {COOKIE_FORMATS}"
        )
    return fmt, cookies


def cookie_record(cookie, now: Optional[float] = None) -> Dict:
    """
    Flatten an http.cookiejar.Cookie into a plain dict.

    'expires' is None for a session cookie; 'remaining' is seconds until
    expiry (negative once expired) or None for a session cookie. 'host_only'
    follows the Netscape convention used by requests_fermi_sso: a domain
    without a leading dot applies to that host alone.
    """
    now = time.time() if now is None else now
    domain = cookie.domain or ""
    expires = int(cookie.expires) if cookie.expires else None
    remaining = (expires - now) if expires is not None else None
    if expires is None:
        state = "session"
    elif remaining <= 0:
        state = "expired"
    elif remaining <= SOON_SECONDS:
        state = "soon"
    else:
        state = "live"
    return {
        "name": cookie.name,
        "value": cookie.value if cookie.value is not None else "",
        "domain": domain,
        "host_only": not domain.startswith("."),
        "path": cookie.path or "/",
        "secure": bool(cookie.secure),
        "httponly": _is_httponly(cookie),
        "expires": expires,
        "remaining": remaining,
        "state": state,
    }


# --------------------------------------------------------------------------
# filtering
# --------------------------------------------------------------------------


def domain_matches(domain: str, pattern: str) -> bool:
    """
    True when the cookie domain is pattern, a subdomain of it, or a
    glob match. Leading dots on either side are ignored, so
    'fnal.gov' selects .fnal.gov, pingprod.fnal.gov and mu2e-docdb.fnal.gov.
    """
    d = domain.lstrip(".").lower()
    p = pattern.lstrip(".").lower()
    if any(ch in p for ch in "*?["):
        return fnmatch.fnmatchcase(d, p)
    return d == p or d.endswith("." + p)


def select(
    records: Iterable[Dict],
    domains: Iterable[str] = (),
    names: Iterable[str] = (),
    states: Iterable[str] = (),
) -> List[Dict]:
    """Keep records matching any of each non-empty filter group."""
    domains, names, states = list(domains), list(names), list(states)
    kept = []
    for rec in records:
        if domains and not any(domain_matches(rec["domain"], p) for p in domains):
            continue
        if names and not any(fnmatch.fnmatchcase(rec["name"], p) for p in names):
            continue
        if states and rec["state"] not in states:
            continue
        kept.append(rec)
    return kept


# --------------------------------------------------------------------------
# formatting
# --------------------------------------------------------------------------


def mask_value(value: str, show: bool = False) -> str:
    """Show the first few characters and the length unless show is set."""
    if show:
        return value
    if not value:
        return "(empty)"
    if len(value) <= MASK_PREFIX:
        return "*" * len(value) + f" ({len(value)} chars)"
    return value[:MASK_PREFIX] + "…" + f" ({len(value)} chars)"


def format_duration(seconds: float) -> str:
    """'3d 4h', '2h 15m', '45s', with a leading '-' once negative."""
    sign = "-" if seconds < 0 else ""
    seconds = abs(int(seconds))
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    if days:
        return f"{sign}{days}d {hours}h"
    if hours:
        return f"{sign}{hours}h {minutes}m"
    if minutes:
        return f"{sign}{minutes}m {secs}s"
    return f"{sign}{secs}s"


def format_timestamp(epoch: Optional[int], utc: bool = False) -> str:
    if epoch is None:
        return "session"
    if utc:
        return datetime.fromtimestamp(epoch, timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
    return datetime.fromtimestamp(epoch).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")


def expiry_column(rec: Dict) -> str:
    if rec["expires"] is None:
        return "session"
    if rec["state"] == "expired":
        return f"expired {format_duration(-rec['remaining'])} ago"
    return f"in {format_duration(rec['remaining'])}"


def flags_column(rec: Dict) -> str:
    flags = []
    if rec["secure"]:
        flags.append("secure")
    if rec["httponly"]:
        flags.append("httponly")
    flags.append("host-only" if rec["host_only"] else "subdomains")
    return ",".join(flags)


def format_table(records: List[Dict], show_values: bool = False) -> str:
    """Aligned one-line-per-cookie view."""
    if not records:
        return "(no cookies)\n"
    rows = [
        (
            rec["domain"],
            rec["path"],
            rec["name"],
            expiry_column(rec),
            flags_column(rec),
            mask_value(rec["value"], show_values),
        )
        for rec in records
    ]
    header = ("DOMAIN", "PATH", "NAME", "EXPIRES", "FLAGS", "VALUE")
    widths = [
        max(len(str(row[i])) for row in rows + [header]) for i in range(len(header) - 1)
    ]
    lines = []
    for row in [header] + rows:
        cells = [str(row[i]).ljust(widths[i]) for i in range(len(widths))]
        cells.append(str(row[-1]))
        lines.append("  ".join(cells).rstrip())
    return "\n".join(lines) + "\n"


def format_long(records: List[Dict], show_values: bool = False, utc: bool = False) -> str:
    """One labelled block per cookie."""
    if not records:
        return "(no cookies)\n"
    blocks = []
    for rec in records:
        lines = [
            f"{rec['name']}",
            f"  domain   : {rec['domain']}"
            + ("  (this host only)" if rec["host_only"] else "  (and subdomains)"),
            f"  path     : {rec['path']}",
            f"  expires  : {format_timestamp(rec['expires'], utc)}"
            + ("" if rec["expires"] is None else f"  ({expiry_column(rec)})"),
            f"  secure   : {'yes' if rec['secure'] else 'no'}",
            f"  httponly : {'yes' if rec['httponly'] else 'no'}",
            f"  state    : {rec['state']}",
            f"  value    : {mask_value(rec['value'], show_values)}",
        ]
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks) + "\n"


def format_json(records: List[Dict], show_values: bool = False, **meta) -> str:
    """Machine-readable dump: metadata plus the record list."""
    out = []
    for rec in records:
        item = dict(rec)
        if not show_values:
            item["value"] = mask_value(rec["value"])
            item["value_masked"] = True
        if item["remaining"] is not None:
            item["remaining"] = int(item["remaining"])
        out.append(item)
    return json.dumps(dict(meta, cookies=out), indent=2) + "\n"


def summarize(records: List[Dict]) -> Dict[str, int]:
    counts = {"total": len(records), "live": 0, "soon": 0, "session": 0, "expired": 0}
    for rec in records:
        counts[rec["state"]] += 1
    return counts


def file_mode_warning(path: str) -> Optional[str]:
    """A warning string when the jar is readable by group or other."""
    try:
        mode = os.stat(path).st_mode
    except OSError:
        return None
    if os.name == "nt":
        return None
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        return (
            f"warning: {path} is mode {stat.S_IMODE(mode):03o}; a cookie jar is a "
            f"bearer credential, chmod 600 it"
        )
    return None


# --------------------------------------------------------------------------
# command line
# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fermi_sso_cookies",
        description="List the cookies held in a saved jar, with domain, path, "
        "expiry and flags.",
        epilog="Settings resolve as: commandline > environment > .env file > "
        "defaults. See fermi_sso_cookies(1).",
    )
    parser.add_argument(
        "file",
        nargs="?",
        default=None,
        help=f"cookie jar to read (default ${ENV_COOKIE_FILE})",
    )
    parser.add_argument(
        "-c",
        "--cookie-file",
        metavar="FILE",
        dest="file_opt",
        default=None,
        help="same as the positional FILE",
    )
    parser.add_argument(
        "--cookie-format",
        choices=COOKIE_FORMATS,
        default=None,
        help=f"cookie file format (${ENV_COOKIE_FORMAT}; default: detect from the "
        f"extension and contents)",
    )
    parser.add_argument(
        "-e",
        "--env-file",
        metavar="FILE",
        default=None,
        help="load settings from FILE (default: ./.env, then ~/.fermi_sso.env)",
    )
    parser.add_argument(
        "--no-env-file", action="store_true", help="ignore .env files entirely"
    )
    view = parser.add_argument_group("output")
    view.add_argument(
        "-l", "--long", action="store_true", help="one labelled block per cookie"
    )
    view.add_argument(
        "-j", "--json", action="store_true", help="machine-readable JSON on stdout"
    )
    view.add_argument(
        "-s",
        "--show-values",
        action="store_true",
        help="print cookie values in full instead of a masked prefix",
    )
    view.add_argument(
        "--utc", action="store_true", help="show expiry times in UTC (with --long)"
    )
    view.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="omit the file header and summary; print only the cookies",
    )
    filt = parser.add_argument_group("filters")
    filt.add_argument(
        "-D",
        "--domain",
        metavar="DOMAIN",
        action="append",
        default=[],
        help="only cookies for DOMAIN or its subdomains (glob allowed); repeatable",
    )
    filt.add_argument(
        "-N",
        "--name",
        metavar="NAME",
        action="append",
        default=[],
        help="only cookies whose name matches the glob NAME; repeatable",
    )
    filt.add_argument(
        "--live",
        action="store_true",
        help="only cookies that would be loaded by FermiSSOSession: live, soon, "
        "and session cookies",
    )
    filt.add_argument(
        "--expired", action="store_true", help="only cookies past their expiry"
    )
    parser.add_argument("-V", "--version", action="version", version=__version__)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    environ = dict(os.environ)

    def warn(message):
        print(message, file=sys.stderr)

    if args.no_env_file:
        dotenv: Dict[str, str] = {}
    else:
        if args.env_file and not os.path.isfile(os.path.expanduser(args.env_file)):
            warn(f"error: env file not found: {args.env_file}")
            return 2
        dotenv = load_env_file(find_env_file(args.env_file, environ), warn=warn)

    path = resolve(args.file_opt or args.file, ENV_COOKIE_FILE, environ, dotenv)
    fmt = resolve(args.cookie_format, ENV_COOKIE_FORMAT, environ, dotenv)
    if not path:
        warn(f"error: no cookie file; give FILE or set ${ENV_COOKIE_FILE}")
        return 2
    path = os.path.expanduser(path)
    if fmt and fmt not in COOKIE_FORMATS:
        warn(f"error: ${ENV_COOKIE_FORMAT} must be one of {COOKIE_FORMATS}, not {fmt!r}")
        return 2

    try:
        fmt, cookies = read_jar(path, fmt)
    except FileNotFoundError:
        warn(f"error: cookie file not found: {path}")
        return 2
    except (OSError, ValueError) as exc:
        warn(f"error: cannot read cookie file {path}: {exc}")
        return 2

    now = time.time()
    records = [cookie_record(c, now) for c in cookies]
    records.sort(key=lambda r: (r["domain"].lstrip(".").lower(), r["path"], r["name"]))

    states = []
    if args.live:
        states += ["live", "soon", "session"]
    if args.expired:
        states.append("expired")
    shown = select(records, args.domain, args.name, states)
    counts = summarize(records)

    if args.json:
        sys.stdout.write(
            format_json(
                shown,
                args.show_values,
                file=path,
                format=fmt,
                generated=int(now),
                counts=counts,
                shown=len(shown),
            )
        )
        return 0 if shown else 1

    if not args.quiet:
        print(f"file    : {path}")
        print(f"format  : {fmt}")
        print(
            f"cookies : {counts['total']} total, {counts['live'] + counts['soon']} live"
            + (f" ({counts['soon']} expiring soon)" if counts["soon"] else "")
            + f", {counts['session']} session, {counts['expired']} expired"
        )
        if len(shown) != counts["total"]:
            print(f"shown   : {len(shown)} after filters")
        print()
    if args.long:
        sys.stdout.write(format_long(shown, args.show_values, args.utc))
    else:
        sys.stdout.write(format_table(shown, args.show_values))

    mode_warning = file_mode_warning(path)
    if mode_warning and not args.quiet:
        warn(mode_warning)
    return 0 if shown else 1


if __name__ == "__main__":
    sys.exit(main())

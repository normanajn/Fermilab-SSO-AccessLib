#!/usr/bin/env python3
"""
fermi_sso_jar_tui -- curses viewer for the SSO cookie jar.

The top pane lists the identity provider and every catalog site with the
state of its cookies in the jar; the bottom pane shows the cookies of the
selected row. Keys prime, refresh, verify and clear through the same
JarManager that fermi-sso-jar uses, so anything the command line can do
the viewer can too. Network work runs in a daemon thread and the screen
keeps updating while it is in flight.

The jar is re-read every few seconds, so a login performed by another
process (the probe, a script, the GUI) shows up without a keypress.

Settings resolve as for fermi_sso_jar(1): commandline > environment >
.env file > catalog settings > defaults. See fermi_sso_jar_tui(1).
"""

import argparse
import curses
import curses.textpad
import os
import queue
import sys
import threading
import time
from typing import Dict, List, Optional

import fermi_sso_jar as jar_tool
from fermi_sso_cookies import domain_matches, format_duration, mask_value
from fermi_sso_jar import (
    IDP_KEY,
    Credential,
    JarManager,
    PrimeResult,
    SiteStatus,
    add_common_options,
    add_credential_options,
    resolve_credential,
)
from requests_fermi_sso import __version__ as _lib_version

#: single source of truth lives in the library module
__version__ = _lib_version

#: Seconds between automatic re-reads of the jar file.
POLL_SECONDS = 5.0

HELP_LINES = [
    "fermi-sso-jar-tui keys",
    "",
    "  up/down, j/k   select a site          enter   toggle cookie detail",
    "  p              prime the selected site (log in if needed, save jar)",
    "  P              prime every site        R       refresh stale sites only",
    "  v              verify selected site (cookies only, network)",
    "  V              verify every site",
    "  c              clear the selected site's cookies from the jar",
    "  x              purge expired cookies   s       show/mask cookie values",
    "  r              re-read the jar now     ?       this help",
    "  q              quit",
    "",
    "A prime or refresh that needs a password asks for it at the bottom.",
    "Press any key.",
]


class Worker:
    """
    Runs one JarManager network job at a time in a daemon thread and posts
    (kind, payload) events to a queue the UI drains.
    """

    def __init__(self, mgr: JarManager):
        self.mgr = mgr
        self.events: "queue.Queue" = queue.Queue()
        self.busy: Optional[str] = None

    def start(self, label: str, fn, *args, **kwargs) -> bool:
        if self.busy:
            return False
        self.busy = label

        def run():
            try:
                fn(*args, **kwargs)
            except Exception as exc:  # surfaced on the status line
                self.events.put(("error", f"{type(exc).__name__}: {exc}"))
            finally:
                self.events.put(("done", label))

        threading.Thread(target=run, name="fermi-sso-jar-tui-worker", daemon=True).start()
        return True

    def prime(self, keys: List[str], cred: Credential, save: bool = True):
        def progress(key, result: Optional[PrimeResult]):
            if result is None:
                self.events.put(("info", f"{key}: signing in ..."))
            else:
                self.events.put(("result", result))

        return self.start("prime", self.mgr.prime_many, keys, cred, save, progress=progress)

    def verify(self, keys: List[str]):
        def job():
            for key in keys:
                self.events.put(("info", f"{key}: verifying ..."))
                self.events.put(("result", self.mgr.verify(key)))

        return self.start("verify", job)


class App:
    def __init__(self, stdscr, mgr: JarManager, cred: Credential, save: bool = True):
        self.scr = stdscr
        self.mgr = mgr
        self.cred = cred
        self.save = save
        self.worker = Worker(mgr)
        self.statuses: List[SiteStatus] = []
        self.records: List[Dict] = []
        self.selected = 0
        self.show_values = False
        self.detail = True
        self.message = "? for help"
        self.message_is_error = False
        self.last_read = 0.0
        self.log: List[str] = []
        self.reload()

    # -- data --------------------------------------------------------------

    def reload(self):
        now = time.time()
        try:
            self.records = self.mgr.records(now)
            self.statuses = self.mgr.status(now=now)
        except (OSError, ValueError) as exc:
            self.records, self.statuses = [], []
            self.say(f"cannot read {self.mgr.jar}: {exc}", error=True)
        self.last_read = now
        self.selected = max(0, min(self.selected, len(self.statuses) - 1))

    def selected_status(self) -> Optional[SiteStatus]:
        if not self.statuses:
            return None
        return self.statuses[self.selected]

    def cookies_for(self, status: SiteStatus) -> List[Dict]:
        return [
            r for r in self.records
            if any(domain_matches(r["domain"], d) for d in status.domains)
        ]

    def say(self, text: str, error: bool = False):
        self.message = text
        self.message_is_error = error
        self.log.append(text)
        del self.log[:-200]

    # -- drawing -----------------------------------------------------------

    def color(self, state: str) -> int:
        if not curses.has_colors():
            return 0
        pair = {"live": 1, "soon": 2, "session": 3, "expired": 4, "absent": 5}.get(state, 0)
        return curses.color_pair(pair)

    def draw(self):
        scr = self.scr
        scr.erase()
        height, width = scr.getmaxyx()
        jar_note = "" if os.path.isfile(self.mgr.jar) else "  (no jar yet)"
        busy = f"  [{self.worker.busy} running]" if self.worker.busy else ""
        self.addstr(0, 0, f" fermi-sso-jar  {self.mgr.jar}{jar_note}{busy}", curses.A_REVERSE, width)
        self.addstr(1, 0, f" credential: {self.cred.describe()}   margin: {format_duration(self.mgr.margin)}   read {int(time.time() - self.last_read)}s ago", 0, width)

        header = f" {'SITE':<16}{'STATE':<9}{'COOKIES':>7}  {'EXPIRES':<28}{'CONN':<6}NAME"
        self.addstr(3, 0, header, curses.A_BOLD, width)
        table_rows = max(1, min(len(self.statuses), (height - 6) // 2 if self.detail else height - 6))
        top = max(0, min(self.selected - table_rows + 1, len(self.statuses) - table_rows))
        for i in range(table_rows):
            idx = top + i
            if idx >= len(self.statuses):
                break
            s = self.statuses[idx]
            attr = self.color(s.state)
            if idx == self.selected:
                attr |= curses.A_REVERSE
            line = f" {s.key:<16}{s.state:<9}{s.cookies:>7}  {s.expiry_text:<28}{(s.connection or '-'):<6}{s.name}"
            self.addstr(4 + i, 0, line, attr, width)

        y = 4 + table_rows + 1
        if self.detail and y < height - 2:
            status = self.selected_status()
            if status is not None:
                cookies = self.cookies_for(status)
                title = f" cookies for {status.key} ({len(cookies)})"
                if status.url:
                    title += f"   {status.url}"
                self.addstr(y, 0, title, curses.A_BOLD, width)
                y += 1
                if not cookies:
                    self.addstr(y, 0, "   (none in the jar)", 0, width)
                for r in cookies:
                    if y >= height - 2:
                        break
                    if r["expires"] is None:
                        exp = "session"
                    elif r["state"] == "expired":
                        exp = f"expired {format_duration(-r['remaining'])} ago"
                    else:
                        exp = f"in {format_duration(r['remaining'])}"
                    flags = ("S" if r["secure"] else "-") + ("H" if r["httponly"] else "-")
                    line = f"   {r['domain']:<30}{r['name']:<26}{exp:<22}{flags}  {mask_value(r['value'], self.show_values)}"
                    self.addstr(y, 0, line, self.color(r["state"]), width)
                    y += 1

        attr = curses.A_BOLD if self.message_is_error else 0
        self.addstr(height - 1, 0, f" {self.message}", attr, width)
        scr.refresh()

    def addstr(self, y: int, x: int, text: str, attr: int, width: int):
        try:
            self.scr.addnstr(y, x, text, max(0, width - x - 1), attr)
        except curses.error:
            pass

    def show_help(self):
        self.scr.erase()
        for i, line in enumerate(HELP_LINES):
            self.addstr(i + 1, 2, line, 0, self.scr.getmaxyx()[1])
        self.scr.refresh()
        self.scr.nodelay(False)
        self.scr.getch()
        self.scr.nodelay(True)

    # -- prompting ---------------------------------------------------------

    def prompt(self, label: str, secret: bool = False) -> Optional[str]:
        """Line editor on the bottom row; Esc or empty returns None."""
        height, width = self.scr.getmaxyx()
        self.scr.nodelay(False)
        curses.curs_set(1)
        self.addstr(height - 1, 0, " " * (width - 1), 0, width)
        self.addstr(height - 1, 0, f" {label}: ", curses.A_BOLD, width)
        self.scr.refresh()
        buf: List[str] = []
        x0 = len(label) + 3
        while True:
            ch = self.scr.getch()
            if ch in (10, 13):
                break
            if ch == 27:
                buf = []
                break
            if ch in (curses.KEY_BACKSPACE, 127, 8):
                if buf:
                    buf.pop()
            elif 32 <= ch < 127:
                buf.append(chr(ch))
            shown = ("*" * len(buf)) if secret else "".join(buf)
            self.addstr(height - 1, x0, " " * (width - x0 - 1), 0, width)
            self.addstr(height - 1, x0, shown, 0, width)
            self.scr.refresh()
        curses.curs_set(0)
        self.scr.nodelay(True)
        return "".join(buf) or None

    def credential_for_login(self) -> Optional[Credential]:
        """The configured credential, asking for a password if that is what it lacks."""
        cred = self.cred
        if cred.auth_method == "password" and not cred.password:
            if not cred.user:
                user = self.prompt("Fermilab account")
                if not user:
                    self.say("cancelled")
                    return None
                cred = cred._replace(user=user)
            password = self.prompt(f"password for {cred.user}", secret=True)
            if not password:
                self.say("cancelled")
                return None
            # keep it for this run only; the jar, not the password, is what persists
            cred = cred._replace(password=password, prompt=None)
            self.cred = cred
        return cred

    def confirm(self, question: str) -> bool:
        answer = self.prompt(f"{question} (y/N)")
        return bool(answer) and answer.lower().startswith("y")

    # -- actions -----------------------------------------------------------

    def site_keys(self) -> List[str]:
        return [s.key for s in self.statuses if s.key != IDP_KEY]

    def start_prime(self, keys: List[str]):
        if self.worker.busy:
            self.say(f"{self.worker.busy} already running", error=True)
            return
        if not keys:
            self.say("nothing to prime")
            return
        cred = self.credential_for_login()
        if cred is None:
            return
        self.say(f"priming {', '.join(keys)} with {cred.describe()}")
        self.worker.prime(keys, cred, self.save)

    def start_verify(self, keys: List[str]):
        if self.worker.busy:
            self.say(f"{self.worker.busy} already running", error=True)
            return
        self.say(f"verifying {', '.join(keys)}")
        self.worker.verify(keys)

    def handle_key(self, ch: int) -> bool:
        """Returns False to quit."""
        status = self.selected_status()
        if ch in (ord("q"), ord("Q")):
            return False
        if ch in (curses.KEY_DOWN, ord("j")):
            self.selected = min(self.selected + 1, len(self.statuses) - 1)
        elif ch in (curses.KEY_UP, ord("k")):
            self.selected = max(self.selected - 1, 0)
        elif ch in (10, 13, curses.KEY_ENTER):
            self.detail = not self.detail
        elif ch == ord("?"):
            self.show_help()
        elif ch == ord("r"):
            self.reload()
            self.say("jar re-read")
        elif ch == ord("s"):
            self.show_values = not self.show_values
            self.say("values shown (bearer credentials: do not paste them anywhere)" if self.show_values else "values masked")
        elif ch == ord("p") and status is not None:
            if status.key == IDP_KEY:
                self.say("the identity provider is primed by priming any site")
            else:
                self.start_prime([status.key])
        elif ch == ord("P"):
            self.start_prime(self.site_keys())
        elif ch == ord("R"):
            stale = self.mgr.stale_keys()
            if not stale:
                self.say("nothing to refresh: every site is live")
            else:
                self.start_prime(stale)
        elif ch == ord("v") and status is not None and status.key != IDP_KEY:
            self.start_verify([status.key])
        elif ch == ord("V"):
            self.start_verify(self.site_keys())
        elif ch == ord("c") and status is not None:
            if status.key == IDP_KEY:
                if self.confirm("drop the identity provider's cookies (every site re-logs in)?"):
                    n = self.mgr.clear([], idp=True)
                    self.say(f"removed {n} cookie(s)")
            elif self.confirm(f"drop {status.key}'s cookies from the jar?"):
                n = self.mgr.clear([status.key])
                self.say(f"removed {n} cookie(s)")
            self.reload()
        elif ch == ord("x"):
            n = self.mgr.purge_expired()
            self.say(f"purged {n} expired cookie(s)")
            self.reload()
        return True

    def drain_events(self):
        while True:
            try:
                kind, payload = self.worker.events.get_nowait()
            except queue.Empty:
                return
            if kind == "info":
                self.say(payload)
            elif kind == "result":
                r: PrimeResult = payload
                self.say(f"{r.key}: {r.summary()}", error=not r.ok)
                self.reload()
            elif kind == "error":
                self.say(payload, error=True)
            elif kind == "done":
                self.worker.busy = None
                self.reload()

    def run(self):
        curses.curs_set(0)
        self.scr.nodelay(True)
        self.scr.keypad(True)
        if curses.has_colors():
            curses.start_color()
            curses.use_default_colors()
            curses.init_pair(1, curses.COLOR_GREEN, -1)
            curses.init_pair(2, curses.COLOR_YELLOW, -1)
            curses.init_pair(3, curses.COLOR_CYAN, -1)
            curses.init_pair(4, curses.COLOR_RED, -1)
            curses.init_pair(5, curses.COLOR_MAGENTA, -1)
        while True:
            self.drain_events()
            if time.time() - self.last_read > POLL_SECONDS:
                self.reload()
            self.draw()
            ch = self.scr.getch()
            if ch == -1:
                curses.napms(100)
                continue
            if ch == curses.KEY_RESIZE:
                continue
            if not self.handle_key(ch):
                return


# --------------------------------------------------------------------------
# command line
# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fermi_sso_jar_tui",
        description="Terminal viewer for the Fermilab SSO cookie jar: see each "
        "site's session, prime, refresh, verify and clear them.",
        epilog="Settings resolve as for fermi_sso_jar(1). See fermi_sso_jar_tui(1).",
    )
    add_common_options(parser)
    add_credential_options(parser)
    parser.add_argument("-V", "--version", action="version", version=__version__)
    parser.add_argument("-d", "--debug", action="store_true", default=None, help=argparse.SUPPRESS)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    warnings: List[str] = []

    try:
        ctx = jar_tool._context(args, warnings.append)
        cred = resolve_credential(
            ctx.environ, ctx.dotenv, ctx.mgr.catalog.settings,
            auth=args.auth, user=args.user, password=args.password,
            password_env=args.password_env, pin_source=args.pin_source,
        )
    except SystemExit as exc:
        if isinstance(exc.code, str):
            print(exc.code, file=sys.stderr)
            return 2
        raise
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if not sys.stdout.isatty():
        print("error: fermi-sso-jar-tui needs a terminal; use fermi-sso-jar for scripts", file=sys.stderr)
        return 2

    def start(stdscr):
        app = App(stdscr, ctx.mgr, cred, save=not args.no_save_cookies)
        for w in warnings:
            app.say(w, error=True)
        app.run()

    curses.wrapper(start)
    return 0


if __name__ == "__main__":
    sys.exit(main())

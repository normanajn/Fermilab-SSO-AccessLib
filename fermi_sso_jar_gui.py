#!/usr/bin/env python3
"""
fermi_sso_jar_gui -- Qt viewer for the SSO cookie jar.

A window with the catalog sites and their jar state on the left, the
selected site's cookies on the right, and buttons for the same operations
fermi-sso-jar offers: prime, refresh, verify, clear, add a site, and
setup. Network work runs on a worker thread and reports back through Qt
signals; the jar file is re-read on a timer so logins performed by other
processes appear on their own.

Needs PySide6 (preferred) or PyQt6: ``pip install 'requests-fermi_sso[gui]'``.

Settings resolve as for fermi_sso_jar(1). See fermi_sso_jar_gui(1).
"""

import argparse
import os
import sys
import time
from typing import List, Optional

import fermi_sso_jar as jar_tool
from fermi_sso_cookies import domain_matches, format_duration, format_timestamp, mask_value
from fermi_sso_jar import (
    DEFAULT_ENV_FILE,
    IDP_KEY,
    Credential,
    JarManager,
    PrimeResult,
    SiteStatus,
    add_common_options,
    add_credential_options,
    resolve_credential,
    scheduler_snippet,
    shell_snippet,
    write_env_file,
)
from fermi_sso_sites import USER_SITES_FILE, SiteError, add_user_site, user_entry
from requests_fermi_sso import AUTH_METHODS
from requests_fermi_sso import __version__ as _lib_version

#: single source of truth lives in the library module
__version__ = _lib_version

#: Milliseconds between automatic re-reads of the jar.
POLL_MS = 5000


def _import_qt():
    """PySide6 first, then PyQt6; both expose the same names used here."""
    try:
        from PySide6 import QtCore, QtGui, QtWidgets

        return QtCore, QtGui, QtWidgets, "PySide6"
    except ImportError:
        pass
    try:
        from PyQt6 import QtCore, QtGui, QtWidgets

        QtCore.Signal = QtCore.pyqtSignal
        QtCore.Slot = QtCore.pyqtSlot
        return QtCore, QtGui, QtWidgets, "PyQt6"
    except ImportError:
        raise ImportError(
            "fermi-sso-jar-gui needs PySide6 or PyQt6: pip install 'requests-fermi_sso[gui]'"
        )


STATE_COLORS = {
    "live": "#2e7d32",
    "soon": "#ef6c00",
    "session": "#0277bd",
    "expired": "#c62828",
    "absent": "#6a1b9a",
}


def build_window_class():
    """
    Defined inside a function so the module imports (for --help, tests)
    without Qt. Returns (QApplication, MainWindow).
    """
    QtCore, QtGui, QtWidgets, _ = _import_qt()

    class Worker(QtCore.QObject):
        """Runs one JarManager job on a QThread; emits progress and results."""

        info = QtCore.Signal(str)
        result = QtCore.Signal(object)
        failed = QtCore.Signal(str)
        finished = QtCore.Signal()

        def __init__(self, job):
            super().__init__()
            self.job = job

        def run(self):
            try:
                self.job(self)
            except Exception as exc:
                self.failed.emit(f"{type(exc).__name__}: {exc}")
            finally:
                self.finished.emit()

    class AddSiteDialog(QtWidgets.QDialog):
        def __init__(self, parent=None):
            super().__init__(parent)
            self.setWindowTitle("Add a site to the catalog")
            form = QtWidgets.QFormLayout(self)
            self.key = QtWidgets.QLineEdit()
            self.key.setPlaceholderText("short key, e.g. my-site")
            self.url = QtWidgets.QLineEdit()
            self.url.setPlaceholderText("https://host/sso/entry")
            self.name = QtWidgets.QLineEdit()
            self.expect = QtWidgets.QLineEdit()
            self.expect.setPlaceholderText("text that must appear when signed in (optional)")
            self.domains = QtWidgets.QLineEdit()
            self.domains.setPlaceholderText("cookie domains, comma separated (default: the URL host)")
            self.connection = QtWidgets.QComboBox()
            self.connection.addItems(["unknown", "saml", "oidc"])
            self.js = QtWidgets.QCheckBox("follow a JavaScript location= redirect stub")
            self.notes = QtWidgets.QLineEdit()
            self.test = QtWidgets.QCheckBox("verify after adding (cookies only)")
            form.addRow("Key", self.key)
            form.addRow("SSO entry URL", self.url)
            form.addRow("Name", self.name)
            form.addRow("Expect", self.expect)
            form.addRow("Domains", self.domains)
            form.addRow("Connection", self.connection)
            form.addRow("", self.js)
            form.addRow("Notes", self.notes)
            form.addRow("", self.test)
            buttons = QtWidgets.QDialogButtonBox(
                QtWidgets.QDialogButtonBox.StandardButton.Ok
                | QtWidgets.QDialogButtonBox.StandardButton.Cancel
            )
            buttons.accepted.connect(self.accept)
            buttons.rejected.connect(self.reject)
            form.addRow(buttons)

        def entry(self):
            conn = self.connection.currentText()
            domains = [d.strip() for d in self.domains.text().split(",") if d.strip()]
            return self.key.text().strip(), user_entry(
                self.key.text().strip(), self.url.text().strip(),
                name=self.name.text().strip() or None,
                expect=self.expect.text().strip() or None,
                domains=domains or None,
                connection=None if conn == "unknown" else conn,
                js_redirect=self.js.isChecked(),
                notes=self.notes.text().strip(),
            )

    class SetupDialog(QtWidgets.QDialog):
        def __init__(self, cred: Credential, jar: str, parent=None):
            super().__init__(parent)
            self.setWindowTitle("Set up the fermi-sso tools")
            form = QtWidgets.QFormLayout(self)
            self.user = QtWidgets.QLineEdit(cred.user or "")
            self.auth = QtWidgets.QComboBox()
            self.auth.addItems(list(AUTH_METHODS))
            self.auth.setCurrentText(cred.auth_method)
            self.pin = QtWidgets.QLineEdit(cred.pin_source or "")
            self.jar = QtWidgets.QLineEdit(jar)
            self.env = QtWidgets.QLineEdit(os.path.expanduser(DEFAULT_ENV_FILE))
            self.store_pw = QtWidgets.QCheckBox("store the password in the env file (mode 600)")
            self.password = QtWidgets.QLineEdit()
            self.password.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
            self.password.setEnabled(False)
            self.store_pw.toggled.connect(self.password.setEnabled)
            self.scheduler = QtWidgets.QCheckBox("show a cron/launchd/schtasks refresh recipe")
            form.addRow("Account", self.user)
            form.addRow("Auth method", self.auth)
            form.addRow("PIN file (yubikey)", self.pin)
            form.addRow("Cookie jar", self.jar)
            form.addRow("Env file to write", self.env)
            form.addRow("", self.store_pw)
            form.addRow("Password", self.password)
            form.addRow("", self.scheduler)
            buttons = QtWidgets.QDialogButtonBox(
                QtWidgets.QDialogButtonBox.StandardButton.Save
                | QtWidgets.QDialogButtonBox.StandardButton.Cancel
            )
            buttons.accepted.connect(self.accept)
            buttons.rejected.connect(self.reject)
            form.addRow(buttons)

    class MainWindow(QtWidgets.QMainWindow):
        def __init__(self, mgr: JarManager, cred: Credential, save: bool = True):
            super().__init__()
            self.mgr = mgr
            self.cred = cred
            self.save = save
            self.show_values = False
            self.statuses: List[SiteStatus] = []
            self.records = []
            self.thread: Optional[QtCore.QThread] = None
            self.setWindowTitle(f"fermi-sso-jar  {mgr.jar}")
            self.resize(1100, 600)
            self._build()
            self.timer = QtCore.QTimer(self)
            self.timer.timeout.connect(self.reload)
            self.timer.start(POLL_MS)
            self.reload()

        # -- layout ----------------------------------------------------

        def _build(self):
            central = QtWidgets.QWidget()
            self.setCentralWidget(central)
            outer = QtWidgets.QVBoxLayout(central)

            top = QtWidgets.QHBoxLayout()
            self.jar_label = QtWidgets.QLabel()
            self.cred_label = QtWidgets.QLabel()
            top.addWidget(self.jar_label)
            top.addStretch(1)
            top.addWidget(self.cred_label)
            outer.addLayout(top)

            split = QtWidgets.QSplitter()
            outer.addWidget(split, 1)

            self.sites = QtWidgets.QTableWidget(0, 5)
            self.sites.setHorizontalHeaderLabels(["Site", "State", "Cookies", "Expires", "Connection"])
            self.sites.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
            self.sites.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.SingleSelection)
            self.sites.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
            self.sites.verticalHeader().setVisible(False)
            self.sites.horizontalHeader().setStretchLastSection(True)
            self.sites.itemSelectionChanged.connect(self.fill_cookies)
            split.addWidget(self.sites)

            right = QtWidgets.QWidget()
            rl = QtWidgets.QVBoxLayout(right)
            self.site_info = QtWidgets.QLabel()
            self.site_info.setWordWrap(True)
            self.site_info.setTextInteractionFlags(QtCore.Qt.TextInteractionFlag.TextSelectableByMouse)
            rl.addWidget(self.site_info)
            self.cookies = QtWidgets.QTableWidget(0, 6)
            self.cookies.setHorizontalHeaderLabels(["Domain", "Name", "Path", "Expires", "Flags", "Value"])
            self.cookies.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
            self.cookies.verticalHeader().setVisible(False)
            self.cookies.horizontalHeader().setStretchLastSection(True)
            rl.addWidget(self.cookies, 1)
            split.addWidget(right)
            split.setSizes([500, 600])

            buttons = QtWidgets.QHBoxLayout()
            outer.addLayout(buttons)

            def button(text, slot, tip):
                b = QtWidgets.QPushButton(text)
                b.setToolTip(tip)
                b.clicked.connect(slot)
                buttons.addWidget(b)
                return b

            self.btn_prime = button("Prime site", self.prime_selected, "Log in to the selected site if its cookies do not sign in, and save the jar")
            self.btn_prime_all = button("Prime all", self.prime_all, "Prime every site in the catalog through one IdP session")
            self.btn_refresh = button("Refresh stale", self.refresh, "Prime only sites whose cookies are absent, expired or expiring soon")
            self.btn_verify = button("Verify site", self.verify_selected, "Cookies-only network check of the selected site")
            self.btn_verify_all = button("Verify all", self.verify_all, "Cookies-only network check of every site")
            self.btn_clear = button("Clear site", self.clear_selected, "Remove the selected site's cookies from the jar")
            button("Purge expired", self.purge_expired, "Drop every expired cookie from the jar")
            buttons.addStretch(1)
            self.btn_values = button("Show values", self.toggle_values, "Cookie values are bearer credentials; shown only on request")
            button("Add site...", self.add_site, f"Append an entry to {USER_SITES_FILE}")
            button("Setup...", self.setup, "Write the env file and show the shell/scheduler wiring")
            button("Reload", self.reload, "Re-read the jar now")

            self.log = QtWidgets.QPlainTextEdit()
            self.log.setReadOnly(True)
            self.log.setMaximumBlockCount(500)
            self.log.setFixedHeight(120)
            outer.addWidget(self.log)
            self.statusBar().showMessage("ready")

        # -- data ------------------------------------------------------

        def say(self, text: str, error: bool = False):
            stamp = time.strftime("%H:%M:%S")
            self.log.appendPlainText(f"{stamp}  {text}")
            self.statusBar().showMessage(text)

        def reload(self):
            now = time.time()
            try:
                self.records = self.mgr.records(now)
                self.statuses = self.mgr.status(now=now)
            except (OSError, ValueError) as exc:
                self.records, self.statuses = [], []
                self.say(f"cannot read {self.mgr.jar}: {exc}", error=True)
            exists = os.path.isfile(self.mgr.jar)
            self.jar_label.setText(
                f"<b>jar</b> {self.mgr.jar}" + ("" if exists else "  <i>(does not exist yet)</i>")
                + f"   <b>margin</b> {format_duration(self.mgr.margin)}"
            )
            self.cred_label.setText(f"<b>credential</b> {self.cred.describe()}")
            selected = self.selected_key()
            self.sites.setRowCount(len(self.statuses))
            for row, s in enumerate(self.statuses):
                exp = s.expiry_text
                if s.expires is not None and s.state != "expired":
                    exp += f"  ({format_timestamp(s.expires)})"
                cells = [s.key, s.state, str(s.cookies), exp, s.connection or "-"]
                for col, text in enumerate(cells):
                    item = QtWidgets.QTableWidgetItem(text)
                    item.setToolTip(s.name + (f"\n{s.url}" if s.url else ""))
                    if col == 1:
                        item.setForeground(QtGui.QColor(STATE_COLORS.get(s.state, "#000000")))
                    self.sites.setItem(row, col, item)
                if s.key == selected:
                    self.sites.selectRow(row)
            self.sites.resizeColumnsToContents()
            if self.sites.currentRow() < 0 and self.statuses:
                self.sites.selectRow(0)
            self.fill_cookies()

        def selected_key(self) -> Optional[str]:
            row = self.sites.currentRow()
            if row < 0 or row >= len(self.statuses):
                return None
            return self.statuses[row].key

        def selected_status(self) -> Optional[SiteStatus]:
            key = self.selected_key()
            for s in self.statuses:
                if s.key == key:
                    return s
            return None

        def fill_cookies(self):
            status = self.selected_status()
            if status is None:
                self.cookies.setRowCount(0)
                self.site_info.setText("")
                return
            info = f"<b>{status.name}</b>"
            if status.url:
                info += f"<br>{status.url}"
            info += f"<br>domains: {', '.join(status.domains)}"
            self.site_info.setText(info)
            mine = [
                r for r in self.records
                if any(domain_matches(r["domain"], d) for d in status.domains)
            ]
            self.cookies.setRowCount(len(mine))
            for row, r in enumerate(mine):
                if r["expires"] is None:
                    exp = "session"
                elif r["state"] == "expired":
                    exp = f"expired {format_duration(-r['remaining'])} ago"
                else:
                    exp = f"in {format_duration(r['remaining'])}  ({format_timestamp(r['expires'])})"
                flags = ",".join(
                    f for f, on in (("secure", r["secure"]), ("httponly", r["httponly"]),
                                    ("host-only", r["host_only"])) if on
                )
                cells = [r["domain"], r["name"], r["path"], exp, flags, mask_value(r["value"], self.show_values)]
                for col, text in enumerate(cells):
                    item = QtWidgets.QTableWidgetItem(text)
                    if col == 3:
                        item.setForeground(QtGui.QColor(STATE_COLORS.get(r["state"], "#000000")))
                    self.cookies.setItem(row, col, item)
            self.cookies.resizeColumnsToContents()

        # -- worker ----------------------------------------------------

        def busy(self) -> bool:
            return self.thread is not None and self.thread.isRunning()

        def run_job(self, label: str, job):
            if self.busy():
                self.say("a network job is already running", error=True)
                return
            self.thread = QtCore.QThread(self)
            self.worker = Worker(job)
            self.worker.moveToThread(self.thread)
            self.thread.started.connect(self.worker.run)
            self.worker.info.connect(self.say)
            self.worker.result.connect(self.on_result)
            self.worker.failed.connect(lambda m: self.say(m, error=True))
            self.worker.finished.connect(self.thread.quit)
            self.worker.finished.connect(self.on_finished)
            self.thread.finished.connect(self.worker.deleteLater)
            self.set_buttons(False)
            self.say(f"{label} started")
            self.thread.start()

        def on_result(self, result: PrimeResult):
            self.say(f"{result.key}: {result.summary()}", error=not result.ok)
            self.reload()

        def on_finished(self):
            self.set_buttons(True)
            self.reload()
            self.statusBar().showMessage("done")

        def set_buttons(self, enabled: bool):
            for b in (self.btn_prime, self.btn_prime_all, self.btn_refresh,
                      self.btn_verify, self.btn_verify_all, self.btn_clear):
                b.setEnabled(enabled)

        # -- credentials -----------------------------------------------

        def credential_for_login(self) -> Optional[Credential]:
            cred = self.cred
            if cred.auth_method != "password" or cred.password:
                return cred
            user = cred.user
            if not user:
                user, ok = QtWidgets.QInputDialog.getText(self, "Account", "Fermilab services account:")
                if not ok or not user:
                    return None
            password, ok = QtWidgets.QInputDialog.getText(
                self, "Password", f"Fermilab password for {user}:",
                QtWidgets.QLineEdit.EchoMode.Password,
            )
            if not ok or not password:
                return None
            self.cred = cred._replace(user=user, password=password, prompt=None)
            self.cred_label.setText(f"<b>credential</b> {self.cred.describe()}")
            return self.cred

        # -- actions ---------------------------------------------------

        def site_keys(self) -> List[str]:
            return [s.key for s in self.statuses if s.key != IDP_KEY]

        def prime_keys(self, keys: List[str]):
            if not keys:
                self.say("nothing to prime")
                return
            cred = self.credential_for_login()
            if cred is None:
                self.say("cancelled")
                return
            mgr, save = self.mgr, self.save

            def job(w):
                def progress(key, result):
                    if result is None:
                        w.info.emit(f"{key}: signing in ...")
                    else:
                        w.result.emit(result)

                mgr.prime_many(keys, cred, save, progress=progress)

            self.run_job(f"prime {', '.join(keys)}", job)

        def prime_selected(self):
            status = self.selected_status()
            if status is None:
                return
            if status.key == IDP_KEY:
                self.say("the identity provider is primed by priming any site")
                return
            self.prime_keys([status.key])

        def prime_all(self):
            self.prime_keys(self.site_keys())

        def refresh(self):
            stale = self.mgr.stale_keys()
            if not stale:
                self.say("nothing to refresh: every site is live")
                return
            self.prime_keys(stale)

        def verify_keys(self, keys: List[str]):
            mgr = self.mgr

            def job(w):
                for key in keys:
                    w.info.emit(f"{key}: verifying ...")
                    w.result.emit(mgr.verify(key))

            self.run_job(f"verify {', '.join(keys)}", job)

        def verify_selected(self):
            status = self.selected_status()
            if status is None or status.key == IDP_KEY:
                return
            self.verify_keys([status.key])

        def verify_all(self):
            self.verify_keys(self.site_keys())

        def clear_selected(self):
            status = self.selected_status()
            if status is None:
                return
            if status.key == IDP_KEY:
                question = "Drop the identity provider's cookies? Every site will need a login again."
            else:
                question = f"Drop {status.key}'s cookies from the jar?"
            answer = QtWidgets.QMessageBox.question(self, "Clear cookies", question)
            if answer != QtWidgets.QMessageBox.StandardButton.Yes:
                return
            n = self.mgr.clear([], idp=True) if status.key == IDP_KEY else self.mgr.clear([status.key])
            self.say(f"removed {n} cookie(s)")
            self.reload()

        def purge_expired(self):
            n = self.mgr.purge_expired()
            self.say(f"purged {n} expired cookie(s)")
            self.reload()

        def toggle_values(self):
            self.show_values = not self.show_values
            self.btn_values.setText("Mask values" if self.show_values else "Show values")
            if self.show_values:
                self.say("values shown: they are bearer credentials, do not paste them anywhere")
            self.fill_cookies()

        def add_site(self):
            dlg = AddSiteDialog(self)
            if dlg.exec() != QtWidgets.QDialog.DialogCode.Accepted:
                return
            try:
                key, entry = dlg.entry()
                path = add_user_site(key, entry)
                self.mgr.catalog.merge({key: entry}, path)
            except SiteError as exc:
                QtWidgets.QMessageBox.warning(self, "Invalid site", str(exc))
                return
            self.say(f"wrote {key} to {path}")
            self.reload()
            if dlg.test.isChecked():
                self.verify_keys([key])

        def setup(self):
            dlg = SetupDialog(self.cred, self.mgr.jar, self)
            if dlg.exec() != QtWidgets.QDialog.DialogCode.Accepted:
                return
            values = {
                jar_tool.probe.ENV_USER: dlg.user.text().strip(),
                jar_tool.probe.ENV_AUTH: dlg.auth.currentText(),
                jar_tool.probe.ENV_COOKIE_FILE: os.path.expanduser(dlg.jar.text().strip()),
                jar_tool.probe.ENV_PIN_SOURCE: dlg.pin.text().strip(),
            }
            if dlg.store_pw.isChecked() and dlg.password.text():
                values[jar_tool.probe.ENV_PASSWORD] = dlg.password.text()
            env_path = os.path.expanduser(dlg.env.text().strip())
            try:
                write_env_file(env_path, values)
            except OSError as exc:
                QtWidgets.QMessageBox.warning(self, "Setup failed", str(exc))
                return
            self.say(f"wrote {env_path} (mode 600)")
            text = (
                f"Wrote {env_path}.\n\nAdd to your shell rc:\n\n"
                + shell_snippet(env_path, values[jar_tool.probe.ENV_COOKIE_FILE], jar_tool._detect_shell())
            )
            if dlg.scheduler.isChecked():
                text += "\n" + scheduler_snippet(env_path, values[jar_tool.probe.ENV_COOKIE_FILE])
            box = QtWidgets.QMessageBox(self)
            box.setWindowTitle("Setup")
            box.setText("Setup written. Details below (select to copy).")
            box.setDetailedText(text)
            box.exec()
            self.cred = self.cred._replace(
                user=values[jar_tool.probe.ENV_USER] or None,
                auth_method=values[jar_tool.probe.ENV_AUTH],
                pin_source=values[jar_tool.probe.ENV_PIN_SOURCE] or None,
            )
            self.reload()

    return QtWidgets.QApplication, MainWindow


# --------------------------------------------------------------------------
# command line
# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fermi_sso_jar_gui",
        description="Qt viewer for the Fermilab SSO cookie jar: see each site's "
        "session, prime, refresh, verify and clear them.",
        epilog="Settings resolve as for fermi_sso_jar(1). See fermi_sso_jar_gui(1).",
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
    try:
        QApplication, MainWindow = build_window_class()
    except ImportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    app = QApplication.instance() or QApplication(sys.argv[:1])
    window = MainWindow(ctx.mgr, cred, save=not args.no_save_cookies)
    for w in warnings:
        window.say(w, error=True)
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())

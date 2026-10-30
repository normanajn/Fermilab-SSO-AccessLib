"""
Tests for fermi_sso_jar_gui and fermi_sso_jar_tui that run without a
display: the GUI's tables through pytest-qt on the offscreen platform, and
the TUI's non-terminal refusal and shared argument parsing.

Skipped when PySide6/PyQt6 or pytest-qt are not installed.
"""

import os
import sys

import pytest

import fermi_sso_jar as tool
import fermi_sso_jar_tui as tui
import fermi_sso_sites as sites
import requests_fermi_sso as rfs

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("pytestqt")
try:
    import fermi_sso_jar_gui as gui

    gui._import_qt()
except ImportError:
    pytest.skip("PySide6/PyQt6 not installed", allow_module_level=True)

NOW = 1_800_000_000


def _catalog():
    cat = sites.Catalog()
    cat.merge({"docdb": {"url": "https://mu2e-docdb.fnal.gov/cgi-bin/sso/DocumentDatabase", "domains": ["mu2e-docdb.fnal.gov"]}}, "test")
    return cat


def _jar(tmp_path):
    path = str(tmp_path / "jar.cookies")
    tool._write_jar(path, "netscape", [
        rfs._make_cookie("mellon-cookie", "abcdefgh", "mu2e-docdb.fnal.gov", "/", True, None, True, host_only=True),
        rfs._make_cookie("PF", "xyz", "pingprod.fnal.gov", "/", True, NOW * 2, True, host_only=True),
    ])
    return path


def test_main_window_lists_sites_and_cookies(qtbot, tmp_path):
    QApplication, MainWindow = gui.build_window_class()
    mgr = tool.JarManager(_jar(tmp_path), _catalog())
    window = MainWindow(mgr, tool.Credential())
    qtbot.addWidget(window)
    assert window.sites.rowCount() == 2  # idp + docdb
    assert window.sites.item(0, 0).text() == "idp" and window.sites.item(0, 1).text() == "live"
    window.sites.selectRow(1)
    assert window.selected_key() == "docdb"
    assert window.cookies.rowCount() == 1
    # masked by default, in full on request
    assert window.cookies.item(0, 5).text().startswith("abcd")
    assert "chars" in window.cookies.item(0, 5).text()
    window.toggle_values()
    assert window.cookies.item(0, 5).text() == "abcdefgh"


def test_main_window_clear_and_purge_update_the_table(qtbot, tmp_path, monkeypatch):
    QApplication, MainWindow = gui.build_window_class()
    QtWidgets = gui._import_qt()[2]
    mgr = tool.JarManager(_jar(tmp_path), _catalog())
    window = MainWindow(mgr, tool.Credential())
    qtbot.addWidget(window)
    window.sites.selectRow(1)
    monkeypatch.setattr(
        QtWidgets.QMessageBox, "question",
        staticmethod(lambda *a, **k: QtWidgets.QMessageBox.StandardButton.Yes),
    )
    window.clear_selected()
    assert window.sites.item(1, 1).text() == "absent"
    window.purge_expired()
    assert "purged 0" in window.log.toPlainText()


def test_gui_main_rejects_a_bad_env_file(tmp_path, capsys):
    assert gui.main(["-e", str(tmp_path / "nope.env")]) == 2
    assert "env file not found" in capsys.readouterr().err


def test_tui_refuses_without_a_terminal(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
    assert tui.main(["--no-env-file", "-c", str(tmp_path / "jar.cookies")]) == 2
    assert "needs a terminal" in capsys.readouterr().err


def test_tui_and_gui_share_the_jar_tool_options():
    for mod in (tui, gui):
        opts = {a.dest for a in mod.build_parser()._actions}
        for name in ("cookie_file", "sites_file", "margin", "auth", "user", "password_env", "no_prompt"):
            assert name in opts, (mod.__name__, name)

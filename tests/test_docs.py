"""
Checks that the shipped documentation keeps up with the code.

These are the things that go stale silently: a setting added to a module
with no matching line in env.example, or a script with no man page.
"""

import glob
import io
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: Named in the modules but deliberately not a user-facing setting.
NOT_SETTINGS = set()


def read(*parts):
    return io.open(os.path.join(ROOT, *parts), encoding="utf-8").read()


def env_names(text):
    return set(re.findall(r"FERMI_[A-Z0-9_]+", text))


def test_env_example_documents_every_setting():
    in_code = set()
    for path in glob.glob(os.path.join(ROOT, "*.py")):
        in_code |= env_names(read(os.path.basename(path)))
    in_code -= NOT_SETTINGS

    documented = env_names(read("env.example"))

    assert in_code - documented == set(), "undocumented in env.example"


def test_every_console_script_has_a_man_page():
    scripts = {
        "fermi_sso_probe": "man/fermi_sso_probe.1",
        "fermi_sso_cookies": "man/fermi_sso_cookies.1",
        "fermi_sso_yubikey": "man/fermi_sso_yubikey.3",
        "fermi_sso_jar": "man/fermi_sso_jar.1",
        "fermi_sso_jar_tui": "man/fermi_sso_jar_tui.1",
        "fermi_sso_jar_gui": "man/fermi_sso_jar_gui.1",
        "fermi_sso_sites": "man/fermi_sso_sites.5",
    }
    missing = [p for p in scripts.values() if not os.path.exists(os.path.join(ROOT, p))]
    assert missing == []


def test_bootstrap_has_a_man_page():
    assert os.path.exists(os.path.join(ROOT, "man", "bootstrap.sh.1"))


def test_claude_skills_installer_and_skills():
    assert os.path.isfile(os.path.join(ROOT, "man", "install-claude-skills.sh.1"))
    assert os.path.isfile(os.path.join(ROOT, "install-claude-skills.ps1"))
    assert os.access(os.path.join(ROOT, "install-claude-skills.sh"), os.X_OK)
    for name in ("fermi-sso", "fermi-sso-embed"):
        head = read("claude-skills", name, "SKILL.md").split("---")[1]
        assert f"name: {name}\n" in head and "description: " in head


def test_no_test_shaped_scripts_outside_the_tests_directory():
    """
    A file matching pytest's default test*.py pattern at the repository root
    gets collected by any invocation that bypasses testpaths. test2.py used
    to sit here and would prompt for a password and hit the network.
    """
    stray = [
        os.path.basename(p)
        for p in glob.glob(os.path.join(ROOT, "test*.py"))
    ]
    assert stray == []

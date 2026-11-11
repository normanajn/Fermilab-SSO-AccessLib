"""
Checks on pyproject.toml's metadata.

An invalid classifier is only caught at upload time, by twine or PyPI, long
after the mistake is made; a python_requires that claims more than the code
supports lets pip install something that cannot be imported; and a missing
data file or entry-point target only fails when the wheel is built or the
command is run.
"""

import ast
import importlib
import os
import re
import sys

import pytest

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - depends on the interpreter
    tomllib = pytest.importorskip(
        "tomli", reason="pip install tomli to read pyproject.toml on Python < 3.11"
    )

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PYPROJECT = os.path.join(ROOT, "pyproject.toml")


@pytest.fixture(scope="module")
def pyproject():
    with open(PYPROJECT, "rb") as fh:
        return tomllib.load(fh)


def floor_of(requires_python):
    assert requires_python.startswith(">=")
    major, minor = (int(part) for part in requires_python[2:].split(".")[:2])
    return major, minor


def test_distribution_name(pyproject):
    """The PyPI name; normalizes to fermi-sso-accesslib."""
    name = pyproject["project"]["name"]
    assert re.sub(r"[-_.]+", "-", name).lower() == "fermi-sso-accesslib"


def test_every_classifier_is_registered(pyproject):
    trove = pytest.importorskip(
        "trove_classifiers", reason="pip install trove-classifiers to check these"
    )
    unknown = [
        c for c in pyproject["project"]["classifiers"] if c not in trove.classifiers
    ]
    assert unknown == []


def test_no_license_classifier_alongside_a_license_expression(pyproject):
    """setuptools >= 77 refuses a License :: classifier when `license` is an
    SPDX expression (PEP 639)."""
    assert isinstance(pyproject["project"]["license"], str)
    assert not [
        c for c in pyproject["project"]["classifiers"] if c.startswith("License ::")
    ]


def test_license_files_exist(pyproject):
    for path in pyproject["project"]["license-files"]:
        assert os.path.isfile(os.path.join(ROOT, path)), path


def test_python_requires_is_not_below_what_the_code_needs(pyproject):
    """
    requests_fermi_sso uses the f"{x=}" form, which is 3.8+. Declaring
    anything lower means pip installs a package that fails at import.
    """
    assert floor_of(pyproject["project"]["requires-python"]) >= (3, 8)


def test_the_running_interpreter_satisfies_python_requires(pyproject):
    floor = floor_of(pyproject["project"]["requires-python"])
    assert sys.version_info[:2] >= floor


def test_python_classifiers_match_requires_python(pyproject):
    floor = floor_of(pyproject["project"]["requires-python"])
    listed = [
        tuple(int(p) for p in c.rsplit(":: ", 1)[1].split("."))
        for c in pyproject["project"]["classifiers"]
        if re.match(r"Programming Language :: Python :: 3\.\d+$", c)
    ]
    assert listed
    assert min(listed) == floor


def test_every_py_module_exists(pyproject):
    for mod in pyproject["tool"]["setuptools"]["py-modules"]:
        assert os.path.isfile(os.path.join(ROOT, mod + ".py")), mod


def test_every_console_script_target_exists(pyproject):
    for script, target in pyproject["project"]["scripts"].items():
        module_name, func = target.split(":")
        assert module_name in pyproject["tool"]["setuptools"]["py-modules"], script
        module = importlib.import_module(module_name)
        assert callable(getattr(module, func, None)), target


def test_every_man_page_is_shipped(pyproject):
    """Each page under man/ is listed in data-files, and each listed page
    exists; a missing one fails the wheel build."""
    listed = [
        path
        for paths in pyproject["tool"]["setuptools"]["data-files"].values()
        for path in paths
    ]
    for path in listed:
        assert os.path.isfile(os.path.join(ROOT, path)), path
    on_disk = sorted(
        "man/" + f for f in os.listdir(os.path.join(ROOT, "man")) if not f.startswith(".")
    )
    assert sorted(listed) == on_disk


def test_man_pages_go_to_the_section_their_suffix_names(pyproject):
    for target, paths in pyproject["tool"]["setuptools"]["data-files"].items():
        section = target.rsplit("man", 1)[1]
        for path in paths:
            assert path.rsplit(".", 1)[1] == section, (target, path)


# --------------------------------------------------------------------------
# version
# --------------------------------------------------------------------------


def test_the_library_module_exposes_a_version():
    """`from requests_fermi_sso import __version__` is what a consumer
    reaches for first, and it used to raise ImportError."""
    import requests_fermi_sso

    assert isinstance(requests_fermi_sso.__version__, str)
    assert requests_fermi_sso.__version__


def test_every_module_reports_the_same_version():
    import fermi_sso_cookies
    import fermi_sso_probe
    import fermi_sso_yubikey
    import requests_fermi_sso

    versions = {
        m.__name__: m.__version__
        for m in (
            requests_fermi_sso,
            fermi_sso_probe,
            fermi_sso_yubikey,
            fermi_sso_cookies,
        )
    }
    assert len(set(versions.values())) == 1, versions


def test_version_is_statically_resolvable(pyproject):
    """
    The build reads the version with `attr = requests_fermi_sso.__version__`.
    setuptools resolves that from the AST when the assignment is a plain
    string literal; otherwise it imports the module, which needs requests in
    the isolated build environment and fails.
    """
    import requests_fermi_sso

    attr = pyproject["tool"]["setuptools"]["dynamic"]["version"]["attr"]
    module_name, name = attr.rsplit(".", 1)
    with open(os.path.join(ROOT, module_name + ".py"), encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    literal = [
        node.value.value
        for node in tree.body
        if isinstance(node, ast.Assign)
        and [getattr(t, "id", None) for t in node.targets] == [name]
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    ]
    assert literal == [requests_fermi_sso.__version__]


def test_version_is_major_minor_patch():
    import requests_fermi_sso

    assert re.fullmatch(r"\d+\.\d+\.\d+", requests_fermi_sso.__version__)


def test_man_page_headers_carry_the_library_version():
    import requests_fermi_sso

    version = requests_fermi_sso.__version__
    for name in os.listdir(os.path.join(ROOT, "man")):
        with open(os.path.join(ROOT, "man", name), encoding="utf-8") as fh:
            first = fh.readline()
        assert first.startswith(".TH"), name
        assert version in first, (name, first)

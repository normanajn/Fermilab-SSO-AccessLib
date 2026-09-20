"""
Checks on setup.py's metadata.

An invalid classifier is only caught at upload time, by twine or PyPI, long
after the mistake is made; and a python_requires that claims more than the
code supports lets pip install something that cannot be imported.
"""

import ast
import io
import os
import sys

import pytest

SETUP_PY = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "setup.py"
)


def setup_kwargs():
    """The keyword arguments of the setup() call, without executing it."""
    tree = ast.parse(io.open(SETUP_PY, encoding="utf-8").read())
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and getattr(node.func, "id", None) == "setup"
        ):
            kwargs = {}
            for kw in node.keywords:
                if kw.arg is None:
                    continue
                try:
                    kwargs[kw.arg] = ast.literal_eval(kw.value)
                except ValueError:
                    # computed, e.g. long_description read from README.md
                    continue
            return kwargs
    raise AssertionError("no setup() call found in setup.py")


def test_every_classifier_is_registered():
    trove = pytest.importorskip(
        "trove_classifiers", reason="pip install trove-classifiers to check these"
    )
    unknown = [
        c for c in setup_kwargs()["classifiers"] if c not in trove.classifiers
    ]
    assert unknown == []


def test_python_requires_is_not_below_what_the_code_needs():
    """
    requests_fermi_sso uses the f"{x=}" form, which is 3.8+. Declaring
    anything lower means pip installs a package that fails at import.
    """
    floor = setup_kwargs()["python_requires"]
    assert floor.startswith(">=")
    major, minor = (int(part) for part in floor[2:].split(".")[:2])
    assert (major, minor) >= (3, 8)


def test_the_running_interpreter_satisfies_python_requires():
    floor = setup_kwargs()["python_requires"]
    major, minor = (int(part) for part in floor[2:].split(".")[:2])
    assert sys.version_info[:2] >= (major, minor)

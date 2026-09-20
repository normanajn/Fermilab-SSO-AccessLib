from setuptools import setup, find_packages
import pathlib
import re

here = pathlib.Path(__file__).parent.resolve()


def read_version():
    """The version from requests_fermi_sso.py, without importing it (that
    would need requests at build time)."""
    text = (here / "requests_fermi_sso.py").read_text(encoding="utf-8")
    match = re.search(r'^__version__ = "([^"]+)"', text, re.M)
    if not match:
        raise RuntimeError("no __version__ in requests_fermi_sso.py")
    return match.group(1)


def wrap_find_packages(*args, **kwargs):
    res = find_packages(*args, **kwargs)
    print(f"find_packages returns {res}")
    return res


# Get the long description from the README file
long_description = (here / "README.md").read_text(encoding="utf-8")
setup(
    name="requests-fermi_sso",
    py_modules=[
        "requests_fermi_sso",
        "fermi_sso_probe",
        "fermi_sso_yubikey",
        "fermi_sso_cookies",
    ],
    version=read_version(),
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Marc Mengel",
    author_email="mengel@fnal.gov",
    classifiers=[
        "Development Status :: 3 - Alpha",
        # Indicate who your project is intended for
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    # 3.9 is the floor the project supports. Note the f"{x=}" form in
    # requests_fermi_sso.py is 3.8+, so anything lower does not merely lack
    # features, it fails at import.
    python_requires=">=3.9",
    install_requires=["requests"],
    extras_require={"test": ["pytest"], "kerberos": ["requests-gssapi"]},
    entry_points={
        "console_scripts": [
            "fermi-sso-probe=fermi_sso_probe:main",
            "fermi-sso-yubikey=fermi_sso_yubikey:main",
            "fermi-sso-cookies=fermi_sso_cookies:main",
        ],
    },
    data_files=[
        ("share/man/man1", ["man/fermi_sso_probe.1", "man/fermi_sso_cookies.1"]),
        ("share/man/man3", ["man/FermiSSOSession.3", "man/fermi_sso_yubikey.3"]),
    ],
)

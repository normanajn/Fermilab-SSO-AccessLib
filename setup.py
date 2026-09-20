from setuptools import setup, find_packages
import pathlib

here = pathlib.Path(__file__).parent.resolve()


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
    version="0.2.0",
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

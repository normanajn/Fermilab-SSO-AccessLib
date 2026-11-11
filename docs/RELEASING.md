# Releasing Fermi-SSO-AccessLib to PyPI

The distribution name is `Fermi-SSO-AccessLib` (normalized by PyPI to
`fermi-sso-accesslib`). The importable modules are unchanged:
`requests_fermi_sso`, `fermi_sso_probe`, `fermi_sso_yubikey`,
`fermi_sso_cookies`.

Packaging is defined entirely in `pyproject.toml` (setuptools >= 77 backend).
The version is read from `__version__` in `requests_fermi_sso.py`, so that
string is the only place to bump it. The man page `.TH` headers carry the
same version, and `tests/test_packaging.py` fails if they differ.

## One-time setup

Publishing uses PyPI *trusted publishing*: GitHub Actions authenticates
to PyPI with an OIDC token, so no API token is stored anywhere.

1. On <https://pypi.org/manage/account/publishing/>, add a **pending
   publisher**:
   - PyPI project name: `Fermi-SSO-AccessLib`
   - Owner: `normanajn`
   - Repository: `Fermilab-SSO-AccessLib`
   - Workflow: `publish.yml`
   - Environment: `pypi`
2. Do the same on <https://test.pypi.org/manage/account/publishing/>, with
   environment `testpypi`.
3. In the GitHub repository, go to **Settings > Environments** and create
   `pypi` and `testpypi`. Adding yourself as a required reviewer on `pypi`
   gives a manual approval step before each upload.

Note: PyPI renders `README.md` as the project page and links to the GitHub
repository. While the repository is private, those links return 404.

## Building and checking locally

```bash
python -m pip install -r requirements-dev.txt
python -m pytest tests
rm -rf dist && python -m build          # dist/*.tar.gz and dist/*.whl
python -m twine check --strict dist/*   # README renders, metadata valid
```

Check the wheel in a clean venv:

```bash
python -m venv /tmp/fsa && /tmp/fsa/bin/pip install dist/*.whl
/tmp/fsa/bin/fermi-sso-probe --version
ls /tmp/fsa/share/man/man1 /tmp/fsa/share/man/man3
```

## Release

1. Bump `__version__` in `requests_fermi_sso.py` and the version in the
   `.TH` line of every page in `man/`. Run the tests.
2. Optionally, rehearse on TestPyPI: go to **Actions > publish > Run
   workflow** on the branch. Then:
   ```bash
   pip install -i https://test.pypi.org/simple/ \
       --extra-index-url https://pypi.org/simple/ fermi-sso-accesslib
   ```
3. Merge to `main`, then tag and push:
   ```bash
   git tag -a 0.4.0 -m "0.4.0"
   git push origin 0.4.0
   ```
   The `publish` workflow runs the test matrix (Linux/macOS/Windows on
   Python 3.9 and 3.13), builds the package, checks that the tag equals
   `__version__`, and uploads to PyPI.

PyPI never accepts the same version twice, even after a release is deleted.
If something is wrong after an upload, release the next patch version.

## Manual fallback (API token)

If you can't use trusted publishing:

```bash
python -m twine upload dist/*      # prompts; or set TWINE_USERNAME=__token__ TWINE_PASSWORD=pypi-...
```

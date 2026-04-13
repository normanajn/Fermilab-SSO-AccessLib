
## Fermi SSO signon for Scripts

This is a plugin for the Python requests library that will let scripts sign into Fermilab SSO with a user name and password.

Basic theory:  If we go to fetch a page and get sent to the SSO pages, we choose password authentication and login and then go on to the page.

Non-interactive scripts would need to request a "special account" from the authentication folks for a username and password to pass.

Usage

```
from requests_fermi_sso import FermiSSOSession

s = FermiSSOSession(userpass=f"{user}:{pass}")
resp = s.get("https://site/page")

```


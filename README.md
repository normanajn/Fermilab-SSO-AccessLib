
== Fermi SSO kerberos signon for Scripts ==

This is (in development) a plugin for the Python requests library that will (hopefully) let scripts sign into Fermilab SSO with a kerberos credential.

Basic theory:  If we go to fetch a page and get sent to the SSO pages, we request kerberos authentication, and use the kerberos library to do the kerberos authentication.

It is hoped that this can be used both:
* for interactive users who have a kerberos TGT in their ticket cache
* for batch/monitoring scripts that have a service principal or possilby a host principal in a keytab, and who have done a kinit -k /their/keytab already

It might be possible to automate the kinit from a keytab with an environment variable(?) 
o

# register

Self Service Account Registration

It is often tedious but not at all necessary to add a linux computer to a domain or to authenticate the users via LDAP. 
This small script is started under a special "register" user as its "login-shell".
Users log in via: `ssh register@mycom.com` using a wellknown password.

After that a user can enter his company account and will be authenticated via LDAP. 
If successful, he can create a new account. It is also possible to reset the password. Authorization can be done via LDAP groups.

An ansible script for installation is provided. Use `ansible-playbook setup.yml ...` or use manual installation.
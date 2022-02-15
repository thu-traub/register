# Self Service Account Registration

Manual Installation

## Packages

Install the following packages:

* python3.8
* python3-pip
* python3.8-dev
* libsasl2-dev
* libldap2-dev
* libssl-dev

## Install Python modules

The script is currently tested for python3.8.
It might run with newer versions as well.

To install other modules we need pip.
If pip (better pip3) is already installed, bring in the ldap module:

    sudo -H pip3 install python-ldap

If pip is not installed yet, you can load it with:

    wget https://bootstrap.pypa.io/get-pip.py
    python3.8 get-pip.py

## Install the LDAP certificate

Because LDAP connection uses TLS, we need to trust the LDAP severs certificate.

Copy the LDAP servers certificate (hsu-root.crt) to the ca directory and update the root store:

    sudo cp hsu-root.crt /usr/local/share/ca-certificates
    sudo update-ca-certificate

You should see, that one certificate was added to the store.

## Create a registration user

* Create a new user, e.g. `register` with a known password.
* Create a new directory `/usr/local/bin/register`
* Copy the script and config to this directory
* Change the directories owner: `chown register /usr/local/bin/register`
* Login as user `register` and start and stop the script to check if python works.
* Edit `/etc/passwd` and change the users shell to `/usr/local/bin/register/register.py`

Even though anybody knows the register users password, the only thing what this user can do is to run the script. To prevent brute forece attacks, the script waits one second before contacting the LDAP server.

## Edit configuration

Edit the configuration file `config.json`.
If we need LDAP authorization to restrict users, add the `authorize` section.
Only users who are members of this list are allowed.
If `recurse` is set to true, the LDAP groups are resolved recursively.

## Logging

Create a new subdirectory for logging, e.g.

    mkdir /var/log/register
    chown register /var/log/register

This directory has to match the settings in the config file or course.


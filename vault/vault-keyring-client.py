#!/usr/bin/env python
# -*- coding: utf-8 -*-
# (c) 2014, Matt Martz <matt@sivel.net>
# (c) 2016, Justin Mayer <https://justinmayer.com/>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#
# =============================================================================
#
# This script is to be used with ansible-vault's --vault-id arg
# to retrieve the vault password via your OS's native keyring application.
#
# This file *MUST* be saved with executable permissions. Otherwise, Ansible
# will try to parse as a password file and display: "ERROR! Decryption failed"
#
# The `keyring` Python module is required: https://pypi.org/project/keyring/
#
# By default, this script will store the specified password in the keyring of
# the user that invokes the script. To specify a user keyring, pass the
# --username option to the script
#
# In useage like:
#
#    ansible-vault --vault-id keyring_id@contrib/vault/vault-keyring-client.py view some_encrypted_file
#
#  --vault-id will call this script like:
#
#     contrib/vault/vault-keyring-client.py --vault-id keyring_id
#
# That will retrieve the password from users keyring for the
# keyring service 'keyring_id'. The equivalent of:
#
#      keyring get keyring_id $USER
#
# If no vault-id name is specified to ansible command line, the vault-keyring-client.py
# script will be called without a '--vault-id' and will default to the keyring service 'ansible'
# This is equivalent to:
#
#    keyring get ansible $USER
#
# You can configure the `vault_password_file` option in ansible.cfg:
#
# [defaults]
# ...
# vault_password_file = /path/to/vault-keyring-client.py
# ...
# or in your environment
# ```
# export ANSIBLE_VAULT_PASSWORD_FILE=/path/to/vault-keyring-client.py
# ```
#
# Meanwhile if your intend to use several vault-id you should rather
# set a vault identity list and let the above unset
# ```
# export ANSIBLE_VAULT_IDENTITY_LIST=vaultid1@/path/to/vault-keyring-client,vaultid2@/path/to/vault-keyring-client
# ```
#
# To set your password, `cd` to your project directory and run:
#
#   # will use default keyring service / vault-id of 'ansible'
#   /path/to/vault-keyring-client.py --set
#
# or to specify the keyring service / vault-id of 'my_ansible_secret':
#
#  /path/to/vault-keyring-client.py --vault-id my_ansible_secret --set
#
# If you choose not to configure the path to `vault_password_file` or
# to set an identity list, you can invoke your playbook as follows:
#
# ansible-playbook --vault-id=keyring_id@/path/to/vault-keyring-client.py site.yml

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import argparse
import sys
import getpass
import keyring

KEYNAME_UNKNOWN_RC = 2


def build_arg_parser():
    parser = argparse.ArgumentParser(description='Get a vault password from user keyring')

    parser.add_argument('--vault-id', action='store', default="ansible",
                        dest='vault_id',
                        help='name of the vault secret to get from keyring')
    parser.add_argument('--username', action='store', default=getpass.getuser(),
                        help='the username whose keyring is queried')
    parser.add_argument('--set', action='store_true', default=False,
                        dest='set_password',
                        help='set the password instead of getting it')
    return parser


def main():

    # Read values from command line (which override the previous if given)
    arg_parser = build_arg_parser()
    args = arg_parser.parse_args()

    username = args.username
    vault_id = args.vault_id

    if args.set_password:
        intro = 'Storing password in "{}" user keyring using key name: {}\n'
        sys.stdout.write(intro.format(username, vault_id))
        password = getpass.getpass()
        confirm = getpass.getpass('Confirm password: ')
        if password == confirm:
            keyring.set_password(vault_id, username, password)
        else:
            sys.stderr.write('Passwords do not match\n')
            sys.exit(1)
    else:
        secret = keyring.get_password(vault_id, username)
        if secret is None:
            sys.stderr.write('vault-keyring-client could not find key="%s" for user="%s" via backend="%s"\n' %
                             (vault_id, username, keyring.get_keyring().name))
            sys.exit(KEYNAME_UNKNOWN_RC)

        sys.stdout.write('%s\n' % secret)

    sys.exit(0)


if __name__ == '__main__':
    main()

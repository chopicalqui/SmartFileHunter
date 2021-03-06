#!/usr/bin/env python3

"""

"""

__author__ = "Lukas Reiter"
__license__ = "GPL v3.0"
__copyright__ = """Copyright 2018 Lukas Reiter

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
__version__ = 0.1

import sys
import argparse
import logging
import tempfile
import traceback
from hunters.modules.smb import SmbSensitiveFileHunter
from hunters.modules.ftp import FtpSensitiveFileHunter
from hunters.modules.nfs import NfsSensitiveFileHunter

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-l", "--list", action='store_true', help="list existing workspaces")
    sub_parser = parser.add_subparsers(help='list of available file hunter modules', dest="module")
    parser_smb = sub_parser.add_parser('smb', help='enumerate SMB services')
    parser_ftp = sub_parser.add_parser('ftp', help='enumerate FTP services')
    parser_nfs = sub_parser.add_parser('nfs', help='enumerate NFS services')
    # create SMB arguments
    parser_smb.add_argument('-v', '--verbose', action="store_true", help='create verbose output')
    smb_target_group = parser_smb.add_argument_group('target information')
    smb_target_group.add_argument('--host', type=str, metavar="HOST", help="the target SMB service's IP address")
    smb_target_group.add_argument('--port', type=int, default=445, metavar="PORT",
                                  help="the target SMB service's port")
    smb_target_group.add_argument('--shares', type=str, nargs="*", metavar="SHARES",
                                  help="list of shares to enumerate. if not specified, then all shares will be "
                                       "enumerated.")
    smb_authentication_group = parser_smb.add_argument_group('authentication')
    smb_authentication_group.add_argument('-u', '--username', action="store", required=True,
                                          metavar="USERNAME", help='the name of the user to use for authentication')
    smb_authentication_group.add_argument('-d', '--domain', action="store", required=True,
                                          metavar="DOMAIN", help='the domain to use for authentication')
    parser_smb_credential_group = smb_authentication_group.add_mutually_exclusive_group(required=True)
    parser_smb_credential_group.add_argument('--hash', action="store",
                                             metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    parser_smb_credential_group.add_argument('-p', '--password', action="store",
                                             metavar="PASSWORD", help='password of given user')
    # create FTP arguments
    parser_ftp.add_argument('-v', '--verbose', action="store_true", help='create verbose output')
    parser_ftp.add_argument('-t', '--tls', action="store_true", help='use TLS')
    ftp_target_group = parser_ftp.add_argument_group('target information')
    ftp_target_group.add_argument('--host', type=str, metavar="HOST", help="the target FTP service's IP address")
    ftp_authentication_group = parser_ftp.add_argument_group('authentication')
    ftp_authentication_group.add_argument('-u', '--username', action="store", default='',
                                          metavar="USERNAME", help='the name of the user to use for authentication')
    ftp_authentication_group.add_argument('-p', '--password', action="store", default='',
                                          metavar="PASSWORD", help='password of given user')
    # create NFS arguments
    parser_nfs.add_argument('-v', '--verbose', action="store_true", help='create verbose output')
    parser_nfs.add_argument('--version', type=int, choices=[3, 4], default=3, help='NFS version to use')
    nfs_target_group = parser_nfs.add_argument_group('target information')
    nfs_target_group.add_argument('--host', type=str, metavar="HOST", help="the target NFS service's IP address")
    nfs_target_group.add_argument('--port', type=int, default=445, metavar="PORT", help="the target NFS service's port")
    nfs_target_group.add_argument('--path', type=str, metavar="PATH", help="path to enumerate")
    args = parser.parse_args()

    if len(sys.argv) <= 1:
        parser.print_help()
        sys.exit(1)

    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            if args.module == "smb":
                hunter = SmbSensitiveFileHunter(args, temp_dir=temp_dir)
                hunter.enumerate()
            elif args.module == "ftp":
                hunter = FtpSensitiveFileHunter(args, temp_dir=temp_dir)
                hunter.enumerate()
            elif args.module == "nfs":
                hunter = NfsSensitiveFileHunter(args, temp_dir=temp_dir)
                hunter.enumerate()
    except Exception as ex:
        traceback.print_exc(ex)
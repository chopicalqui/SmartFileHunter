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
import tempfile
import traceback
from database.core import Engine
from database.core import ManageDatabase
from database.core import DeclarativeBase
from hunters.modules.smb import SmbSensitiveFileHunter
from hunters.modules.ftp import FtpSensitiveFileHunter
from hunters.modules.nfs import NfsSensitiveFileHunter


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-l", "--list", action='store_true', help="list existing workspaces")
    sub_parser = parser.add_subparsers(help='list of available file hunter modules', dest="module")
    parser_database = sub_parser.add_parser('db', help='allows setting up and managing the database')
    parser_smb = sub_parser.add_parser('smb', help='enumerate SMB services')
    parser_ftp = sub_parser.add_parser('ftp', help='enumerate FTP services')
    parser_nfs = sub_parser.add_parser('nfs', help='enumerate NFS services')
    # setup database parser
    parser_database.add_argument('-a', '--add',
                                 type=str,
                                 help="create the given workspace")
    parser_database.add_argument("--init",
                                 help="creates tables, views, functions, and triggers in the filehunter database",
                                 action="store_true")
    parser_database.add_argument("--drop",
                                 help="drops tables, views, functions, and triggers in the filehunter database",
                                 action="store_true")
    parser_database.add_argument("--backup", metavar="FILE", type=str, help="writes database backup to FILE")
    parser_database.add_argument("--restore", metavar="FILE", type=str, help="restores database backup from FILE")
    parser_database.add_argument("--setup",
                                 action="store_true",
                                 help="run initial setup for filehunter")
    parser_database.add_argument("--setup-dbg",
                                 action="store_true",
                                 help="like --setup but just prints commands for initial setup for filehunter")
    # setup SMB parser
    parser_smb.add_argument('-v', '--verbose', action="store_true", help='create verbose output')
    parser_smb.add_argument('-w', '--workspace', type=str, required=True, help='the workspace used for the enumeration')
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
    # setup FTP parser
    parser_ftp.add_argument('-v', '--verbose', action="store_true", help='create verbose output')
    parser_ftp.add_argument('-t', '--tls', action="store_true", help='use TLS')
    parser_ftp.add_argument('-w', '--workspace', type=str, required=True, help='the workspace used for the enumeration')
    ftp_target_group = parser_ftp.add_argument_group('target information')
    ftp_target_group.add_argument('--host', type=str, metavar="HOST", help="the target FTP service's IP address")
    ftp_authentication_group = parser_ftp.add_argument_group('authentication')
    ftp_authentication_group.add_argument('-u', '--username', action="store", default='',
                                          metavar="USERNAME", help='the name of the user to use for authentication')
    ftp_authentication_group.add_argument('-p', '--password', action="store", default='',
                                          metavar="PASSWORD", help='password of given user')
    # setup NFS parser
    parser_nfs.add_argument('-v', '--verbose', action="store_true", help='create verbose output')
    parser_nfs.add_argument('--version', type=int, choices=[3, 4], default=3, help='NFS version to use')
    parser_nfs.add_argument('-w', '--workspace', type=str, required=True, help='the workspace used for the enumeration')
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
            enumeration_class = None
            if args.list:
                engine = Engine()
                DeclarativeBase.metadata.bind = engine.engine
                engine.print_workspaces()
            elif args.module == "db":
                ManageDatabase(args).run()
            elif args.module == "smb":
                enumeration_class = SmbSensitiveFileHunter
            elif args.module == "ftp":
                enumeration_class = FtpSensitiveFileHunter
            elif args.module == "nfs":
                enumeration_class = NfsSensitiveFileHunter
            if enumeration_class:
                engine = Engine()
                DeclarativeBase.metadata.bind = engine.engine
                hunter = enumeration_class(args, engine=engine, temp_dir=temp_dir)
                hunter.enumerate()
    except Exception as ex:
        traceback.print_exc(ex)

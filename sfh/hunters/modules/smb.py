# -*- coding: utf-8 -*-
"""
this file implements the core functionality to hunt for any sensitive files on SMB shares.
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

import re
import os
import ntpath
import getpass
import logging
import impacket
import argparse
import tempfile
import datetime
from database.model import Path
from database.model import File
from database.model import HunterType
from impacket.smbconnection import SMB_DIALECT
from impacket.smbconnection import SMB2_DIALECT_002
from impacket.smbconnection import SMB2_DIALECT_21
from impacket.smbconnection import SMBConnection
from impacket.smbconnection import FILE_SHARE_READ
from hunters.modules.core import BaseSensitiveFileHunter

logger = logging.getLogger('smb')


class SmbSensitiveFileHunter(BaseSensitiveFileHunter):
    """
    This class implements the core functionality to hunt for files on SMB shares.
    """

    def __init__(self, args: argparse.Namespace, **kwargs):
        super().__init__(args, address=args.host, port=args.port, service_name=HunterType.smb, **kwargs)
        if (args.password or args.prompt_for_password or args.hash or args.prompt_for_hash) and not args.username:
            raise ValueError("arguments -p, -h, -P, and -H require a username")
        if args.username:
            self.username = args.username
        else:
            self.username = ''
        if args.password:
            self.password = args.password
            self.lm_hash = ''
            self.nt_hash = ''
        elif args.hash:
            if ":" in args.hash:
                self.lm_hash, self.nt_hash = args.hash.split(':')
            else:
                self.nt_hash = args.hash
                self.lm_hash = 'aad3b435b51404eeaad3b435b51404ee'
            self.password = ''
        elif args.prompt_for_password:
            self.password = getpass.getpass("password: ")
            self.lm_hash = ''
            self.nt_hash = ''
        elif args.prompt_for_hash:
            self.nt_hash = getpass.getpass("NT hash: ")
            self.password = ''
            self.lm_hash = 'aad3b435b51404eeaad3b435b51404ee'
        else:
            self.password = ''
            self.lm_hash = ''
            self.nt_hash = ''
        if self.lm_hash and not re.search("^[0-9a-z]{32,32}$", self.lm_hash, re.IGNORECASE):
            raise ValueError("invalid LM hash: {}".format(self.lm_hash))
        if self.nt_hash and not re.search("^[0-9a-z]{32,32}$", self.nt_hash, re.IGNORECASE):
            raise ValueError("invalid NT hash: {}".format(self.nt_hash))
        self.domain = args.domain
        self.client = SMBConnection(self.service.host.address, self.service.host.address, sess_port=self.service.port)
        self.client.login(self.username, self.password, self.domain, self.lm_hash, self.nt_hash)
        if self.verbose:
            dialect = self.client.getDialect()
            if dialect == SMB_DIALECT:
                logging.info("smbv1 dialect used")
            elif dialect == SMB2_DIALECT_002:
                logging.info("smbv2.0 dialect used")
            elif dialect == SMB2_DIALECT_21:
                logging.info("smbv2.1 dialect used")
            else:
                logging.info("smbv3.0 dialect used")
        self.shares = args.shares if args.shares else self.list_shares()

    def __del__(self):
        if self.client:
            self.client.close()

    @staticmethod
    def add_argparse_arguments(parser: argparse.ArgumentParser) -> None:
        """
        This method initializes command line arguments that are required by the current module.
        :param parser: The argument parser to which the required command line arguments shall be added.
        :return:
        """
        BaseSensitiveFileHunter.add_argparse_arguments(parser)
        parser.add_argument('--domains', type=str, nargs="*", metavar="USERDOMAIN",
                            help='the name of the domain name of existing microsoft active directories. if specified, '
                                 'then the specified values become additional file content matching rules with'
                                 'search pattern: "USERDOMAIN[/\\]\\w+". the objective is the identification domain '
                                 'user names in files.')
        smb_target_group = parser.add_argument_group('target information')
        smb_target_group.add_argument('--host', type=str, metavar="HOST", help="the target SMB service's IP address")
        smb_target_group.add_argument('--port', type=int, default=445, metavar="PORT",
                                      help="the target SMB service's port")
        group = smb_target_group.add_mutually_exclusive_group()
        group.add_argument('--shares', type=str, nargs="*", metavar="SHARES",
                           help="list of shares to enumerate. if not specified, then all shares will be "
                                "enumerated.")
        group.add_argument('--show', action='store_true', help="just display existing share names without enumerating "
                                                               "them")
        smb_authentication_group = parser.add_argument_group('authentication')
        smb_authentication_group.add_argument('-u', '--username', type=str,
                                              metavar="USERNAME", help='the name of the user to use for authentication')
        smb_authentication_group.add_argument('-d', '--domain', default=".", type=str,
                                              metavar="DOMAIN", help='the domain to use for authentication')
        parser_smb_credential_group = smb_authentication_group.add_mutually_exclusive_group()
        parser_smb_credential_group.add_argument('--hash', action="store",
                                                 metavar="LMHASH:NTHASH", help='NTLM hashes, valid formats are'
                                                                               'LMHASH:NTHASH or NTHASH')
        parser_smb_credential_group.add_argument('-p', '--password', action="store",
                                                 metavar="PASSWORD", help='password of given user')
        parser_smb_credential_group.add_argument('-P', dest="prompt_for_password", action="store_true",
                                                 help='ask for the password via an user input prompt')
        parser_smb_credential_group.add_argument('-H', dest="prompt_for_hash", action="store_true",
                                                 help='ask for the hash via an user input prompt')

    def finish(self):
        """
        This method is called after enumeration is completed.
        :return:
        """
        if not self._args.show:
            super().finish()

    def pathify(self, path):
        """
        Method obtained from smbmap
        :param path: Path to pathify
        :return:
        """
        result = ntpath.join(path,'*')
        result = result.replace('/','\\')
        result = result.replace('\\\\','\\')
        result = ntpath.normpath(result)
        return result

    def list_shares(self) -> list:
        """
        This
        :return:
        """
        result = []
        shares = self.client.listShares()
        for i in range(len(shares)):
            result.append(shares[i]['shi1_netname'][:-1])
        return result

    def enumerate(self) -> None:
        """
        This method enumerates all files on the given service.
        :return:
        """
        if self._args.show:
            for name in self.shares:
                print(name)
        else:
            super().enumerate()

    def _enumerate(self) -> None:
        """
        This method enumerates all files on the given service.
        :return:
        """
        for name in self.shares:
            try:
                logger.debug("enumerate share: {}/{}".format(str(self.service), name))
                self.__enumerate(name)
            except Exception:
                logger.error("cannot access share: {}/{}".format(str(self.service), name),
                             exc_info=self._args.verbose)

    def __enumerate(self, share: str, directory: str = "/") -> None:
        try:
            items = self.client.listPath(share, self.pathify(directory))
            for item in items:
                file_size = item.get_filesize()
                filename = item.get_longname()
                is_directory = item.is_directory()
                if filename not in ['.', '..']:
                    full_path = os.path.join(directory, filename)
                    if is_directory:
                        self.__enumerate(share, os.path.join(directory, filename))
                    else:
                        path = Path(service=self.service,
                                    full_path=full_path,
                                    share=share,
                                    access_time=datetime.datetime.utcfromtimestamp(item.get_atime_epoch()),
                                    modified_time=datetime.datetime.utcfromtimestamp(item.get_mtime_epoch()),
                                    creation_time=datetime.datetime.utcfromtimestamp(item.get_ctime_epoch()))
                        if self.is_file_size_below_threshold(path, file_size):
                            try:
                                # Obtain file content
                                with tempfile.NamedTemporaryFile(dir=self.temp_dir) as temp:
                                    with open(temp.name, "wb") as file:
                                        self.client.getFile(share, full_path, file.write, FILE_SHARE_READ)
                                    with open(temp.name, "rb") as file:
                                        content = file.read()
                                path.file = File(content=content)
                                # Add file to queue
                                self.file_queue.put(path)
                            except impacket.smbconnection.SessionError:
                                # Catch permission exception, if SMB user does not have read permission on a certain file
                                logger.error("cannot read file: {}".format(str(path)), exc_info=self._args.verbose)
                        elif file_size > 0:
                            path.file = File(content="[file ({}) not imported as file size ({}) "
                                                     "is above threshold]".format(str(path), file_size).encode('utf-8'))
                            path.file.size_bytes = file_size
                            relevance = self._analyze_path_name(path)
                            if not relevance:
                                logger.debug("ignoring file (threshold: above, size: {}): {}".format(file_size,
                                                                                                     str(path)))
        except impacket.smbconnection.SessionError:
            # Catch permission exception, if SMB user does not have read permission on a certain directory
            logger.error("cannot access item: {}/{}{}".format(str(self.service), share, str(directory)),
                         exc_info=self._args.verbose)

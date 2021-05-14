# -*- coding: utf-8 -*-
"""
this file implements the core functionality to hunt for any sensitive files on FTP services.
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

import os
import ftplib
import logging
import getpass
import argparse
import tempfile
from datetime import datetime
from database.model import Path
from database.model import File
from database.model import HunterType
from hunters.modules.core import BaseSensitiveFileHunter

logger = logging.getLogger('ftp')


class FtpSensitiveFileHunter(BaseSensitiveFileHunter):
    """
    This class implements the core functionality to hunt for files on FTP services.
    """

    def __init__(self, args: argparse.Namespace, **kwargs):
        super().__init__(args, address=args.host, port=args.port, service_name=HunterType.ftp, **kwargs)
        self.username = args.username
        self.password = args.password
        if args.prompt_for_password:
            self.password = getpass.getpass(prompt="password: ")
        self.tls = args.tls
        if self.tls:
            self.client = ftplib.FTP_TLS()
            self.client.connect(self.service.host.address, self.service.port)
            self.client.login(user=self.username, passwd=self.password, secure=False)
        else:
            self.client = ftplib.FTP()
            self.client.connect(self.service.host.address, self.service.port)
            self.client.login(self.username, self.password)
        if self.verbose:
            self.client.getwelcome()

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
        parser.add_argument('--tls', action="store_true", help='use TLS')
        parser.add_argument('--domains', type=str, nargs="*", metavar="USERDOMAIN",
                            help='the name of the domain name of existing microsoft active directories. if specified, '
                                 'then the specified values become additional file content matching rules with'
                                 'search pattern: "USERDOMAIN[/\\]\\w+". the objective is the identification domain '
                                 'user names in files.')
        ftp_target_group = parser.add_argument_group('target information')
        ftp_target_group.add_argument('--host', type=str, metavar="HOST", help="the target FTP service's IP address")
        ftp_target_group.add_argument('--port', type=int, default=21, metavar="PORT",
                                      help="the target FTP service's port")
        ftp_authentication_group = parser.add_argument_group('authentication')
        ftp_authentication_group.add_argument('-u', '--username', action="store", default='',
                                              metavar="USERNAME", help='the name of the user to use for authentication')
        parser_ftp_credential_group = ftp_authentication_group.add_mutually_exclusive_group()
        parser_ftp_credential_group.add_argument('-p', '--password', action="store", default='',
                                                 metavar="PASSWORD", help='password of given user')
        parser_ftp_credential_group.add_argument('-P', dest="prompt_for_password", action="store_true",
                                                 help='ask for the password via an user input prompt')

    def _enumerate(self, cwd: str = None) -> None:
        """
        This method enumerates all files on the given service.
        :return:
        """
        cwd = self.client.pwd() if not cwd else cwd
        try:
            for name, facts in self.client.mlsd(cwd):
                full_path = os.path.join(cwd, name)
                item_type = facts["type"]
                file_size = int(facts["size"]) if "size" in facts else 0
                if item_type == "dir":
                    self._enumerate(os.path.join(cwd, full_path))
                elif item_type == "file":
                    last_modified = facts["modify"]
                    modified_time = datetime.strptime(last_modified, '%Y%m%d%H%M%S') \
                        if last_modified else None
                    path = Path(service=self.service,
                                full_path=full_path,
                                modified_time=modified_time)
                    if self.is_file_size_below_threshold(path, file_size):
                        try:
                            # Obtain file content
                            with tempfile.NamedTemporaryFile(dir=self.temp_dir) as temp:
                                with open(temp.name, "wb") as file:
                                    self.client.retrbinary('RETR {}'.format(full_path), file.write)
                                with open(temp.name, "rb") as file:
                                    content = file.read()
                            path.file = File(content=content)
                            # Add file to queue
                            self.file_queue.put(path)
                        except ftplib.error_perm:
                            # Catch permission exception, if FTP user does not have read permission on a certain file
                            logger.error("cannot read file: {}".format(str(path)), exc_info=self._args.verbose)
                    elif file_size > 0:
                        path.file = File(content="[file ({}) not imported as file size ({}) "
                                                 "is above threshold]".format(str(path), file_size).encode('utf-8'))
                        path.file.size_bytes = file_size
                        relevance = self._analyze_path_name(path)
                        if self._args.debug and not relevance:
                            logger.debug("ignoring file (threshold: above, size: {}): {}".format(file_size, str(path)))
                else:
                    logger.debug("skip type item: {} (type: {})".format(name, item_type))
        except ftplib.error_perm:
            # Catch permission exception, if FTP user does not have read permission on a certain directory
            logger.error("cannot access item: {}/{}".format(str(self.service), str(cwd)), exc_info=self._args.verbose)

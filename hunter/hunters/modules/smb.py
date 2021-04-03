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

import os
import ntpath
import logging
import argparse
import tempfile
import datetime
from database.model import Path
from database.model import File
from impacket.smbconnection import SMB_DIALECT
from impacket.smbconnection import SMB2_DIALECT_002
from impacket.smbconnection import SMB2_DIALECT_21
from impacket.smbconnection import SMBConnection
from impacket.smbconnection import SessionError
from impacket.smbconnection import FILE_SHARE_READ
from hunters.core import BaseSensitiveFileHunter

logger = logging.getLogger('smb')


class SmbSensitiveFileHunter(BaseSensitiveFileHunter):
    """
    This class implements the core functionality to hunt for files on SMB shares.
    """

    def __init__(self, args: argparse.Namespace, **kwargs):
        super().__init__(args, port=args.port, service_name="smb", **kwargs)
        self.username = args.username
        if args.password:
            self.password = args.password
            self.lm_hash = ''
            self.nt_hash = ''
        else:
            self.lm_hash, self.nt_hash = args.hashes.split(':')
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
        self.client.close()

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
            result.append((shares[i]['shi1_netname'][:-1], shares[i]['shi1_remark'][:-1]))
        return result

    def enumerate(self) -> None:
        """
        This method enumerates all files on the given service.
        :return:
        """
        for name, _ in self.shares:
            try:
                logger.debug("enumerate share: {}".format(name))
                self._enumerate(name)
            except SessionError as ex:
                pass
            except Exception as ex:
                if "STATUS_ACCESS_DENIED" not in str(ex):
                    logger.exception(ex)

    def _enumerate(self, share: str, directory: str = "/") -> None:
        items = self.client.listPath(share, self.pathify(directory))
        for item in items:
            file_size = item.get_filesize()
            filename = item.get_longname()
            is_directory = item.is_directory()
            if filename not in ['.', '..']:
                full_path = os.path.join(directory, filename)
                if is_directory:
                    self._enumerate(share, os.path.join(directory, filename))
                elif self.is_file_size_below_threshold(file_size):
                    path = Path(service=self.service,
                                full_path=full_path,
                                share=share,
                                access_time=datetime.datetime.utcfromtimestamp(item.get_atime_epoch()),
                                modified_time=datetime.datetime.utcfromtimestamp(item.get_mtime_epoch()),
                                creation_time=datetime.datetime.utcfromtimestamp(item.get_ctime_epoch()))
                    # Obtain file content
                    with tempfile.NamedTemporaryFile(dir=self.temp_dir) as temp:
                        with open(temp.name, "wb") as file:
                            self.client.getFile(share, full_path, file.write, FILE_SHARE_READ)
                        with open(temp.name, "rb") as file:
                            content = file.read()
                    path.file = File(content=content)
                    # Add file to queue
                    if path.file.size_bytes > 0:
                        logger.debug("enqueue file: {}".format(path.full_path))
                        self.file_queue.put(path)

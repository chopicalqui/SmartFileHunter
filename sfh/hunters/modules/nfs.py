# -*- coding: utf-8 -*-
"""
this file implements the core functionality to hunt for any sensitive files on NFS shares.
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
import stat
import libnfs
import logging
import argparse
from datetime import datetime
from datetime import timezone
from database.model import Path
from database.model import File
from database.model import HunterType
from hunters.modules.core import BaseSensitiveFileHunter

logger = logging.getLogger('nfs')


class NfsSensitiveFileHunter(BaseSensitiveFileHunter):
    """
    This class implements the core functionality to hunt for files on NFS shares.
    """

    def __init__(self, args: argparse.Namespace, **kwargs):
        super().__init__(args, address=args.host, port=args.port, service_name=HunterType.nfs, **kwargs)
        self.path = args.path
        self.version = args.version
        self.connection_string = "nfs://{}/{}?version={}&nfsport={}".format(self.service.host.address,
                                                                            self.path,
                                                                            self.version,
                                                                            self.service.port)
        self.client = libnfs.NFS(self.connection_string)

    @staticmethod
    def add_argparse_arguments(parser: argparse.ArgumentParser) -> None:
        """
        This method initializes command line arguments that are required by the current module.
        :param parser: The argument parser to which the required command line arguments shall be added.
        :return:
        """
        BaseSensitiveFileHunter.add_argparse_arguments(parser)
        parser.add_argument('--version', type=int, choices=[3, 4], default=3, help='NFS version to use')
        parser.add_argument('--netbios', type=str, nargs="*", metavar="NETBIOS",
                            help='the netbios name of the existing microsoft active directories. if specified, '
                                 'then the specified values become additional file content matching rules with'
                                 'search pattern: "NETBIOS[/\\]\\w+". the objective is the identification of files '
                                 'containing domain user names and eventually their passwords.')
        parser.add_argument('--upn', type=str, nargs="*", metavar="DOMAIN",
                            help='the domain name of the existing microsoft active directories. if specified, '
                                 'then the specified values become additional file content matching rules with'
                                 'search pattern: "\\w+@DOMAIN". the objective is the identification of files '
                                 'containing UPNs and eventually their passwords.')
        nfs_target_group = parser.add_argument_group('target information')
        nfs_target_group.add_argument('--host', type=str, metavar="HOST", help="the target NFS service's IP address")
        nfs_target_group.add_argument('--port', type=int, default=2049, metavar="PORT",
                                      help="the target NFS service's port")
        nfs_target_group.add_argument('--path', type=str, metavar="PATH", help="path to enumerate")

    def _enumerate(self, cwd: str = "") -> None:
        """
        This method enumerates all files on the given service.
        :return:
        """
        items = self.client.listdir(cwd)
        for item in items:
            if item not in [".", ".."]:
                full_path = os.path.join(cwd, item)
                stats = self.client.stat(full_path)
                file_size = stats['size']
                if stat.S_ISDIR(stats['mode']):
                    self._enumerate(full_path)
                else:
                    path = Path(service=self.service,
                                full_path=full_path,
                                access_time=datetime.fromtimestamp(stats['atime']['sec'], tz=timezone.utc),
                                modified_time=datetime.fromtimestamp(stats['mtime']['sec'], tz=timezone.utc),
                                creation_time=datetime.fromtimestamp(stats['ctime']['sec'], tz=timezone.utc))
                    if self.is_file_size_below_threshold(path, file_size):
                        content = self.client.open(full_path, mode='rb').read()
                        path.file = File(content=bytes(content))
                        # Add file to queue
                        self.file_queue.put(path)
                    elif file_size > 0:
                        path.file = File(content="[file ({}) not imported as file size ({}) "
                                                 "is above threshold]".format(str(path), file_size).encode('utf-8'))
                        path.file.size_bytes = file_size
                        relevance = self._analyze_path_name(path)
                        if not relevance:
                            logger.debug("ignoring file (threshold: above, size: {}): {}".format(file_size,
                                                                                                 str(path)))

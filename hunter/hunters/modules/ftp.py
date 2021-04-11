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
import argparse
import tempfile
from datetime import datetime
from database.model import Path
from database.model import File
from database.model import HunterType
from hunters.core import BaseSensitiveFileHunter

logger = logging.getLogger('ftp')


class FtpSensitiveFileHunter(BaseSensitiveFileHunter):
    """
    This class implements the core functionality to hunt for files on FTP services.
    """

    def __init__(self, args: argparse.Namespace, **kwargs):
        super().__init__(args, address=args.host, port=21, service_name=HunterType.ftp.name, **kwargs)
        self.username = args.username
        self.password = args.password
        self.tls = args.tls
        if self.tls:
            self.client = ftplib.FTP_TLS(host=self.service.host.address, user=self.username, passwd=self.password)
        else:
            self.client = ftplib.FTP(host=self.service.host.address, user=self.username, passwd=self.password)
        if self.verbose:
            self.client.getwelcome()

    def __del__(self):
        self.client.close()

    def _enumerate(self, cwd: str = None) -> None:
        """
        This method enumerates all files on the given service.
        :return:
        """
        cwd = self.client.pwd() if not cwd else cwd
        for name, facts in self.client.mlsd(cwd):
            full_path = os.path.join(cwd, name)
            item_type = facts["type"]
            file_size = int(facts["size"]) if "size" in facts else 0
            if item_type == "dir":
                self.enumerate(os.path.join(cwd, full_path))
            elif item_type == "file" and self.is_file_size_below_threshold(file_size):
                last_modified = facts["modify"]
                modified_time = datetime.strptime(last_modified, '%Y%m%d%H%M%S') \
                    if last_modified else None
                path = Path(service=self.service,
                            full_path=full_path,
                            modified_time=modified_time)
                # Obtain file content
                with tempfile.NamedTemporaryFile(dir=self.temp_dir) as temp:
                    with open(temp.name, "wb") as file:
                        self.client.retrbinary('RETR {}'.format(full_path), file.write)
                    with open(temp.name, "rb") as file:
                        content = file.read()
                path.file = File(content=content)
                # Add file to queue
                logger.debug("enqueue file: {}".format(path.full_path))
                self.file_queue.put(path)
            else:
                logger.debug("skip type item: {} (type: {})".format(name, item_type))
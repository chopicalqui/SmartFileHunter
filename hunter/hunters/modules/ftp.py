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

import ftplib
import logging
import argparse
from hunters.core import BaseSensitiveFileHunter

logger = logging.getLogger('ftp')


class FtpSensitiveFileHunter(BaseSensitiveFileHunter):
    """
    This class implements the core functionality to hunt for files on FTP services.
    """

    def __init__(self, args: argparse.Namespace, **kwargs):
        super().__init__(args, **kwargs)
        self.username = args.username
        self.password = args.password
        self.tls = args.tls
        if self.tls:
            self.client = ftplib.FTP_TLS(host=self.target_ip, user=self.username, passwd=self.password)
        else:
            self.client = ftplib.FTP(host=self.target_ip, user=self.username, passwd=self.password)
        if self.verbose:
            self.client.getwelcome()

    def __del__(self):
        self.client.close()
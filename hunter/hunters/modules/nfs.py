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

import libnfs
import logging
import argparse
from hunters.core import BaseSensitiveFileHunter

logger = logging.getLogger('nfs')


class NfsSensitiveFileHunter(BaseSensitiveFileHunter):
    """
    This class implements the core functionality to hunt for files on NFS shares.
    """

    def __init__(self, args: argparse.Namespace, **kwargs):
        super().__init__(args, port=args.port, service_name="nfs", **kwargs)
        self.path = args.path
        self.version = args.version
        self.connection_string = "nfs://{}/{}?version={}&nfsport={}".format(self.service.host.address,
                                                                            self.path,
                                                                            self.version,
                                                                            self.service.port)

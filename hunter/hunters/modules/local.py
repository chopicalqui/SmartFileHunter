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
import glob
import logging
import argparse
from datetime import datetime
from datetime import timezone
from database.model import Path
from database.model import File
from database.model import HunterType
from hunters.modules.core import BaseSensitiveFileHunter

logger = logging.getLogger('nfs')


class LocalSensitiveFileHunter(BaseSensitiveFileHunter):
    """
    This class implements the core functionality to hunt for files on local file system
    """

    def __init__(self, args: argparse.Namespace, **kwargs):
        super().__init__(args, address="127.0.0.1", service_name=HunterType.local, **kwargs)
        self.path = [os.path.abspath(item) for item in args.path]

    def _enumerate(self) -> None:
        """
        This method enumerates all files on the given service.
        :return:
        """
        for path in self.path:
            path = path if path[-1] == "/" else path + "/"
            for item in glob.iglob(path + "**", recursive=True):
                stats = os.stat(item)
                if os.path.isfile(item):
                    path = Path(service=self.service,
                                full_path=item,
                                access_time=datetime.fromtimestamp(stats.st_atime, tz=timezone.utc),
                                modified_time=datetime.fromtimestamp(stats.st_mtime, tz=timezone.utc),
                                creation_time=datetime.fromtimestamp(stats.st_ctime, tz=timezone.utc))
                    if self.is_file_size_below_threshold(stats.st_size):
                        with open(item, "rb") as file:
                            content = file.read()
                        path.file = File(content=content)
                        logger.debug("enqueue file: {}".format(path.full_path))
                        self.file_queue.put(path)
                    else:
                        path.file = File(content="[file ({}) not imported as file size ({})"
                                                 "is above threshold]".format(str(path), stats.st_size).encode('utf-8'))
                        path.file.size_bytes = stats.st_size
                        self._analyze_path_name(path)

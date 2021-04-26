# -*- coding: utf-8 -*-
"""
this file implements the core functionality for analysing files
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
import tempfile
from datetime import datetime
from datetime import timezone
from pyunpack import Archive
from hunters.core import BaseAnalyzer
from database.model import Path
from database.model import File

logger = logging.getLogger('analyzer')


class FileAnalzer(BaseAnalyzer):
    """
    This class is responsible for analysing a given file.
    """
    ID = 0

    def __init__(self, **kwargs):
        super().__init__(daemon=True, **kwargs)
        FileAnalzer.ID += 1
        self._id = FileAnalzer.ID
        self._number_of_processed_files = 0
        self._number_of_failed_files = 0

    def run(self):
        while True:
            try:
                path = self.file_queue.get()
                self._number_of_processed_files += 1
                self.analyze(path)
            except Exception as ex:
                logger.exception(ex)
                self._number_of_failed_files += 1
            self.file_queue.task_done()

    def __repr__(self):
        return "thread {:>3d}: " \
               "files processed (success): {:>5d}\t" \
               "files processed (failed): {:>5d}".format(self._id,
                                                         self._number_of_processed_files,
                                                         self._number_of_failed_files)

    def analyze(self, path: Path) -> None:
        """
        This method analyses the given path object to determine its relevance for the penetration test.
        :param path: The path object to be analysed.
        :return:
        """
        with self.engine.session_scope() as session:
            workspace = self.engine.get_workspace(session=session, name=self.workspace)
            file = self.engine.get_file(session=session,
                                        workspace=workspace,
                                        sha256_value=path.file.sha256_value)
            exists = file is not None
            if exists:
                self.add_content(path=path, file=file)
        if not exists:
            success = False
            if self.config.is_archive(path):
                try:
                    self._extract_archive(path)
                    success = True
                except Exception as ex:
                    logger.exception(ex)
            if not success:
                result = False
                # 1. Try analyzing the content of every file (even binary files)
                try:
                    result = self._analyze_content(path)
                except Exception as ex:
                    logger.exception(ex)
                # If content search did not return any results or failed, then just analyze the file name
                if not result:
                    result = self._analyze_path_name(path)
                    if self._args.debug and not result:
                        logger.debug("ignoring file (threshold: below, size: {}): {}".format(path.file.size_bytes,
                                                                                             str(path)))

    def _extract_archive(self, path: Path):
        """
        This method extracts and analyses the given archive file.
        """
        with tempfile.NamedTemporaryFile() as file_name:
            with open(file_name.name, "wb") as file:
                file.write(path.file.content)
            with tempfile.TemporaryDirectory() as dir_name:
                Archive(file_name.name).extractall(dir_name)
                for item in glob.glob(dir_name + "/**", recursive=True):
                    stats = os.stat(item)
                    if os.path.isfile(item):
                        full_path = item.replace(dir_name, path.full_path, 1)
                        with open(item, "rb") as file:
                            content = file.read()
                        tmp = Path(service=path.service,
                                   full_path=full_path,
                                   access_time=datetime.fromtimestamp(stats.st_atime, tz=timezone.utc),
                                   modified_time=datetime.fromtimestamp(stats.st_mtime, tz=timezone.utc),
                                   creation_time=datetime.fromtimestamp(stats.st_ctime, tz=timezone.utc),
                                   file=File(content=content))
                        self.analyze(tmp)
                    elif os.path.isfile(item):
                        logger.debug("skip file: {}".format(item))
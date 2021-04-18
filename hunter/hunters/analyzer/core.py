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

import logging
import argparse
from queue import Queue
from threading import Lock
from threading import Thread
from database.core import Engine
from database.model import Path
from database.model import File
from database.model import MatchRule
from database.model import SearchLocation
from database.model import FileRelevance
from config.config import FileHunter as FileHunterConfig

logger = logging.getLogger('analyzer')

mutex = Lock()


class FileAnalzer(Thread):
    """
    This class is responsible for analysing a given file.
    """
    ID = 0

    def __init__(self,
                 args: argparse.Namespace,
                 engine: Engine,
                 file_queue: Queue,
                 config: FileHunterConfig,
                 **kwargs):
        super().__init__(daemon=True)
        self._args = args
        self.workspace = args.workspace
        self.engine = engine
        self.config = config
        self.file_queue = file_queue
        FileAnalzer.ID += 1
        self._id = FileAnalzer.ID
        self._number_of_processed_files = 0

    def run(self):
        while True:
            path = self.file_queue.get()
            logger.debug("thread {} dequeues path: {}".format(self._id, str(path)))
            self.analyze(path)
            self._number_of_processed_files += 1
            self.file_queue.task_done()

    def add_content(self, path: Path, rule: MatchRule = None, file: File = None):
        if rule and file:
            raise ValueError("parameters rule and file are mutual exclusive")
        elif not rule and not file:
            raise ValueError("either parameter rule or file must be given")
        with mutex:
            with self.engine.session_scope() as session:
                workspace = self.engine.get_workspace(session, name=self.workspace)
                host = self.engine.add_host(session=session,
                                            workspace=workspace,
                                            address=path.service.host.address)
                service = self.engine.add_service(session=session,
                                                  port=path.service.port,
                                                  name=path.service.name,
                                                  host=host)
                if rule:
                    match_file = self.engine.add_match_rule(session=session,
                                                            search_location=rule.search_location,
                                                            search_pattern=rule.search_pattern,
                                                            relevance=rule.relevance,
                                                            accuracy=rule.accuracy,
                                                            category=rule.category)
                    file = self.engine.add_file(session=session,
                                                workspace=workspace,
                                                file=path.file)
                    file.add_match_rule(match_file)
                self.engine.add_path(session=session,
                                     service=service,
                                     full_path=path.full_path,
                                     share=path.share,
                                     file=file,
                                     access_time=path.access_time,
                                     modified_time=path.modified_time,
                                     creation_time=path.creation_time)

    def _analyze_content(self, path: Path) -> FileRelevance:
        """
        This method analyzes the file's content for interesting information.
        :param path: The path object whose content shall be analyzed.
        :return: True if file is of relevance
        """
        result = None
        for rule in self.config.matching_rules[SearchLocation.file_content.name]:
            if rule.is_match(path):
                logger.info("Match: {} ({})".format(str(path), rule.get_text(not self._args.nocolor)))
                result = rule.relevance
                self.add_content(path=path, rule=rule)
                break
        return result

    def _analyze_path_name(self, path: Path) -> FileRelevance:
        """
        This method analyzes the file's name for interesting information.
        :param path: The path object whose name shall be analyzed.
        :return: True if file is of relevance
        """
        result = None
        for rule in self.config.matching_rules[SearchLocation.file_name.name]:
            if rule.is_match(path):
                logger.info("Match: {} ({})".format(str(path), rule.get_text(not self._args.nocolor)))
                result = rule.relevance
                self.add_content(rule=rule, path=path)
                break
        return result

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
            if "zip archive data" in path.file.file_type:
                pass
            else:
                result = False
                # 1. Try analyzing the content of every file (even binary files)
                try:
                    result = self._analyze_content(path)
                except Exception as ex:
                    logger.exception(ex)
                # If content search did not return any results or failed, then just analyze the file name
                if not result:
                    self._analyze_path_name(path)

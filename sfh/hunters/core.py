# -*- coding: utf-8 -*-
"""
this file implements the core functionality for collectors and analyzers
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
from database.config import FileHunter as FileHunterConfig
from urllib.parse import urljoin

logger = logging.getLogger('analyzer')


class BaseAnalyzer(Thread):
    """
    This class implements all base functionalities for collectors and analyzers
    """

    DB_OPERATION_MUTEX = Lock()

    def __init__(self,
                 engine: Engine,
                 args: argparse.Namespace,
                 config: FileHunterConfig,
                 file_queue: Queue,
                 daemon: bool = False):
        super().__init__(daemon=daemon)
        self.engine = engine
        self.file_queue = file_queue
        self._args = args
        self.workspace = args.workspace
        self.config = config

    def is_file_size_below_threshold(self, path: Path, size: int) -> bool:
        """
        This method determines if the given file size in bytes is below the configured threshold.
        """
        return self.config.is_below_threshold(path, size)

    def add_content(self, path: Path, rule: MatchRule = None, file: File = None):
        """
        This method adds the rule matching result to the database.
        """
        if rule and file:
            raise ValueError("parameters rule and file are mutual exclusive")
        elif not rule and not file:
            raise ValueError("either parameter rule or file must be given")
        with BaseAnalyzer.DB_OPERATION_MUTEX:
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
                if "git-repository" in path.extra_info:
                    git_repo_home = path.extra_info["git-repository"].lower().rstrip(".git")
                    relative_path = "/".join(path.full_path.split("/")[3:])
                    path.full_path = "{}/{}".format(git_repo_home, relative_path)
                    path.full_path += " ({}, {})".format(path.extra_info["git-branch"], path.extra_info["git-commit"])
                self.engine.add_path(session=session,
                                     service=service,
                                     full_path=path.full_path,
                                     share=path.share.name if path.share else None,
                                     file=file,
                                     extra_info=path.extra_info,
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
        # First we search the full path
        for rule in self.config.matching_rules[SearchLocation.full_path.name]:
            if rule.is_match(path):
                logger.info("Match: {} ({})".format(str(path), rule.get_text(not self._args.nocolor)))
                result = rule.relevance
                self.add_content(rule=rule, path=path)
                break
        else:
            # If nothing is found, then we search the file name
            for rule in self.config.matching_rules[SearchLocation.file_name.name]:
                if rule.is_match(path):
                    logger.info("Match: {} ({})".format(str(path), rule.get_text(not self._args.nocolor)))
                    result = rule.relevance
                    self.add_content(rule=rule, path=path)
                    break
        return result
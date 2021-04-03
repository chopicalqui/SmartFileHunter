# -*- coding: utf-8 -*-
"""
this file implements the core functionality to hunt for any sensitive files.
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

import argparse
from queue import Queue
from database.core import Engine
from database.model import Host
from database.model import Service
from database.model import Workspace
from config.config import FileHunter as FileHunterConfig


class BaseSensitiveFileHunter:
    """
    This class implements the core functionality to hunt for files.
    """

    def __init__(self,
                 args: argparse.Namespace,
                 file_queue: Queue, temp_dir,
                 config: FileHunterConfig,
                 address: str,
                 service_name: str,
                 engine: Engine,
                 port: int = None,
                 **kwargs):
        self.service = Service(port=port, name=service_name)
        self.service.host = Host(address=address)
        self.service.workspace = Workspace(name=args.workspace)
        self.verbose = args.verbose
        self.config = config
        self.port = port
        self.address = address
        self.temp_dir = temp_dir
        self.file_queue = file_queue
        self.file_size_threshold = self.config.config["general"].getint("max_file_size_kb")
        # we add the current host and service to the database so that the consumer threads can use them
        with engine.session_scope() as session:
            workspace = engine.get_workspace(session, name=args.workspace)
            host = engine.add_host(session=session,
                                   workspace=workspace,
                                   address=address)
            engine.add_service(session=session,
                               port=port,
                               name=service_name,
                               host=host)
            for match_rules in self.config.matching_rules.values():
                for match_rule in match_rules:
                    engine.add_match_rule(session=session,
                                          search_location=match_rule.search_location,
                                          search_pattern=match_rule.search_pattern,
                                          relevance=match_rule.relevance,
                                          category=match_rule.category)

    def is_file_size_below_threshold(self, size: int) -> bool:
        return size > 0 and (self.file_size_threshold <= 0 or size <= self.file_size_threshold)

    def enumerate(self):
        """
        This method enumerates all files on the given service.
        :return:
        """
        raise NotImplementedError("this method must be implemented by all subclasses.")
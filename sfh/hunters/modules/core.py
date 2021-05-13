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
import logging
from hunters.core import BaseAnalyzer
from database.model import Host
from database.model import Service
from database.model import Workspace
from database.model import HunterType
from database.model import FileRelevance

logger = logging.getLogger('smb')


class BaseSensitiveFileHunter(BaseAnalyzer):
    """
    This class implements the core functionality to hunt for files.
    """

    def __init__(self,
                 args: argparse.Namespace,
                 temp_dir: str,
                 address: str,
                 service_name: HunterType,
                 port: int = None,
                 **kwargs):
        super().__init__(args=args, daemon=False, **kwargs)
        self.client = None
        self.service = Service(port=port, name=service_name)
        self.service.host = Host(address=address)
        self.service.workspace = Workspace(name=args.workspace)
        self.verbose = args.verbose
        self.reanalyze = args.reanalyze
        self.port = port
        self.address = address
        self.temp_dir = temp_dir
        # we add the current host and service to the database so that the consumer threads can use them
        with self.engine.session_scope() as session:
            workspace = self.engine.get_workspace(session, name=args.workspace)
            host = self.engine.add_host(session=session,
                                        workspace=workspace,
                                        address=address)
            self.engine.add_service(session=session,
                                    port=port,
                                    name=service_name,
                                    host=host)
            for match_rules in self.config.matching_rules.values():
                for match_rule in match_rules:
                    self.engine.add_match_rule(session=session,
                                               search_location=match_rule.search_location,
                                               search_pattern=match_rule.search_pattern,
                                               relevance=match_rule.relevance,
                                               accuracy=match_rule.accuracy,
                                               category=match_rule.category)

    @staticmethod
    def add_argparse_arguments(parser: argparse.ArgumentParser) -> None:
        """
        This method initializes command line arguments that are required by the current module.
        :param parser: The argument parser to which the required command line arguments shall be added.
        :return:
        """
        relevance = [item.name for item in FileRelevance]
        parser.add_argument('-r', '--reanalyze', action="store_true", help='reanalyze already analyzed services')
        parser.add_argument('-w', '--workspace', type=str, required=True, help='the workspace used for the enumeration')
        parser.add_argument('-t', '--threads', type=int, default=10, help='number of analysis threads')

    def enumerate(self):
        """
        This method enumerates all files on the given service.
        :return:
        """
        # Determine if service was analyzed before
        with self.engine.session_scope() as session:
            service = session.query(Service) \
                .join(Host) \
                .join(Workspace) \
                .filter(Workspace.name == self.service.workspace.name,
                        Host.address == self.address,
                        Service.port == self.port).one()
            complete = service.complete
        if not complete or self.reanalyze:
            self._enumerate()
        else:
            logger.info("skipping service as it was already analyzed")

    def _enumerate(self):
        """
        This method enumerates all files on the given service.
        :return:
        """
        raise NotImplementedError("this method must be implemented by all subclasses")

# -*- coding: utf-8 -*-
"""
this file implements the core functionality to hunt for any sensitive files on Stash.
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
import git
import shutil
import tempfile
import getpass
import logging
import argparse
from database.model import HunterType
from hunters.modules.core import BaseSensitiveFileHunter
from hunters.modules.local import LocalSensitiveFileHunter
from urllib.parse import urlparse

logger = logging.getLogger('git')


class GitSensitiveFileHunterBase(BaseSensitiveFileHunter):
    """
    This class implements the core functionality to hunt for files in Git repositories
    """

    def __init__(self, address: str, args: argparse.Namespace, **kwargs):
        super().__init__(args=args, address=address, **kwargs)
        self._local_hunter = LocalSensitiveFileHunter(args=args, **kwargs)

    def parse_commit(self, repo: git.Git, dedup: dict, extra_info: dict = {}):
        """
        This method parses all branches and their commits for interesting files.
        :param repo: The Git repository that should be parsed.
        :param dedup: Commits that have already been parsed, do not have to be parsed again.
        :return:
        """
        for branch in repo.branch("-r").split(os.linesep):
            branch = branch.strip()
            if " -> " not in branch:
                extra_info["git-branch"] = branch
                repo.checkout(branch)
                for commit in repo.log("--pretty=format:%H").split(os.linesep):
                    commit = commit.strip()
                    if commit not in dedup:
                        dedup[commit] = None
                        repo.checkout(commit)
                        extra_info["git-commit"] = commit
                        self._local_hunter._enumerate([repo.working_dir], extra_info=extra_info)


class LocalGitSensitiveFileHunter(GitSensitiveFileHunterBase):
    """
    This class implements the core functionality to hunt for files in local Git repositories
    """

    def __init__(self, args: argparse.Namespace, **kwargs):
        super().__init__(args=args, address="localhost", service_name=HunterType.gitlocal, **kwargs)
        self._repositories = args.local
        if args.Local:
            with open(args.Local, "r") as file:
                self._repositories = file.readlines()
        for item in self._repositories:
            if not os.path.exists(item):
                raise NotADirectoryError("item '{}' is not a directory.".format(item))

    @staticmethod
    def add_argparse_arguments(parser: argparse.ArgumentParser) -> None:
        """
        This method initializes command line arguments that are required by the current module.
        :param parser: The argument parser to which the required command line arguments shall be added.
        :return:
        """
        BaseSensitiveFileHunter.add_argparse_arguments(parser)
        source_group = parser.add_argument_group('sources') \
            .add_mutually_exclusive_group()
        source_group.add_argument('--local', type=str, nargs="+",
                                  help='List of paths to local Git repositories.')
        source_group.add_argument('--Local', type=str,
                                  help='File containing list of paths (one per line) to local Git repositories.')

    def _enumerate(self) -> None:
        """
        This method enumerates all files on the given service.
        :return:
        """
        for repository in self._repositories:
            dedup = {}
            repository = repository.strip()
            with tempfile.TemporaryDirectory() as directory:
                repository = os.path.abspath(repository)
                target = os.path.join(directory, os.path.basename(repository))
                shutil.copytree(repository, target)
                repo = git.Git(target)
                self.parse_commit(repo, dedup=dedup, extra_info={"git-repository": repository})


class RemoteGitSensitiveFileHunter(GitSensitiveFileHunterBase):
    """
    This class implements the core functionality to hunt for files on local file system
    """

    def __init__(self, args: argparse.Namespace, **kwargs):
        self._repositories = args.remote
        if args.Remote:
            with open(args.Remote, "r") as file:
                self._repositories = file.readlines()
        hostname = list(set([urlparse(item).hostname for item in self._repositories]))
        if len(hostname) != 1:
            raise ValueError("all remote git repositories must be hosted on the same server.")
        super().__init__(args=args, address=hostname[0], service_name=HunterType.gitremote, **kwargs)
        self.username = args.username
        self.password = args.password
        if args.prompt_for_password:
            self.password = getpass.getpass(prompt="password: ")

    @staticmethod
    def add_argparse_arguments(parser: argparse.ArgumentParser) -> None:
        """
        This method initializes command line arguments that are required by the current module.
        :param parser: The argument parser to which the required command line arguments shall be added.
        :return:
        """
        BaseSensitiveFileHunter.add_argparse_arguments(parser)
        source_group = parser.add_argument_group('sources') \
            .add_mutually_exclusive_group()
        source_group.add_argument('--remote', type=str, nargs="+",
                                  help='List of URLs (e.g., https://github.com/chopicalqui/KaliIntelligenceSuite.git) '
                                       'to remote Git repositories.')
        source_group.add_argument('--Remote', type=str,
                                  help='File containing list of URLs (one per line) to remote Git repositories.')
        authentication_group = parser.add_argument_group('authentication')
        authentication_group.add_argument('-u', '--username', action="store", default='',
                                          metavar="USERNAME", help='the name of the user to use for authentication')
        parser_credential_group = authentication_group.add_mutually_exclusive_group()
        parser_credential_group.add_argument('-p', '--password', action="store", default='',
                                             metavar="PASSWORD", help='password of given user')
        parser_credential_group.add_argument('-P', dest="prompt_for_password", action="store_true",
                                             help='ask for the password via an user input prompt')

    def _enumerate(self) -> None:
        """
        This method enumerates all files on the given service.
        :return:
        """
        for repository in self._repositories:
            dedup = {}
            repository = repository.strip()
            with tempfile.TemporaryDirectory() as directory:
                if self.username and self.password:
                    tmp = urlparse(repository)
                    repository = "{scheme}://{user}:{password}@{netloc}{path}".format(scheme=tmp.scheme,
                                                                                          user=self.username,
                                                                                          password=self.password,
                                                                                          netloc=tmp.netloc,
                                                                                          path=tmp.path)
                git.Repo.clone_from(repository, directory)
                repo = git.Git(directory)
                self.parse_commit(repo, dedup=dedup, extra_info={"git-repository": repository})

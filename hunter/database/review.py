# -*- coding: utf-8 -*-
""""This file contains general functionality for the sensitive file hunter console."""

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
import sys
import enum
import argparse
from cmd import Cmd
from database.core import Engine
from database.model import File
from database.model import MatchRule
from database.model import SearchLocation
from database.model import Workspace
from database.model import ReviewResult
from sqlalchemy import desc


class ConsoleOptions(enum.Enum):
    workspace = enum.auto()


class ReviewConsole(Cmd):
    prompt = 'sfh> '

    def __init__(self, args: argparse.Namespace):
        super().__init__()
        self._args = args
        self._cursor_id = 0
        self._options = {item: None for item in ConsoleOptions}
        self._environment = None
        self._engine = Engine()
        self._file_ids = []
        if args.workspace:
            self._options[ConsoleOptions.workspace] = args.workspace
        self._update_file_list()
        self._update_prompt_text()
        if args.workspace:
            self.do_n(None)

    def _update_prompt_text(self):
        """
        This method returns the current command prompt.
        """
        result = "sfh"
        if self._options[ConsoleOptions.workspace]:
            result += " ({})".format(self._options[ConsoleOptions.workspace])
        if self._cursor_id:
            result += " [{}/{}]".format(self._cursor_id, len(self._file_ids))
        result += "> "
        self.prompt = result

    def _update_file_list(self):
        """
        Load the list of files ID to review into memory
        """
        with self._engine.session_scope() as session:
            self._file_ids = [item[0] for item in session.query(File.id)
                .join(Workspace)
                .join((MatchRule, File.matches))
                .filter(Workspace.name == self._options[ConsoleOptions.workspace], File.review_result.is_(None))
                #.filter(Workspace.name == self._options[ConsoleOptions.workspace], File.review_result == ReviewResult.relevant)
                .order_by(desc(MatchRule.relevance))]

    def _update_view(self):
        """
        This method displays the currently selected file
        """
        if 0 < self._cursor_id <= len(self._file_ids):
            id = self._file_ids[self._cursor_id - 1]
            with self._engine.session_scope() as session:
                file = session.query(File).filter_by(id=id).one_or_none()
                rules = session.query(MatchRule).filter_by(search_location=SearchLocation.file_content)
                if file:
                    result = file.get_text(color=not self._args.nocolor, match_rules=rules)
                    self._update_prompt_text()
            if sys.platform == "windows":
                os.system("cls")
            else:
                os.system("clear")
            print(os.linesep.join(result))

    def do_n(self, input: str):
        """
        Display the next file
        """
        if self._options[ConsoleOptions.workspace]:
            if (self._cursor_id + 1) <= len(self._file_ids):
                self._cursor_id += 1
                self._update_view()
            else:
                print("no more items available")
        else:
            print("select a workspace first")

    def help_n(self):
        print('obtain the next file for review from the database')

    def do_p(self, input: str):
        """
        Display the previous file
        """
        if (self._cursor_id - 1) > 0:
            self._cursor_id -= 1
            self._update_view()

    def help_p(self):
        print('obtain previous file for review from the database')

    def do_1(self, input: str):
        """
        Set file relevant
        """
        id = self._file_ids[self._cursor_id - 1]
        with self._engine.session_scope() as session:
            file = session.query(File).filter_by(id=id).one_or_none()
            file.review_result = ReviewResult.relevant
        self.do_n(input)

    def help_1(self):
        print('mark current file as relevant and move to next file')

    def do_2(self, input: str):
        """
        Set file relevant
        """
        id = self._file_ids[self._cursor_id - 1]
        with self._engine.session_scope() as session:
            file = session.query(File).filter_by(id=id).one_or_none()
            file.review_result = ReviewResult.irrelevant
        self.do_n(input)

    def help_2(self):
        print('mark current file as irrelevant and move to next file')

    def do_export(self, input: str):
        """
        Set file relevant
        """
        if input:
            id = self._file_ids[self._cursor_id - 1]
            with self._engine.session_scope() as session:
                file_object = session.query(File).filter_by(id=id).one_or_none()
                if file_object:
                    with open(input, "wb") as file:
                        file.write(file_object.content)
                else:
                    print("file not found")

    def help_export(self):
        print('export the current file to the given file (e.g., export /tmp/file.txt)')

    def do_comment(self, input: str):
        """
        Set file relevant
        """
        if input:
            id = self._file_ids[self._cursor_id - 1]
            with self._engine.session_scope() as session:
                file_object = session.query(File).filter_by(id=id).one_or_none()
                if file_object:
                    file_object.comment = input
                else:
                    print("file not found")

    def help_comment(self):
        print('add a review comment to the current file')

    def do_stats(self, input: str):
        """
        Print stats about the identified files
        """
        pass

    def do_set(self, input: str):
        """
        Set environment variables
        """
        arguments = input.split(" ")
        if len(arguments) != 2:
            print("invalid input; valid command is for example: set workspace test")
            return
        option, value = arguments
        if option not in [item.name for item in ConsoleOptions]:
            print("{} is an invalid option".format(option))
            return
        # input validation
        option = ConsoleOptions[option]
        if option == ConsoleOptions.workspace:
            with self._engine.session_scope() as session:
                if session.query(Workspace).filter_by(name=value).count() == 0:
                    print("workspace '{}' does not exist.".format(value))
                    return
        self._options[option] = value
        self._update_prompt_text()

    def help_set(self):
        print('set one of the following options: {}'.format(", ".join([item.name for item in self._options.keys()])))

    def help_back(self):
        print('leave the current environment')

    def do_exit(self, input: str):
        return True

    def help_exit(self):
        print('exit the application. Shorthand: x q Ctrl-D.')

    def default(self, input: str):
        if input == 'x' or input == 'q':
            return self.do_exit(input)

    do_EOF = do_exit
    help_EOF = help_exit
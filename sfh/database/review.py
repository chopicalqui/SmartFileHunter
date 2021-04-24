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
from config.config import FileHunter as FileHunterConfig
from database.core import Engine
from database.model import File
from database.model import MatchRule
from database.model import SearchLocation
from database.model import Workspace
from database.model import ReviewResult
from database.model import Path
from sqlalchemy import text
from sqlalchemy import asc
from sqlalchemy import desc


class ConsoleOption(enum.Enum):
    workspace = enum.auto()
    filter = enum.auto()

    @staticmethod
    def get_text(option):
        if option == ConsoleOption.workspace:
            result = """ review files in the given workspace"""
        elif option == ConsoleOption.filter:
            result = """ update where clause to limit review list. examples of valid filters are:
 - All files that have not been reviewed  and do not have the extension log: (File.review_result IS NULL OR File.review_result = 'tbd') AND Path.extension NOT IN ('.log')
 - All files that have not been reviewed:                                    File.review_result IS NULL OR File.review_result = 'tbd'
 - Only relevant files:                                                      File.review_result IS NOT NULL AND File.review_result = 'relevant'
 - Get all results:                                                          1=1"""
        else:
            raise NotImplementedError("case not implemented")
        return result


class ReviewConsole(Cmd):
    prompt = 'sfh> '

    def __init__(self, args: argparse.Namespace):
        super().__init__()
        self._args = args
        self._cursor_id = 0
        self._options = {item: None for item in ConsoleOption}
        self._environment = None
        self._engine = Engine()
        self._file_ids = []
        self._config = FileHunterConfig()
        if args.workspace:
            self._options[ConsoleOption.workspace] = args.workspace
        self._options[ConsoleOption.filter] = "File.review_result IS NULL OR File.review_result = 'tbd'"
        self._update_file_list()

    def _update_prompt_text(self):
        """
        This method returns the current command prompt.
        """
        result = "sfh"
        if self._options[ConsoleOption.workspace]:
            result += " ({})".format(self._options[ConsoleOption.workspace])
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
                .join((Path, File.paths))
                .filter(text("Workspace.name = '{}' and {}".format(self._options[ConsoleOption.workspace],
                                                                   self._options[ConsoleOption.filter])))
                .distinct()
                .order_by(asc(MatchRule.relevance), asc(MatchRule.accuracy), asc(Path.extension))]
        self._cursor_id = 0
        self._update_prompt_text()
        self.do_n(None)

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
                    result = file.get_text(color=not self._args.nocolor,
                                           match_rules=rules,
                                           threshold=self._config.threshold)
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
        if self._options[ConsoleOption.workspace]:
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
            try:
                id = self._file_ids[self._cursor_id - 1]
                with self._engine.session_scope() as session:
                    file_object = session.query(File).filter_by(id=id).one_or_none()
                    if file_object:
                        with open(input, "wb") as file:
                            file.write(file_object.content)
                    else:
                        print("file not found")
            except Exception as ex:
                pass

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

    def do_refresh(self, input: str):
        """
        Load current results into memory
        """
        self._update_file_list()

    def help_refresh(self):
        print('update view by loading current results from database into memory for review')

    def do_set(self, input: str):
        """
        Set environment variables
        """
        arguments = input.strip().split(" ")
        # Show all options
        if not input:
            print(" Name            Value")
            print(" ----            -----")
            for item in ConsoleOption:
                print(" {:<15} {}".format(item.name, self._options[item]))
            return
        # Make sure that option exists
        if arguments[0] in [item.name for item in ConsoleOption]:
            option = ConsoleOption[arguments[0]]
        else:
            print("option '{}' des not exist".format(input))
            return
        # Show value of given value
        if len(arguments) == 1:
            tmp = ConsoleOption[arguments[0]]
            print(" {}: {}".format(arguments[0], self._options[tmp]))
            print(" ")
            print(ConsoleOption.get_text(tmp))
            return
        previous_value = self._options[option]
        value = " ".join(arguments[1:])
        # input validation
        if option == ConsoleOption.workspace:
            with self._engine.session_scope() as session:
                if session.query(Workspace).filter_by(name=value).count() == 0:
                    print("workspace '{}' does not exist.".format(value))
                    return
        self._options[option] = value
        if option == ConsoleOption.filter:
            self._options[option] = value
            try:
                self._update_file_list()
            except Exception as ex:
                print(ex)
                self._options[option] = previous_value
                return
        elif option == ConsoleOption.workspace:
            self._update_file_list()

    def help_set(self):
        print("""Usage: set [option] [value]

set the given option to value.  If value is omitted, print the current value.
If both are omitted, print options that are currently set.""")

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
# -*- coding: utf-8 -*-
""""This file contains general functionality to setup SFH."""

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
import time
import enum
import argparse
import subprocess
import logging
from threading import Thread
from database.core import Engine
from database.model import Workspace
from config.config import DatabaseType
from config.config import DatabaseFactory
from config.config import FileHunter as FileHunterConfig
from sqlalchemy.orm import sessionmaker

Session = sessionmaker()

logger = logging.getLogger('setup')


class SetupTask(enum.Enum):
    create_link_file = enum.auto()
    setup_database = enum.auto()
    install_software_packages = enum.auto()


class SetupCommand:

    def __init__(self, description: str, command: list, return_code: int = None):
        self._description = description
        self._return_code = return_code
        self._command = command

    def _print_output(self, prefix: str, output: list) -> None:
        for line in iter(output.readline, b''):
            line = line.decode("utf-8").strip()
            print("{}   {}".format(prefix, line))

    def execute(self, debug: bool=False) -> bool:
        "Executes the given command"
        rvalue = True
        print("[*] {}".format(self._description))
        print("    $ {}".format(subprocess.list2cmdline(self._command)))
        if not debug:
            p = subprocess.Popen(self._command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            Thread(target=self._print_output, args=("[*]", p.stdout, ), daemon=True).start()
            Thread(target=self._print_output, args=("[e]", p.stderr, ), daemon=True).start()
            return_code = p.wait()
            rvalue = (self._return_code == return_code if self._return_code is not None else True)
            time.sleep(1)
        return rvalue


class ManageDatabase:
    """
    This class implements the initial setup for SFH
    """
    def __init__(self, args: argparse.Namespace):
        self._arguments = args
        self._hunter_config = FileHunterConfig()
        self._db_config = DatabaseFactory()

    def run(self):
        if self._arguments.module == "db":
            if self._arguments.backup:
                engine = Engine()
                engine.create_backup(self._arguments.backup)
            if self._arguments.restore:
                engine = Engine()
                engine.restore_backup(self._arguments.restore)
            if self._arguments.drop:
                engine = Engine()
                engine.recreate_database()
            if self._arguments.init:
                engine = Engine()
                engine.init()
            if self._arguments.add:
                engine = Engine()
                with engine.session_scope() as session:
                    workspace = Workspace(name=self._arguments.add)
                    session.add(workspace)
        elif self._arguments.module == "setup":
            self._setup()

    def _setup(self):
        debug = self._arguments.debug
        args_dict = vars(self._arguments)
        file = self._hunter_config.scripts[0]
        base_name = os.path.splitext(file)[0]
        real_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        python_script = os.path.join(real_path, file)
        setup_commands = []
        tasks = [SetupTask[item.replace("-", "_")] for item in self._arguments.tasks]
        # Update configuration file
        if DatabaseType.postgresql.name in args_dict and args_dict[DatabaseType.postgresql.name]:
            print("set postgresql")
            self._db_config.type = DatabaseType.postgresql.name
        elif DatabaseType.sqlite.name in args_dict and args_dict[DatabaseType.sqlite.name]:
            print("set sqlite")
            self._db_config.type = DatabaseType.sqlite.name
        # Create link file
        if SetupTask.create_link_file in tasks:
            link_file = os.path.join("/usr/bin", base_name)
            if os.path.isfile(link_file):
                os_command = ["rm", "-f", link_file]
                setup_commands.append(SetupCommand(description="deleting link file as it "
                                                               "already exists".format(python_script),
                                                   command=os_command))
            os_command = ["ln", "-sT", python_script, link_file]
            setup_commands.append(SetupCommand(description="creating link file for {}".format(python_script),
                                               command=os_command))
        # Setup databases
        if SetupTask.setup_database in tasks:
            # Setup PostgreSQL database
            if DatabaseType.postgresql.name in args_dict and args_dict[DatabaseType.postgresql.name]:
                setup_commands.append(SetupCommand(description="adding PostgresSql database to auto start",
                                                   command=["update-rc.d", "postgresql", "enable"],
                                                   return_code=0))
                setup_commands.append(SetupCommand(description="starting PostgreSql database",
                                                   command=["service", "postgresql", "start"],
                                                   return_code=0))
                setup_commands.append(SetupCommand(description="adding PostgreSql database user '{}'"
                                                   .format(self._db_config.username),
                                                   command=["sudo", "-u", "postgres", "createuser",
                                                            self._db_config.username]))
                setup_commands.append(SetupCommand(description="setting PostgreSql database user '{}' password"
                                                   .format(self._db_config.username),
                                                   command=["sudo", "-u", "postgres", "psql", "-c",
                                                            "alter user {} with encrypted password '{}'"
                                                   .format(self._db_config.database, self._db_config.password)]))
                for database in self._db_config.databases:
                    setup_commands.append(SetupCommand(description=
                                                       "creating PostgreSql database '{}'".format(database),
                                                       command=["sudo", "-u", "postgres", "createdb", database]))
                    setup_commands.append(SetupCommand(description="setting PostgreSql database user '{}' "
                                                                   "permissions on database '{}'"
                                                       .format(self._db_config.username, database),
                                                       command=["sudo", "-u", "postgres", "psql", "-c",
                                                                "grant all privileges on database {} to {}"
                                                       .format(database, self._db_config.username)],
                                                       return_code=0))
            # Setup SQLite database
            if DatabaseType.sqlite.name in args_dict and args_dict[DatabaseType.sqlite.name]:
                self._db_config.type = DatabaseType.sqlite.name
                if not self._hunter_config.is_docker() and not os.path.exists(self._hunter_config.get_home_dir()):
                    setup_commands.append(SetupCommand(description="create ~/.sfh directory for SQLite database",
                                                       command=["mkdir", self._hunter_config.get_home_dir()],
                                                       return_code=0))
        # Install OS packages
        if SetupTask.install_software_packages in tasks:
            if self._hunter_config.kali_packages:
                apt_command = ["apt-get", "install", "-q", "--yes"]
                apt_command.extend(self._hunter_config.kali_packages)
                setup_commands.append(SetupCommand(description="installing additional Kali packages",
                                                   command=apt_command,
                                                   return_code=0))
        ok = True
        for command in setup_commands:
            if ok:
                ok = command.execute(debug)
        # Save configuration file, if not in debug mode
        if not debug:
            self._db_config.write()

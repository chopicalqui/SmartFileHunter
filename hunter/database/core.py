# -*- coding: utf-8 -*-
""""This file contains general functionality for database communication."""

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

import sys
import time
import passgen
import argparse
import sqlalchemy
from threading import Thread
from sqlalchemy import create_engine
from config import config
from config.config import FileHunter as FileHunterConfig
from config.config import Database as DatabaseConfig
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import sessionmaker
from contextlib import contextmanager

DeclarativeBase = declarative_base()
Session = sessionmaker()

from database.model import *

logger = logging.getLogger('database')


class Engine:
    """This class implements general methods to interact with the underlying database."""

    def __init__(self, production: bool = True):
        self.production = production
        self._config = config.Database(production)
        self.engine = create_engine(self._config.connection_string)
        self._session_factory = sessionmaker(bind=self.engine)
        self._Session = scoped_session(self._session_factory)

    @contextmanager
    def session_scope(self):
        """Provide a transactional scope around a series of operations."""
        session = self.get_session()
        try:
            yield session
            session.commit()
        except Exception as ex:
            logger.exception(ex)
            session.rollback()
            raise
        finally:
            session.close()

    def init(self):
        """This method initializes the database."""
        self._create_tables()

    def drop(self):
        """This method drops all views and tables in the database."""
        self._drop_tables()

    def _create_tables(self) -> None:
        """This method creates all tables."""
        DeclarativeBase.metadata.create_all(self.engine, checkfirst=True)

    def _drop_tables(self) -> None:
        """This method drops all tables in the database."""
        DeclarativeBase.metadata.drop_all(self.engine, checkfirst=True)

    def get_workspace(self, session, name: str) -> Workspace:
        try:
            workspace = session.query(Workspace).filter(Workspace.name == name).one()
        except sqlalchemy.orm.exc.NoResultFound:
            print("Only the following workspaces exist:", file=sys.stderr)
            self.list_workspaces()
            workspace = None
        return workspace

    def print_workspaces(self):
        with self.session_scope() as session:
            workspaces = session.query(Workspace).all()
            if workspaces:
                print("the following workspaces exist:")
                for workspace in workspaces:
                    print("- {}".format(workspace.name))
            else:
                print("database does not contain any workspaces")

    def get_session(self):
        return self._Session()

    def list_workspaces(self):
        with self.session_scope() as session:
            for workspace in session.query(Workspace).all():
                print(workspace.name)

    def create_backup(self, file: str) -> None:
        """
        This method creates a backup of the KIS database into the given file
        :param file:
        :return:
        """
        if os.path.exists(file):
            raise FileExistsError("the file '{}' exists.".format(file))
        with open(file, "wb") as file:
            rvalue = subprocess.Popen(['sudo', '-u', 'postgres', 'pg_dump', self._config.database],
                                      stdout=file, stderr=subprocess.DEVNULL).wait()
        if rvalue != 0:
            raise subprocess.CalledProcessError("creating backup failed with return code {}".format(rvalue))

    def restore_backup(self, file: str) -> None:
        """
        This method restores a backup of the KIS database from the given file
        :param file:
        :return:
        """
        if not os.path.exists(file):
            raise FileExistsError("the file '{}' does not exist.".format(file))
        self.drop()
        with open(file, "rb") as file:
            rvalue = subprocess.Popen(['sudo', '-u', 'postgres', 'psql', self._config.database],
                                      stdin=file, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).wait()

    def recreate_database(self):
        """
        This method drops the databases
        """
        """This method drops all views and tables in the database."""
        for database in [self._config.production_database, self._config.test_database]:
            # drop database
            result = subprocess.Popen(['sudo', '-u', 'postgres', 'dropdb', database],
                                      stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL).wait()
            if result != 0:
                raise subprocess.CalledProcessError("dropping database '{}' failed with return code {}".format(database,
                                                                                                               result))
            # create database
            result = subprocess.Popen(['sudo', '-u', 'postgres', 'createdb', database],
                                      stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL).wait()
            if result != 0:
                raise subprocess.CalledProcessError("creating database '{}' failed with return code {}".format(database,
                                                                                                               result))
            # assign privileges to database
            result = subprocess.Popen(['sudo', '-u', 'postgres', 'psql',
                                       '-c', 'grant all privileges on database {} to {}'.format(database,
                                                                                                self._config.username)],
                                      stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL).wait()
            if result != 0:
                raise subprocess.CalledProcessError("assigning privileges on database '{}' for '{}' "
                                                    "failed with return code {}".format(database,
                                                                                        self._config.username,
                                                                                        result))

    @staticmethod
    def get_or_create(session, model, one_or_none=True, **kwargs):
        """
        This method queries the given model based on the filter kwargs or creates a new instance

        The method queries, the given model (e.g. Host) for existing entries based on the filter stored in kwargs. If
        argument one_or_none is set to true, then the query must return one argument, else an exception is thrown. If
        the argument is false, then the first value returned by the filter is returned. If no object is identified, then
        a new entry is created and added to the session.

        :param session: The database session used to query the database and eventually add a new object.
        :param model: The class that is queried (e.g., Task or Project).
        :param one_or_none: Specifies whether an exception shall be thrown if the query returns more than one result.
        :param kwargs: The filter to query for entries in the model.
        :return: An instance of type model.
        """
        if one_or_none:
            instance = session.query(model).filter_by(**kwargs).one_or_none()
        else:
            instance = session.query(model).filter_by(**kwargs).first()
        if not instance:
            instance = model(**kwargs)
            session.add(instance)
            session.flush()
        return instance


class ManageDatabase:
    """
    This class implements the initial setup for KIS
    """
    def __init__(self, args: argparse.Namespace):
        self._arguments = args
        self._hunter_config = FileHunterConfig()
        self._db_config = DatabaseConfig()
        self._databases = [self._db_config.config.get("production", "database"),
                           self._db_config.config.get("unittesting", "database")]
        self._db_config.password = passgen.passgen(30)

    def run(self):
        if self._arguments.add:
            engine = Engine()
            DeclarativeBase.metadata.bind = engine.engine
            with engine.session_scope() as session:
                workspace = Workspace(name=self._arguments.add)
                session.add(workspace)
        elif self._arguments.backup:
            engine = Engine()
            DeclarativeBase.metadata.bind = engine.engine
            engine.create_backup(self._arguments.backup)
        elif self._arguments.restore:
            engine = Engine()
            DeclarativeBase.metadata.bind = engine.engine
            engine.restore_backup(self._arguments.restore)
        elif self._arguments.setup or self._arguments.setup_dbg:
            self._setup(self._arguments.setup_dbg)
        else:
            if self._arguments.drop:
                engine = Engine()
                DeclarativeBase.metadata.bind = engine.engine
                engine.recreate_database()
            if self._arguments.init:
                engine = Engine()
                DeclarativeBase.metadata.bind = engine.engine
                engine.init()

    def _setup(self, debug: bool):
        setup_commands = []
        if not debug:
            self._db_config.write()
        for file in self._hunter_config.scripts:
            base_name = os.path.splitext(file)[0]
            real_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
            python_script = os.path.join(real_path, file)
            os_command = ["ln", "-sT", python_script, os.path.join("/usr/bin", base_name)]
            setup_commands.append(SetupCommand(description="creating link file for {}".format(python_script),
                                               command=os_command))
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
        for database in self._databases:
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
        setup_commands.append(SetupCommand(description="creating the tables, triggers, views, etc. in database {}"
                                           .format(self._db_config.database),
                                           command=["filehunter", "db", "--drop", "--init"]))
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


class SetupCommand:

    def __init__(self, description: str, command: List[str], return_code: int=None):
        self._description = description
        self._return_code = return_code
        self._command = command

    def _print_output(self, prefix: str, output: List[str]) -> None:
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
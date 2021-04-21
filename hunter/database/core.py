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

import grp
import pwd
import time
import passgen
import argparse
import tempfile
import ipaddress
import subprocess
from threading import Thread
from sqlalchemy import create_engine
from config.config import DatabaseFactory
from config.config import FileHunter as FileHunterConfig
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
        self._config = DatabaseFactory(production)
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
        DeclarativeBase.metadata.create_all(self.engine)

    def _drop_tables(self) -> None:
        """This method drops all tables in the database."""
        DeclarativeBase.metadata.drop_all(self.engine)

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
        if self._config.is_postgres:
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
        if self._config.is_postgres:
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
        if self._config.is_postgres:
            with tempfile.TemporaryDirectory() as temp:
                uid = pwd.getpwnam("postgres").pw_uid
                gid = grp.getgrnam("postgres").gr_gid
                os.chown(temp, uid, gid)
                for database in [self._config.production_database, self._config.test_database]:
                    # drop database
                    subprocess.check_output("sudo -u postgres dropdb {}".format(database), shell=True, cwd=temp)
                    # create database
                    subprocess.check_output("sudo -u postgres createdb {}".format(database), shell=True, cwd=temp)
                    # assign privileges to database
                    subprocess.check_output("sudo -u postgres psql -c 'grant all privileges "
                                            "on database {} to {}'".format(database,
                                                                           self._config.username),
                                            shell=True, cwd=temp)
        else:
            self._drop_tables()

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

    def get_workspace(self, session, name: str, ignore: bool = False) -> Workspace:
        workspace = session.query(Workspace).filter(Workspace.name == name).one_or_none()
        if not workspace:
            if not ignore:
                raise WorkspaceNotFound("workspace '{}' not found.".format(name))
            else:
                workspace = Workspace(name=name)
                session.add(workspace)
                session.flush()
        return workspace

    @staticmethod
    def add_workspace(session, name) -> Workspace:
        """
        This method shall be used to add a new workspace to the database
        :param session: Database session used to add the email address
        :param name: The workspace's name
        :return: Database object
        """
        result = session.query(Workspace).filter_by(name=name).one_or_none()
        if not result:
            result = Workspace(name=name)
            session.add(result)
            session.flush()
        return result

    @staticmethod
    def get_host(session: Session,
                 workspace: Workspace,
                 address: str) -> Host:
        """
        This method shall be used to obtain a host object via the given IPv4/IPv6 address from the database
        :param session: Database session used to add the email address
        :param workspace: The workspace to which the network shall be added
        :param address: IPv4/IPv6 address whose host object should be returned from the database
        :return: Database object
        """
        return session.query(Host).filter_by(address=address, workspace_id=workspace.id).one_or_none()

    @staticmethod
    def add_host(session: Session, workspace: Workspace, address: str):
        """
        This method shall be used to add an IPv4 address to the database
        :param session: Database session used to add the email address
        :param workspace: The workspace to which the network shall be added
        :param address: IPv4/IPv6 address that should be added to the database
        :return: Database object
        """
        ip_address = str(ipaddress.ip_address(address))
        result = Engine.get_host(session=session, workspace=workspace, address=ip_address)
        if not result:
            result = Host(address=ip_address, workspace=workspace)
            session.add(result)
            session.flush()
        return result

    @staticmethod
    def get_service(session: Session, port: int, host: Host = None) -> Service:
        """
         This method should be used to obtain a service object from the database
         :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
         :param host: The host object to which the service belongs
         :param port: The port number that shall be added
         :param protocol_type: The protocol type that shall be added
         :return: Database object
         """
        return session.query(Service) \
            .filter(Service.port == port, Service.host_id == host.id).one_or_none()

    @staticmethod
    def add_service(session: Session,
                    port: int,
                    host: Host,
                    name: HunterType = None,
                    complete: bool = False) -> Service:
        """
         This method should be used to add a service to the database
         :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
         :param host: The host object to which the service belongs
         :param port: The port number that shall be added
         :param protocol_type: The protocol type that shall be added
         :param name: Specifies the service's name
         :param complete: Specifies if the enumeration is completed (True) or not (False)
         :return: Database object
         """
        result = Engine.get_service(session=session, port=port, host=host)
        if not result:
            result = Service(port=port, name=name, host=host, complete=complete)
            session.add(result)
            session.flush()
        return result

    @staticmethod
    def get_path(session: Session,
                 service: Service,
                 full_path: str) -> Path:
        """
        This method should be used to obtain a path object from the database
        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param service: The service object to which the path belongs
        :param full_path: The path that shall be returned
        :return: Database object
        """
        return session.query(Path).filter_by(_full_path=full_path, service_id=service.id).one_or_none()

    @staticmethod
    def add_path(session: Session,
                 service: Service,
                 full_path: str,
                 file: File,
                 share: str = None,
                 access_time: DateTime = None,
                 modified_time: DateTime = None,
                 creation_time: DateTime = None) -> Path:
        """
        This method should be used to add a path to the database
        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param service: The service object to which the path belongs
        :param full_path: The path that shall be added
        :param file: The file object to which the path points to
        :param access_time: The file's last access time
        :param modified_time: The file's last modified time
        :param creation_time: The file's creation time
        :return: Database object
        """
        result = Engine.get_path(session=session, service=service, full_path=full_path)
        if not result:
            result = Path(service=service,
                          full_path=full_path,
                          file=file,
                          share=share,
                          access_time=access_time,
                          modified_time=modified_time,
                          creation_time=creation_time)
            session.add(result)
            session.flush()
        return result

    @staticmethod
    def get_file(session: Session,
                 workspace: Workspace,
                 sha256_value: str) -> File:
        """
        This method should be used to obtain a file object from the database
        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param sha256_value: The sha256 value of the file
        :return: Database object
        """
        return session.query(File).filter_by(sha256_value=sha256_value, workspace_id=workspace.id).one_or_none()

    @staticmethod
    def add_file(session: Session,
                 workspace: Workspace,
                 file: File,
                 import_action: ImportAction = ImportAction.full_import) -> File:
        """
        This method should be used to add a file to the database
        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param workspace: The workspace to which the network shall be added
        :param file: The file object that shall be added
        :param add_content: True if the file's content shall be added to the database
        :return: Database object
        """
        result = Engine.get_file(session=session, workspace=workspace, sha256_value=file.sha256_value)
        if not result:
            result = File(workspace_id=workspace.id,
                          _content=file.content,
                          sha256_value=file.sha256_value,
                          file_type=file.file_type,
                          size_bytes=file.size_bytes,
                          mime_type=file.mime_type)
            session.add(result)
            session.flush()
        else:
            updated = False
            if import_action.full_import:
                if not result.content and file.content:
                    updated = True
                    result.content = file.content
            else:
                updated = True
                result.file_type = file.file_type
                result.mime_type = file.mime_type
                result.size_bytes = file.size_bytes
            if result.review_result != file.review_result and file.review_result:
                updated = True
                result.review_result = file.review_result
            if updated:
                session.flush()
        return result

    @staticmethod
    def get_match_rule(session: Session,
                       search_location: SearchLocation,
                       search_pattern: str) -> MatchRule:
        """
        This method should be used to obtain a match rule object from the database
        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param search_location: The match rule's search location
        :param search_pattern: The match rule's search pattern
        :return: Database object
        """
        return session.query(MatchRule).filter_by(search_location=search_location,
                                                  _search_pattern=search_pattern).one_or_none()

    @staticmethod
    def add_match_rule(session: Session,
                       search_location: SearchLocation,
                       search_pattern: str,
                       relevance: FileRelevance,
                       accuracy: MatchRuleAccuracy,
                       category: str = None) -> MatchRule:
        """
        This method should be used to add a match rule to the database
        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param search_location: The match rule's search location
        :param search_pattern: The match rule's search pattern
        :param relevance: The potential relevance of the file based on the given match rule
        :param accuracy: The accuracy of the given match rule
        :return: Database object
        """
        result = Engine.get_match_rule(session=session,
                                       search_location=search_location,
                                       search_pattern=search_pattern)
        if not result:
            result = MatchRule(search_location=search_location,
                               search_pattern=search_pattern,
                               relevance=relevance,
                               accuracy=accuracy)
            session.add(result)
            session.flush()
        if category:
            result.category = category
        return result


class ManageDatabase:
    """
    This class implements the initial setup for KIS
    """
    def __init__(self, args: argparse.Namespace):
        self._arguments = args
        self._hunter_config = FileHunterConfig()
        self._db_config = DatabaseFactory()
        self._db_config.password = passgen.passgen(30)

    def run(self):
        if self._arguments.setup_dbg:
            self._db_config.type = self._arguments.setup_dbg
            self._setup(debug=True)
        elif self._arguments.setup:
            self._db_config.type = self._arguments.setup
            self._setup(debug=False)
        if self._arguments.backup:
            engine = Engine()
            DeclarativeBase.metadata.bind = engine.engine
            engine.create_backup(self._arguments.backup)
        if self._arguments.restore:
            engine = Engine()
            DeclarativeBase.metadata.bind = engine.engine
            engine.restore_backup(self._arguments.restore)
        if self._arguments.drop:
            engine = Engine()
            DeclarativeBase.metadata.bind = engine.engine
            engine.recreate_database()
        if self._arguments.init:
            engine = Engine()
            DeclarativeBase.metadata.bind = engine.engine
            engine.init()
        if self._arguments.add:
            engine = Engine()
            DeclarativeBase.metadata.bind = engine.engine
            with engine.session_scope() as session:
                workspace = Workspace(name=self._arguments.add)
                session.add(workspace)

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
        if self._db_config.is_postgres:
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
        setup_commands.append(SetupCommand(description="creating the tables, triggers, views, etc.",
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

    def __init__(self, description: str, command: List[str], return_code: int = None):
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
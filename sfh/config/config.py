# -*- coding: utf-8 -*-
""""This file contains common functionality to access configuration files."""

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
import re
import enum
import json
import logging
import passgen
import argparse
import configparser
from database.model import MatchRule
from database.model import FileRelevance
from database.model import SearchLocation
from database.model import MatchRuleAccuracy

logger = logging.getLogger("config")


class DatabaseType(enum.Enum):
    sqlite = enum.auto()
    postgresql = enum.auto()


class BaseConfig:
    """
    This class implements common functionality to access configuration files.
    """

    def __init__(self, config_file: str):
        self._config_file = config_file
        self._config_dir = os.path.dirname(__file__)
        self.full_path = os.path.join(self._config_dir, config_file)
        if not os.path.exists(self.full_path):
            raise FileNotFoundError("the database configuration file  \"{}\" does not exist!".format(self.full_path))
        self.config = configparser.ConfigParser()
        self.config.read(self.full_path)

    def write(self) -> None:
        with open(self.full_path, "w") as file:
            self.config.write(file)

    def get_config_str(self, section: str, name: str) -> str:
        return self.config[section][name]

    def get_config_int(self, section: str, name: str) -> int:
        return self.config[section].getint(name)

    @staticmethod
    def get_home_dir():
        return os.path.join(os.path.expanduser("~"), ".sfh")

    @staticmethod
    def is_docker():
        return os.path.exists("/.dockerenv")


class FileHunter(BaseConfig):
    """This class contains the ConfigParser object for the database"""

    def __init__(self, args: argparse.Namespace):
        super().__init__("hunter.config")
        self.matching_rules = {item.name: [] for item in SearchLocation}
        self.supported_archives = []
        self.threshold = self.get_config_int("general", "max_file_size_bytes")
        self.archive_threshold = self.get_config_int("general", "max_archive_size_bytes")
        self.kali_packages = json.loads(self.get_config_str("setup", "kali_packages"))
        self.scripts = json.loads(self.get_config_str("setup", "scripts"))
        for match_rule in json.loads(self.get_config_str("general", "match_rules")):
            try:
                rule = MatchRule.from_json(match_rule)
                if rule.search_location.name not in self.matching_rules:
                    self.matching_rules[rule.search_location.name] = []
                self.matching_rules[rule.search_location.name].append(rule)
            except re.error:
                logging.error("failed to compile regex: {}".format(match_rule["search_pattern"]))
        # Add Microsoft Active Directory domain names to search list
        if "netbios" in args and args.netbios:
            for name in args.netbios:
                match_rule = MatchRule(search_location=SearchLocation.file_content,
                                       relevance=FileRelevance.medium,
                                       accuracy=MatchRuleAccuracy.medium,
                                       search_pattern="{}[\\\\/]\\w+".format(name))
                self.matching_rules[SearchLocation.file_content.name].append(match_rule)
        # Add Microsoft Active Directory UPNs to search list
        if "upn" in args and args.upn:
            for name in args.upn:
                match_rule = MatchRule(search_location=SearchLocation.file_content,
                                       relevance=FileRelevance.medium,
                                       accuracy=MatchRuleAccuracy.medium,
                                       search_pattern="\\w+@{}".format(name))
                self.matching_rules[SearchLocation.file_content.name].append(match_rule)
        # Sort matching rules according to their priority
        for key, value in self.matching_rules.items():
            self.matching_rules[key] = sorted(value, key=lambda rule: rule.priority, reverse=True)
        for item in json.loads(self.get_config_str("general", "supported_archives")):
            if item not in self.supported_archives:
                self.supported_archives.append(item.lower())

    def is_archive(self, path) -> bool:
        """
        Returns true if the given path file has an extension in the self.supported_archives list.
        """
        return path and path.extension and path.extension.lower() in self.supported_archives

    def is_below_threshold(self, path, file_size: int) -> bool:
        """
        This method determines if the given file size in bytes is below the configured threshold.
        """
        is_archive = self.is_archive(path)
        return file_size > 0 and ((is_archive and (self.archive_threshold <= 0 or
                                                   file_size <= self.archive_threshold)) or
                                  (not is_archive and (self.threshold <= 0 or file_size <= self.threshold)))

class BaseDatabase(BaseConfig):
    """
    This class contains base functionality for all databases.
    """

    def __init__(self,
                 production_section: str,
                 unittest_section: str,
                 production: bool = True):
        super().__init__("database.config")
        self._production = production
        self._production_section = production_section
        self._unittest_section = unittest_section

    @property
    def type(self) -> DatabaseType:
        result = self.get_config_str("database", "active")
        return DatabaseType[result]

    @type.setter
    def type(self, value: str):
        self.config["database"]["active"] = value

    @property
    def production_section(self) -> str:
        return self._production_section

    @property
    def dialect(self) -> str:
        return self.get_config_str(self._production_section, "dialect")


class DatabasePostgreSql(BaseDatabase):
    """This class contains the ConfigParser object for the database"""

    def __init__(self, production: bool = True):
        super().__init__(production=production,
                         production_section="postgresql_production",
                         unittest_section="postgresql_unittesting")
        if not self.password:
            self.password = passgen.passgen(30)

    @property
    def host(self) -> str:
        return self.get_config_str(self._production_section, "host")

    @property
    def port(self) -> int:
        return self.get_config_int(self._production_section, "port")

    @property
    def username(self) -> str:
        return self.get_config_str(self._production_section, "username")

    @property
    def password(self) -> str:
        result= self.get_config_str(self._production_section, "password")
        return result

    @password.setter
    def password(self, value: str) -> None:
        self.config[self._production_section]["password"] = value

    @property
    def production_database(self) -> str:
        return self.get_config_str(self._production_section, "database")

    @property
    def test_database(self) -> str:
        return self.get_config_str(self._unittest_section, "database")

    @property
    def database(self) -> str:
        return self.production_database if self._production else self.test_database

    @property
    def connection_string(self):
        return "{}://{}:{}@{}:{}/{}".format(self.dialect,
                                            self.username,
                                            self.password,
                                            self.host,
                                            self.port,
                                            self.database)


class DatabaseSqlite(BaseDatabase):
    """This class contains the ConfigParser object for the database"""

    def __init__(self, production: bool = True):
        super().__init__(production=production,
                         production_section="sqlite_production",
                         unittest_section="sqlite_unittesting")

    def get_path(self, section_name: str):
        """
        This method returns the location of the SQLite database. Thereby, the following three cases exists.
        1. If the database name, which is specified in the configuration file starts with a /, then this method
           assumes that the configuration file contains an absolute path to the SQLlite database. In this case, this
           path is used.
        2. If SFH is executed in the docker container (environment variable SFH_DOCKER is present), then the SQLlite
           database is stored in SFH's configuration directory.
        3. If SFH is natively executed, then the SQLite database is stored in the user's home directory.
        """
        database_name = self.get_config_str(section_name, "name")
        if database_name and database_name[0] == "/":
            # If the database name contains an absolulte path, then we take this path
            result = database_name
        elif self.is_docker():
            # If SFH is running inside a docker container, then we use SFH's configuration directory
            result = os.path.join(self._config_dir, database_name)
        else:
            # In any other case we use ~/.sfh
            result = os.path.join(self.get_home_dir(), database_name)
        return result

    @property
    def production_name(self) -> str:
        return self.get_path(self._production_section)

    @property
    def test_name(self) -> str:
        return self.get_path(self._unittest_section)

    @property
    def path(self) -> str:
        return self.production_name if self._production else self.test_name

    @property
    def connection_string(self):
        return "{}+pysqlite:///{}".format(self.dialect, self.path)


class DatabaseFactory(BaseConfig):
    """
    This class manages the database configuration
    """

    def __init__(self, production: bool = True):
        super().__init__("database.config")
        self._database = None
        self.production = production
        self.type = self.get_config_str("database", "active")

    @property
    def type(self) -> str:
        return self._database.type

    @type.setter
    def type(self, value: str):
        result = DatabaseType[value]
        if result == DatabaseType.postgresql:
            self._database = DatabasePostgreSql(self.production)
        elif result == DatabaseType.sqlite:
            self._database = DatabaseSqlite(self.production)
        else:
            raise NotImplementedError("database type not implemented")
        self._database.type = value

    @property
    def is_postgres(self) -> bool:
        return self.type == DatabaseType.postgresql

    @property
    def production_database(self):
        result = None
        if self.is_postgres:
            result = self._database.production_database
        return result

    @property
    def test_database(self):
        result = None
        if self.is_postgres:
            result = self._database.test_database
        return result

    @property
    def username(self):
        result = None
        if self.is_postgres:
            result = self._database.username
        return result

    @property
    def password(self) -> str:
        result = None
        if self.is_postgres:
            result = self._database.password
        return result

    @password.setter
    def password(self, value: str) -> None:
        if self.is_postgres:
            self._database.password = value

            #self.config[self._database.production_section]["password"] = value

    @property
    def database(self) -> str:
        result = None
        if self.is_postgres:
            result = self.production_database if self.production else self.test_database
        return result

    @property
    def databases(self) -> list:
        return [self.production_database, self.test_database] if self.is_postgres else []

    @property
    def connection_string(self):
        return self._database.connection_string

    def write(self):
        self._database.write()


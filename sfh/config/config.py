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
import configparser
from database.model import MatchRule

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


class FileHunter(BaseConfig):
    """This class contains the ConfigParser object for the database"""

    def __init__(self):
        super().__init__("hunters.config")
        self.matching_rules = {}
        self.supported_archives = []
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
        # sort matching rules according to their priority
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
    def dialect(self) -> str:
        return self.get_config_str(self._production_section, "dialect")


class DatabasePostgreSql(BaseDatabase):
    """This class contains the ConfigParser object for the database"""

    def __init__(self, production: bool = True):
        super().__init__(production=production,
                         production_section="postgresql_production",
                         unittest_section="postgresql_unittesting")

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
        return self.get_config_str(self._production_section, "password")

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

    @property
    def production_name(self) -> str:
        return os.path.abspath(os.path.join(self._config_dir, "..", self.get_config_str(self._production_section, "name")))

    @property
    def test_name(self) -> str:
        return os.path.abspath(os.path.join(self._config_dir, "..", self.get_config_str(self._unittest_section, "name")))

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
        return DatabaseType[self._type]

    @type.setter
    def type(self, value: str):
        self._type = DatabaseType[value]
        if self._type == DatabaseType.postgresql:
            self._database = DatabasePostgreSql(self.production)
        elif self._type == DatabaseType.sqlite:
            self._database = DatabaseSqlite(self.production)
        else:
            raise NotImplementedError("database type not implemented")
        self.config["database"]["active"] = value

    @property
    def is_postgres(self) -> bool:
        return self._type == DatabaseType.postgresql

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

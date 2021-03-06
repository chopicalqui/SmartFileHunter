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
import json
import configparser
import pwd
from argparse import RawDescriptionHelpFormatter
from operator import attrgetter
from typing import List


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


class FileHunter(BaseConfig):
    """This class contains the ConfigParser object for the database"""

    def __init__(self):
        super().__init__("hunters.config")
#!/usr/bin/env python3
"""
this file implements unittests for the data model
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

import unittest
from test.core import ArgumentHelper
from database.model import Path
from config.config import FileHunter as FileHunterConfig


class TestFileHunterConfig(unittest.TestCase):
    """
    This method tests the correct load of file hunter configurations
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)
        self._config = FileHunterConfig(args=ArgumentHelper())

    def test_match_rules_correctly_sorted(self):
        for rules in self._config.matching_rules.values():
            priority = None
            for rule in rules:
                if priority:
                    self.assertLessEqual(rule.priority, priority)
                priority = rule.priority


class TestFileSizeThreshold(unittest.TestCase):
    """
    this method determines whether the file size thresholds are correctly determined.
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)
        self._config = FileHunterConfig(args=ArgumentHelper())

    def test_zip_file_below_threshold(self):
        result = self._config.is_below_threshold(path=Path(full_path="/tmp/test.zip"),
                                                 file_size=self._config.archive_threshold - 1)
        self.assertTrue(result)

    def test_zip_file_above_threshold(self):
        result = self._config.is_below_threshold(path=Path(full_path="/tmp/test.zip"),
                                                 file_size=self._config.archive_threshold + 1)
        self.assertFalse(result)

    def test_zip_file_above_threshold_but_threshold_deactivated(self):
        self._config.archive_threshold = 0
        result = self._config.is_below_threshold(path=Path(full_path="/tmp/test.zip"),
                                                 file_size=10000000000)
        self.assertTrue(result)

    def test_file_below_threshold(self):
        result = self._config.is_below_threshold(path=Path(full_path="/tmp/test.txt"),
                                                 file_size=self._config.threshold - 1)
        self.assertTrue(result)

    def test_file_above_threshold(self):
        result = self._config.is_below_threshold(path=Path(full_path="/tmp/test.txt"),
                                                 file_size=self._config.threshold + 1)
        self.assertFalse(result)

    def test_file_above_threshold_but_threshold_deactivated(self):
        self._config.threshold = 0
        result = self._config.is_below_threshold(path=Path(full_path="/tmp/test.txt"),
                                                 file_size=10000000000)
        self.assertTrue(result)
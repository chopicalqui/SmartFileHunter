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
from config.config import FileHunter as FileHunterConfig


class TestFileHunterConfig(unittest.TestCase):
    """
    This method tests the correct load of file hunter configurations
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)
        self._config = FileHunterConfig()

    def test_match_rules_correctly_sorted(self):
        for rules in self._config.matching_rules.values():
            priority = None
            for rule in rules:
                if priority:
                    self.assertLessEqual(rule.priority, priority)
                priority = rule.priority

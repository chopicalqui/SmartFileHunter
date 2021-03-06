# -*- coding: utf-8 -*-
"""
this file implements the core functionality for analysing files
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

import magic
import logging

logger = logging.getLogger('smb')


class FileAnalzer:
    """
    This class is responsible for analysing a given file.
    """
    def __init__(self, **args):
        self.magic = magic.Magic()

    def _analyze_file_content(self, file_path) -> bool:
        result = False
        return result

    def _analyze_file_name(self, file_path) -> bool:
        result = False
        return result

    def analyze(self, file_path: str) -> bool:
        result = False
        magic_result = self.magic.from_file(file_path).lower()
        if "ascii text" in magic_result:
            pass
        elif "zip archive data" in magic_result:
            pass
        else:
            result = self._analyze_file_name(file_path)
            if not result:
                logger.debug("Ignoring file: {} ({})".format(file_path, magic_result))
        return result
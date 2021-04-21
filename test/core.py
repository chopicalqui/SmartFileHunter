#!/usr/bin/python3
"""
this file implements core functionalities that can be used by all unittests
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
from database.core import Engine
from sqlalchemy.orm.session import Session


class BaseTestCase(unittest.TestCase):
    """
    This method implements all base functionalities for test cases
    """
    def __init__(self, test_name: str):
        super().__init__(test_name)
        self._engine = Engine(production=False)
        self._workspaces = ["test1", "test2"]

    def init_db(self):
        self._engine.drop()
        self._engine.init()


class BaseDataModelTestCase(BaseTestCase):
    """
    This class implements functionalities for testing the data model
    """

    def __init__(self, test_name: str, model: type):
        super().__init__(test_name)
        self._model = model

    def _check_exception(self, ex: Exception, ex_messages: list) -> bool:
        result = False
        for item in ex_messages:
            result = item in str(ex)
            if result:
                break
        return result

    def _test_success(self,
                      session: Session,
                      **kwargs):
        result = self._model(**kwargs)
        session.add(result)
        session.commit()
        self.assertIsNotNone(result)
        return result

    def _test_unique_constraint(self, session: Session,
                                ex_message: list = ["UNIQUE constraint failed:",
                                                    "duplicate key value violates unique constraint"],
                                **kwargs):
        try:
            result1 = self._model(**kwargs)
            result2 = self._model(**kwargs)
            session.add(result1)
            session.add(result2)
            session.commit()
        except Exception as ex:
            self.assertTrue(self._check_exception(ex, ex_message))
            session.rollback()
            return
        if ex_message:
            self.assertIsNone(result2)

    def _test_not_null_constraint(self,
                                  session: Session,
                                  ex_message: list = ["NOT NULL constraint failed:", "violates not-null constraint"],
                                  **kwargs):
        self._test_check_constraint(session=session,
                                    ex_message=ex_message,
                                    **kwargs)

    def _test_check_constraint(self,
                               session: Session,
                               ex_message: list = "violates check constraint",
                               **kwargs):
        try:
            result = self._model(**kwargs)
            session.add(result)
            session.commit()
        except Exception as ex:
            self.assertTrue(self._check_exception(ex, ex_message))
            session.rollback()
            return
        if ex_message:
            self.assertIsNone(result)
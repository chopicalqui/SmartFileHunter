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

import datetime
from test.core import BaseTestCase
from test.core import BaseDataModelTestCase
from database.model import Workspace
from database.model import Host
from database.model import Service
from database.model import Path
from database.model import File
from database.model import MatchRule


class TestWorkspace(BaseDataModelTestCase):
    """
    Test data model for workspace
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, Workspace)

    def test_unique_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            self._test_unique_constraint(session, name="unittest")

    def test_not_null_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            self._test_not_null_constraint(session)

    def test_check_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            pass

    def test_success(self):
        self.init_db()
        with self._engine.session_scope() as session:
            self._test_success(session, name="unittest")


class TestHost(BaseDataModelTestCase):
    """
    Test data model for host
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, model=Host)

    def test_unique_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = self._engine.add_workspace(session=session, name=self._workspaces[0])
            self._test_unique_constraint(session, address="192.168.1.1", workspace=workspace)

    def test_not_null_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = self._engine.add_workspace(session=session, name=self._workspaces[0])
            self._test_not_null_constraint(session, address="192.168.1.1")
            self._test_not_null_constraint(session, workspace=workspace)

    def test_check_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            pass

    def test_success(self):
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = self._engine.add_workspace(session=session, name=self._workspaces[0])
            self._test_success(session, workspace=workspace, address="192.168.1.1")


class TestService(BaseDataModelTestCase):
    """
    Test data model for service
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, model=Service)

    def test_unique_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = self._engine.add_workspace(session=session, name=self._workspaces[0])
            host = self._engine.add_host(session, workspace=workspace, address="127.0.0.1")
            self._test_unique_constraint(session, port=445, name="smb", host=host)

    def test_not_null_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = self._engine.add_workspace(session=session, name=self._workspaces[0])
            host = self._engine.add_host(session, workspace=workspace, address="127.0.0.1")
            self._test_not_null_constraint(session)
            self._test_not_null_constraint(session, name="smb", host=host)
            self._test_not_null_constraint(session, port=445, host=host)
            self._test_not_null_constraint(session, port=445, name="smb")

    def test_check_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            pass

    def test_success(self):
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = self._engine.add_workspace(session=session, name=self._workspaces[0])
            host = self._engine.add_host(session, workspace=workspace, address="127.0.0.1")
            self._test_success(session,
                               port=445,
                               name="smb",
                               host=host)


class TestPath(BaseDataModelTestCase):
    """
    Test data model for path
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, Path)

    def test_unique_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = self._engine.add_workspace(session=session, name=self._workspaces[0])
            host = self._engine.add_host(session, workspace=workspace, address="127.0.0.1")
            service = self._engine.add_service(session, host=host, port=445, name="name")
            file = self._engine.add_file(session, workspace=workspace, file=File(content=b'test'))
            self._test_unique_constraint(session=session,
                                         service=service,
                                         file=file,
                                         full_path="/tmp")

    def test_not_null_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = self._engine.add_workspace(session=session, name=self._workspaces[0])
            host = self._engine.add_host(session, workspace=workspace, address="127.0.0.1")
            service = self._engine.add_service(session, host=host, port=445, name="name")
            file = self._engine.add_file(session, workspace=workspace, file=File(content=b'test'))
            self._test_not_null_constraint(session)
            self._test_not_null_constraint(session, service=service)

    def test_check_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            pass

    def test_success(self):
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = self._engine.add_workspace(session=session, name=self._workspaces[0])
            host = self._engine.add_host(session, workspace=workspace, address="127.0.0.1")
            service = self._engine.add_service(session, host=host, port=445, name="name")
            file = self._engine.add_file(session, workspace=workspace, file=File(content=b'test'))
            self._test_success(session=session,
                               service=service,
                               file=file,
                               access_time=datetime.datetime.utcnow(),
                               modified_time=datetime.datetime.utcnow(),
                               creation_time=datetime.datetime.utcnow(),
                               full_path="/tmp")

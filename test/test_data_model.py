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
from test.core import BaseDataModelTestCase
from database.model import HunterType
from database.model import Workspace
from database.model import Host
from database.model import Service
from database.model import Path
from database.model import File
from database.model import MatchRule
from database.model import SearchLocation
from database.model import FileRelevance
from database.model import MatchRuleAccuracy


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
            self._test_unique_constraint(session, port=445, name=HunterType.smb, host=host)

    def test_not_null_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = self._engine.add_workspace(session=session, name=self._workspaces[0])
            host = self._engine.add_host(session, workspace=workspace, address="127.0.0.1")
            self._test_not_null_constraint(session)
            self._test_not_null_constraint(session, host=host)
            self._test_not_null_constraint(session, name=HunterType.smb)

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
                               name=HunterType.smb,
                               host=host)

    def test_repr_without_host(self):
        service = Service(name=HunterType.smb, port=445)
        self.assertEqual("", str(service))

    def test_repr_with_host(self):
        host = Host(address="127.0.0.1")
        service = Service(name=HunterType.smb, port=445, host=host)
        self.assertEqual("smb://127.0.0.1:445", str(service))

    def test_repr_with_host_without_port(self):
        host = Host(address="127.0.0.1")
        service = Service(name=HunterType.local, host=host)
        self.assertEqual("local://127.0.0.1", str(service))


class TestFile(BaseDataModelTestCase):
    """
    Test data model for file
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, File)

    def test_unique_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = self._engine.add_workspace(session=session, name=self._workspaces[0])
            self._test_unique_constraint(session=session,
                                         workspace=workspace,
                                         size_bytes=0,
                                         sha256_value='asdf')

    def test_not_null_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = self._engine.add_workspace(session=session, name=self._workspaces[0])
            self._test_not_null_constraint(session=session,
                                           size_bytes=0,
                                           sha256_value='asdf')
            self._test_not_null_constraint(session=session,
                                           workspace=workspace,
                                           sha256_value='asdf')
            self._test_not_null_constraint(session=session,
                                           workspace=workspace,
                                           size_bytes=0)

    def test_check_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            pass

    def test_success(self):
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = self._engine.add_workspace(session=session, name=self._workspaces[0])
            self._test_success(session=session,
                               workspace=workspace,
                               size_bytes=0,
                               sha256_value='asdf')

    def test_properties(self):
        file = File(content=b"""<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <connectionStrings>
    <add name="myConnectionString" connectionString="server=localhost;database=myDb;uid=myUser;password=myPass;" />
  </connectionStrings>
</configuration>""")
        self.assertEqual('XML 1.0 document, ASCII text', file.file_type)
        self.assertEqual('text/xml', file.mime_type)
        self.assertEqual('9773eb31e10323ab04bd846a0da237a4652ec56a09c991ce9dc0c2439a5d023b', file.sha256_value)
        self.assertEqual(232, file.size_bytes)
        self.assertIn(b"server=localhost;database=myDb;uid=myUser;password=myPass;", file.content)


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
            service = self._engine.add_service(session, host=host, port=445, name=HunterType.smb)
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
            service = self._engine.add_service(session, host=host, port=445, name=HunterType.smb)
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
            service = self._engine.add_service(session, host=host, port=445, name=HunterType.smb)
            file = self._engine.add_file(session, workspace=workspace, file=File(content=b'test'))
            self._test_success(session=session,
                               service=service,
                               file=file,
                               access_time=datetime.datetime.utcnow(),
                               modified_time=datetime.datetime.utcnow(),
                               creation_time=datetime.datetime.utcnow(),
                               full_path="/tmp")

    def test_repr_without_service(self):
        path = Path(full_path="/IT/creds.txt")
        self.assertEqual("", str(path))

    def test_repr_without_host(self):
        service = Service(name=HunterType.smb, port=445)
        path = Path(full_path="/IT/creds.txt", service=service)
        self.assertEqual("", str(path))

    def test_repr_with_host_and_smb_service(self):
        host = Host(address="127.0.0.1")
        service = Service(name=HunterType.smb, port=445, host=host)
        path = Path(full_path="/IT/creds.txt", share="$D", service=service)
        self.assertEqual("smb://127.0.0.1:445/$D/IT/creds.txt", str(path))

    def test_repr_with_host_and_ftp_service_01(self):
        host = Host(address="127.0.0.1")
        service = Service(name=HunterType.ftp, port=21, host=host)
        path = Path(full_path="/IT/creds.txt", service=service)
        self.assertEqual("ftp://127.0.0.1:21/IT/creds.txt", str(path))

    def test_repr_with_host_and_ftp_service_02(self):
        host = Host(address="127.0.0.1")
        service = Service(name=HunterType.ftp, port=21, host=host)
        path = Path(full_path="IT/creds.txt", service=service)
        self.assertEqual("ftp://127.0.0.1:21/IT/creds.txt", str(path))

    def test_repr_with_host_and_ftp_service_and_path_is_none(self):
        host = Host(address="127.0.0.1")
        service = Service(name=HunterType.ftp, port=21, host=host)
        path = Path(service=service)
        self.assertEqual("ftp://127.0.0.1:21", str(path))


class TestMatchRule(BaseDataModelTestCase):
    """
    Test data model for workspace
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, MatchRule)

    def test_unique_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            self._test_unique_constraint(session,
                                         search_location=SearchLocation.file_name,
                                         relevance=FileRelevance.high,
                                         accuracy=MatchRuleAccuracy.high,
                                         search_pattern=".*")

    def test_not_null_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            self._test_not_null_constraint(session,
                                           relevance=FileRelevance.high,
                                           accuracy=MatchRuleAccuracy.high,
                                           search_pattern=".*")
            self._test_not_null_constraint(session,
                                           search_location=SearchLocation.file_name,
                                           accuracy=MatchRuleAccuracy.high,
                                           search_pattern=".*")
            self._test_not_null_constraint(session,
                                           search_location=SearchLocation.file_name,
                                           accuracy=MatchRuleAccuracy.high,
                                           relevance=FileRelevance.high)
            self._test_not_null_constraint(session,
                                           search_location=SearchLocation.file_name,
                                           relevance=FileRelevance.high,
                                           search_pattern=".*")

    def test_check_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            pass

    def test_success(self):
        self.init_db()
        with self._engine.session_scope() as session:
            self._test_success(session,
                               search_location=SearchLocation.file_name,
                               category="test",
                               relevance=FileRelevance.high,
                               accuracy=MatchRuleAccuracy.high,
                               search_pattern=".*")
        with self._engine.session_scope() as session:
            file_match = session.query(MatchRule).one()
            self.assertEqual(SearchLocation.file_name, file_match.search_location)
            self.assertEqual("test", file_match.category)
            self.assertEqual(FileRelevance.high, file_match.relevance)
            self.assertEqual(MatchRuleAccuracy.high, file_match.accuracy)
            self.assertEqual(".*", file_match.search_pattern)
            self.assertEqual(162, file_match.priority)

    def test_highlight_text(self):
        text = b"""# Oracle DB properties
#jdbc.driver=oracle.jdbc.driver.OracleDriver
#jdbc.url=jdbc:oracle:thin:@localhost:1571:MyDbSID
#jdbc.username=root
#jdbc.password=admin

# MySQL DB properties
jdbc.driver=com.mysql.jdbc.Driver
jdbc.url=jdbc:mysql://localhost:3306/MyDbName
jdbc.username=root
jdbc.password=admin"""
        rule = MatchRule(search_location=SearchLocation.file_content,
                         search_pattern="jdbc\.password\s*[=:]?",
                         relevance=FileRelevance.high)
        text, hits = rule.highlight_text(text)
        self.assertEqual(2, hits)
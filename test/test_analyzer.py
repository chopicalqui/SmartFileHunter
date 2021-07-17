#!/usr/bin/env python3
"""
this file implements unittests for analysing files
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

import queue
import base64
from database.model import Host
from database.model import Path
from database.model import File
from database.model import Service
from database.model import MatchRule
from database.model import HunterType
from database.model import SearchLocation
from database.model import FileRelevance
from database.model import MatchRuleAccuracy
from test.core import BaseTestCase
from test.core import ArgumentHelper
from hunters.analyzer.core import FileAnalzer
from config.config import FileHunter


class BaseTestFileAnalyzer(BaseTestCase):

    def __init__(self, test_name: str):
        super().__init__(test_name)

    def _add_file_content(self, workspace: str, full_path: str, b64_content: str = None, txt_content: str = None):
        """
        This method analyzes the given file.
        """
        content = base64.b64decode(b64_content) if b64_content else txt_content.encode()
        # Add workspace
        with self._engine.session_scope() as session:
            self._engine.add_workspace(session=session, name=workspace)
        # Initialize analyzer and create workspace
        analyzer = FileAnalzer(args=ArgumentHelper(workspace=workspace),
                               engine=self._engine,
                               file_queue=queue.Queue(),
                               config=FileHunter(args=ArgumentHelper()))
        path = Path(service=Service(name=HunterType.local,
                                    host=Host(address="127.0.0.1")),
                    full_path=full_path,
                    file=File(content=content))
        analyzer.analyze(path)


class TestArchives(BaseTestFileAnalyzer):

    def __init__(self, test_name: str):
        super().__init__(test_name)

    def test_invalid_zip_file(self):
        """
        Test handling of invalid ZIP files
        """
        self.init_db()
        # Analyze given data
        self._add_file_content(workspace="test",
                               full_path="/SHARE$/it/backup.zip",
                               b64_content="""IyBPcmFjbGUgREIgcHJvcGVydGllcw0KI2pkYmMuZHJpdmVyPW9yYWNsZS5qZGJjLmRyaXZlci5P
cmFjbGVEcml2ZXINCiNqZGJjLnVybD1qZGJjOm9yYWNsZTp0aGluOkBsb2NhbGhvc3Q6MTU3MTpN
eURiU0lEDQojamRiYy51c2VybmFtZT1yb290DQojamRiYy5wYXNzd29yZD1hZG1pbg0KDQojIE15
U1FMIERCIHByb3BlcnRpZXMNCmpkYmMuZHJpdmVyPWNvbS5teXNxbC5qZGJjLkRyaXZlcg0KamRi
Yy51cmw9amRiYzpteXNxbDovL2xvY2FsaG9zdDozMzA2L015RGJOYW1lDQpqZGJjLnVzZXJuYW1l
PXJvb3QNCmpkYmMucGFzc3dvcmQ9YWRtaW4=""")
        # Verify database
        with self._engine.session_scope() as session:
            results = [item.full_path for item in session.query(Path).all()]
            results.sort()
            self.assertListEqual(['/SHARE$/it/backup.zip'], results)

    def test_recursive_zip_analysis(self):
        """
        Test recursive analysis of ZIP file
        """
        self.init_db()
        # Analyze given data
        self._add_file_content(workspace="test",
                               full_path="/SHARE$/it/backup.zip",
                               b64_content="""UEsDBBQAAAAIAGynklIKAuSBqQAAADcBAAANABwAZGIucHJvcGVydGllc1VUCQADi4F8YJiBfGB1
eAsAAQQAAAAABAAAAABtzt8KwiAYh+Hzwe5B2LlrjAoEIcKToBWxK3AqtNC5Pq3Y3bc/WFt0pj/e
D54EnYELrRDboxZsq8DXysVRcpOVwBLqpwJqxwTPJjxdsfET6gdoOjzI1BN/rRuy01ZwfbXOk2y9
zUjRsao8sM+NU9BwoyhY68PYcudeFiTl0tRNHPU7KrrycvxVzpHCGmw6d9eTM9CWsjEgafpF5flq
kw6oU68I+RL1x/QGUEsDBAoAAAAAAHKnklKe7ADxWQEAAFkBAAAMABwAdW5pdHRlc3QuemlwVVQJ
AAOYgXxgmIF8YHV4CwABBAAAAAAEAAAAAFBLAwQUAAAACABsp5JSCgLkgakAAAA3AQAADQAcAGRi
LnByb3BlcnRpZXNVVAkAA4uBfGCLgXxgdXgLAAEEAAAAAAQAAAAAbc7fCsIgGIfh88HuQdi5a4wK
BCHCk6AVsStwKrTQuT6t2N23P1hbdKY/3g+eBJ2BC60Q26MWbKvA18rFUXKTlcAS6qcCascEzyY8
XbHxE+oHaDo8yNQTf60bstNWcH21zpNsvc1I0bGqPLDPjVPQcKMoWOvD2HLnXhYk5dLUTRz1Oyq6
8nL8Vc6RwhpsOnfXkzPQlrIxIGn6ReX5apMOqFOvCPkS9cf0BlBLAQIeAxQAAAAIAGynklIKAuSB
qQAAADcBAAANABgAAAAAAAEAAADtgQAAAABkYi5wcm9wZXJ0aWVzVVQFAAOLgXxgdXgLAAEEAAAA
AAQAAAAAUEsFBgAAAAABAAEAUwAAAPAAAAAAAFBLAQIeAxQAAAAIAGynklIKAuSBqQAAADcBAAAN
ABgAAAAAAAEAAADtgQAAAABkYi5wcm9wZXJ0aWVzVVQFAAOLgXxgdXgLAAEEAAAAAAQAAAAAUEsB
Ah4DCgAAAAAAcqeSUp7sAPFZAQAAWQEAAAwAGAAAAAAAAAAAAKSB8AAAAHVuaXR0ZXN0LnppcFVU
BQADmIF8YHV4CwABBAAAAAAEAAAAAFBLBQYAAAAAAgACAKUAAACPAgAAAAA=""")
        # Verify database
        with self._engine.session_scope() as session:
            results = [item.full_path for item in session.query(Path).all()]
            results.sort()
            self.assertListEqual(['/SHARE$/it/backup.zip/db.properties',
                                  '/SHARE$/it/backup.zip/unittest.zip/db.properties'], results)

    def test_tar_bz2_analysis(self):
        """
        Test recursive analysis of ZIP file
        """
        self.init_db()
        # Analyze given data
        self._add_file_content(workspace="test",
                               full_path="/SHARE$/it/backup.tar.bz2",
                               b64_content="""QlpoOTFBWSZTWccaJFoAALd/hcwSAEBIAf+SVCeoAH53/6AAAIAgAAgwARrYQ1NTQGgRgTAnpNGA
INGg1QD1GgExGAJgJiaYmAklDKj9NJmgiDRoaA0DT1NqfqnHjZRMEHy5IEYY85jrg8uYSChWiIW6
tX5tppp9mkHUPXEKgj8QGDJG1Z2OMiASmt+MA2HMySpnWnJpZCpezySIkqJ1UUwqYliN4iEpnQ/k
PJA9EOzC2AchOz1jEtzdbPfhVCiwPQkcMTLMyxGBRBZn2FcSf6CqL1v6kw38jgWrkpOGTzlYiB6+
7MzDXGg46AuM92VK2Ed16gXldCVjpkiIQGTdxrPAtZaPGY7CSmOO/S42qoTjeRKymwoBlfgpBPYh
xNdpISDsXckU4UJDHGiRaA==""")
        # Verify database
        with self._engine.session_scope() as session:
            results = [item.full_path for item in session.query(Path).all()]
            results.sort()
            self.assertListEqual(['/SHARE$/it/backup.tar.bz2/db.properties'], results)

    def test_zip_file_content_above_threshold(self):
        """
        Test files above threshold are ignored during archive file analysis
        :return:
        """
        self.init_db()
        # Analyze given data
        self._add_file_content(workspace="test",
                               full_path="/SHARE$/it/backup.zip",
                               b64_content="""UEsDBBQAAAAIAIMQ8VL5kLWCLAQAABcEEAAFABwAemVyb3NVVAkAA3Ye8mBxHvJgdXgLAAEE6AMA
AAToAwAA7cGhDYAwEADA1+zSERCEdgGCIwgSPA0vWB+NY4C7i/gqpR+Zz3WfOW5Lq9O8troHAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAT8MLUEsBAh4DFAAA
AAgAgxDxUvmQtYIsBAAAFwQQAAUAGAAAAAAAAAAAAKSBAAAAAHplcm9zVVQFAAN2HvJgdXgLAAEE
6AMAAAToAwAAUEsFBgAAAAABAAEASwAAAGsEAAAAAA==""")
        # Verify database
        with self._engine.session_scope() as session:
            result = session.query(File).count()
            self.assertEqual(0, result)

    def test_zip_file_content_below_threshold(self):
        """
        Test files below threshold are processed during archive file analysis
        :return:
        """
        self.init_db()
        # Analyze given data
        self._add_file_content(workspace="test",
                               full_path="/SHARE$/it/backup.zip",
                               b64_content="""UEsDBBQAAAAIAHgQ8VKeexCOPgAAABYoAAAGABwAemVyb3MyVVQJAANkHvJgaB7yYHV4CwABBOgD
AAAE6AMAAO3KsQ2AIAAAMGZ+4QQHIzxg3AwDibtGBt/nAB5waOeGMEnpab1/93st517yuh0l17kB
AAAAAAAAAAAAvxIHUEsBAh4DFAAAAAgAeBDxUp57EI4+AAAAFigAAAYAGAAAAAAAAAAAAKSBAAAA
AHplcm9zMlVUBQADZB7yYHV4CwABBOgDAAAE6AMAAFBLBQYAAAAAAQABAEwAAAB+AAAAAAA=""")
        # Verify database
        with self._engine.session_scope() as session:
            results = [item.full_path for item in session.query(Path).all()]
            results.sort()
            self.assertListEqual(['/SHARE$/it/backup.zip/zeros2'], results)


class TestFileSize(BaseTestFileAnalyzer):

    def __init__(self, test_name: str):
        super().__init__(test_name)

    def test_file_size_only_update(self):
        """
        If only the file size is stored in the database (without actual file content), then the file size should not
        be updated
        """
        self.init_db()
        workspace = self._workspaces[0]
        file_size = 100000000
        full_path = "/tmp/test.vmdk"
        # Add workspace
        with self._engine.session_scope() as session:
            self._engine.add_workspace(session=session, name=workspace)
        # Initialize analyzer and create workspace
        analyzer = FileAnalzer(args=ArgumentHelper(workspace=workspace),
                               engine=self._engine,
                               file_queue=queue.Queue(),
                               config=FileHunter(args=ArgumentHelper()))
        path = Path(service=Service(name=HunterType.local,
                                    host=Host(address="127.0.0.1")),
                    full_path=full_path)
        path.file = File(content="[file ({}) not imported as file size ({}) "
                                 "is above threshold]".format(str(path), file_size).encode('utf-8'))
        path.file.size_bytes = file_size
        analyzer._analyze_path_name(path)
        # Verify database
        with self._engine.session_scope() as session:
            result = session.query(Path).one()
            self.assertEqual(full_path, result.full_path)
            self.assertEqual(file_size, result.file.size_bytes)


class TestFileContent(BaseTestFileAnalyzer):

    def __init__(self, test_name: str):
        super().__init__(test_name)

    def test_commandline_argument_dbpass(self):
        self.init_db()
        # Analyze given data
        self._add_file_content(workspace="test",
                               full_path="/var/www/html/install.sh",
                               txt_content="""#!/bin/bash
php server-install.php --install --dbhost=127.0.0.1 --dbuser=root --dbpass=root
exit 0""")
        # Verify database
        with self._engine.session_scope() as session:
            result = session.query(MatchRule) \
                .join(File, MatchRule.files).one()
            self.assertEqual(SearchLocation.file_content, result.search_location)
            self.assertEqual(FileRelevance.high, result.relevance)
            self.assertEqual(MatchRuleAccuracy.medium, result.accuracy)
            self.assertEqual("\\s+-{1,2}[a-z0-9]*pass[a-z0-9]*[\\s:=,]", result.search_pattern)

    def test_commandline_argument_adminpass(self):
        self.init_db()
        # Analyze given data
        self._add_file_content(workspace="test",
                               full_path="/var/www/html/install.sh",
                               txt_content="""#!/bin/bash
php server-install.php --install --dbhost=127.0.0.1 --dbuser=root --adminpass admin
exit 0""")
        # Verify database
        with self._engine.session_scope() as session:
            result = session.query(MatchRule) \
                .join(File, MatchRule.files).one()
            self.assertEqual(SearchLocation.file_content, result.search_location)
            self.assertEqual(FileRelevance.high, result.relevance)
            self.assertEqual(MatchRuleAccuracy.medium, result.accuracy)
            self.assertEqual("\\s+-{1,2}[a-z0-9]*pass[a-z0-9]*[\\s:=,]", result.search_pattern)

    def test_commandline_argument_password(self):
        self.init_db()
        # Analyze given data
        self._add_file_content(workspace="test",
                               full_path="/var/www/html/install.sh",
                               txt_content="""#!/bin/bash
svn --username='[REDACTED]' --password='[REDACTED]' checkout [REDACTED] /usr/local/[REDACTED]/
exit 0""")
        # Verify database
        with self._engine.session_scope() as session:
            result = session.query(MatchRule) \
                .join(File, MatchRule.files).one()
            self.assertEqual(SearchLocation.file_content, result.search_location)
            self.assertEqual(FileRelevance.high, result.relevance)
            self.assertEqual(MatchRuleAccuracy.medium, result.accuracy)
            self.assertEqual("\\s+-{1,2}[a-z0-9]*password[a-z0-9]*[\\s:=,]", result.search_pattern)

    def test_commandline_mysqladmin_password_update(self):
        self.init_db()
        # Analyze given data
        self._add_file_content(workspace="test",
                               full_path="/var/www/html/install.sh",
                               txt_content="""#!/bin/bash
mysqladmin -u root password [REDACTED]
exit 0""")
        # Verify database
        with self._engine.session_scope() as session:
            result = session.query(MatchRule) \
                .join(File, MatchRule.files).one()
            self.assertEqual(SearchLocation.file_content, result.search_location)
            self.assertEqual(FileRelevance.medium, result.relevance)
            self.assertEqual(MatchRuleAccuracy.low, result.accuracy)
            self.assertEqual("\\s[a-z0-9]*password[a-z0-9]*\\s", result.search_pattern)

    def test_commandline_passwd_password_update(self):
        self.init_db()
        # Analyze given data
        self._add_file_content(workspace="test",
                               full_path="/var/www/html/install.sh",
                               txt_content="""#!/bin/bash
echo '[REDACTED]' | passwd root --stdin
exit 0""")
        # Verify database
        with self._engine.session_scope() as session:
            result = session.query(MatchRule) \
                .join(File, MatchRule.files).one()
            self.assertEqual(SearchLocation.file_content, result.search_location)
            self.assertEqual(FileRelevance.medium, result.relevance)
            self.assertEqual(MatchRuleAccuracy.low, result.accuracy)
            self.assertEqual("\\s[a-z0-9]*passwd[a-z0-9]*\\s", result.search_pattern)

    def test_commandline_mysql_login(self):
        self.init_db()
        # Analyze given data
        self._add_file_content(workspace="test",
                               full_path="/var/www/html/install.sh",
                               txt_content="""#!/bin/bash
echo "drop database mysql;" | mysql -u root -pREDACTED
exit 0""")
        # Verify database
        with self._engine.session_scope() as session:
            result = session.query(MatchRule) \
                .join(File, MatchRule.files).one()
            self.assertEqual(SearchLocation.file_content, result.search_location)
            self.assertEqual(FileRelevance.medium, result.relevance)
            self.assertEqual(MatchRuleAccuracy.low, result.accuracy)
            self.assertEqual("\\s+-p[a-z0-9\\s:=,]", result.search_pattern)

    def test_private_key(self):
        self.init_db()
        # Analyze given data
        self._add_file_content(workspace="test",
                               full_path="/root/.ssh/id_test",
                               txt_content="""-----BEGIN RSA PRIVATE KEY-----
[REDACTED]
-----END RSA PRIVATE KEY-----""")
        # Verify database
        with self._engine.session_scope() as session:
            result = session.query(MatchRule) \
                .join(File, MatchRule.files).one()
            self.assertEqual(SearchLocation.file_content, result.search_location)
            self.assertEqual(FileRelevance.high, result.relevance)
            self.assertEqual(MatchRuleAccuracy.high, result.accuracy)
            self.assertEqual("^-+BEGIN.*?PRIVATE KEY-+", result.search_pattern)

    def test_perl_password_dict(self):
        self.init_db()
        # Analyze given data
        self._add_file_content(workspace="test",
                               full_path="/var/www/html/login.pl",
                               txt_content="""$opt = {
         'mysql_config' => 'mysql_config',
         'embedded' => '',
         'ssl' => 0,
         'nocatchstderr' => 0,
         'libs' => '-rdynamic -L/usr/local/mysql/lib/mysql -lmysqlclient -lz -lcrypt -lnsl -lm',
         'testhost' => '',
         'nofoundrows' => 0,
         'testdb' => 'test',
         'cflags' => '-I/usr/local/mysql/include/mysql -DUNIV_LINUX',
         'testuser' => '[REDACTED]',
         'testpassword' => '[REDACTED]',
         'testsocket' => ''
       };""")
        # Verify database
        with self._engine.session_scope() as session:
            result = session.query(MatchRule) \
                .join(File, MatchRule.files).one()
            self.assertEqual(SearchLocation.file_content, result.search_location)
            self.assertEqual(FileRelevance.high, result.relevance)
            self.assertEqual(MatchRuleAccuracy.medium, result.accuracy)
            self.assertEqual("[a-z0-9]*password[a-z0-9]*\\s*[=:><\"',]", result.search_pattern)

    def test_powershell(self):
        self.init_db()
        # Analyze given data
        self._add_file_content(workspace="test",
                               full_path="C:\\temp\\test.ps1",
                               txt_content="""$pwd = ConvertTo-SecureString "[REDACTED]" -AsPlainText -Force""")
        # Verify database
        with self._engine.session_scope() as session:
            result = session.query(MatchRule) \
                .join(File, MatchRule.files).one()
            self.assertEqual(SearchLocation.file_content, result.search_location)
            self.assertEqual(FileRelevance.high, result.relevance)
            self.assertEqual(MatchRuleAccuracy.high, result.accuracy)
            self.assertEqual("ConvertTo-SecureString\\s+", result.search_pattern)

    def test_password_in_config_json(self):
        self.init_db()
        # Analyze given data
        self._add_file_content(workspace="test",
                               full_path="/var/www/html/config.json",
                               txt_content="""{"Users":[{"Id":"1","Name":"Administrator","Email":"","EncryptedPassword":"[REDACTED]]"},{"Id":"2","Name":"guest","EncryptedPassword":"[REDACTED]"}]}""")
        # Verify database
        with self._engine.session_scope() as session:
            result = session.query(MatchRule) \
                .join(File, MatchRule.files).one()
            self.assertEqual(SearchLocation.file_content, result.search_location)
            self.assertEqual(FileRelevance.high, result.relevance)
            self.assertEqual(MatchRuleAccuracy.medium, result.accuracy)
            self.assertEqual("[a-z0-9]*password[a-z0-9]*\\s*[=:><\"',]", result.search_pattern)

    def test_password_in_server_xml(self):
        self.init_db()
        # Analyze given data
        self._add_file_content(workspace="test",
                               full_path="/var/www/html/server.xml",
                               txt_content="""<Server port="18005" shutdown="SHUTDOWN">
  <GlobalNamingResources >
    <Resource name="jdbc/TEST" auth="Container"
              type="javax.sql.DataSource" username="postgres" password="postgres"
              driverClassName="org.postgresql.Driver" url="jdbc:postgresql://localhost:5432/test"
              maxActive="100" maxIdle="30" maxWait="10000" factory="org.apache.commons.dbcp.BasicDataSourceFactory" />
  </GlobalNamingResources >
</Server>""")
        # Verify database
        with self._engine.session_scope() as session:
            result = session.query(MatchRule) \
                .join(File, MatchRule.files).one()
            self.assertEqual(SearchLocation.file_content, result.search_location)
            self.assertEqual(FileRelevance.high, result.relevance)
            self.assertEqual(MatchRuleAccuracy.medium, result.accuracy)
            self.assertEqual("[a-z0-9]*password[a-z0-9]*\\s*[=:><\"',]", result.search_pattern)

    def test_connection_string_xml(self):
        self.init_db()
        # Analyze given data
        self._add_file_content(workspace="test",
                               full_path="/var/www/html/web.config",
                               txt_content="""<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <connectionStrings>
    <add name="myConnectionString" connectionString="server=localhost;database=db;uid=root;password=REDACTED;" />
  </connectionStrings>
</configuration>""")
        # Verify database
        with self._engine.session_scope() as session:
            result = session.query(MatchRule) \
                .join(File, MatchRule.files).one()
            self.assertEqual(SearchLocation.file_content, result.search_location)
            self.assertEqual(FileRelevance.high, result.relevance)
            self.assertEqual(MatchRuleAccuracy.high, result.accuracy)
            self.assertEqual("connectionString=[\"'].*password\\s*=", result.search_pattern)

    def test_connection_string_xml_02(self):
        self.init_db()
        # Analyze given data
        self._add_file_content(workspace="test",
                               full_path="/var/www/html/web.config",
                               txt_content="""<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <connectionStrings>
    <add name="SiteSqlServer" connectionString="Data Source=localhost;Initial Catalog=database;User ID=administrator;Password=[REDACTED]" providerName="System.Data.SqlClient" />
  </connectionStrings>
</configuration>""")
        # Verify database
        with self._engine.session_scope() as session:
            result = session.query(MatchRule) \
                .join(File, MatchRule.files).one()
            self.assertEqual(SearchLocation.file_content, result.search_location)
            self.assertEqual(FileRelevance.high, result.relevance)
            self.assertEqual(MatchRuleAccuracy.high, result.accuracy)
            self.assertEqual("connectionString=[\"'].*password\\s*=", result.search_pattern)

    def test_connection_string_json(self):
        self.init_db()
        # Analyze given data
        self._add_file_content(workspace="test",
                               full_path="C:\\temp\\appsettings.json",
                               txt_content="""{
  "ConnectionStrings": {
    "DefaultConnection": "Server=localhost\\SQLEXPRESS;Database=DB;User Id=DBUser;Password=[REDACTED];Integrated Security=False;MultipleActiveResultSets=True"
  },
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft": "Warning",
      "Microsoft.Hosting.Lifetime": "Information"
    }
  },
  "AllowedHosts": "*",
  "StaticFiles": {
    "Headers": {
      "Cache-Control": "max-age=3600",
      "Pragma": "cache",
      "Expires": null
    }
  }
}""")
        # Verify database
        with self._engine.session_scope() as session:
            result = session.query(MatchRule) \
                .join(File, MatchRule.files).one()
            self.assertEqual(SearchLocation.file_content, result.search_location)
            self.assertEqual(FileRelevance.high, result.relevance)
            self.assertEqual(MatchRuleAccuracy.high, result.accuracy)
            self.assertEqual("Connection[\"']\\s*:\\s*[\"'].*?password\\s*=", result.search_pattern)

    def test_cpassword(self):
        self.init_db()
        # Analyze given data
        self._add_file_content(workspace="test",
                               full_path="\\DC01\\SYSVOL\\..\\Machine\\Preferences\\Groups.xml",
                               txt_content="""<?xml version="1.0" encoding="utf-8" ?>
<Groups clsid="{[REDACTED]}">
  <User clsid="{[REDACTED]}" name="admin" image="0" changed="2018-12-31 07:00:00" uid="{[REDACTED]}">
    <Properties action="C" fullName="admin" description="" cpassword="qRI/NPQtItGsMjwMkhF7ZDvK6n9KlOhBZ/XShO2IZ80" changeLogon="0" noChange="0" neverExpires="0" acctDisabled="0" userName="admin" />
  </User>
</Groups>""")
        # Verify database
        with self._engine.session_scope() as session:
            result = session.query(MatchRule) \
                .join(File, MatchRule.files).one()
            self.assertEqual(SearchLocation.file_content, result.search_location)
            self.assertEqual(FileRelevance.high, result.relevance)
            self.assertEqual(MatchRuleAccuracy.high, result.accuracy)
            self.assertEqual("<properties\\s.*?\\scpassword=[\"'].*[\"'].*?/>", result.search_pattern)

    def test_autologin(self):
        self.init_db()
        # Analyze given data
        self._add_file_content(workspace="test",
                               full_path="\\DC01\\SYSVOL\\..\\Machine\\Preferences\\Registry.xml",
                               txt_content="""<?xml version="1.0" encoding="utf-8"?>
<RegistrySettings clsid="{A3CCFC41-DFDB-43a5-8D26-0FE8B954DA51}"><Registry clsid="{9CD4B2F4-923D-47f5-A062-E897DD1DAD50}" name="AutoAdminLogon" status="AutoAdminLogon" image="7" changed="2021-05-13 19:40:35" uid="{7DA1B569-F1F6-4521-8135-DA796D27B750}"><Properties action="U" displayDecimal="1" default="0" hive="HKEY_LOCAL_MACHINE" key="SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" name="AutoAdminLogon" type="REG_SZ" value="1"/></Registry>
	<Registry clsid="{9CD4B2F4-923D-47f5-A062-E897DD1DAD50}" name="DefaultDomainName" status="DefaultDomainName" image="7" changed="2021-05-13 19:41:06" uid="{4F4F208A-F33B-441C-B288-D76A291DAB47}"><Properties action="U" displayDecimal="1" default="0" hive="HKEY_LOCAL_MACHINE" key="SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" name="DefaultDomainName" type="REG_SZ" value="TEST"/></Registry>
	<Registry clsid="{9CD4B2F4-923D-47f5-A062-E897DD1DAD50}" name="DefaultUserName" status="DefaultUserName" image="7" changed="2021-05-13 19:41:39" uid="{9122F660-7ADF-410F-A8FC-EAD1CA0AFAE3}"><Properties action="U" displayDecimal="1" default="0" hive="HKEY_LOCAL_MACHINE" key="SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" name="DefaultUserName" type="REG_SZ" value="AutoUser"/></Registry>
	<Registry clsid="{9CD4B2F4-923D-47f5-A062-E897DD1DAD50}" name="DefaultPassword" status="DefaultPassword" image="7" changed="2021-05-13 19:42:01" uid="{C15A6EE5-F6D0-4FC5-B29E-39EBF7780C04}"><Properties action="U" displayDecimal="1" default="0" hive="HKEY_LOCAL_MACHINE" key="SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" name="DefaultPassword" type="REG_SZ" value="[REDACTED]"/></Registry>
</RegistrySettings>""")
        # Verify database
        with self._engine.session_scope() as session:
            result = session.query(MatchRule) \
                .join(File, MatchRule.files).one()
            self.assertEqual(SearchLocation.file_content, result.search_location)
            self.assertEqual(FileRelevance.high, result.relevance)
            self.assertEqual(MatchRuleAccuracy.high, result.accuracy)
            self.assertEqual("<registry\\s.*?\\skey=[\"']SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon[\"'].*/>", result.search_pattern)

    def test_jwt(self):
        self.init_db()
        # Analyze given data
        self._add_file_content(workspace="test",
                               full_path="C:\\temp\\appsettings.json",
                               txt_content="""{"jwt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"}""")
        # Verify database
        with self._engine.session_scope() as session:
            result = session.query(MatchRule) \
                .join(File, MatchRule.files).one()
            self.assertEqual(SearchLocation.file_content, result.search_location)
            self.assertEqual(FileRelevance.medium, result.relevance)
            self.assertEqual(MatchRuleAccuracy.medium, result.accuracy)
            self.assertEqual('eyJ\\w+?\\.eyJ\\w+?\\.', result.search_pattern)

    def test_domain_name_argument(self):
        self.init_db()
        workspace = self._workspaces[0]
        # Add workspace
        with self._engine.session_scope() as session:
            self._engine.add_workspace(session=session, name=workspace)
        # Initialize analyzer and create workspace
        argument_helper = ArgumentHelper(workspace=workspace, netbios=["CONTOSO"])
        analyzer = FileAnalzer(args=argument_helper,
                               engine=self._engine,
                               file_queue=queue.Queue(),
                               config=FileHunter(args=argument_helper))
        path = Path(service=Service(name=HunterType.local,
                                    host=Host(address="127.0.0.1")),
                    full_path="\\\\DC1\\...\\{xyz}\\Machine\\Scripts\\application.log")
        path.file = File(content=""""2021-07-12 11:00:01 - CONTOSO\Test:[REDACTED] logged in.""".encode('utf-8'))
        analyzer._analyze_content(path)
        # Verify database
        with self._engine.session_scope() as session:
            result = session.query(MatchRule) \
                .join(File, MatchRule.files).one()
            self.assertEqual(SearchLocation.file_content, result.search_location)
            self.assertEqual(FileRelevance.medium, result.relevance)
            self.assertEqual(MatchRuleAccuracy.medium, result.accuracy)
            self.assertEqual("CONTOSO[\\\\/]\\w+", result.search_pattern)

    def test_netbios_name_argument(self):
        self.init_db()
        workspace = self._workspaces[0]
        # Add workspace
        with self._engine.session_scope() as session:
            self._engine.add_workspace(session=session, name=workspace)
        # Initialize analyzer and create workspace
        argument_helper = ArgumentHelper(workspace=workspace, upn=["contoso.org"])
        analyzer = FileAnalzer(args=argument_helper,
                               engine=self._engine,
                               file_queue=queue.Queue(),
                               config=FileHunter(args=argument_helper))
        path = Path(service=Service(name=HunterType.local,
                                    host=Host(address="127.0.0.1")),
                    full_path="\\\\DC1\\...\\{xyz}\\Machine\\Scripts\\application.log")
        path.file = File(content=""""2021-07-12 11:00:01 - test@contoso.org:[REDACTED] logged in.""".encode('utf-8'))
        analyzer._analyze_content(path)
        # Verify database
        with self._engine.session_scope() as session:
            result = session.query(MatchRule) \
                .join(File, MatchRule.files).one()
            self.assertEqual(SearchLocation.file_content, result.search_location)
            self.assertEqual(FileRelevance.medium, result.relevance)
            self.assertEqual(MatchRuleAccuracy.medium, result.accuracy)
            self.assertEqual("\\w+@contoso.org", result.search_pattern)


class TestFileName(BaseTestFileAnalyzer):

    def __init__(self, test_name: str):
        super().__init__(test_name)

    def test_tomcat_users(self):
        self.init_db()
        # Analyze given data
        self._add_file_content(workspace="test",
                               full_path="/var/www/html/tomcat-users.xml",
                               txt_content="")
        # Verify database
        with self._engine.session_scope() as session:
            result = session.query(MatchRule) \
                .join(File, MatchRule.files).one()
            self.assertEqual(SearchLocation.file_name, result.search_location)
            self.assertEqual(FileRelevance.high, result.relevance)
            self.assertEqual(MatchRuleAccuracy.medium, result.accuracy)
            self.assertEqual("^tomcat-users(-\\d+)?\\.xml$", result.search_pattern)

    def test_startup_script_machine(self):
        self.init_db()
        # Analyze given data
        self._add_file_content(workspace="test",
                               full_path="\\\\DC1\\...\\{xyz}\\Machine\\Scripts\\scripts.ini",
                               txt_content="""[Startup]
0CmdLine=AutoLogin.bat
0Parameters=DOMAIN Administrator MySecret""")
        # Verify database
        with self._engine.session_scope() as session:
            result = session.query(MatchRule) \
                .join(File, MatchRule.files).one()
            self.assertEqual(SearchLocation.full_path, result.search_location)
            self.assertEqual(FileRelevance.medium, result.relevance)
            self.assertEqual(MatchRuleAccuracy.high, result.accuracy)
            self.assertEqual("^.*/((Machine)|(User))/Scripts/(ps)?scripts\\.ini$", result.search_pattern)

    def test_tomcat_users9(self):
        self.init_db()
        # Analyze given data
        self._add_file_content(workspace="test",
                               full_path="/var/www/html/tomcat-users-7.xml",
                               txt_content="")
        # Verify database
        with self._engine.session_scope() as session:
            result = session.query(MatchRule) \
                .join(File, MatchRule.files).one()
            self.assertEqual(SearchLocation.file_name, result.search_location)
            self.assertEqual(FileRelevance.high, result.relevance)
            self.assertEqual(MatchRuleAccuracy.medium, result.accuracy)
            self.assertEqual("^tomcat-users(-\\d+)?\\.xml$", result.search_pattern)

    def test_appsettings_json(self):
        self.init_db()
        # Analyze given data
        self._add_file_content(workspace="test",
                               full_path="C:\\temp\\appsettings.json",
                               txt_content="")
        # Verify database
        with self._engine.session_scope() as session:
            result = session.query(MatchRule) \
                .join(File, MatchRule.files).one()
            self.assertEqual(SearchLocation.file_name, result.search_location)
            self.assertEqual(FileRelevance.medium, result.relevance)
            self.assertEqual(MatchRuleAccuracy.medium, result.accuracy)
            self.assertEqual("^appsettings\\.json$", result.search_pattern)

    def test_appsettings_development_json(self):
        self.init_db()
        # Analyze given data
        self._add_file_content(workspace="test",
                               full_path="C:\\temp\\appsettings.Development.json",
                               txt_content="")
        # Verify database
        with self._engine.session_scope() as session:
            result = session.query(MatchRule) \
                .join(File, MatchRule.files).one()
            self.assertEqual(SearchLocation.file_name, result.search_location)
            self.assertEqual(FileRelevance.medium, result.relevance)
            self.assertEqual(MatchRuleAccuracy.medium, result.accuracy)
            self.assertEqual("^appsettings\\..*?\\.json$", result.search_pattern)

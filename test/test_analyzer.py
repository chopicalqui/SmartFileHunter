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
from database.model import HunterType
from test.core import BaseTestCase
from hunters.analyzer.core import FileAnalzer
from config.config import FileHunter


class ArgumentHelper:
    def __init__(self, workspace: str = 'test',
                 host: str = "127.0.0.1",
                 nocolor: bool = True):
        self.workspace = workspace
        self.host = host
        self.nocolor = nocolor


class TestFileAnalzer(BaseTestCase):

    def __init__(self, test_name: str):
        super().__init__(test_name)

    def _add_file_content(self, workspace: str, full_path: str, b64_content: str):
        """
        This method analyzes the given file.
        """
        content = base64.b64decode(b64_content)
        # Add workspace
        with self._engine.session_scope() as session:
            self._engine.add_workspace(session=session, name=workspace)
        # Initialize analyzer and create workspace
        analyzer = FileAnalzer(args=ArgumentHelper(workspace=workspace),
                               engine=self._engine,
                               file_queue=queue.Queue(),
                               config=FileHunter())
        path = Path(service=Service(name=HunterType.local,
                                    host=Host(address="127.0.0.1")),
                    full_path=full_path,
                    file=File(content=content))
        analyzer.analyze(path)

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
                               config=FileHunter())
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

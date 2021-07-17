# -*- coding: utf-8 -*-
""""This file contains all functionality to convert the data of the database into a report."""

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
import csv
import sys
import enum
from database.model import Path
from database.model import File
from database.model import Workspace
from database.model import ReviewResult
from database.core import Engine
from OpenSSL import crypto
from openpyxl import Workbook
from datetime import datetime
from openpyxl.worksheet.table import Table, TableStyleInfo
from openpyxl.worksheet.worksheet import Worksheet
from openpyxl.utils.exceptions import IllegalCharacterError
from typing import List
from sqlalchemy.orm.session import Session


class ExcelReport(enum.Enum):
    relevant = enum.auto()
    certificate = enum.auto()


class _BaseReportGenerator:
    """
    This class implements all base functionality for generating reports
    """

    TRUE = "•"

    def __init__(self,
                 args,
                 session: Session,
                 workspaces: List[Workspace],
                 name: str,
                 description: str,
                 title: str,
                 **kwargs) -> None:
        self._args = args
        self._name = name
        self._session = session
        self._workspaces = workspaces
        self._kwargs = kwargs
        self.description = description
        self.title = title

    def fill_excel_sheet(self,
                         worksheet: Worksheet,
                         csv_list: list,
                         name: str=None,
                         title: str = None,
                         description: str = None) -> None:
        """
        This method adds an additional sheet to the given workbook
        :return:
        """
        start_row = 1
        name = name if name is not None else self._name
        title = title if title is not None else self.title
        description = description if description is not None else self.description
        worksheet.title = name
        if description:
            csv_list.insert(0, [])
            csv_list.insert(0, [description])
            start_row += 2
        if title:
            csv_list.insert(0, [])
            csv_list.insert(0, [title])
            start_row += 2
        for row in csv_list:
            try:
                worksheet.append(row)
            except IllegalCharacterError:
                print("ignoring row due to illegal character: {}".format(row), file=sys.stderr)
            except ValueError:
                raise ValueError("cannot add row to sheet '{}': {}".format(self._name, row))
        dimension = worksheet.calculate_dimension()
        dimension = "A{}:{}".format(start_row, dimension.split(":")[-1])
        table = Table(displayName=self._name.replace(" ", ""), ref=dimension)
        style = TableStyleInfo(name="TableStyleLight8")
        table.tableStyleInfo = style
        worksheet.add_table(table)


class _FileSummaryReportGenerator(_BaseReportGenerator):
    """
    This method creates the report about all relevant files.
    """

    def __init__(self, args, session: Session, workspaces: List[Workspace], **kwargs) -> None:
        super().__init__(args,
                         session,
                         workspaces,
                         name="file summary",
                         title="List of identified relevant files",
                         description="The table provides an overview about all files, which have been identified"
                                     "during the review.",
                         **kwargs)

    def get_csv(self) -> List[List[str]]:
        """
        Method determines whether the given item shall be included into the report
        """
        result = [["Ref.",
                   "Workspace",
                   "Full Path",
                   "Creation Date",
                   "Last Modified",
                   "SHA256 Value",
                   "Comment"]]
        ref = 1
        dedup = {}
        for workspace_str in self._workspaces:
            for file in self._session.query(File) \
                .join(Workspace) \
                .join((Path, File.paths)) \
                .filter(Workspace.name == workspace_str, File.review_result == ReviewResult.relevant).all():
                for path in file.paths:
                    full_path = str(path)
                    if full_path not in dedup:
                        dedup[full_path] = None
                        result.append([ref,
                                       workspace_str,
                                       str(path),
                                       path.creation_time.strftime('%m/%d/%Y %H:%M:%S'),
                                       path.modified_time.strftime('%m/%d/%Y %H:%M:%S'),
                                       file.sha256_value,
                                       file.comment])
                        ref += 1
        return result


class ReportExtension(enum.Enum):
    subjectAltName = enum.auto()
    basicConstraints = enum.auto()
    keyUsage = enum.auto()
    extendedKeyUsage = enum.auto()


class CertificateExtension:
    """
    This class holds certificate extension information
    """
    def __init__(self, extension: crypto.X509Extension):
        self.name = extension.get_short_name().decode()
        self.critical = extension.get_critical() != 0
        self.value = str(extension)


class _CertificateReportGenerator(_BaseReportGenerator):
    """
    This method creates the report about all collected certificates.
    """

    def __init__(self, args, session: Session, workspaces: List[Workspace], **kwargs) -> None:
        super().__init__(args,
                         session,
                         workspaces,
                         name="certificate summary",
                         title="List of identified relevant files",
                         description="The table provides an overview about all files, which have been identified"
                                     "during the review.",
                         **kwargs)

    def _get_certificate(self, file: File) -> crypto.X509:
        result = None
        try:
            result = crypto.load_certificate(crypto.FILETYPE_ASN1, file.content)
        except:
            try:
                result = crypto.load_certificate(crypto.FILETYPE_PEM, file.content)
            except:
                try:
                    result = crypto.load_certificate(crypto.FILETYPE_TEXT, file.content)
                except:
                    pass
        return result

    def get_csv(self) -> List[List[str]]:
        """
        Method determines whether the given item shall be included into the report
        """
        result = [["Ref.",
                   "Workspace",
                   "Review Result",
                   "Full Paths",
                   "Common Name",
                   "Issuer",
                   "Version",
                   "Valid From",
                   "Valid To",
                   "Valid Years",
                   "Has Expired",
                   "Algorithm",
                   "Key Size",
                   "Serial Number",
                   "File DB ID",
                   "Critical Extensions"]]
        result[0] += [item.name for item in ReportExtension]
        date_converter = lambda x: datetime.strptime(x.decode().replace("Z", "UTC"), "%Y%m%d%H%M%S%Z")
        x509_name = lambda x: ", ".join(["{}={}".format(key.decode(), value.decode()) for key, value in x.get_components()])
        ref = 1
        for workspace_str in self._workspaces:
            for file in self._session.query(File) \
                .join(Workspace) \
                .join((Path, File.paths)) \
                .filter(Workspace.name == workspace_str, File.review_result == ReviewResult.relevant).all():
                certificate = self._get_certificate(file)
                row = []
                if certificate:
                    date_from = date_converter(certificate.get_notBefore())
                    date_to = date_converter(certificate.get_notAfter())
                    validity = ((date_to - date_from).total_seconds()) / (3600 * 24 * 365)
                    # Parse extensions
                    extensions = {}
                    for i in range(0, certificate.get_extension_count()):
                        try:
                            extension = CertificateExtension(certificate.get_extension(i))
                            extensions[extension.name] = extension
                        except:
                            pass
                    row = [ref,
                           workspace_str,
                           file.review_result.name,
                           ", ".join([item.full_path for item in file.paths]),
                           x509_name(certificate.get_subject()),
                           x509_name(certificate.get_issuer()),
                           certificate.get_version(),
                           date_from.strftime("%Y-%m-%d %H:%M"),
                           date_to.strftime("%Y-%m-%d %H:%M"),
                           certificate.has_expired(),
                           validity,
                           certificate.get_signature_algorithm().decode(),
                           certificate.get_pubkey().bits(),
                           hex(certificate.get_serial_number())[2:],
                           file.id,
                           ", ".join([item.name for item in extensions.values() if item.critical])]
                    row += [extensions[item.name].value if item.name in extensions else None for item in ReportExtension]
                    result.append(row)
                    ref += 1
        return result


class ReportGenerator:
    """This class creates all reports"""

    def __init__(self, args):
        self._generators = {ExcelReport.relevant.name: _FileSummaryReportGenerator,
                            ExcelReport.certificate.name: _CertificateReportGenerator}
        self._args = args
        self._workspaces = args.workspace
        self._engine = Engine()

    def run(self) -> None:
        """
        This method runs the desired report
        :return:
        """
        if self._args.csv:
            generator = self._generators[self._args.csv]
            with self._engine.session_scope() as session:
                instance = generator(self._args, session, self._workspaces)
                csv_list = instance.get_csv()
                csv_writer = csv.writer(sys.stdout)
                csv_writer.writerows(csv_list)
        if self._args.excel:
            if os.path.exists(self._args.excel):
                os.unlink(self._args.excel)
            workbook = Workbook()
            first = True
            with self._engine.session_scope() as session:
                for generator in self._generators.values():
                    instance = generator(self._args, session, self._workspaces)
                    csv_list = instance.get_csv()
                    if len(csv_list) > 1:
                        if first:
                            instance.fill_excel_sheet(workbook.active, csv_list=csv_list)
                            first = False
                        else:
                            instance.fill_excel_sheet(workbook.create_sheet(), csv_list=csv_list)
            workbook.save(self._args.excel)

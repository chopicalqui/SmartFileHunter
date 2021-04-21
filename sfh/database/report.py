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
from datetime import datetime
from openpyxl import Workbook
from openpyxl.worksheet.table import Table, TableStyleInfo
from openpyxl.worksheet.worksheet import Worksheet
from openpyxl.utils.exceptions import IllegalCharacterError
from typing import List
from sqlalchemy.orm.session import Session


class ExcelReport(enum.Enum):
    file = enum.auto()


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


class _ReportGenerator(_BaseReportGenerator):
    """
    This method creates all reports for hosts
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


class ReportGenerator:
    """This class creates all reports"""

    def __init__(self, args):
        self._generators = {ExcelReport.file.name: _ReportGenerator}
        self._args = args
        self._workspaces = args.workspace
        self._engine = Engine()

    def run(self) -> None:
        """
        This method runs the desired report
        :return:
        """
        if self._args.csv:
            generator = self._generators[ExcelReport.file.name]
            with self._engine.session_scope() as session:
                instance = generator(self._args, session, self._workspaces)
                csv_list = instance.get_csv()
                csv_writer = csv.writer(sys.stdout)
                csv_writer.writerows(csv_list)
        if self._args.excel:
            if os.path.exists(self._args.excel):
                os.unlink(self._args.excel)
            workbook = Workbook()
            generator = self._generators[ExcelReport.file.name]
            first = True
            with self._engine.session_scope() as session:
                instance = generator(self._args, session, self._workspaces)
                csv_list = instance.get_csv()
                if len(csv_list) > 1:
                    if first:
                        instance.fill_excel_sheet(workbook.active, csv_list=csv_list)
                        first = False
                    else:
                        instance.fill_excel_sheet(workbook.create_sheet(), csv_list=csv_list)
            workbook.save(self._args.excel)

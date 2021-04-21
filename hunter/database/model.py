# -*- coding: utf-8 -*-
"""
This file contains all classes for object relational mappings.
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

import os
import re
import hashlib
import magic
import enum
import logging
import hexdump
from sqlalchemy import Column
from sqlalchemy import Integer
from sqlalchemy import Boolean
from sqlalchemy import String
from sqlalchemy import DateTime
from sqlalchemy import ForeignKey
from sqlalchemy import Text
from sqlalchemy import Enum
from sqlalchemy import Table
from sqlalchemy import LargeBinary
from sqlalchemy.orm import relationship
from sqlalchemy.orm import backref
from sqlalchemy import UniqueConstraint
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime
from termcolor import colored
from typing import List

DeclarativeBase = declarative_base()

logger = logging.getLogger('model')


class WorkspaceNotFound(Exception):
    def __init__(self, workspace: str):
        super().__init__("workspace '{}' does not exist in database".format(workspace))


class HunterType(enum.Enum):
    smb = enum.auto()
    ftp = enum.auto()
    nfs = enum.auto()
    local = enum.auto()


class ReviewResult(enum.Enum):
    irrelevant = enum.auto()
    relevant = enum.auto()
    tbd = enum.auto()


class FileRelevance(enum.Enum):
    low = 100
    medium = 80
    high = 70


class MatchRuleAccuracy(enum.Enum):
    low = 100
    medium = 80
    high = 70


class SearchLocation(enum.Enum):
    file_name = 20
    directory_name = 10
    file_content = 0


file_match_rule_mapping = Table("file_match_rule_mapping", DeclarativeBase.metadata,
                                Column("id", Integer, primary_key=True),
                                Column("file_id", Integer, ForeignKey('file.id',
                                                                      ondelete='cascade'), nullable=False),
                                Column("match_rule_id", Integer, ForeignKey('match_rule.id',
                                                                            ondelete='cascade'), nullable=False),
                                Column("creation_date", DateTime, nullable=False, default=datetime.utcnow()),
                                Column("last_modified", DateTime, nullable=True, onupdate=datetime.utcnow()))


class Workspace(DeclarativeBase):
    """This class holds all information about a project."""

    __tablename__ = "workspace"
    id = Column(Integer, primary_key=True)
    name = Column(String(25), nullable=False, unique=True)
    hosts = relationship("Host",
                         backref=backref("workspace"),
                         cascade="delete, delete-orphan",
                         order_by="asc(Host.address)")
    files = relationship("File",
                         backref=backref("workspace"),
                         cascade="all",
                         order_by="desc(File.size_bytes)")
    creation_date = Column(DateTime, nullable=False, default=datetime.utcnow())
    last_modified = Column(DateTime, nullable=True, onupdate=datetime.utcnow())


class Host(DeclarativeBase):
    """This class holds all information about a host."""

    __tablename__ = "host"
    id = Column("id", Integer, primary_key=True)
    address = Column("address", Text, nullable=False, unique=False)
    workspace_id = Column(Integer, ForeignKey("workspace.id", ondelete='cascade'), nullable=False, unique=False)
    creation_date = Column(DateTime, nullable=False, default=datetime.utcnow())
    last_modified = Column(DateTime, nullable=True, onupdate=datetime.utcnow())
    services = relationship("Service",
                            backref=backref("host"),
                            cascade="all, delete-orphan",
                            order_by="asc(Service.port)")
    __table_args__ = (UniqueConstraint('workspace_id', 'address', name='_host_unique'),)


class Service(DeclarativeBase):
    """This class holds all information about a service."""

    __tablename__ = "service"
    id = Column(Integer, primary_key=True)
    port = Column(Integer, nullable=True, unique=False)
    name = Column(Enum(HunterType), nullable=False, unique=False)
    complete = Column(Boolean, nullable=True, unique=False)
    host_id = Column(Integer, ForeignKey("host.id", ondelete='cascade'), nullable=False, unique=False)
    creation_date = Column(DateTime, nullable=False, default=datetime.utcnow())
    last_modified = Column(DateTime, nullable=True, onupdate=datetime.utcnow())
    paths = relationship("Path",
                         backref=backref("service"),
                         cascade="all",
                         order_by="asc(Path._full_path)")
    __table_args__ = (UniqueConstraint("port", "host_id", name="_service_host_unique"),)

    def __repr__(self):
        result = ""
        if self.host:
            if self.name == HunterType.smb:
                result = "//{}".format(self.host.address)
            else:
                result = "{}://{}".format(self.name.name, self.host.address)
            if self.port and (self.name == HunterType.smb and self.port != 445 or
                              self.name == HunterType.ftp and self.port != 21 or
                              self.name == HunterType.nfs and self.port != 2049):
                result += ":{}".format(self.port)
        return result


class Path(DeclarativeBase):
    """This class holds all information about identified paths."""

    __tablename__ = "path"
    id = Column(Integer, primary_key=True)
    _full_path = Column("full_path", Text, nullable=False, unique=False)
    file_name = Column(Text, nullable=False, unique=False)
    extension = Column(Text, nullable=False, unique=False)
    share = Column(Text, nullable=True, server_default='')
    access_time = Column(DateTime, nullable=True)
    modified_time = Column(DateTime, nullable=True)
    creation_time = Column(DateTime, nullable=True)
    service_id = Column(Integer, ForeignKey("service.id", ondelete='cascade'), nullable=False, unique=False)
    file_id = Column(Integer, ForeignKey("file.id", ondelete='cascade'), nullable=True, unique=False)
    creation_date = Column(DateTime, nullable=False, default=datetime.utcnow())
    last_modified = Column(DateTime, nullable=True, onupdate=datetime.utcnow())
    file = relationship("File",
                        backref=backref("paths"),
                        cascade="all",
                        order_by="desc(File.size_bytes)")
    __table_args__ = (UniqueConstraint('full_path', 'share', 'service_id', name='_path_unique'),)

    @property
    def full_path(self) -> str:
        return self._full_path

    @full_path.setter
    def full_path(self, value: str) -> None:
        self.extension = os.path.splitext(value)[1]
        if self.extension:
            self.extension = self.extension.lstrip(".")
        self._full_path = value.replace("\\", "/")
        self.file_name = os.path.basename(self._full_path)

    def __repr__(self):
        result = ""
        if self.service and self.service.host:
            result = str(self.service)
            if self.service.name == HunterType.smb and self.share:
                result += "/{}".format(self.share)
            if self.full_path:
                result += self.full_path if self.full_path[0] == "/" else ("/" + self.full_path)
        return result


class File(DeclarativeBase):
    """This class holds all files"""

    __tablename__ = "file"
    id = Column(Integer, primary_key=True)
    _content = Column("content", LargeBinary, nullable=True, unique=False)
    size_bytes = Column(Integer, nullable=False, unique=False)
    sha256_value = Column(Text, nullable=False, unique=False)
    file_type = Column(Text, nullable=True, unique=False)
    mime_type = Column(Text, nullable=True, unique=False)
    comment = Column(Text, nullable=True, unique=False)
    review_result = Column(Enum(ReviewResult), nullable=True, unique=False)
    workspace_id = Column(Integer, ForeignKey("workspace.id", ondelete='cascade'), nullable=False, unique=False)
    creation_date = Column(DateTime, nullable=False, default=datetime.utcnow())
    last_modified = Column(DateTime, nullable=True, onupdate=datetime.utcnow())
    __table_args__ = (UniqueConstraint('sha256_value', 'workspace_id', name='_file_unique'),)
    matches = relationship("MatchRule",
                           secondary=file_match_rule_mapping,
                           backref=backref("files",
                                           order_by="asc(MatchRule.relevance)"))
    @property
    def content(self) -> bytes:
        return self._content

    @content.setter
    def content(self, value: bytes):
        self._content = value
        self.size_bytes = len(value)
        self.sha256_value = self.calculate_sha256_value(value)
        self.file_type = magic.from_buffer(value)
        self.mime_type = magic.from_buffer(value, mime=True)

    @property
    def review_result_str(self) -> str:
        return self.review_result.name if self.review_result else ReviewResult.tbd.name

    @property
    def review_result_with_color_str(self) -> str:
        result = self.review_result_str
        colors = {"": None,
                  ReviewResult.tbd.name: "blue",
                  ReviewResult.irrelevant.name: "grey",
                  ReviewResult.relevant.name: "red"}
        return colored(result, colors[result], attrs=["bold"])

    def add_match_rule(self, match_rule):
        """
        This method shall be used to add a match rule to tis file
        :param match_rule: The match rule object that shall be added
        :return:
        """
        if match_rule not in self.matches:
            self.matches.append(match_rule)

    @staticmethod
    def calculate_sha256_value(content: bytes) -> str:
        """
        This method calculates the sha256 value of the given content.
        :param content:
        :return:
        """
        return hashlib.sha256(content).hexdigest()

    def get_text(self, color: bool = False, match_rules = []) -> List[str]:
        """
        This method returns the details about the review.
        """
        result = []
        hits_total = 0
        print_bold = lambda x: colored(x, attrs=['bold']) if color else x
        review_result = self.review_result_with_color_str if color else self.review_result_str
        try:
            content = self.content.decode("utf-8")
            for item in match_rules:
                content, hits = item.highlight_text(content)
                hits_total += hits
            result.append(content)
        except:
            try:
                for line in hexdump.dumpgen(self.content):
                    result.append(line)
            except Exception as ex:
                result.append(print_bold("exception while decoding file: {}".format(str(ex))))
                result.append(print_bold("could not print file. try to export and analyze with another program"))
        result.append("")
        result.append("{}       {}".format(print_bold("File ID"), self.id))
        result.append("{}         {}".format(print_bold("Paths"),
                                              "; ".join([str(item) for item in self.paths])))
        result.append("{}     {}".format(print_bold("MIME type"), self.mime_type))
        result.append(print_bold("Match rules"))
        for item in self.matches:
            result.append("- {}".format(item.get_text(color)))
        result.append("{} {}".format(print_bold("Review result"), review_result))
        if self.comment:
            result.append("{}       {}".format(print_bold("Comment"), self.comment))
        if color:
            result.append("{}          {}".format(print_bold("Hits"), colored(hits_total, "red", attrs=["bold"])))
        else:
            result.append("{}          {}".format(print_bold("Hits"), hits_total))
        return result


class MatchRule(DeclarativeBase):
    """This class holds all files"""

    __tablename__ = "match_rule"
    id = Column(Integer, primary_key=True)
    search_location = Column(Enum(SearchLocation), nullable=False, unique=False)
    _search_pattern = Column("search_pattern", Text, nullable=False, unique=False)
    category = Column(Text, nullable=True, unique=False)
    relevance = Column(Enum(FileRelevance), nullable=False, unique=False)
    accuracy = Column(Enum(MatchRuleAccuracy), nullable=False, unique=False)
    creation_date = Column(DateTime, nullable=False, default=datetime.utcnow())
    last_modified = Column(DateTime, nullable=True, onupdate=datetime.utcnow())
    _search_pattern_re = None
    action = None
    __table_args__ = (UniqueConstraint('search_location', 'search_pattern', name='_match_rule_unique'),)

    @property
    def priority(self):
        """Returns the priority of the given rule"""
        result = 0
        if self.search_location and self.relevance and self.accuracy and self.search_pattern:
            result = self.search_location.value + self.relevance.value + self.accuracy.value + len(self.search_pattern)
        return result

    @property
    def search_pattern(self) -> str:
        return self._search_pattern

    @search_pattern.setter
    def search_pattern(self, value: str) -> None:
        self._search_pattern = value
        self._search_pattern_re = re.compile(value.encode("utf-8"), re.IGNORECASE)

    @property
    def search_pattern_re(self):
        if self._search_pattern_re is None:
            self._search_pattern_re = re.compile(self._search_pattern.encode("utf-8"), re.IGNORECASE)
        return self._search_pattern_re

    @property
    def search_pattern_re_text(self):
        if self._search_pattern_re is None:
            self._search_pattern_re = re.compile(self._search_pattern, re.IGNORECASE)
        return self._search_pattern_re

    @property
    def relevance_str(self):
        return self.relevance.name if self.relevance else ""

    @property
    def relevance_with_color_str(self):
        result = self.relevance_str
        colors = {"": None,
                  FileRelevance.high.name: "red",
                  FileRelevance.medium.name: "yellow",
                  FileRelevance.low.name: "blue"}
        return colored(result, colors[result], attrs=["bold"])

    @property
    def accuracy_str(self):
        return self.accuracy.name if self.accuracy else ""

    @property
    def accuracy_with_color_str(self):
        result = self.accuracy_str
        colors = {"": None,
                  MatchRuleAccuracy.high.name: "red",
                  MatchRuleAccuracy.medium.name: "yellow",
                  MatchRuleAccuracy.low.name: "blue"}
        return colored(result, colors[result], attrs=["bold"])

    def __eq__(self, value):
        return self.search_location == value.search_location and self.search_pattern == value.search_pattern

    def is_match(self, path: Path) -> bool:
        """
        This method determines whether the given path object matches this match rule.
        :param path: The path object that is analyzed.
        :return:
        """
        if self.search_location == SearchLocation.file_content:
            result = len(self.search_pattern_re.findall(path.file.content)) > 0
        elif self.search_location == SearchLocation.file_name:
            result = self.search_pattern_re.match(path.file_name.encode("utf-8")) is not None
        elif self.search_location == SearchLocation.directory_name:
            result = self.search_pattern_re.match(path.full_pathencode("utf-8")) is not None
        else:
            raise NotImplementedError("this case is not implemented")
        return result

    @staticmethod
    def from_json(json_object: dict):
        """
        This method converts the given json_object into a MatchRule object
        :param json_object: The json_object containing all information to create a MatchRule object
        :return: The match rule object
        """
        search_location = SearchLocation[json_object["search_location"]]
        category = json_object["category"]
        relevance = FileRelevance[json_object["relevance"]]
        accuracy = MatchRuleAccuracy[json_object["accuracy"]]
        search_pattern = json_object["search_pattern"]
        rule = MatchRule(search_location=search_location,
                         category=category,
                         relevance=relevance,
                         search_pattern=search_pattern,
                         accuracy=accuracy)
        return rule

    def __repr__(self):
        return "priority: {}, category: {}, search_location: {}, relevance: {}, " \
               "accuracy: {}, search_pattern: {}".format(self.priority,
                                                         self.category,
                                                         self.search_location.name,
                                                         self.relevance_str,
                                                         self.accuracy.name,
                                                         self.search_pattern)

    def highlight_text(self, text: str, color: bool = False) -> tuple:
        """
        Highlights the matched text in the given text
        """
        hits = 0
        if self.search_pattern_re_text is not None and text:
            offset = 0
            for item in self.search_pattern_re_text.finditer(text):
                for i, j in item.regs:
                    hits += 1
                    if color:
                        text = text[:i] + colored(text[i:j], color="red", attrs=["bold"]) + text[j:]
                    offset += 1
        return (text, hits)

    def get_text(self, color: bool = False) -> str:
        """
        Returns the current object state as string
        """
        relevance = self.relevance_with_color_str if color else self.relevance_str
        accuracy = self.accuracy_with_color_str if color else self.accuracy_str
        print_bold = lambda x: colored(x, attrs=['bold']) if color else x
        if self.category:
            result = "{}: {}; {}: {}; {}: {}; {}: {}, {}: {}".format(print_bold("search location"),
                                                             self.search_location.name,
                                                             print_bold("pattern"),
                                                             self._search_pattern,
                                                             print_bold("category"),
                                                             self.category,
                                                             print_bold("relevance"),
                                                             relevance,
                                                             print_bold("accuracy"),
                                                             accuracy)
        else:
            result = "{}: {}; {}: {}; {}: {}, {}: {}".format(print_bold("search location"),
                                                     self.search_location.name,
                                                     print_bold("pattern"),
                                                     self._search_pattern,
                                                     print_bold("relevance"),
                                                     relevance,
                                                     print_bold("accuracy"),
                                                     accuracy)
        return result

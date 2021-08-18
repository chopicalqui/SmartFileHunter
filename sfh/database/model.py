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
import enum
import magic
import hashlib
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


class DecodingOption(enum.Enum):
    ignore = enum.auto()
    hexdump = enum.auto()


class FileRelevance(enum.Enum):
    low = 200
    medium = 2000
    high = 20000


class MatchRuleAccuracy(enum.Enum):
    low = 100
    medium = 1000
    high = 10000


class SearchLocation(enum.Enum):
    file_name = 1
    full_path = 1000
    file_content = 10000


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
    shares = relationship("Share",
                          backref=backref("service"),
                          cascade="all",
                          order_by="asc(Share.name)")
    __table_args__ = (UniqueConstraint("port", "host_id", name="_service_host_unique"),)

    def __repr__(self):
        result = ""
        if self.host:
            if self.name == HunterType.smb:
                result = "//{}".format(self.host.address)
            elif self.name != HunterType.local:
                result = "{}://{}".format(self.name.name, self.host.address)
            if self.port and (self.name == HunterType.smb and self.port != 445 or
                              self.name == HunterType.ftp and self.port != 21 or
                              self.name == HunterType.nfs and self.port != 2049):
                result += ":{}".format(self.port)
        return result


class Share(DeclarativeBase):
    """This class holds all information about identified shares."""

    __tablename__ = "share"
    id = Column(Integer, primary_key=True)
    name = Column(Text, nullable=False, unique=False)
    complete = Column(Boolean, nullable=True, unique=False, server_default='false')
    service_id = Column(Integer, ForeignKey("service.id", ondelete='cascade'), nullable=False, unique=False)
    paths = relationship("Path",
                         backref=backref("share"),
                         cascade="all",
                         order_by="asc(Path._full_path)")
    __table_args__ = (UniqueConstraint("name", "service_id", name="_share_service_unique"),)

    def __repr__(self):
        result = ""
        if self.service and self.service.host:
            result = str(self.service)
            if self.service.name == HunterType.smb:
                result += "/{}".format(self.name)
        return result


class Path(DeclarativeBase):
    """This class holds all information about identified paths."""

    __tablename__ = "path"
    id = Column(Integer, primary_key=True)
    _full_path = Column("full_path", Text, nullable=False, unique=False)
    file_name = Column(Text, nullable=False, unique=False)
    extension = Column(Text, nullable=False, unique=False)
    access_time = Column(DateTime, nullable=True)
    modified_time = Column(DateTime, nullable=True)
    creation_time = Column(DateTime, nullable=True)
    service_id = Column(Integer, ForeignKey("service.id", ondelete='cascade'), nullable=False, unique=False)
    share_id = Column(Integer, ForeignKey("share.id", ondelete='cascade'), nullable=True, unique=False)
    file_id = Column(Integer, ForeignKey("file.id", ondelete='cascade'), nullable=True, unique=False)
    creation_date = Column(DateTime, nullable=False, default=datetime.utcnow())
    last_modified = Column(DateTime, nullable=True, onupdate=datetime.utcnow())
    file = relationship("File",
                        backref=backref("paths"),
                        cascade="all",
                        order_by="desc(File.size_bytes)")
    __table_args__ = (UniqueConstraint('full_path', 'share_id', 'service_id', name='_path_unique'),)

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
        if self.share:
            result = str(self.share)
        elif self.service and self.service.host:
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
                                           order_by="asc(MatchRule._relevance)"))
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

    @staticmethod
    def apply_highlights(text: str,
                         markers: list,
                         summarize: bool = True,
                         color: bool = False,
                         extra_characters_before: int = 30,
                         extra_characters_after: int = 30) -> str:
        """
        This method color-codes the text based on the given marker ranges.
        """
        if not markers:
            return text
        if color:
            color_code = lambda x: colored(x, "red",  attrs=['bold'])
        else:
            color_code = lambda x: x
        result = ""
        text_length = len(text) - 1
        current_position = 0
        markers.sort()
        if summarize:
            for i, j in markers:
                # Compile before highlights
                start_position = i - extra_characters_before
                if start_position < 0:
                    start_position = 0
                else:
                    result += "[...]"
                current_text = text[start_position:i]
                # Compile highlights
                current_text += color_code(text[i:j])
                # Compile after highlights
                end_position = j + extra_characters_after
                if end_position > text_length:
                    current_text += text[j:]
                else:
                    current_text += text[j:end_position] + "[...]"
                if current_text[-1] != os.linesep:
                    current_text += os.linesep
                result += current_text
        else:
            for i, j in markers:
                result += text[current_position:i]
                result += color_code(text[i:j])
                current_position = j
            result += text[current_position:]
        return result

    def get_text(self,
                 decoding: DecodingOption,
                 color: bool = False,
                 summarize: bool = False,
                 match_rules: list = [],
                 threshold: int = 0) -> List[str]:
        """
        This method returns the details about the review.
        """
        result = []
        markers = []
        decoding_successful = False
        print_bold = lambda x: colored(x, attrs=['bold']) if color else x
        review_result = self.review_result_with_color_str if color else self.review_result_str
        # Try to decode file content
        try:
            file_content = self.content.decode("utf-8")
            decoding_successful = True
        except:
            try:
                if decoding == DecodingOption.ignore:
                    file_content = self.content.decode(errors="ignore")
                else:
                    file_content = os.linesep.join([line for line in hexdump.dumpgen(self.content)])
            except Exception as ex:
                result.append(print_bold("exception while decoding file: {}".format(str(ex))))
                result.append(print_bold("could not print file. try to export and analyze with another program"))
                file_content = None
        if file_content:
            for item in match_rules:
                markers = item.get_text_markers(file_content, markers)
            file_content = self.apply_highlights(file_content,
                                                 markers=markers,
                                                 summarize=summarize and decoding != DecodingOption.hexdump,
                                                 color=color)
        result.append(file_content)
        result.append("")
        result.append("{}       {}".format(print_bold("File ID"), self.id))
        result.append("{}         {}".format(print_bold("Paths"),
                                             "; ".join([str(item) for item in self.paths])))
        result.append("{}     {}".format(print_bold("MIME type"), self.mime_type))
        if threshold:
            result.append("{}     {} ({})".format(print_bold("File size"),
                                                  self.size_bytes,
                                                  "<= threshold" if self.size_bytes < threshold else "> threshold"))
        else:
            result.append("{}     {}".format(print_bold("File size"), self.size_bytes))
        result.append(print_bold("Match rules"))
        for item in self.matches:
            result.append("- {}".format(item.get_text(color)))
        result.append("{} {}".format(print_bold("Review result"), review_result))
        if self.comment:
            result.append("{}       {}".format(print_bold("Comment"), self.comment))
        if color:
            result.append("{}      {}".format(print_bold("Decoding"),
                                              "Successful" if decoding_successful else colored("Failed", "red", attrs=["bold"])))
            result.append("{}          {}".format(print_bold("Hits"), colored(len(markers), "red", attrs=["bold"])))
        else:
            result.append("{}          {}".format(print_bold("Hits"), len(markers)))
            result.append("{}      {}".format(print_bold("Decoding"),
                                              "Successful" if decoding_successful else "Failed"))
        return result


class MatchRule(DeclarativeBase):
    """This class holds all files"""

    __tablename__ = "match_rule"
    id = Column(Integer, primary_key=True)
    _search_location = Column("search_location", Integer, nullable=False, unique=False)
    _search_pattern = Column("search_pattern", Text, nullable=False, unique=False)
    category = Column(Text, nullable=True, unique=False)
    _relevance = Column("relevance", Integer, nullable=False, unique=False)
    _accuracy = Column("accuracy", Integer, nullable=False, unique=False)
    creation_date = Column(DateTime, nullable=False, default=datetime.utcnow())
    last_modified = Column(DateTime, nullable=True, onupdate=datetime.utcnow())
    _search_pattern_re = None
    action = None
    __table_args__ = (UniqueConstraint('search_location', 'search_pattern', name='_match_rule_unique'),)

    @property
    def priority(self):
        """Returns the priority of the given rule"""
        result = 0
        if self._search_location and self._relevance and self._accuracy and self.search_pattern:
            result = self._search_location + self._relevance + self._accuracy + len(self.search_pattern)
        return result

    @property
    def search_pattern(self) -> str:
        return self._search_pattern

    @search_pattern.setter
    def search_pattern(self, value: str) -> None:
        self._search_pattern = value
        self._search_pattern_re = re.compile(value.encode("utf-8"), re.IGNORECASE)

    @property
    def search_location(self):
        result = None
        if self._search_location:
            result = SearchLocation(self._search_location)
        return result

    @search_location.setter
    def search_location(self, value):
        if value:
            self._search_location = value.value

    @property
    def relevance(self) -> FileRelevance:
        result = None
        if self._relevance:
            result = FileRelevance(self._relevance)
        return result

    @relevance.setter
    def relevance(self, value: FileRelevance):
        if value:
            self._relevance = value.value

    @property
    def accuracy(self) -> MatchRuleAccuracy:
        result = None
        if self._accuracy:
            result = MatchRuleAccuracy(self._accuracy)
        return result

    @accuracy.setter
    def accuracy(self, value: MatchRuleAccuracy):
        if value:
            self._accuracy = value.value

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
        return self.relevance.name if self._relevance else ""

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
        elif self.search_location == SearchLocation.full_path:
            result = self.search_pattern_re.match(path.full_path.encode("utf-8")) is not None
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

    def get_text_markers(self, text: str, known_markers: list = []) -> list:
        """
        This method searches the given text for a matches and returns a list of tuples documenting the
        locations where the matches started and stopped.
        :param text: The text that is searched.
        :param known_markers: Markers that have previously already identified.
        """
        result = list(known_markers)
        if self.search_pattern_re_text is not None and text:
            for item in self.search_pattern_re_text.finditer(text):
                if known_markers:
                    for new_index in range(0, len(item.regs)):
                        i, j = item.regs[new_index]
                        for current_index in range(0, len(result)):
                            k, m = result[current_index]
                            if i <= k and j >= m:
                                result[current_index] = (i, j)
                                break
                            elif k <= i <= m and k <= j <= m:
                                break
                            elif k <= i <= m and j >= m:
                                result[current_index] = (k, j)
                                break
                            elif i <= k and k <= j <= m:
                                result[current_index] = (i, m)
                                break
                        else:
                            result.append((i, j))
                elif item.regs:
                    result.extend(item.regs)
        return result

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

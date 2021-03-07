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
import sqlalchemy as sa
from sqlalchemy import Column
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy import DateTime
from sqlalchemy import ForeignKey
from sqlalchemy import Text
from sqlalchemy import Enum
from sqlalchemy import Table
from sqlalchemy.ext.mutable import Mutable
from sqlalchemy.orm import relationship
from sqlalchemy.orm import backref
from sqlalchemy import UniqueConstraint
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.dialects.postgresql import BYTEA
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

DeclarativeBase = declarative_base()

logger = logging.getLogger('model')


class WorkspaceNotFound(Exception):
    def __init__(self, workspace: str):
        super().__init__("workspace '{}' does not exist in database".format(workspace))


class ReviewResult(enum.Enum):
    unreviewed = enum.auto()
    irrelevant = enum.auto()
    relevant = enum.auto()
    tbd = enum.auto()


class ImportAction(enum.Enum):
    full_import = enum.auto()
    path_only = enum.auto()


class FileRelevance(enum.Enum):
    low = 100
    medium = 80
    high = 70


class SearchLocation(enum.Enum):
    file_name = 20
    directory_name = 10
    file_content = 0


class CastingArray(ARRAY):
    def bind_expression(self, bindvalue):
        return sa.cast(bindvalue, self)


class MutableList(Mutable, list):
    def append(self, value):
        list.append(self, value)
        self.changed()

    @classmethod
    def coerce(cls, key, value):
        if not isinstance(value, MutableList):
            if isinstance(value, list):
                return MutableList(value)
            return Mutable.coerce(key, value)
        else:
            return value


class MutableDict(Mutable, dict):
    @classmethod
    def coerce(cls, key, value):
        "Convert plain dictionaries to MutableDict."
        if not isinstance(value, MutableDict):
            if isinstance(value, dict):
                return MutableDict(value)

            # this call will raise ValueError
            return Mutable.coerce(key, value)
        else:
            return value

    def __setitem__(self, key, value):
        "Detect dictionary set events and emit change events."
        dict.__setitem__(self, key, value)
        self.changed()

    def __delitem__(self, key):
        "Detect dictionary del events and emit change events."
        dict.__delitem__(self, key)
        self.changed()


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
    address = Column("address", INET, nullable=False, unique=False)
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
    port = Column(Integer, nullable=False, unique=False)
    name = Column(String(10), nullable=True, unique=False)
    host_id = Column(Integer, ForeignKey("host.id", ondelete='cascade'), nullable=True, unique=False)
    creation_date = Column(DateTime, nullable=False, default=datetime.utcnow())
    last_modified = Column(DateTime, nullable=True, onupdate=datetime.utcnow())
    paths = relationship("Path",
                         backref=backref("service"),
                         cascade="all",
                         order_by="asc(Path._full_path)")
    __table_args__ = (UniqueConstraint("port", "host_id", name="_service_host_unique"),)


class Path(DeclarativeBase):
    """This class holds all information about identified paths."""

    __tablename__ = "path"
    id = Column(Integer, primary_key=True)
    _full_path = Column("full_path", Text, nullable=False, unique=False)
    file_name = Column(Text, nullable=False, unique=False)
    extension = Column(Text, nullable=False, unique=False)
    share = Column(Text, nullable=True)
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
        self._full_path = value.replace("\\", "/")
        self.file_name = os.path.basename(self._full_path)


class File(DeclarativeBase):
    """This class holds all files"""

    __tablename__ = "file"
    id = Column(Integer, primary_key=True)
    _content = Column("content", BYTEA, nullable=True, unique=False)
    size_bytes = Column(Integer, nullable=False, unique=False)
    sha256_value = Column(Text, nullable=False, unique=False)
    file_type = Column(Text, nullable=True, unique=False)
    mime_type = Column(Text, nullable=True, unique=False)
    review_result = Column(Enum(ReviewResult), nullable=False, unique=False, default=ReviewResult.unreviewed)
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
        self.sha256_value = hashlib.sha256(value).hexdigest()
        self.file_type = magic.from_buffer(value)
        self.mime_type = magic.from_buffer(value, mime=True)

    def add_match_rule(self, match_rule):
        """
        This method shall be used to add a match rule to tis file
        :param match_rule: The match rule object that shall be added
        :return:
        """
        if match_rule not in self.matches:
            self.matches.append(match_rule)

    def __repr__(self) -> str:
        return "<File sha256_value='{}' file_type='{}' mime_type='{}' />".format(self.sha256_value,
                                                                                 self.file_type,
                                                                                 self.mime_type)


class MatchRule(DeclarativeBase):
    """This class holds all files"""

    __tablename__ = "match_rule"
    id = Column(Integer, primary_key=True)
    search_location = Column(Enum(SearchLocation), nullable=False, unique=False)
    _search_pattern = Column("search_pattern", Text, nullable=False, unique=False)
    category = Column(Text, nullable=True, unique=False)
    relevance = Column(Enum(FileRelevance), nullable=False, unique=False)
    creation_date = Column(DateTime, nullable=False, default=datetime.utcnow())
    last_modified = Column(DateTime, nullable=True, onupdate=datetime.utcnow())
    search_pattern_re = None
    priority = None
    action = None
    __table_args__ = (UniqueConstraint('search_location', 'search_pattern', name='_match_rule_unique'),)

    @property
    def search_pattern(self) -> str:
        return self._search_pattern

    @search_pattern.setter
    def search_pattern(self, value: str) -> None:
        self._search_pattern = value
        self.search_pattern_re = re.compile(value, re.IGNORECASE)

    def __eq__(self, value):
        return self.search_location == value.search_location and self.search_pattern == value.search_pattern

    def is_match(self, path: Path) -> bool:
        """
        This method determines whether the given path object matches this match rule.
        :param path: The path object that is analyzed.
        :return:
        """
        if self.search_location == SearchLocation.file_content:
            result = len(self.search_pattern_re.findall(path.file.content.decode('utf-8'))) > 0
        elif self.search_location == SearchLocation.file_name:
            result = self.search_pattern_re.match(path.file_name) is not None
        elif self.search_location == SearchLocation.directory_name:
            result = self.search_pattern_re.match(path.full_path) is not None
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
        search_pattern = json_object["search_pattern"]
        action = ImportAction[json_object["action"]]
        priority = search_location.value + relevance.value
        rule = MatchRule(search_location=search_location,
                         category=category,
                         relevance=relevance,
                         search_pattern=search_pattern,
                         action=action,
                         priority=priority)
        return rule
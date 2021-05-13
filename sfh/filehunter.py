#!/usr/bin/env python3

"""
this application can be used to search FTP, NFS, or CIFS file services for interesting files
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

import sys
import ftplib
import logging
import argparse
import tempfile
import impacket
from queue import Queue
from database.core import Engine
from database.core import DeclarativeBase
from database.setup import SetupTask
from database.setup import ManageDatabase
from database.review import ReviewConsole
from database.report import ReportGenerator
from database.model import WorkspaceNotFound
from database.model import HunterType
from database.model import Host
from database.model import Service
from database.model import Workspace
from config.config import DatabaseType
from hunters.analyzer.core import FileAnalzer
from hunters.modules.smb import SmbSensitiveFileHunter
from hunters.modules.ftp import FtpSensitiveFileHunter
from hunters.modules.nfs import NfsSensitiveFileHunter
from hunters.modules.local import LocalSensitiveFileHunter
from config.config import FileHunter as FileHunterConfig

logger = logging.getLogger("main")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-l", "--list", action='store_true', help="list existing workspaces")
    parser.add_argument("-i", "--ignore", action='store_true', help="if workspace does not exist, then automatically"
                                                                    "add it")
    parser.add_argument("--nocolor", action='store_true', help="disable color coding")
    parser.add_argument("-d", "--debug", action='store_true', help="print debug messages to standard output")
    parser.add_argument("-v", "--verbose", action='store_true', help="print additional information (e.g., stack traces "
                                                                     "or banner information)")
    parser.add_argument("--log", metavar="FILE", type=str, help="log messages to the given file")
    sub_parser = parser.add_subparsers(help='list of available file hunter modules', dest="module")
    parser_database = sub_parser.add_parser('db', help='allows managing the database')
    if not FileHunterConfig.is_docker():
        parser_setup = sub_parser.add_parser('setup', help='allows setting up smart file hunter')
    parser_review = sub_parser.add_parser('review', help='start file hunter console')
    parser_report = sub_parser.add_parser("report", help='obtain reports about the collected data')
    # setup database parser
    parser_database.add_argument('-a', '--add',
                                 type=str,
                                 help="create the given workspace")
    parser_database.add_argument("--init",
                                 help="creates tables, views, functions, and triggers in the filehunter database",
                                 action="store_true")
    parser_database.add_argument("--drop",
                                 help="drops tables, views, functions, and triggers in the filehunter database",
                                 action="store_true")
    parser_database.add_argument("--backup", metavar="FILE", type=str, help="writes database backup to FILE")
    parser_database.add_argument("--restore", metavar="FILE", type=str, help="restores database backup from FILE")
    # setup SFH parser
    if not FileHunterConfig.is_docker():
        parser_setup_db = parser_setup.add_mutually_exclusive_group()
        parser_setup_db.add_argument("--{}".format(DatabaseType.postgresql.name),
                                     action="store_true",
                                     help="setup a PostgreSQL database")
        parser_setup_db.add_argument("--{}".format(DatabaseType.sqlite.name),
                                     action="store_true",
                                     help="setup a SQLite database")
        parser_setup.add_argument("--debug", action="store_true", help="only print but do not execute commands")
        choices = [item.name.replace("_", "-") for item in SetupTask]
        parser_setup.add_argument("--tasks", nargs="+", choices=choices, default=choices)
    # setup console parser
    parser_review.add_argument('-w', '--workspace',
                               required=True,
                               type=str,
                               help='the workspace used for the enumeration')
    # setup report parser
    parser_report.add_argument('-w', '--workspace',
                               nargs="+",
                               type=str,
                               required=True,
                               help='the workspace used for the enumeration')
    parser_report.add_argument('-e', '--excel', type=str, help="write report to given excel file")
    parser_report.add_argument('-c', '--csv', action="store_true", help="print report results to stdout as CSV")

    # setup SMB parser
    parser_smb = sub_parser.add_parser(HunterType.smb.name, help='enumerate SMB services')
    SmbSensitiveFileHunter.add_argparse_arguments(parser_smb)

    # setup FTP parser
    parser_ftp = sub_parser.add_parser(HunterType.ftp.name,
                                       help='enumerate FTP services. note that the FTP service must support the MLSD '
                                            'command')
    FtpSensitiveFileHunter.add_argparse_arguments(parser_ftp)

    # setup NFS parser
    parser_nfs = sub_parser.add_parser(HunterType.nfs.name, help='enumerate NFS services')
    NfsSensitiveFileHunter.add_argparse_arguments(parser_nfs)

    # setup local parser
    parser_local = sub_parser.add_parser(HunterType.local.name, help='enumerate local file system')
    LocalSensitiveFileHunter.add_argparse_arguments(parser_local)
    args = parser.parse_args()
    
    level = logging.DEBUG if args.debug else logging.INFO
    handlers = [logging.StreamHandler()]
    if args.log:
        handlers.append(logging.FileHandler(args.log))
    logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S',
                        level=level,
                        handlers=handlers)

    if len(sys.argv) <= 1:
        parser.print_help()
        sys.exit(1)

    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            enumeration_class = None
            if args.list:
                engine = Engine()
                DeclarativeBase.metadata.bind = engine.engine
                engine.print_workspaces()
            elif args.module in ["db", "setup"]:
                ManageDatabase(args).run()
            elif args.module == "review":
                if args.workspace:
                    engine = Engine()
                    with engine.session_scope() as session:
                        engine.get_workspace(session=session, name=args.workspace, ignore=args.ignore)
                ReviewConsole(args=args).cmdloop()
            elif args.module == "report":
                if args.workspace:
                    engine = Engine()
                    with engine.session_scope() as session:
                        for workspace in args.workspace:
                            engine.get_workspace(session=session, name=workspace, ignore=args.ignore)
                ReportGenerator(args=args).run()
            elif args.module == HunterType.smb.name:
                enumeration_class = SmbSensitiveFileHunter
            elif args.module == HunterType.ftp.name:
                enumeration_class = FtpSensitiveFileHunter
            elif args.module == HunterType.nfs.name:
                enumeration_class = NfsSensitiveFileHunter
            elif args.module == HunterType.local.name:
                enumeration_class = LocalSensitiveFileHunter
            if enumeration_class:
                analyzers = []
                engine = Engine()
                config = FileHunterConfig(domain_names=args.domains)
                file_queue = Queue(maxsize=20)
                DeclarativeBase.metadata.bind = engine.engine
                # Check wheather name space exists
                with engine.session_scope() as session:
                    workspace = engine.get_workspace(session=session, name=args.workspace, ignore=args.ignore)
                # Create analysis/consumer threads
                for i in range(args.threads):
                    analyzer = FileAnalzer(args=args, engine=engine, file_queue=file_queue, config=config)
                    analyzers.append(analyzer)
                    analyzer.start()
                hunter = enumeration_class(args, engine=engine, file_queue=file_queue, config=config, temp_dir=temp_dir)
                hunter.enumerate()
                if args.verbose:
                    logger.info("consumer thread finished enumeration. current queue "
                                "size: {:>2d}".format(file_queue.qsize()))
                file_queue.join()
                if args.verbose:
                    # print statistics
                    for item in analyzers:
                        logger.info("completed consumer " + str(item))
                    with engine.session_scope() as session:
                        service = session.query(Service) \
                            .join(Host) \
                            .join(Workspace) \
                            .filter(Workspace.name == args.workspace,
                                    Host.address == hunter.address,
                                    Service.port == hunter.port).one()
                        service.complete = True
    except WorkspaceNotFound as ex:
        pass
    except ftplib.error_perm:
        logger.error("FTP login failed", exc_info=args.verbose)
    except impacket.smbconnection.SessionError:
        logger.error("SMB login failed", exc_info=args.verbose)
    except NotADirectoryError:
        logger.error("Given item is not a directory", exc_info=args.verbose)
    except Exception as ex:
        logger.error("execution failed", exc_info=args.verbose)

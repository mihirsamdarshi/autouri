#!/usr/bin/env python3
from __future__ import annotations

import argparse
import logging
import os
import sys

from .autouri import AutoURI, URIBase
from .gcsuri import GCSURI
from .s3uri import S3URI

logger = logging.getLogger(__name__)


DEFAULT_RMDIR_NTH = 6


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument("-v", "--version", action="store_true", help="Show version")

    parent_all = argparse.ArgumentParser(add_help=False)
    group_log_level = parent_all.add_mutually_exclusive_group()
    group_log_level.add_argument(
        "-D", "--debug", action="store_true", help="Prints all logs >= DEBUG level"
    )

    parent_src = argparse.ArgumentParser(add_help=False)
    parent_src.add_argument("src", help="Source file URI")

    parent_lock = argparse.ArgumentParser(add_help=False)
    parent_lock.add_argument(
        "--no-lock", action="store_true", help="No file locking for write/rm action."
    )

    parent_target = argparse.ArgumentParser(add_help=False)
    parent_target.add_argument(
        "target",
        help="Target file/directory URI (e.g. gs://here/me.txt, s3://here/my-dir/) ."
        "Directory must have a trailing directory separator "
        "(e.g. /hello/. gs://where/am/i/).",
    )

    parent_cp = argparse.ArgumentParser(add_help=False)
    parent_cp.add_argument(
        "--use-gsutil-for-s3",
        action="store_true",
        help="Use gsutil for DIRECT TRANSFER between gs:// and s3://. "
        "gsutil must be installed and configured to have AWS credentials "
        'in ~/.boto file. Run "gsutil config" do generate it.',
    )
    parent_cp.add_argument(
        "--make-md5-file",
        action="store_true",
        help="Make .md5 file to store file's md5 hexadecimal string. "
        "This file can be used later to prevent repeated md5sum calculation. "
        "This is for local path only since cloud URIs already provide md5 hash "
        "info in HTTP headers.",
    )

    subparser = parser.add_subparsers(dest="action")

    subparser.add_parser(
        "metadata",
        help="AutoURI(src).get_metadata(): Get metadata of source.",
        parents=[parent_src, parent_all],
    )

    subparser.add_parser(
        "cp",
        help="AutoURI(src).cp(target): Copy source to target. "
        "target must be a full filename/directory. "
        "Target directory must have a trailing directory separator "
        "(e.g. /)",
        parents=[parent_src, parent_lock, parent_target, parent_cp, parent_all],
    )
    subparser.add_parser(
        "find",
        help="AutoURI(src).find_all_files(): Recursively list all files (not sub-directories) "
        "on source (directory).",
        parents=[parent_src, parent_all],
    )

    subparser.add_parser(
        "read",
        help="AutoURI(src).read(): Read from source.",
        parents=[parent_src, parent_all],
    )

    p_write = subparser.add_parser(
        "write",
        help="AutoURI(src).write(text): Write text on source.",
        parents=[parent_src, parent_lock, parent_all],
    )
    p_write.add_argument("text", help="Text to be written to source file.")

    subparser.add_parser(
        "rm",
        help="AutoURI(src).rm(): Delete source.",
        parents=[parent_src, parent_lock, parent_all],
    )

    p_rmdir = subparser.add_parser(
        "rmdir",
        help="AutoURI(src).rmdir(): Recursively delete all files on source directory.",
        parents=[parent_src, parent_lock, parent_all],
    )
    p_rmdir.add_argument("--delete", action="store_true", help="DELETE outputs.")
    p_rmdir.add_argument(
        "-t",
        "--num-threads",
        default=URIBase.DEFAULT_NUM_THREADS,
        type=int,
        help="Number of threads used for deleting "
        "multiple files on cloud buckets (gs://, s3://).",
    )

    p_loc = subparser.add_parser(
        "loc",
        help="AutoURI(src).localize_on(target): Localize source on target directory "
        "Target directory must end with directory separator",
        parents=[parent_src, parent_target, parent_cp, parent_lock, parent_all],
    )
    p_loc.add_argument(
        "--recursive",
        action="store_true",
        help="Recursively localize source into target directory.",
    )

    p_presign = subparser.add_parser(
        "presign",
        help="AutoURI(src).get_presigned_url(). For cloud-based URIs only.",
        parents=[parent_src, parent_all],
    )
    p_presign.add_argument(
        "--gcp-private-key-file",
        help="GCP private key file (JSON format) to presign gs:// URIs.",
    )
    p_presign.add_argument("--duration", type=int, help="Duration of presigned URL in seconds.")

    if len(sys.argv[1:]) == 0:
        parser.print_help()
        parser.exit()

    args = parser.parse_args()
    if args.version:
        parser.exit()

    log_level = "DEBUG" if args.debug else "INFO"
    logging.basicConfig(
        level=log_level, format="%(asctime)s|%(name)s|%(levelname)s| %(message)s"
    )
    # suppress filelock logging
    logging.getLogger("filelock").setLevel("CRITICAL")

    return args


def get_local_path_if_valid(s) -> str:
    abspath = str(os.path.abspath(os.path.expanduser(s)))
    dirname = os.path.dirname(abspath)
    if os.path.isdir(abspath):
        return abspath + os.sep
    if os.path.exists(abspath) or os.path.exists(dirname):
        return abspath
    return s


def main() -> None:
    args = parse_args()

    src = get_local_path_if_valid(args.src)

    if args.action in ("cp", "loc"):
        if args.use_gsutil_for_s3:
            GCSURI.init_gcsuri(use_gsutil_for_s3=True)
        target = get_local_path_if_valid(args.target)

    if args.action == "metadata":
        AutoURI(src).get_metadata()

    elif args.action == "cp":
        u_src = AutoURI(src)
        _, flag = u_src.cp(
            target,
            make_md5_file=args.make_md5_file,
            return_flag=True,
            no_lock=args.no_lock,
        )

        if flag == 0:
            logger.info(f"Copying from file {src} to {target} done")
        elif flag:
            if flag == 1:
                reason = "skipped due to md5 hash match"
            elif flag == 2:
                reason = "skipped due to filename/size match and mtime test"
            else:
                raise NotImplementedError
            logger.info(f"Copying from file {src} to {target} {reason}")
    elif args.action == "read":
        AutoURI(src).read()

    elif args.action == "find":
        for _uri in AutoURI(src).find_all_files():
            pass

    elif args.action == "write":
        AutoURI(src).write(args.text, no_lock=args.no_lock)
        logger.info(f"Text has been written to {src}")

    elif args.action == "rm":
        u = AutoURI(src)
        if not u.exists:
            msg = f"File does not exist. {src}"
            raise ValueError(msg)
        u.rm(no_lock=args.no_lock)
        logger.info(f"Deleted {src}")

    elif args.action == "rmdir":
        AutoURI(src).rmdir(
            dry_run=not args.delete, num_threads=args.num_threads, no_lock=args.no_lock
        )
        if not args.delete:
            logger.warning(
                "rmdir ran in a dry-run mode. Use --delete to DELETE ALL FILES on a directory."
            )

    elif args.action == "loc":
        _, localized = AutoURI(src).localize_on(
            target,
            recursive=args.recursive,
            make_md5_file=args.make_md5_file,
            return_flag=True,
            no_lock=args.no_lock,
        )
        if localized:
            logger.info(f"Localized {src} on {target}")
        else:
            logger.info(f"No need to localize {src} on {target}")

    elif args.action == "presign":
        u = AutoURI(src)

        if isinstance(u, GCSURI):
            if not args.gcp_private_key_file:
                msg = "GCP private key file (--gcp-private-key-file) not found."
                raise ValueError(msg)
            u.get_presigned_url(
                duration=args.duration, private_key_file=args.gcp_private_key_file
            )

        elif isinstance(u, S3URI):
            u.get_presigned_url(duration=args.duration)

        else:
            msg = "Presigning URL is available for cloud URIs (gs://, s3://) only."
            raise ValueError(msg)


if __name__ == "__main__":
    main()

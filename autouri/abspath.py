"""Local filesystem implementation for AutoURI.

Important update to allow relative path for some file extensions:
As AbsPath's name implies, it was originally designed to have an absolute path only.
but will allow relative path of a file if it exists on CWD and has an allowed extension
(,json, .csv, .tsv). Such relative path will be automatically converted to absolute path.
"""

from __future__ import annotations

import errno
import glob
import hashlib
import logging
import os
import shutil
from shutil import SameFileError, copyfile

from filelock import SoftFileLock

from .autouri import AutoURI, URIBase
from .metadata import URIMetadata

logger = logging.getLogger(__name__)

EXTS_ALLOWED_FOR_RELPATH_TO_ABSPATH_CONVERSION = (".json", ".csv", ".tsv")


def convert_relpath_to_abspath_if_valid(
    rel_path,
    base_dir=os.getcwd(),
    allowed_exts=EXTS_ALLOWED_FOR_RELPATH_TO_ABSPATH_CONVERSION,
):
    """Valid means it is an existing file with an extensions in allowed_exts."""
    if os.path.isabs(rel_path):
        return rel_path
    abs_path = os.path.join(base_dir, rel_path)
    if (
        os.path.exists(abs_path)
        and os.path.isfile(abs_path)
        and abs_path.endswith(allowed_exts)
    ):
        return abs_path
    return rel_path


class AbsPath(URIBase):
    """
    File-path based implementation of URIBase.

    Class constants:
        LOC_PREFIX (inherited):
            Path prefix for localization. Inherited from URIBase class.
        MAP_PATH_TO_URL:
            Dict to replace path prefix with URL prefix.
            Useful to convert absolute path into URL on a web server.
        MD5_CALC_CHUNK_SIZE:
            Chunk size to calculate md5 hash of a local file.
    """

    MAP_PATH_TO_URL: dict[str, str] = {}
    MD5_CALC_CHUNK_SIZE: int = 4096

    _LOC_SUFFIX = ".local"
    _PATH_SEP = os.sep

    def __init__(self, uri, thread_id=-1) -> None:
        if isinstance(uri, str):
            uri = os.path.expanduser(uri)

        super().__init__(uri, thread_id=thread_id)

        self._uri = convert_relpath_to_abspath_if_valid(self._uri)

    @property
    def is_valid(self):
        return os.path.isabs(self._uri)

    def rmdir(self, dry_run: bool = False, num_threads: int = 1, no_lock: bool = False) -> None:
        """Do `rm -rf` instead of deleting individual files.

        For dry-run mode, call base class' method to show files to be deleted.
        """
        if not os.path.exists(self._uri):
            msg = f"Directory does not exist. deleted already? {self._uri}"
            raise FileNotFoundError(msg)
        if dry_run:
            super().rmdir(dry_run=True, num_threads=num_threads, no_lock=no_lock)
        else:
            shutil.rmtree(self._uri)

    def _get_lock(self, timeout=None, poll_interval=None):
        """Use filelock.SoftFileLock for AbsPath.

        filelock.SoftFileLock watches a .lock file with faster polling.
        It's stable and also platform-independent

        Args:
            poll_interval:
                This is dummy.
                Fixed polling rate defined in BaseFileLock is used.
        """
        if timeout is None:
            timeout = AbsPath.LOCK_TIMEOUT
        # create directory and use default poll_interval
        u_lock = AbsPath(self._uri + AbsPath.LOCK_FILE_EXT)
        u_lock.mkdir_dirname()
        return SoftFileLock(u_lock._uri, timeout=timeout)

    def get_metadata(self, skip_md5=False, make_md5_file=False):
        """If md5 file doesn't exist then use hashlib.md5() to calculate md5 hash."""
        exists = os.path.exists(self._uri)
        mt, sz, md5 = None, None, None
        if exists:
            mt = os.path.getmtime(self._uri)
            sz = os.path.getsize(self._uri)
            if not skip_md5:
                md5 = self.md5_from_file
                if md5 is None:
                    md5 = self.__calc_md5sum()
                if make_md5_file:
                    self.md5_file_uri.write(md5)

        return URIMetadata(exists=exists, mtime=mt, size=sz, md5=md5)

    def read(self, byte=False):
        param = "rb" if byte else "r"
        with open(self._uri, param) as fp:
            return fp.read()

    def find_all_files(self):
        query = os.path.join(self._uri, "**")
        result = []
        for f in glob.glob(query, recursive=True):
            if os.path.isfile(f):
                result.append(os.path.abspath(f))
        return result

    def _write(self, s) -> None:
        self.mkdir_dirname()
        param = "w" if isinstance(s, str) else "wb"
        with open(self._uri, param) as fp:
            fp.write(s)

    def _rm(self):
        return os.remove(self._uri)

    def _cp(self, dest_uri) -> bool:
        """Copy from AbsPath to other classes."""
        dest_uri = AutoURI(dest_uri)

        if isinstance(dest_uri, AbsPath):
            dest_uri.mkdir_dirname()
            try:
                copyfile(self._uri, dest_uri._uri, follow_symlinks=True)
            except SameFileError:
                logger.debug(
                    "cp: ignored SameFileError. src=%s, dest=%s", self._uri, dest_uri._uri
                )
                if os.path.islink(dest_uri._uri):
                    dest_uri._rm()
                    copyfile(self._uri, dest_uri._uri, follow_symlinks=True)

            return True
        return False

    def _cp_from(self, src_uri) -> bool:
        return False

    def get_mapped_url(self, map_path_to_url=None) -> str | None:
        """
        Generates a mapped URL for the current path.

        Replaces a path prefix with a corresponding URL prefix based on a mapping provided, or
        a default mapping if none is supplied.

        Args:
            map_path_to_url:
                dict with k, v where k is a path prefix and v is a URL prefix
                k will be replaced with v.
                If not given, defaults to use class constant AbsPath.MAP_PATH_TO_URL
        """
        if map_path_to_url is None:
            map_path_to_url = AbsPath.MAP_PATH_TO_URL
        for k, v in map_path_to_url.items():
            if k and self._uri.startswith(k):
                return self._uri.replace(k, v, 1)
        return None

    def mkdir_dirname(self) -> None:
        """Create a directory but raise if no write permission on it."""
        os.makedirs(self.dirname, exist_ok=True)
        if not os.access(self.dirname, os.W_OK):
            msg = f"No permission to write on directory: {self.dirname}"
            raise PermissionError(msg)

    def soft_link(self, target, force=False) -> None:
        """Make a soft link of self on target absolute path.

        If target already exists delete it and create a link.

        Args:
            target:
                Target file's absolute path or URI object.
            force:
                Delete target file (or link) if it exists
        """
        target = AbsPath(target)
        if not target.is_valid:
            msg = f"Target path is not a valid abs path: {target.uri}."
            raise ValueError(msg)
        try:
            target.mkdir_dirname()
            os.symlink(self._uri, target._uri)
        except OSError as e:
            if e.errno == errno.EEXIST and force:
                target.rm()
                os.symlink(self._uri, target._uri)
            else:
                raise

    def __calc_md5sum(self):
        """Expensive md5 calculation."""
        logger.debug("calculating md5sum hash of local file: %s", self._uri)
        hash_md5 = hashlib.md5(usedforsecurity=False)
        with open(self._uri, "rb") as fp:
            for chunk in iter(lambda: fp.read(AbsPath.MD5_CALC_CHUNK_SIZE), b""):
                hash_md5.update(chunk)

        logger.debug("calculating md5sum is done for local file: %s", self._uri)
        return hash_md5.hexdigest()

    @staticmethod
    def get_abspath_if_exists(path):
        if isinstance(path, URIBase):
            path = path._uri
        if isinstance(path, str) and os.path.exists(os.path.expanduser(path)):
            return os.path.abspath(os.path.expanduser(path))
        return path

    @staticmethod
    def init_abspath(
        loc_prefix: str | None = None,
        map_path_to_url: dict[str, str] | None = None,
        md5_calc_chunk_size: int | None = None,
    ) -> None:
        if loc_prefix is not None:
            AbsPath.LOC_PREFIX = loc_prefix
        if map_path_to_url is not None:
            AbsPath.MAP_PATH_TO_URL = map_path_to_url
        if md5_calc_chunk_size is not None:
            AbsPath.MD5_CALC_CHUNK_SIZE = md5_calc_chunk_size

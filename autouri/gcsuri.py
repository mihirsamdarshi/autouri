"""GCS implementation for AutoURI.

GCS Bucket configuration:
Object versioning must be turned off
    Check it with "gsutil versioning get gs://BUCKET-NAME"
    https://cloud.google.com/storage/docs/object-versioning
"""

from __future__ import annotations

import logging
import os
import time
from datetime import timedelta
from subprocess import check_call
from tempfile import NamedTemporaryFile, TemporaryDirectory
from typing import overload

import requests
from filelock import BaseFileLock
from google.api_core.exceptions import (
    ClientError,
    Forbidden,
    NotFound,
    PermissionDenied,
)
from google.auth.exceptions import DefaultCredentialsError
from google.cloud import storage
from google.cloud.storage import Blob, Bucket
from google.oauth2.service_account import Credentials

from .autouri import AutoURI, URIBase
from .metadata import URIMetadata, get_seconds_from_epoch, parse_md5_str
from .ntp_now import now_utc

logger = logging.getLogger(__name__)


ENV_VAR_GOOGLE_APPLICATION_CREDENTIALS = "GOOGLE_APPLICATION_CREDENTIALS"
GCS_TEMPORARY_HOLD_ERROR_MSG = "is under active Temporary hold"


def add_google_app_creds_to_env(service_account_key_file: str) -> None:
    """Set up Google auth with a service account.

    To globally use the key file for all GCS Client() with different thread IDs,
    update environment variable `GOOGLE_APPLICATION_CREDENTIALS` with a given
    service account key JSON file.
    """
    service_account_key_file = os.path.abspath(os.path.expanduser(service_account_key_file))
    if ENV_VAR_GOOGLE_APPLICATION_CREDENTIALS in os.environ:
        existing_key_file = os.environ[ENV_VAR_GOOGLE_APPLICATION_CREDENTIALS]
        if not os.path.samefile(existing_key_file, service_account_key_file):
            logger.warning(
                "Environment variable %s does not match with given service_account_key_file. "
                "Using application default credentials? ",
                ENV_VAR_GOOGLE_APPLICATION_CREDENTIALS,
            )
    logger.debug(
        "Adding service account key JSON %s to environment variable %s",
        service_account_key_file,
        ENV_VAR_GOOGLE_APPLICATION_CREDENTIALS,
    )
    os.environ[ENV_VAR_GOOGLE_APPLICATION_CREDENTIALS] = service_account_key_file


class GCSURILock(BaseFileLock):
    """
    File-based lock for GCSURI operations.

    Class constants:
    - LOCK_FILE_EXPIRATION_SEC:
        Expiration of a lock file based on its modtime in seconds
        If expired then such lock file is ignored.
    """

    LOCK_FILE_EXPIRATION_SEC = 1800

    def __init__(self, lock_file, timeout=900, poll_interval=10.0, no_lock=False) -> None:
        super().__init__(lock_file, timeout=timeout)
        self._poll_interval = poll_interval
        self._lock_read_delay = self._poll_interval / 10.0

    def acquire(self, timeout=None, poll_interval=5.0) -> None:
        """To use self._poll_interval instead of poll_interval in args."""
        super().acquire(timeout=timeout, poll_interval=self._poll_interval)

    def _acquire(self) -> None:
        """Unlike GCSURI, this module does not use S3 Object locking.

        This will write id(self) on a .lock file.
        """
        u = GCSURI(self.lock_file)
        str_id = str(id(self))
        try:
            if (
                not u.exists
                or now_utc().timestamp() > u.mtime + GCSURILock.LOCK_FILE_EXPIRATION_SEC
            ):
                u.write(str_id, no_lock=True)
                self._context.lock_file_fd = id(self)

            elif u.read() == str_id:
                self._context.lock_file_fd = id(self)

        except Forbidden:
            raise
        except (NotFound, ClientError, ValueError):
            pass
        except TypeError:
            # this happens if file exists and failed to get metadata, so u.mtime is None
            pass

    def _release(self) -> None:
        u = GCSURI(self.lock_file)
        try:
            u.rm(no_lock=True, silent=True)
            self._context.lock_file_fd = None
        except (ClientError, ValueError):
            pass


class GCSURI(URIBase):
    """
    GCS implementation of URIBase.

    Class constants:
        LOC_PREFIX (inherited):
            Path prefix for localization. Inherited from URIBase class.
        PRIVATE_KEY_FILE:
            Path for private key file used to get presigned URLs
        DURATION_PRESIGNED_URL:
            Duration for presigned URLs in seconds.
        RETRY_BUCKET:
            Number of retrial to access a bucket.
        RETRY_BUCKET_DELAY:
            Delay for each retrial in seconds.
        USE_GSUTIL_FOR_S3 (experimental):
            This is only for direct transfer between S3 and GCS buckets.

    Warning:
                gsutil must be configured correctly to have all
                AWS credentials in ~/.boto file.
                Run "aws configure" first and then
                run "gsutil config" to generate corrensponding ~/.boto file.

    Protected class constants:
        _CACHED_GCS_CLIENTS:
            Per-thread GCS client object is required since
            GCS client is not thread-safe.
        _CACHED_PRESIGNED_URLS:
            Can use cached presigned URLs.
        _GCS_PUBLIC_URL_FORMAT:
            End point for a bucket with public access + key path
    """

    PRIVATE_KEY_FILE: str = ""
    DURATION_PRESIGNED_URL: int = 4233600

    RETRY_BUCKET: int = 5
    RETRY_BUCKET_DELAY: int = 10
    USE_GSUTIL_FOR_S3: bool = False

    _CACHED_GCS_CLIENTS = {}
    _CACHED_GCS_ANONYMOUS_CLIENTS = {}
    _CACHED_PRESIGNED_URLS = {}
    _GCS_PUBLIC_URL_FORMAT = "http://storage.googleapis.com/{bucket}/{path}"

    _LOC_SUFFIX = ".gcs"
    _SCHEMES = ("gs://",)

    def __init__(self, uri, thread_id=-1) -> None:
        super().__init__(uri, thread_id=thread_id)

    def _get_lock(self, timeout=None, poll_interval=None):
        if timeout is None:
            timeout = GCSURI.LOCK_TIMEOUT
        if poll_interval is None:
            poll_interval = GCSURI.LOCK_POLL_INTERVAL
        return GCSURILock(
            self._uri + GCSURI.LOCK_FILE_EXT,
            timeout=timeout,
            poll_interval=poll_interval,
        )

    def get_metadata(self, skip_md5=False, make_md5_file=False):
        exists, mt, sz, md5 = False, None, None, None

        try:
            b, _ = self.get_blob()
            # make keys lower-case
            headers = {k.lower(): v for k, v in b._properties.items()}
            exists = True

            if not skip_md5:
                if "md5hash" in headers:
                    md5 = parse_md5_str(headers["md5hash"])
                elif "etag" in headers:
                    md5 = parse_md5_str(headers["etag"])
                if md5 is None:
                    # make_md5_file is ignored for GCSURI
                    md5 = self.md5_from_file

            if "size" in headers:
                sz = int(headers["size"])

            if "updated" in headers:
                mt = get_seconds_from_epoch(headers["updated"])
            elif "timecreated" in headers:
                mt = get_seconds_from_epoch(headers["timecreated"])

        except Exception:
            logger.debug(f"Failed to get metadata from {self._uri}")

        return URIMetadata(exists=exists, mtime=mt, size=sz, md5=md5)

    @overload
    def read(self, byte: bool = False) -> str: ...
    @overload
    def read(self, byte: bool = True) -> bytes: ...
    def read(self, byte: bool = False) -> str | bytes:
        blob, _ = self.get_blob()
        b = blob.download_as_bytes()
        if byte:
            return b
        return b.decode()

    def find_all_files(self):
        cl = GCSURI.get_gcs_client(self._thread_id)
        bucket, path = self.get_bucket_path()
        sep = GCSURI.get_path_sep()
        if path:
            path = path.rstrip(sep) + sep

        result = []
        blobs = cl.list_blobs(bucket, prefix=path)
        if blobs:
            for blob in blobs:
                scheme = GCSURI.get_schemes()[0]
                uri = scheme + sep.join([bucket, blob.name])
                result.append(uri)
        return result

    def _write(self, s) -> None:
        blob, _ = self.get_blob(new=True)
        blob.upload_from_string(s)
        # blob.update()

    def _rm(self) -> None:
        blob, _ = self.get_blob()
        blob.delete()

    def _cp(self, dest_uri):
        """Copy from GCSURI to
        GCSURI
        S3URI: can use gsutil for direct transfer if USE_GSUTIL_FOR_S3 == True
        AbsPath.
        """
        from .abspath import AbsPath
        from .s3uri import S3URI

        dest_uri = AutoURI(dest_uri)

        if isinstance(dest_uri, (GCSURI, AbsPath)):
            src_blob, src_bucket = self.get_blob()

            if src_blob is None:
                msg = f"Blob does not exist for {self._uri}"
                raise ValueError(msg)

            if isinstance(dest_uri, GCSURI):
                _, dest_path = dest_uri.get_bucket_path()
                _, dest_bucket = dest_uri.get_blob(new=True)
                src_bucket.copy_blob(src_blob, dest_bucket, dest_path)
                return True

            if isinstance(dest_uri, AbsPath):
                dest_uri.mkdir_dirname()
                # mtime is not updated without update().
                src_blob.update()
                src_blob.download_to_filename(dest_uri._uri)
                return True

        elif isinstance(dest_uri, S3URI):
            if GCSURI.USE_GSUTIL_FOR_S3:
                rc = check_call(["gsutil", "-q", "cp", self._uri, dest_uri._uri])
                return rc == 0
            # use local temporary file instead
            with TemporaryDirectory() as tmp_d:
                dest_uri_local = AbsPath(os.path.join(tmp_d, self.basename))
                # lockless copy
                self.cp(dest_uri=dest_uri_local, no_lock=True, no_checksum=True)
                dest_uri_local.cp(dest_uri=dest_uri, no_lock=True, no_checksum=True)
            return True

        return False

    def _cp_from(self, src_uri):
        """Copy to GCSURI from
        S3URI: can use gsutil for direct transfer if USE_GSUTIL_FOR_S3 == True
        AbsPath
        HTTPURL.
        """
        from .abspath import AbsPath
        from .httpurl import HTTPURL
        from .s3uri import S3URI

        src_uri = AutoURI(src_uri)

        if isinstance(src_uri, AbsPath):
            blob, _ = self.get_blob(new=True)
            blob.upload_from_filename(src_uri._uri)
            return True

        if isinstance(src_uri, S3URI):
            if GCSURI.USE_GSUTIL_FOR_S3:
                rc = check_call(["gsutil", "-q", "cp", src_uri._uri, self._uri])
                return rc == 0
            # use local temporary file instead
            with TemporaryDirectory() as tmp_d:
                dest_uri_local = AbsPath(os.path.join(tmp_d, self.basename))
                src_uri.cp(dest_uri=dest_uri_local, no_lock=True, no_checksum=True)
                dest_uri_local.cp(dest_uri=self, no_lock=True, no_checksum=True)
            return True

        if isinstance(src_uri, HTTPURL):
            r = requests.get(
                src_uri._uri,
                stream=True,
                allow_redirects=True,
                headers=requests.utils.default_headers(),
            )
            r.raise_for_status()
            with NamedTemporaryFile() as fp:
                for chunk in r.iter_content(HTTPURL.get_http_chunk_size()):
                    fp.write(chunk)
                fp.seek(0)
                blob, _ = self.get_blob(new=True)
                blob.upload_from_file(fp)
            return True
        return False

    def get_blob(self, new=False) -> tuple[Blob, Bucket]:
        """
        Get an object from a GCS bucket.

        GCS Client() has a bug that shows an outdated version of a file
        when using Blob() without update().
        For read-only functions (e.g. read()), need to directly call
        cl.get_bucket(bucket).get_blob(path) instead of using Blob() class.

        Also, GCS Client() is not thread-safe and it fails for a variety of reasons.
        Retry several times for whatever reasons.

        Client.get_bucket() and Client.get_bucket().get_blob() can fail
        even if the bucket is public (Storage Reader permission for allUsers
        or allAuthenticatedUsers).
        Needs an anonymous client (Client.create_anonymous_client()) for public buckets.
        If this error occurs, then retry with an anonymous client.

        Returns:
            blob:
                Blob object
            bucket_obj:
                Bucket object
        """
        bucket, path = self.get_bucket_path()
        cl = GCSURI.get_gcs_client(self._thread_id)

        bucket_obj = None
        blob = None
        for _retry in range(GCSURI.RETRY_BUCKET):
            try:
                bucket_obj = cl.get_bucket(bucket)
                blob = bucket_obj.get_blob(path)
                if new and blob is None:
                    blob = Blob(name=path, bucket=bucket_obj)
                break
            except Forbidden:
                logger.debug("Bucket/blob is forbidden. Trying again with anonymous client.")
                cl = GCSURI.get_gcs_anonymous_client(self._thread_id)
            except NotFound:
                raise
            except PermissionDenied:
                raise
            except Exception:
                time.sleep(GCSURI.RETRY_BUCKET_DELAY)

        if bucket_obj is None:
            msg = f"Bucket does not exist. {self._uri}"
            raise ValueError(msg)

        if blob is None:
            msg = f"GCS blob does not exist. lack of {'write' if new else 'read'} permission? {self._uri}"
            raise ValueError(msg)

        return blob, bucket_obj

    def get_bucket_path(self) -> tuple[str, str]:
        """Returns a tuple of URI's S3 bucket and path."""
        arr = self.uri_wo_scheme.split(GCSURI.get_path_sep(), maxsplit=1)
        if len(arr) == 1:
            # root directory without path (key)
            bucket, path = arr[0], ""
        else:
            bucket, path = arr
        return bucket, path

    def get_presigned_url(self, duration=None, private_key_file=None, use_cached=False) -> str:
        """
        Generate a presigned URL for a GCS blob.

        Args:
            duration: Duration in seconds. This is ignored if use_cached is on.
            use_cached: Use a cached URL.
        """
        cache = GCSURI._CACHED_PRESIGNED_URLS
        if use_cached and cache is not None and self._uri in cache:
            return cache[self._uri]
        # if not self.exists:
        #     raise Exception('File does not exist. f={f}'.format(self._uri))
        if private_key_file is None:
            private_key_file = os.path.expanduser(GCSURI.PRIVATE_KEY_FILE)
        else:
            private_key_file = os.path.expanduser(private_key_file)
        if not os.path.exists(private_key_file):
            msg = f"GCS private key file not found. f:{private_key_file}"
            raise Exception(msg)
        credentials = Credentials.from_service_account_file(private_key_file)
        duration = duration if duration is not None else GCSURI.DURATION_PRESIGNED_URL
        blob, _ = self.get_blob()
        if blob is None:
            msg = f"Blob does not exist for {self._uri}"
            raise ValueError(msg)
        url = blob.generate_signed_url(
            expiration=timedelta(seconds=duration), credentials=credentials
        )
        cache[self._uri] = url
        return url

    def get_public_url(self) -> str:
        bucket, path = self.get_bucket_path()
        return GCSURI._GCS_PUBLIC_URL_FORMAT.format(bucket=bucket, path=path)

    @staticmethod
    def get_gcs_client(thread_id) -> storage.Client:
        """Get GCS client per thread_id.

        Get default credentials (internally calling google.auth.default()) from:
            - Environment variable GOOGLE_APPLICATION_CREDENTIALS
              - Set a service account key JSON file path as this environment variable.
            - JSON file ~/.config/gcloud/application_default_credentials.json
              - To use end-user's credentials.
              - This file is created by `gcloud auth application-default login`.

        If default credentials are not found, then
            - Make/return an anonymous client instead
            - For this thread_id, it will cache anonymous client instead of failed
              client with credentials.
        """
        cl = GCSURI._CACHED_GCS_CLIENTS.get(thread_id)

        if cl is None:
            try:
                logger.debug(f"New GCS client for thread {thread_id}.")
                cl = storage.Client()
            except DefaultCredentialsError:
                cl = GCSURI.get_gcs_anonymous_client(thread_id)
            # anonymous client can also be cached here
            GCSURI._CACHED_GCS_CLIENTS[thread_id] = cl

        return cl

    @staticmethod
    def get_gcs_anonymous_client(thread_id) -> storage.Client:
        """Get GCS anonymous client per thread_id."""
        cl = GCSURI._CACHED_GCS_ANONYMOUS_CLIENTS.get(thread_id)

        if cl is None:
            logger.debug(f"New GCS anonymous client for thread {thread_id}.")
            cl = storage.Client.create_anonymous_client()
            GCSURI._CACHED_GCS_ANONYMOUS_CLIENTS[thread_id] = cl

        return cl

    @staticmethod
    def init_gcsuri(
        loc_prefix: str | None = None,
        private_key_file: str | None = None,
        duration_presigned_url: int | None = None,
        retry_bucket: int | None = None,
        retry_bucket_delay: int | None = None,
        use_gsutil_for_s3: bool | None = None,
    ) -> None:
        if loc_prefix is not None:
            GCSURI.LOC_PREFIX = loc_prefix
        if private_key_file is not None:
            GCSURI.PRIVATE_KEY_FILE = private_key_file
        if duration_presigned_url is not None:
            GCSURI.DURATION_PRESIGNED_URL = duration_presigned_url
        if retry_bucket is not None:
            GCSURI.RETRY_BUCKET = retry_bucket
        if retry_bucket_delay is not None:
            GCSURI.RETRY_BUCKET_DELAY = retry_bucket_delay
        if use_gsutil_for_s3 is not None:
            GCSURI.USE_GSUTIL_FOR_S3 = use_gsutil_for_s3

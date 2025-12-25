"""URIMetadata and helper functions for metadata."""

from __future__ import annotations

import contextlib
import logging
import warnings
from base64 import b64decode
from binascii import hexlify
from collections import namedtuple
from datetime import datetime, timezone

from dateparser import parse as dateparser_parse
from dateutil.parser import parse as dateutil_parse

logger = logging.getLogger(__name__)

URIMetadata = namedtuple("URIMetadata", ("exists", "mtime", "size", "md5"))


def get_seconds_from_epoch(timestamp: str) -> float:
    """Calculate number of seconds from Unix epoch from a timestamp string.

    If dateutil.parser.parse cannot parse DST timezones
    (e.g. PDT, EDT) correctly, then use dateparser.parse instead.
    """
    utc_epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    utc_t = None

    with warnings.catch_warnings(), contextlib.suppress(Exception):
        warnings.simplefilter("ignore")
        utc_t = dateutil_parse(timestamp)
    if utc_t is None or utc_t.tzname() not in ("UTC", "Z"):
        utc_t = dateparser_parse(timestamp)
    if utc_t is None:
        msg = f"Cannot parse timestamp: {timestamp}"
        raise ValueError(msg)
    utc_t = utc_t.astimezone(timezone.utc)
    return (utc_t - utc_epoch).total_seconds()


def base64_to_hex(b: str) -> str:
    return hexlify(b64decode(b)).decode()


def parse_md5_str(raw: str) -> str | None:
    """Check if it's based on base64 then convert it to hexadecimal string."""
    raw = raw.strip("\"'")
    if len(raw) == 32:
        return raw

    with contextlib.suppress(Exception):
        return base64_to_hex(raw)

    return None

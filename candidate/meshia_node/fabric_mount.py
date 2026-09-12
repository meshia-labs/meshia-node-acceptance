"""App-free native mount facade for a remote-authoritative Meshia workspace.

The adapter is intentionally thin: remote metadata lives in ``FabricDatabase``,
range reads go through ``FabricRangeCache``, and every completed local write is
handed to ``FabricSyncCoordinator``.  The FUSE layer owns no independent sync
truth.  The ordinary ``meshia-node`` user service uses FUSE-T on macOS,
libfuse2 on Linux, and WinFsp on Windows; no Meshia app bundle or privileged
Meshia daemon is required.
"""

from __future__ import annotations

import bisect
from contextlib import contextmanager, ExitStack
import errno
import ctypes
import glob
import hashlib
import json
import logging
import math
import os
import platform
import re
import shlex
import signal
import shutil
import sqlite3
import stat
import struct
import subprocess
import sys
import threading
import time
import traceback
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Mapping, NoReturn

from .compute_icon import (
    USER_TAGS_XATTR,
    decode_tags,
    FINDER_INFO_XATTR,
    RESOURCE_FORK_XATTR,
    ComputeIconPhantom,
    ComputeIconPhantoms,
)
from .errors import InvalidTask, NetworkError, RemoteError, StateError, UnsafePath
from .fabric_cache import FabricCacheError
from .fabric_file_version import FabricFileVersion
from .fabric_write_tree import FileTreeJournal
from .fabric_contract_generated import FabricFileHasher, file_digest_algorithm, FABRIC_FILE_TREE_ALGORITHM
from .fabric_db import (
    FabricDatabase,
    MaterializedEntry,
    PendingOperation,
    RemoteEntry,
)
from .fabric_sync import (
    FabricSyncCoordinator,
    MAX_LOCAL_UPLOAD_FILE_BYTES,
    StagingRepairPending,
)
from .fabric_transfer import StagingQuotaExceeded, TransferError
from .log import NULL_LOGGER, NodeLogger
from .util import ensure_private_dir, run_bounded_capture, write_private_file
from .workspace import FileFingerprint, WorkspaceBoundary, split_relative

MOUNT_NAME = "Meshia"
MOUNT_STAGE_SCHEMA = "meshia.fabric_mount_stage.v1"
MOUNT_STATE_SCHEMA = "meshia.fabric_mount_state.v1"
MOUNT_RECOVERY_CURSOR_SCHEMA = "meshia.fabric_mount_recovery_cursor.v1"
MOUNT_RECOVERY_CURSOR_NAME = ".meshia-recovery-cursor"
MAX_MOUNT_READ_BYTES = 64 * 1024 * 1024
MAX_DIRECTORY_ENTRIES = 100_000
MOUNT_IO_BYTES = 1024 * 1024
# Darwin/Linux statfs consumers commonly multiply the unsigned 64-bit block
# count by the fragment size. Keep the aggregate share at the largest complete
# Meshia I/O block that cannot overflow that byte-capacity calculation.
MAX_STATFS_BYTES = ((2**64 - 1) // MOUNT_IO_BYTES) * MOUNT_IO_BYTES
MOUNT_SETTLE_SECONDS = 0.25
# A directory rename stays an overlay until the engine acknowledges it
# (~0.4-1 s live). Operations under the moved prefix inside that window used
# to answer EBUSY, which FUSE-T's SMB bridge shows as "Permission denied";
# waiting a bounded time lets Finder's move-then-touch sequences succeed.
MOUNT_DIRECTORY_MUTATION_WAIT_SECONDS = 5.0
MOUNT_PUBLISH_RETRY_SECONDS = 0.5
MOUNT_PUBLISH_MAX_RETRY_SECONDS = 30.0
# A mounted delete whose journal handoff keeps *failing* must stop spending
# timers. Its durable ``delete_pending`` marker still hides the path and is
# replayed (and re-armed) on restart, so a bounded budget abandons the loop,
# never the intent. A delete the engine merely *fences* (EAGAIN/EBUSY while
# it reconciles) is not counted against this budget: the fence lifts on its
# own and the capped backoff keeps retrying until the tombstone journals.
MOUNT_DELETE_RETRY_MAX_ATTEMPTS = 12
MOUNT_START_TIMEOUT_SECONDS = 10.0
MOUNT_SMB_START_TIMEOUT_SECONDS = 40.0
MOUNT_HELPER_SETTLE_SECONDS = 0.5
MOUNT_HELPER_DISCOVERY_SECONDS = 0.25
MOUNT_HELPER_TERM_SECONDS = 0.5
MOUNT_SMB_DELETE_LEASE_BREAK_SECONDS = 0.5
# macOS smbfs defers UBC write-back and the matching SMB CLOSE for ~45-60 s
# after an application closes an un-fsynced file. fuse_invalidate_path makes
# the client resolve its cached state immediately (measured 57.9 s -> 2.1 s),
# so nudge any content path that stays quiet after its first content IO.
MOUNT_SMB_WRITEBACK_NUDGE_SECONDS = 1.5
MOUNT_SMB_WRITEBACK_NUDGE_MAX_ATTEMPTS = 8
# With ``noattrcache`` the macOS SMB client re-stats the whole ancestor chain
# on nearly every operation: a 20-file create loop measured 6,570 getattr
# callbacks (~305 per create), 82% of them the same three directories. Every
# mutation and every remote invalidation flows through this adapter, so a
# short server-side attribute cache is coherent for mount-originated changes
# and bounded-stale (one TTL) for out-of-band ones. Client timestamps still
# cross the adapter and explicitly evict the affected entry.
MOUNT_SMB_ATTR_CACHE_SECONDS = 1.0

_LOCAL_ONLY_DIRECTORY_RENAME_MESSAGE = "The Fabric directory rename source is missing."


def _is_local_only_directory_rename(error: InvalidTask) -> bool:
    """The engine found nothing durable or pending under the rename source."""

    return str(error) == _LOCAL_ONLY_DIRECTORY_RENAME_MESSAGE
MOUNT_SMB_ATTR_CACHE_MAX_ENTRIES = 4096
# The FUSE-T transport's own attribute cache bound (seconds); see the darwin
# mount options for why it is on and why one second.
MOUNT_SMB_TRANSPORT_ATTR_CACHE_SECONDS = 1
# Circuit breaker for readdir-plus: if the batched attribute seed fails this
# many times in a row for a directory, stop attempting it for that path for a
# bounded window. A persistently-failing optimization then costs one traceback
# per window, not one per readdir, while the listing itself is unaffected.
MOUNT_PREWARM_TRIP_THRESHOLD = 3
MOUNT_PREWARM_TRIP_SECONDS = 60.0
# Per-callback timing, aggregated per operation and logged as one
# ``fabric_mount_op_stats`` record per window (only when callbacks ran). This
# is the mount's own answer to "where does a create spend its time" -- the
# alternative, sampling the live process, stalls FUSE-T (2026-09-02).
MOUNT_OP_STATS_WINDOW_SECONDS = 30.0
# Callback names whose EACCES/quiet errno means "the listing was fenced", not a
# per-file permission denial -- those must always leave a record.
_LISTING_OPERATIONS = frozenset({"listdir", "listdir_entries"})
# CPython's default 5 ms GIL switch interval starves threaded FUSE callbacks
# while the sync engine holds the interpreter in short slices: a 512 KB
# write+fsync+close measured 13 ms idle, ~10.5 s under pure-Python load, and
# 2.3 s with a 1 ms interval (2026-08-30 FUSE-T SMB probe). Mount callbacks
# are latency-critical and each op is tiny, so prefer the shorter interval
# while an in-process FUSE loop is running. Set to 0 or a negative value to
# leave the interpreter default untouched.
MOUNT_GIL_SWITCH_INTERVAL_ENV = "MESHIA_FUSE_GIL_SWITCH_INTERVAL_SECONDS"
MOUNT_GIL_SWITCH_INTERVAL_SECONDS = 0.001


def tune_interpreter_for_mount_callbacks() -> float | None:
    """Shorten the GIL switch interval for FUSE callback latency.

    Returns the applied interval, or None when tuning is disabled or the
    override is unparsable.
    """

    raw = os.environ.get(MOUNT_GIL_SWITCH_INTERVAL_ENV)
    interval = MOUNT_GIL_SWITCH_INTERVAL_SECONDS
    if raw is not None:
        try:
            interval = float(raw)
        except ValueError:
            return None
    if not interval > 0 or interval > 1:
        return None
    sys.setswitchinterval(interval)
    return interval
MAX_SMB_DELETE_LEASE_BREAK_CANDIDATES = 1_024
MOUNT_THREAD_STOP_SECONDS = 4.0
MOUNT_UNMOUNT_TIMEOUT_SECONDS = 10.0
MOUNT_MIN_FREE_BYTES = 512 * 1024 * 1024
MOUNT_CAPACITY_LOG_INTERVAL_SECONDS = 60.0
MAX_RECOVERY_STAGES = 1_000
MAX_RECOVERY_SCAN_ENTRIES = (2 * MAX_DIRECTORY_ENTRIES) + 1
MAX_RECOVERY_MARKERS = MAX_DIRECTORY_ENTRIES
# Live write sessions (one per file between CREATE and its journal receipt)
# and the recovery scan that re-admits them after a crash share one bound, so
# nothing admitted live can fail to recover. 64 was hit by every Finder bulk
# copy (2026-09-02: an 80k-file drop refused CREATE with EAGAIN after ~30
# files, which Finder reports as "you don't have permission" and aborts); a
# session holds one descriptor, and the service raises RLIMIT_NOFILE to match.
MAX_RECOVERY_ACTIVE_SESSIONS = 512
# A CREATE that finds every session slot taken waits for publication to free
# one instead of refusing. FUSE-T's SMB client retries EAGAIN with backoff and
# Finder aborts the whole copy on it; a short wait is invisible to both.
WRITE_SESSION_ADMISSION_WAIT_SECONDS = 30.0
# Re-opening or unlinking a file whose sealed bytes are still being published
# (a 250 ms settle, then the journal write) used to answer EBUSY. Finder does
# exactly that when it writes a sidecar or sets attributes right after CLOSE.
PUBLISH_REOPEN_WAIT_SECONDS = 10.0
MAX_SMB_COPY_PAIR_EVIDENCE = 1_024
MOUNT_SMB_COPY_PAIR_EVIDENCE_SECONDS = 300.0
MAX_DISCARDABLE_APPLEDOUBLE_BYTES = 64 * 1024
MAX_STAGE_MARKER_BYTES = 64 * 1024
MAX_RECOVERY_CURSOR_BYTES = 4 * 1024
MOUNT_RUNTIME_HELP = "rerun the Meshia installer to install FUSE-T"
MOUNT_RUNTIME_HELP_LINUX = "rerun the Meshia installer to install libfuse2"
MOUNT_RUNTIME_HELP_WINDOWS = "rerun the Meshia installer to install WinFsp"
MAX_MOUNT_STATE_BYTES = 16 * 1024
MAX_MOUNT_REGISTRY_BYTES = 4 * 1024 * 1024
MOUNT_REGISTRATION_CHECK_SECONDS = 2.0
# Upper bound for one OS mount-registry read; mount(8) can block on a dead
# network mount, and an unanswered probe must read as "unknown", never hang.
MOUNT_REGISTRY_PROBE_TIMEOUT_SECONDS = 3.0
FUSE_T_TRANSPORT_HELPER_NAME = "fuse-t-transport-helper"
FUSE_T_TRANSPORT_VERSION = "1.2.7"

_NONTERMINAL_STATES = ("queued", "inflight", "retry")
_REMOTE_ERROR_CODE_RE = re.compile(r"[A-Z][A-Z0-9_]{0,63}")
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_ENOATTR = getattr(errno, "ENOATTR", errno.ENODATA)
_MACOS_QUARANTINE_XATTR = "com.apple.quarantine"
_MAX_MACOS_QUARANTINE_BYTES = 4 * 1024
_MACOS_XATTR_CREATE = 0x0002
_MACOS_XATTR_REPLACE = 0x0004
_DARWIN_XATTR_LOCK = threading.Lock()
_DARWIN_XATTR_LIBRARY: Any | None = None
_DARWIN_XATTR_FUNCTIONS: dict[str, Any] = {}
_DISCARDABLE_MACOS_XATTRS = frozenset(
    {
        "com.apple.FinderInfo",
        "com.apple.TextEncoding",
        "com.apple.lastuseddate#PS",
        "com.apple.provenance",
    }
)
_DISCARDABLE_MACOS_XATTR_PREFIXES = ("com.apple.metadata:",)
# Owner decision 2026-09-03: on the SMB (``nonamedattr``) transport the macOS
# client mirrors every xattr into a ``._name`` AppleDouble sidecar. Those
# sidecars are discarded instead of stored: Finder tags, comments and the
# quarantine flag do not persist across the Meshia mount, and in exchange a
# bulk copy no longer stages, journals and uploads one extra file (and its
# post-close stat) per real file. Set this environment variable to keep the
# previous behaviour (sidecars carrying non-advisory metadata are stored as
# 4 KiB files in the workspace) without a release.
MOUNT_KEEP_APPLEDOUBLE_SIDECARS_ENV = "MESHIA_MOUNT_KEEP_APPLEDOUBLE_SIDECARS"
# A discardable sidecar stays reopenable (unpublished, local-only) for this
# long after it settles. macOS copyfile writes ``._name`` for the first xattr
# and reopens the same path for the next one (provenance after quarantine); a
# sidecar that vanished at settle answered that reopen with ENOENT, which cp
# reports as "could not copy extended attributes: Operation not permitted"
# (2026-09-03: 3 of 400 files in a Mentra copy). The grace is renewed by every
# reopen and the sidecar is cancelled, never published, once it lapses.
MOUNT_APPLEDOUBLE_DISCARD_GRACE_SECONDS = 10.0


def mount_discards_appledouble_sidecars(
    environ: Mapping[str, str] | None = None,
) -> bool:
    env = os.environ if environ is None else environ
    return env.get(MOUNT_KEEP_APPLEDOUBLE_SIDECARS_ENV, "").strip().lower() not in (
        "1", "true", "yes", "on"
    )
_FUSE_T_SMB_APPLEDOUBLE_PROVENANCE = "fuse_t_smb_appledouble_copy_pair.v1"
_FUSE_T_SMB_FINAL_APPLEDOUBLE_PROVENANCE = (
    "fuse_t_smb_final_appledouble_copy_pair.v1"
)
_APPLEDOUBLE_MAGIC = 0x00051607
_APPLEDOUBLE_VERSION_2 = 0x00020000
_APPLEDOUBLE_FINDER_INFO_ENTRY = 9
_APPLEDOUBLE_RESOURCE_FORK_ENTRY = 2
_APPLEDOUBLE_ATTR_MAGIC = b"ATTR"
_APPLEDOUBLE_SYSTEM_IDS = (b"\0" * 16, b"Mac OS X        ")


def _fuse_t_smb_appledouble_temp(path: str) -> bool:
    """Recognize the AppleDouble half of FUSE-T SMB's copy-pair spelling.

    Finder/ditto pairs a ``.BC.T_<nonce>`` data temporary with an
    ``._.BC.T_<nonce>`` AppleDouble sidecar while copying through FUSE-T's SMB
    bridge. The spelling alone is never deletion authority: web, pod, NFS, or
    deliberate SMB writers can create the same basename. Callers must also
    hold persisted same-directory copy-pair provenance.
    """

    name = path.rpartition("/")[2]
    return name.startswith("._.BC.T_") and len(name) > len("._.BC.T_")


def _smb_copy_pair_key(
    path: str,
    *,
    appledouble: bool,
) -> tuple[str, str] | None:
    """Return one same-directory Finder copy-pair identity."""

    parent, _separator, name = path.rpartition("/")
    prefix = "._.BC.T_" if appledouble else ".BC.T_"
    if not name.startswith(prefix) or len(name) <= len(prefix):
        return None
    return parent, name[len(prefix) :]


def _smb_final_copy_pair_key(
    path: str,
    *,
    appledouble: bool,
) -> tuple[str, str] | None:
    """Return the exact same-directory identity of one final SMB copy pair."""

    parent, _separator, name = path.rpartition("/")
    if appledouble:
        if (
            not name.startswith("._")
            or len(name) <= 2
            or _fuse_t_smb_appledouble_temp(path)
        ):
            return None
        return parent, name[2:]
    if name.startswith("._") or name.startswith(".BC.T_") or not name:
        return None
    return parent, name


def _discardable_macos_xattr(name: str) -> bool:
    """Return whether an xattr is advisory Finder metadata, never file data."""

    return name in _DISCARDABLE_MACOS_XATTRS or name.startswith(
        _DISCARDABLE_MACOS_XATTR_PREFIXES
    )


def _empty_appledouble_resource_fork(value: bytes) -> bool:
    """Recognize only macOS's zero-resource placeholder, never fork content."""

    if not value:
        return True
    if len(value) != 286:
        return False
    header = struct.pack(">IIII", 256, 256, 0, 30)
    message = b"This resource fork intentionally left blank   "
    resource_map = header + (b"\0" * 8) + struct.pack(">HHH", 28, 30, 0xFFFF)
    expected = (
        header
        + message
        + (b"\0" * (256 - len(header) - len(message)))
        + resource_map
    )
    return value == expected


def _discardable_appledouble_finder_info(
    document: bytes,
    *,
    offset: int,
    length: int,
    any_metadata: bool = False,
) -> bool:
    """Validate FinderInfo plus only the xattrs Meshia already discards."""

    if length < 32:
        return False
    entry_end = offset + length
    finder_end = offset + 32
    # Keep populated FinderInfo in metadata-preserving mode. SMB's default
    # discards advisory metadata, including Finder's transient brok/MACS
    # incomplete-copy marker; publishing that marker greys out completed files.
    if not any_metadata and any(document[offset:finder_end]):
        return False
    attributes = (finder_end + 3) & ~3
    if attributes > entry_end or any(document[finder_end:attributes]):
        return False
    if attributes == entry_end:
        return True
    if attributes + 36 > entry_end:
        return False
    if document[attributes : attributes + 4] != _APPLEDOUBLE_ATTR_MAGIC:
        return False
    try:
        (
            debug_tag,
            total_size,
            data_start,
            data_length,
            reserved_a,
            reserved_b,
            reserved_c,
        ) = struct.unpack_from(">IIIIIII", document, attributes + 4)
        flags, attribute_count = struct.unpack_from(">HH", document, attributes + 32)
    except struct.error:
        return False
    if (
        debug_tag != 0
        or total_size != entry_end
        or data_start < attributes + 36
        or data_start > entry_end
        or data_length > entry_end - data_start
        or reserved_a != 0
        or reserved_b != 0
        or reserved_c != 0
        or flags != 0
        or attribute_count > 64
    ):
        return False

    cursor = attributes + 36
    value_ranges: list[tuple[int, int, str]] = []
    seen_names: set[str] = set()
    for _index in range(attribute_count):
        if cursor + 11 > data_start:
            return False
        try:
            value_offset, value_length, attribute_flags, name_length = (
                struct.unpack_from(">IIHB", document, cursor)
            )
        except struct.error:
            return False
        cursor += 11
        if name_length < 2 or cursor + name_length > data_start:
            return False
        encoded_name = document[cursor : cursor + name_length]
        if encoded_name[-1] != 0 or b"\0" in encoded_name[:-1]:
            return False
        try:
            name = encoded_name[:-1].decode("utf-8")
        except UnicodeDecodeError:
            return False
        if (
            name in seen_names
            # AppleDouble suppression is deletion authority, so keep it
            # narrower than the FUSE callback policy that merely acknowledges
            # unsupported cosmetic xattrs. In particular,
            # ``com.apple.metadata:*`` includes user-authored Finder tags and
            # comments; preserving their sidecar is safer than silently losing
            # them on the SMB ``nonamedattr`` transport.
            or (not any_metadata and name not in _DISCARDABLE_MACOS_XATTRS)
            or attribute_flags != 0
            or value_offset < data_start
            or value_offset > entry_end
            or value_length > entry_end - value_offset
        ):
            return False
        seen_names.add(name)
        value_ranges.append((value_offset, value_offset + value_length, name))
        cursor += name_length
        cursor = (cursor + 3) & ~3

    if cursor > data_start or any(document[cursor:data_start]):
        return False
    ordered_ranges = sorted(value_ranges)
    previous_end = data_start
    for value_start, value_end, name in ordered_ranges:
        if value_start < previous_end or any(document[previous_end:value_start]):
            return False
        if name == "com.apple.FinderInfo" and (
            value_end - value_start not in (0, 32)
            or (not any_metadata and any(document[value_start:value_end]))
        ):
            return False
        previous_end = value_end
    if previous_end - data_start != data_length:
        return False
    return not any(document[previous_end:entry_end])


def _discardable_appledouble_v2(document: bytes, *, any_metadata: bool = False) -> bool:
    """Fail closed unless bytes are only bounded, advisory macOS metadata.

    With ``any_metadata`` the structure is still validated (this must be a
    real AppleDouble v2 document; anything else is a user's file that merely
    starts with ``._``) but every extended attribute the client mirrored into
    it -- tags, comments, quarantine, FinderInfo flags -- is accepted as
    discardable. That is the SMB transport default (see
    ``MOUNT_KEEP_APPLEDOUBLE_SIDECARS_ENV``).
    """

    if any_metadata and len(document) == 0:
        # An empty ``._name`` is what the SMB bridge leaves when the client
        # created the sidecar and then had nothing to mirror into it (seen on
        # directories in a `cp -R`); it carries no user data.
        return True
    if not 26 <= len(document) <= MAX_DISCARDABLE_APPLEDOUBLE_BYTES:
        return False
    try:
        magic, version = struct.unpack_from(">II", document, 0)
        entry_count = struct.unpack_from(">H", document, 24)[0]
    except struct.error:
        return False
    if (
        magic != _APPLEDOUBLE_MAGIC
        or version != _APPLEDOUBLE_VERSION_2
        or document[8:24] not in _APPLEDOUBLE_SYSTEM_IDS
        or not 1 <= entry_count <= 2
    ):
        return False
    descriptor_end = 26 + (entry_count * 12)
    if descriptor_end > len(document):
        return False

    entries: dict[int, tuple[int, int]] = {}
    intervals: list[tuple[int, int]] = []
    for index in range(entry_count):
        try:
            entry_id, offset, length = struct.unpack_from(
                ">III", document, 26 + (index * 12)
            )
        except struct.error:
            return False
        if (
            entry_id not in (
                _APPLEDOUBLE_FINDER_INFO_ENTRY,
                _APPLEDOUBLE_RESOURCE_FORK_ENTRY,
            )
            or entry_id in entries
            or offset < descriptor_end
            or offset > len(document)
            or length > len(document) - offset
        ):
            return False
        entries[entry_id] = (offset, length)
        intervals.append((offset, offset + length))
    if _APPLEDOUBLE_FINDER_INFO_ENTRY not in entries:
        return False
    intervals.sort()
    cursor = descriptor_end
    for start, end in intervals:
        if start < cursor or any(document[cursor:start]):
            return False
        cursor = end
    if any(document[cursor:]):
        return False

    finder_offset, finder_length = entries[_APPLEDOUBLE_FINDER_INFO_ENTRY]
    if not _discardable_appledouble_finder_info(
        document,
        offset=finder_offset,
        length=finder_length,
        any_metadata=any_metadata,
    ):
        return False
    resource = entries.get(_APPLEDOUBLE_RESOURCE_FORK_ENTRY)
    return bool(
        resource is None
        or _empty_appledouble_resource_fork(
            document[resource[0] : resource[0] + resource[1]]
        )
    )


def _darwin_xattr_function(name: str) -> Any:
    """Return one typed descriptor-based Darwin xattr syscall."""

    if sys.platform != "darwin":
        raise OSError(errno.ENOTSUP, "macOS extended attributes are unavailable.")
    with _DARWIN_XATTR_LOCK:
        cached = _DARWIN_XATTR_FUNCTIONS.get(name)
        if cached is not None:
            return cached
        global _DARWIN_XATTR_LIBRARY
        if _DARWIN_XATTR_LIBRARY is None:
            _DARWIN_XATTR_LIBRARY = ctypes.CDLL(None, use_errno=True)
        function = getattr(_DARWIN_XATTR_LIBRARY, name)
        if name == "fsetxattr":
            function.argtypes = (
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_void_p,
                ctypes.c_size_t,
                ctypes.c_uint32,
                ctypes.c_int,
            )
        elif name == "fgetxattr":
            function.argtypes = (
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_void_p,
                ctypes.c_size_t,
                ctypes.c_uint32,
                ctypes.c_int,
            )
            function.restype = ctypes.c_ssize_t
            _DARWIN_XATTR_FUNCTIONS[name] = function
            return function
        elif name == "fremovexattr":
            function.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int)
        else:  # pragma: no cover - private callers use a closed set
            raise ValueError("Unsupported Darwin xattr function.")
        function.restype = ctypes.c_int
        _DARWIN_XATTR_FUNCTIONS[name] = function
        return function


def _raise_darwin_xattr_error(message: str) -> None:
    code = ctypes.get_errno() or errno.EIO
    raise OSError(code, message)


def _darwin_get_quarantine_xattr(descriptor: int, position: int = 0) -> bytes:
    if position != 0:
        raise OSError(errno.EINVAL, "Quarantine xattrs do not support positions.")
    function = _darwin_xattr_function("fgetxattr")
    name = _MACOS_QUARANTINE_XATTR.encode("utf-8")
    ctypes.set_errno(0)
    size = int(function(descriptor, name, None, 0, 0, 0))
    if size < 0:
        _raise_darwin_xattr_error("The quarantine attribute could not be read.")
    if size > _MAX_MACOS_QUARANTINE_BYTES:
        raise OSError(errno.E2BIG, "The quarantine attribute is too large.")
    if size == 0:
        return b""
    buffer = ctypes.create_string_buffer(size)
    ctypes.set_errno(0)
    received = int(function(descriptor, name, buffer, size, 0, 0))
    if received < 0:
        _raise_darwin_xattr_error("The quarantine attribute could not be read.")
    if received != size:
        raise OSError(errno.EIO, "The quarantine attribute changed while reading.")
    return bytes(buffer.raw[:received])


def _darwin_set_quarantine_xattr(
    descriptor: int,
    value: bytes,
    *,
    options: int = 0,
    position: int = 0,
) -> None:
    if not isinstance(value, bytes):
        raise OSError(errno.EINVAL, "Extended attribute values must be bytes.")
    if len(value) > _MAX_MACOS_QUARANTINE_BYTES:
        raise OSError(errno.E2BIG, "The quarantine attribute is too large.")
    if position != 0 or options & ~(_MACOS_XATTR_CREATE | _MACOS_XATTR_REPLACE):
        raise OSError(errno.EINVAL, "The quarantine attribute options are invalid.")
    if options == (_MACOS_XATTR_CREATE | _MACOS_XATTR_REPLACE):
        raise OSError(errno.EINVAL, "The quarantine attribute options conflict.")
    function = _darwin_xattr_function("fsetxattr")
    buffer = ctypes.create_string_buffer(value) if value else None
    ctypes.set_errno(0)
    result = int(
        function(
            descriptor,
            _MACOS_QUARANTINE_XATTR.encode("utf-8"),
            buffer,
            len(value),
            0,
            options,
        )
    )
    if result != 0:
        _raise_darwin_xattr_error("The quarantine attribute could not be written.")


def _darwin_remove_quarantine_xattr(descriptor: int) -> None:
    function = _darwin_xattr_function("fremovexattr")
    ctypes.set_errno(0)
    if int(function(descriptor, _MACOS_QUARANTINE_XATTR.encode("utf-8"), 0)) != 0:
        _raise_darwin_xattr_error("The quarantine attribute could not be removed.")


def mount_runtime_help(platform_name: str | None = None) -> str:
    current = sys.platform if platform_name is None else platform_name
    if current == "darwin":
        return MOUNT_RUNTIME_HELP
    if current == "win32":
        return MOUNT_RUNTIME_HELP_WINDOWS
    return MOUNT_RUNTIME_HELP_LINUX


def _portable_pread(descriptor: int, size: int, offset: int) -> bytes:
    native = getattr(os, "pread", None)
    if callable(native):
        return native(descriptor, size, offset)
    os.lseek(descriptor, offset, os.SEEK_SET)
    return os.read(descriptor, size)


def _portable_pwrite(descriptor: int, data: memoryview, offset: int) -> int:
    native = getattr(os, "pwrite", None)
    if callable(native):
        return native(descriptor, data, offset)
    os.lseek(descriptor, offset, os.SEEK_SET)
    return os.write(descriptor, data)


class FabricMountError(RuntimeError):
    """One mount lifecycle or durable-stage invariant failed."""


class _LocalStageCapacity:
    """One concurrency-safe admission fence for a mounted staging volume.

    The OS free-space report already includes bytes written by completed calls,
    so only writes currently between their check and syscall are reserved here.
    Each data syscall is capped at ``MOUNT_IO_BYTES``; consequently another
    Meshia writer can never race the reserve by more than one bounded call.
    External processes can still consume disk after a check, and the kernel's
    ENOSPC remains authoritative in that case.
    """

    def __init__(
        self,
        storage_root: Path | str,
        *,
        reserve_bytes: int = MOUNT_MIN_FREE_BYTES,
    ) -> None:
        if reserve_bytes < 0:
            raise ValueError("reserve_bytes must be non-negative")
        self.storage_root = Path(storage_root).expanduser()
        self.reserve_bytes = reserve_bytes
        self._lock = threading.Lock()
        self._pending_bytes = 0
        self._last_rejection_log = float("-inf")

    def _disk_snapshot(self) -> tuple[int, int]:
        """Read one strictly-shaped OS capacity snapshot or fail closed."""

        try:
            usage = shutil.disk_usage(self.storage_root)
            total = usage.total
            free = usage.free
        except (AttributeError, OSError, TypeError, ValueError) as error:
            raise OSError(
                errno.EIO, "The local staging capacity is unavailable."
            ) from error
        if (
            type(total) is not int
            or type(free) is not int
            or total <= 0
            or total > MAX_STATFS_BYTES
            or free < 0
            or free > total
        ):
            raise OSError(errno.EIO, "The local staging capacity is invalid.")
        return total, free

    def snapshot(self) -> tuple[int, int]:
        """Return local total and safely writable bytes from one statvfs read."""

        with self._lock:
            total, free = self._disk_snapshot()
            safe = max(
                0,
                free - self.reserve_bytes - self._pending_bytes,
            )
            return total, safe

    def reserve(self, growth_bytes: int) -> int:
        """Reserve an incremental growth before its local filesystem syscall."""

        if growth_bytes <= 0:
            return 0
        with self._lock:
            _total, free = self._disk_snapshot()
            safe = max(
                0,
                free - self.reserve_bytes - self._pending_bytes,
            )
            if growth_bytes > safe:
                raise OSError(
                    errno.ENOSPC,
                    "The local device cannot stage this mounted write safely.",
                )
            self._pending_bytes += growth_bytes
        return growth_bytes

    def release(self, reserved_bytes: int) -> None:
        if reserved_bytes <= 0:
            return
        with self._lock:
            if reserved_bytes > self._pending_bytes:
                raise FabricMountError("The local staging reservation underflowed.")
            self._pending_bytes -= reserved_bytes

    def record_rejection(
        self,
        logger: NodeLogger,
        *,
        path: str,
        growth_bytes: int,
        error: OSError,
    ) -> None:
        """Rate-limit disk-pressure diagnostics across the shared volume."""

        now = time.monotonic()
        with self._lock:
            if (
                now - self._last_rejection_log
                < MOUNT_CAPACITY_LOG_INTERVAL_SECONDS
            ):
                return
            self._last_rejection_log = now
        logger.record(
            "fabric_mount_local_capacity_rejected",
            path=path,
            growth_bytes=growth_bytes,
            error_code=errno.errorcode.get(error.errno or errno.ENOSPC, "ENOSPC"),
        )


class _RemoteQuotaCapacity:
    """One signed-quota fence shared by a lazy workspace and its runtime.

    The Fabric journal remains the only durable mutation authority. This
    object holds only concurrent open-session reservations and a cached
    projection of that existing journal so multi-megabyte writes do not scan
    SQLite once per chunk. The server repeats quota admission at commit time
    and therefore remains authoritative across other devices and stale-but-
    authenticated catalog snapshots.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._catalog_generation = -1
        self._quota_bytes: int | None = None
        self._used_bytes: int | None = None
        self._reserved_bytes: int = 0
        self._database: FabricDatabase | None = None
        self._pending_delta: int | None = None
        self._pending_refresh_generation = 0
        self._reservations: dict[str, tuple[int, int]] = {}

    def update_catalog(
        self,
        *,
        catalog_generation: int,
        quota_bytes: int | None,
        used_bytes: int | None,
        reserved_bytes: int | None = None,
    ) -> None:
        """Install one monotonic authenticated catalog capacity snapshot.

        A newer ``used_bytes`` value may already include a journal mutation
        that transitioned to ACKed since the prior projection. Invalidate that
        projection under the same generation fence used by concurrent refreshes
        and rebuild it outside the quota lock so the committed bytes are not
        counted once by the catalog and again by stale pending state.
        """

        if (
            isinstance(catalog_generation, bool)
            or not isinstance(catalog_generation, int)
            or catalog_generation < 0
        ):
            raise ValueError("catalog_generation must be non-negative")
        known = quota_bytes is not None and used_bytes is not None
        if known and (
            isinstance(quota_bytes, bool)
            or not isinstance(quota_bytes, int)
            or quota_bytes < 1
            or quota_bytes > MAX_STATFS_BYTES
            or isinstance(used_bytes, bool)
            or not isinstance(used_bytes, int)
            or used_bytes < 0
            or used_bytes > quota_bytes
        ):
            raise ValueError("The workspace quota snapshot is invalid.")
        if reserved_bytes is not None and (
            isinstance(reserved_bytes, bool)
            or not isinstance(reserved_bytes, int)
            or reserved_bytes < 0
            or reserved_bytes > MAX_STATFS_BYTES
        ):
            raise ValueError("The workspace reservation snapshot is invalid.")
        refresh_pending = False
        with self._lock:
            if catalog_generation < self._catalog_generation:
                return
            newer = catalog_generation > self._catalog_generation
            self._catalog_generation = catalog_generation
            self._quota_bytes = quota_bytes if known else None
            self._used_bytes = used_bytes if known else None
            self._reserved_bytes = reserved_bytes if known and reserved_bytes else 0
            if newer and self._database is not None:
                self._pending_delta = None
                self._pending_refresh_generation += 1
                refresh_pending = True
        if refresh_pending:
            self.refresh_pending()

    def attach_database(self, database: FabricDatabase) -> None:
        """Bind the active authority journal and refresh its durable delta."""

        if not isinstance(database, FabricDatabase):
            raise TypeError("database must be a FabricDatabase")
        with self._lock:
            self._database = database
            self._pending_delta = None
            self._pending_refresh_generation += 1
        self.refresh_pending()

    def detach_database(self, database: FabricDatabase) -> None:
        """Drop only the matching closed runtime; keep signed catalog state."""

        with self._lock:
            if self._database is database:
                self._database = None
                self._pending_delta = None
                self._pending_refresh_generation += 1

    def refresh_pending(self) -> bool:
        """Refresh the bounded projection of the existing durable journal."""

        with self._lock:
            database = self._database
            self._pending_refresh_generation += 1
            refresh_generation = self._pending_refresh_generation
        if database is None:
            return False
        try:
            delta = database.pending_quota_delta()
        except (OSError, StateError, sqlite3.Error):
            with self._lock:
                if (
                    self._database is database
                    and self._pending_refresh_generation == refresh_generation
                ):
                    self._pending_delta = None
            return False
        with self._lock:
            if (
                self._database is database
                and self._pending_refresh_generation == refresh_generation
            ):
                self._pending_delta = delta
                return True
        return False

    def _projected_used_locked(
        self,
        *,
        replacement: tuple[str, tuple[int, int]] | None = None,
    ) -> int | None:
        if self._used_bytes is None or self._pending_delta is None:
            return None
        reservations = dict(self._reservations)
        if replacement is not None:
            reservations[replacement[0]] = replacement[1]
        # The server admits writes against manifest bytes plus every active
        # reservation from every device. This host's own pending puts become a
        # subset of those reservations once their tickets are minted, so only
        # reservation bytes beyond this host's own pending growth are added;
        # pending deletes keep their full credit either way.
        own_growth = max(0, self._pending_delta)
        foreign_reserved = max(0, self._reserved_bytes - own_growth)
        return max(
            0,
            self._used_bytes
            + self._pending_delta
            + foreign_reserved
            + sum(projected - base for base, projected in reservations.values()),
        )

    def snapshot(self) -> tuple[int, int] | None:
        """Return quota and projected used bytes without inventing local usage."""

        with self._lock:
            if self._quota_bytes is None or self._used_bytes is None:
                return None
            projected = self._projected_used_locked()
            # A failed journal read must not make ordinary reads or truthful
            # signed statfs unavailable. Growth still fails closed in reserve().
            used = self._used_bytes if projected is None else projected
            return self._quota_bytes, min(used, self._quota_bytes)

    def reserve(self, reservation_id: str, base_bytes: int, projected_bytes: int) -> None:
        """Atomically resize one open-session reservation before byte growth."""

        if not reservation_id or base_bytes < 0 or projected_bytes < 0:
            raise ValueError("The remote quota reservation is invalid.")
        replacement = (reservation_id, (base_bytes, projected_bytes))
        with self._lock:
            previous = self._reservations.get(reservation_id, (base_bytes, base_bytes))
            previous_delta = previous[1] - previous[0]
            next_delta = projected_bytes - base_bytes
            if projected_bytes <= base_bytes or next_delta <= previous_delta:
                self._reservations[reservation_id] = replacement[1]
                return
            projected_used = self._projected_used_locked(replacement=replacement)
            if (
                self._quota_bytes is None
                or projected_used is None
                or projected_used > self._quota_bytes
            ):
                raise OSError(
                    errno.ENOSPC,
                    "The workspace does not have enough remote storage for this write.",
                )
            self._reservations[reservation_id] = replacement[1]

    def track_existing(
        self, reservation_id: str, base_bytes: int, projected_bytes: int
    ) -> None:
        """Restore already-written crash evidence without retroactive rejection."""

        if not reservation_id or base_bytes < 0 or projected_bytes < 0:
            raise ValueError("The remote quota reservation is invalid.")
        with self._lock:
            self._reservations[reservation_id] = (base_bytes, projected_bytes)

    def release(self, reservation_id: str) -> None:
        """Idempotently release one session after abort or durable handoff."""

        with self._lock:
            self._reservations.pop(reservation_id, None)


@dataclass(frozen=True)
class FuseRuntime:
    library_path: Path
    kind: str


def _trusted_fuse_t_server() -> Path | None:
    """Find the pinned FUSE-T mount server with a trusted install owner.

    Meshia's macOS installer verifies and installs FUSE-T 1.2.7. That release
    has a tested loopback SMB helper path. Refuse a different helper version
    instead of assuming its transport or discovery behavior is identical.
    """

    candidates = (
        Path("/usr/local/bin/go-nfsv4"),
        Path("/opt/homebrew/bin/go-nfsv4"),
        Path("/Library/Application Support/fuse-t/bin/go-nfsv4"),
    )
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
            info = resolved.stat()
        except OSError:
            continue
        if (
            stat.S_ISREG(info.st_mode)
            and bool(info.st_mode & stat.S_IXUSR)
            and info.st_uid == 0
            and not bool(info.st_mode & (stat.S_IWGRP | stat.S_IWOTH))
            and resolved.name == f"go-nfsv4-{FUSE_T_TRANSPORT_VERSION}"
        ):
            return resolved
    return None


def _write_fuse_t_transport_helper(state_path: Path | str) -> Path:
    """Create a private launcher for FUSE-T's unadvertised SMB transport.

    FUSE-T 1.2.7's SMB client always uses an internal Guest loopback session.
    Keep Bonjour disabled so that implementation detail is never advertised as
    a connectable server. The native mount is deliberately non-browsable below;
    users enter through the stable ``~/Meshia`` folder instead of Finder's
    transient network-server list.
    """

    server = _trusted_fuse_t_server()
    if server is None:
        raise FabricMountError("The trusted FUSE-T mount helper is unavailable.")
    destination = Path(state_path).expanduser().parent / FUSE_T_TRANSPORT_HELPER_NAME
    ensure_private_dir(destination.parent)
    script = (
        "#!/bin/sh\n"
        f"exec {shlex.quote(str(server))} --bonjour=false \"$@\"\n"
    ).encode("utf-8")
    write_private_file(destination, script)
    os.chmod(destination, 0o700)
    return destination


@dataclass(frozen=True)
class MountNode:
    path: str
    is_directory: bool
    size_bytes: int
    modified_ns: int
    digest: str | None = None

    def stat(self) -> dict[str, int | float]:
        timestamp = self.modified_ns / 1_000_000_000
        mode = (stat.S_IFDIR | 0o755) if self.is_directory else (stat.S_IFREG | 0o644)
        identity = (
            int.from_bytes(
                hashlib.sha256(self.path.encode("utf-8")).digest()[:8], "big"
            )
            or 1
        )
        blocks = (self.size_bytes + 511) // 512
        return {
            "st_mode": mode,
            "st_nlink": 2 if self.is_directory else 1,
            "st_size": self.size_bytes,
            "st_uid": os.getuid() if hasattr(os, "getuid") else 0,
            "st_gid": os.getgid() if hasattr(os, "getgid") else 0,
            "st_ino": identity,
            "st_atime": timestamp,
            "st_mtime": timestamp,
            "st_ctime": timestamp,
            "st_blocks": blocks,
            "st_blksize": MOUNT_IO_BYTES,
        }


@dataclass(frozen=True)
class _FileView:
    remote_path: str
    size_bytes: int
    digest: str | None
    modified_ns: int
    remote_source_path: str | None = None
    local_fingerprint: FileFingerprint | None = None
    session: "_MountWriteSession | None" = None
    native_tree: tuple[str, str] | None = None


@dataclass
class _RetiredLocalRead:
    descriptor: int
    identity: FileFingerprint
    lock: Any = field(default_factory=threading.Lock)


@dataclass
class _ReadHandle:
    view: _FileView
    version: FabricFileVersion | None = None
    retired_local: _RetiredLocalRead | None = None


def _fingerprint(info: os.stat_result) -> FileFingerprint:
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise FabricMountError(
            "A mounted-write stage must remain a single-link regular file."
        )
    size = int(info.st_size)
    if not 0 <= size <= MAX_LOCAL_UPLOAD_FILE_BYTES:
        raise FabricMountError(
            f"Mounted writes must be between 0 and {MAX_LOCAL_UPLOAD_FILE_BYTES} bytes."
        )
    return FileFingerprint(
        size_bytes=size,
        mtime_ns=int(info.st_mtime_ns),
        ctime_ns=int(info.st_ctime_ns),
        device_id=int(info.st_dev),
        file_id=int(info.st_ino),
    )


def _descriptor_fingerprint(descriptor: int) -> FileFingerprint:
    if sys.platform == "win32":
        from .workspace_win import _regular_fingerprint_from_descriptor

        result = _regular_fingerprint_from_descriptor(
            descriptor, "The mounted file must remain a single-link regular file."
        )
        if not 0 <= result.size_bytes <= MAX_LOCAL_UPLOAD_FILE_BYTES:
            raise FabricMountError("The mounted file exceeds the local upload limit.")
        return result
    return _fingerprint(os.fstat(descriptor))


def _set_descriptor_times_ns(descriptor: int, atime_ns: int, mtime_ns: int) -> None:
    if sys.platform == "win32":
        from .workspace_win import _set_windows_descriptor_times_ns

        _set_windows_descriptor_times_ns(descriptor, atime_ns, mtime_ns)
    else:
        os.utime(descriptor, ns=(atime_ns, mtime_ns))


def _fingerprint_document(value: FileFingerprint | None) -> dict[str, int] | None:
    if value is None:
        return None
    return {
        "size_bytes": value.size_bytes,
        "mtime_ns": value.mtime_ns,
        "ctime_ns": value.ctime_ns,
        "device_id": value.device_id,
        "file_id": value.file_id,
    }


def _fingerprint_text(value: FileFingerprint) -> str:
    document = _fingerprint_document(value)
    assert document is not None
    return json.dumps(document, sort_keys=True, separators=(",", ":"))


def _fingerprint_from_document(value: object) -> FileFingerprint | None:
    if value is None:
        return None
    if not isinstance(value, Mapping) or set(value) != {
        "size_bytes",
        "mtime_ns",
        "ctime_ns",
        "device_id",
        "file_id",
    }:
        raise FabricMountError("A mounted-write fingerprint marker is invalid.")
    fields = tuple(
        value[name]
        for name in ("size_bytes", "mtime_ns", "ctime_ns", "device_id", "file_id")
    )
    if any(
        isinstance(item, bool) or not isinstance(item, int) or item < 0
        for item in fields
    ):
        raise FabricMountError("A mounted-write fingerprint marker is invalid.")
    return FileFingerprint(*fields)


def _same_file_bytes(before: FileFingerprint, after: FileFingerprint | None) -> bool:
    """Prove one inode and byte-visible state across an atomic rename.

    Namespace operations may advance ctime, so it is deliberately excluded.
    Device/inode, size, and mtime still fence the exact staged byte state.
    """

    return bool(
        after is not None
        and before.device_id == after.device_id
        and before.file_id == after.file_id
        and before.size_bytes == after.size_bytes
        and before.mtime_ns == after.mtime_ns
    )


def _same_file_storage(
    before: FileFingerprint, after: FileFingerprint | None
) -> bool:
    """Prove one inode and length while explicitly changing its mtime.

    Callers must additionally exclude concurrent writers. This narrower fence
    exists only for a client-originated timestamp syscall, whose purpose is to
    change the mtime that ``_same_file_bytes`` normally protects.
    """

    return bool(
        after is not None
        and before.device_id == after.device_id
        and before.file_id == after.file_id
        and before.size_bytes == after.size_bytes
    )


def _optional_digest(value: object) -> str | None:
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise FabricMountError("A mounted-write digest marker is invalid.")
    return value


def _modified_ns(value: str | None, fallback: int) -> int:
    if value:
        try:
            return int(
                datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp() * 1e9
            )
        except (OverflowError, ValueError):
            pass
    return fallback


def _direct_child(parent: str | None, path: str) -> str | None:
    prefix = "" if parent is None else parent + "/"
    if not path.startswith(prefix):
        return None
    remainder = path[len(prefix) :]
    if not remainder:
        return None
    return remainder.split("/", 1)[0]


class _MountWriteSession:
    """One crash-described write inode, sealed before namespace publication."""

    # Class default so sessions rebuilt from a recovery marker (which bypass
    # __init__) carry the field too.
    discard_grace_deadline: float | None = None
    tree_journal: FileTreeJournal | None = None
    tree_owner: str | None = None
    _inflight_reads: int = 0
    _deferred_disposal: str | None = None

    def __init__(
        self,
        workspace: WorkspaceBoundary,
        remote_path: str,
        *,
        base_digest: str | None,
        expected_existing_fingerprint: FileFingerprint | None,
        pristine_view: _FileView | None,
        created: bool,
        logger: NodeLogger,
        stage_capacity: _LocalStageCapacity | None = None,
        remote_quota: _RemoteQuotaCapacity | None = None,
        base_size_bytes: int | None = None,
        transport_provenance: str | None = None,
        tree_journal: FileTreeJournal | None = None,
        tree_mutation: Callable[[Callable[[], Any]], Any] | None = None,
        tree_release: Callable[[str], None] | None = None,
    ) -> None:
        if tree_journal is not None and (tree_mutation is None or tree_release is None):
            raise ValueError("A native tree requires its admission and lifetime owner")
        if transport_provenance is not None and not self._valid_transport_provenance(
            transport_provenance,
            remote_path,
            original_remote_path=remote_path,
        ):
            raise ValueError("The mounted-write transport provenance is invalid.")
        self.workspace = workspace
        self.remote_path = remote_path
        self.original_remote_path = remote_path
        self.base_digest = base_digest
        self.original_base_digest = base_digest
        self.expected_existing_fingerprint = expected_existing_fingerprint
        self.delete_after_ack: tuple[str, str] | None = None
        self.stage_capacity = stage_capacity or _LocalStageCapacity(workspace.root)
        self.remote_quota = remote_quota
        self.base_size_bytes = (
            pristine_view.size_bytes
            if base_size_bytes is None and pristine_view is not None
            else int(base_size_bytes or 0)
        )
        self.transport_provenance = transport_provenance
        self.logger = logger
        self.token = uuid.uuid4().hex
        root = workspace.mount_staging_directory()
        self.data_path = root / f"{self.token}.data"
        self.marker_path = root / f"{self.token}.json"
        self.descriptor = workspace.open_mount_stage_descriptor(self.data_path, create=True)
        try:
            self.tree_journal = tree_journal
            self._tree_mutation = tree_mutation
            self._tree_release = tree_release
            self.tree_owner = (tree_mutation(lambda: tree_journal.retain(owner=f"mount:{self.token}", publication=False))
                if tree_journal is not None else None)
            if hasattr(os, "fchmod"):
                os.fchmod(self.descriptor, 0o600)
            self.sealed = False
            self.sealed_fingerprint: FileFingerprint | None = None
            self.published = False
            self.publishing = False
            self.journaled = False
            self.detached = False
            self.delete_pending = False
            self.cancelled = False
            # The SMB bridge can retain its writable FUSE description for tens
            # of seconds after delivering FLUSH. A quiet FLUSH settle window is
            # the close fence for that transport: writes before it expires
            # cancel the timer; writes after it expires are rejected by sealed.
            self.flush_closed = False
            self.publish_failures = 0
            # Monotonic deadline until which a discardable sidecar is kept
            # reopenable before cancellation; None until first observed.
            self.discard_grace_deadline: float | None = None
            # FUSE-T's SMB bridge may request O_RDWR for a read-only consumer.
            # Keep the immutable source view lazy until an actual mutation;
            # read/fsync/close must never republish the whole remote file.
            self.pristine_view = pristine_view
            self.seeded = pristine_view is None or tree_journal is not None
            self.modified = created
            self.created = created
            self.failed_mutation = False
            self.failed_mutation_errno: int | None = None
            self._lock = threading.RLock()
            self._write_marker("open")
        except BaseException:
            # __init__ never returns, so no caller can invoke abort() on this
            # half-built object. Retire both resources here rather than leaking
            # an fd and an ownerless .data inode on a full disk.
            try:
                os.close(self.descriptor)
            except OSError:
                pass
            self.descriptor = -1
            if self.tree_owner is not None:
                tree_release(self.tree_owner)
                self.tree_owner = None
            for path in (self.data_path, self.marker_path):
                try:
                    path.unlink()
                except OSError:
                    pass
            raise

    @property
    def mutation_id(self) -> str:
        """Return the journal UUID durably encoded by this session token."""

        return str(uuid.UUID(hex=self.token))

    @staticmethod
    def _valid_transport_provenance(
        provenance: str,
        remote_path: str,
        *,
        original_remote_path: str,
    ) -> bool:
        original_temp = _smb_copy_pair_key(
            original_remote_path,
            appledouble=True,
        )
        if original_temp is None:
            return False
        current_temp = _smb_copy_pair_key(remote_path, appledouble=True)
        current_final = _smb_final_copy_pair_key(remote_path, appledouble=True)
        if provenance == _FUSE_T_SMB_APPLEDOUBLE_PROVENANCE:
            # An exact temp-pair proof can survive a sidecar rename while the
            # companion data rename is still being observed. Only the stronger
            # final-pair receipt below authorizes final-name suppression.
            return bool(
                current_temp == original_temp
                or (
                    current_final is not None
                    and current_final[0] == original_temp[0]
                )
            )
        return bool(
            provenance == _FUSE_T_SMB_FINAL_APPLEDOUBLE_PROVENANCE
            and current_final is not None
            and current_final[0] == original_temp[0]
        )

    @classmethod
    def recover(
        cls,
        workspace: WorkspaceBoundary,
        marker_path: Path,
        *,
        logger: NodeLogger,
        stage_capacity: _LocalStageCapacity | None = None,
        tree_recovery: Callable | None = None,
    ) -> tuple[str, "_MountWriteSession | None"]:
        descriptor = -1
        try:
            descriptor = os.open(str(marker_path), os.O_RDONLY | _NOFOLLOW | _CLOEXEC)
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or (os.name != "nt" and stat.S_IMODE(before.st_mode) != 0o600)
                or (hasattr(os, "geteuid") and before.st_uid != os.geteuid())
            ):
                raise FabricMountError(
                    "A mounted-write marker is not a private regular file."
                )
            raw = os.read(descriptor, MAX_STAGE_MARKER_BYTES + 1)
            after = os.fstat(descriptor)
            if (
                before.st_dev != after.st_dev
                or before.st_ino != after.st_ino
                or before.st_size != after.st_size
                or before.st_mtime_ns != after.st_mtime_ns
                or len(raw) != before.st_size
            ):
                raise FabricMountError(
                    "A mounted-write marker changed while it was read."
                )
        except OSError as error:
            raise FabricMountError("A mounted-write marker cannot be read.") from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        if len(raw) > MAX_STAGE_MARKER_BYTES:
            raise FabricMountError("A mounted-write marker is too large.")
        try:
            document = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise FabricMountError(
                "A mounted-write marker is not valid JSON."
            ) from error
        if (
            not isinstance(document, Mapping)
            or document.get("schema") != MOUNT_STAGE_SCHEMA
        ):
            raise FabricMountError("A mounted-write marker has an unknown schema.")
        is_tree = any(key in document for key in ("tree_journal", "tree_owner", "tree_descriptor"))
        if is_tree and tree_recovery is None:
            # Journal recovery must bind its separate byte and retention
            # ownership before this inode-only reader can touch the marker.
            raise FabricMountError("This write requires native tree-journal recovery.")
        state = document.get("state")
        if state not in (
            "open",
            "flushed",
            "ready",
            "published",
            "delete_pending",
            "cancelled",
        ):
            raise FabricMountError("A mounted-write marker has an invalid state.")
        modified = document.get("modified", True)
        if not isinstance(modified, bool):
            raise FabricMountError("A mounted-write marker has an invalid edit state.")
        if state in (
            "flushed",
            "ready",
            "published",
        ) and not modified:
            raise FabricMountError("An unmodified mounted-write marker cannot be complete.")
        token = document.get("token")
        data_name = document.get("data_name")
        if (
            not isinstance(token, str)
            or len(token) != 32
            or any(character not in "0123456789abcdef" for character in token)
            or data_name != f"{token}.data"
            or marker_path.name != f"{token}.json"
        ):
            raise FabricMountError("A mounted-write marker has an invalid identity.")
        remote_path = document.get("remote_path")
        original_remote_path = document.get("original_remote_path")
        if not isinstance(remote_path, str) or not isinstance(
            original_remote_path, str
        ):
            raise FabricMountError("A mounted-write marker has an invalid path.")
        split_relative(remote_path)
        split_relative(original_remote_path)
        transport_provenance = document.get("transport_provenance")
        if transport_provenance is not None and not cls._valid_transport_provenance(
            transport_provenance,
            remote_path,
            original_remote_path=original_remote_path,
        ):
            raise FabricMountError(
                "A mounted-write marker has invalid transport provenance."
            )
        delete_value = document.get("delete_after_ack")
        delete_after_ack: tuple[str, str] | None = None
        if delete_value is not None:
            if not isinstance(delete_value, list) or len(delete_value) != 2:
                raise FabricMountError("A mounted-write delete dependency is invalid.")
            delete_path, delete_digest = delete_value
            if not isinstance(delete_path, str):
                raise FabricMountError("A mounted-write delete dependency is invalid.")
            split_relative(delete_path)
            parsed_delete_digest = _optional_digest(delete_digest)
            if parsed_delete_digest is None:
                raise FabricMountError("A mounted-write delete dependency is invalid.")
            delete_after_ack = (delete_path, parsed_delete_digest)

        sealed_fingerprint = _fingerprint_from_document(
            document.get("stage_fingerprint")
        )
        if state in (
            "flushed",
            "ready",
            "published",
            "delete_pending",
            "cancelled",
        ) and sealed_fingerprint is None:
            raise FabricMountError(
                "A completed mounted-write marker lacks an inode receipt."
            )

        data_path = marker_path.parent / data_name
        native = None
        native_handed_off = False
        if is_tree:
            if state == "published" or (sealed_fingerprint is not None and sealed_fingerprint.size_bytes != 0):
                raise FabricMountError("A native tree cannot use a published content inode.")
            try:
                native, native_handed_off = tree_recovery(document)
            except (KeyError, TypeError, ValueError, StateError, OSError, sqlite3.Error, RemoteError, NetworkError) as error:
                raise FabricMountError("The native tree close owner could not be restored.") from error
        if state == "open":
            if not modified:
                # A pristine O_RDWR handle contains no user work. It is safe
                # to discard after a crash and must not surface as a recovered
                # empty/full-size file merely because SMB widened open flags.
                for path in (data_path, marker_path):
                    try:
                        path.unlink()
                    except FileNotFoundError:
                        pass
                if native is not None:
                    native.release_later(document["tree_owner"])
                return "discarded", None
            # A process crash cannot prove that close(2) was reached. Preserve
            # these bytes for manual recovery instead of publishing a partial file.
            return state, None
        descriptor = -1
        if state in ("flushed", "ready", "delete_pending"):
            try:
                descriptor = workspace.open_mount_stage_descriptor(data_path)
            except FileNotFoundError:
                # The only legitimate missing-stage case is a crash after the
                # atomic rename but before the marker advanced to published.
                # Admit it only when the destination is the exact same inode
                # with the exact sealed byte-visible state.
                if is_tree:
                    if not native_handed_off:
                        raise FabricMountError("A native close lost its metadata inode before handoff.") from None
                else:
                    try:
                        published = workspace.stat_fingerprint(remote_path)
                    except (OSError, UnsafePath):
                        published = None
                    if not _same_file_bytes(sealed_fingerprint, published):
                        raise FabricMountError(
                            "A ready mounted-write stage disappeared before publication."
                        ) from None
                    state = "published"
            else:
                try:
                    current = _descriptor_fingerprint(descriptor)
                    if current != sealed_fingerprint:
                        raise FabricMountError(
                            "A ready mounted-write stage changed after close."
                        )
                except BaseException:
                    os.close(descriptor)
                    raise
        if state == "published":
            try:
                published = workspace.stat_fingerprint(remote_path)
            except (OSError, UnsafePath):
                published = None
            if not _same_file_bytes(sealed_fingerprint, published):
                raise FabricMountError(
                    "A published mounted-write inode no longer matches its receipt."
                )
        instance = cls.__new__(cls)
        instance.workspace = workspace
        instance.remote_path = remote_path
        instance.original_remote_path = original_remote_path
        instance.base_digest = _optional_digest(document.get("base_digest"))
        instance.original_base_digest = _optional_digest(
            document.get("original_base_digest")
        )
        instance.expected_existing_fingerprint = _fingerprint_from_document(
            document.get("expected_existing_fingerprint")
        )
        instance.delete_after_ack = delete_after_ack
        instance.stage_capacity = stage_capacity or _LocalStageCapacity(
            workspace.root
        )
        instance.remote_quota = None
        instance.base_size_bytes = 0
        instance.transport_provenance = transport_provenance
        instance.logger = logger
        instance.token = token
        instance.data_path = data_path
        instance.marker_path = marker_path
        instance.descriptor = descriptor
        instance.sealed = True
        instance.sealed_fingerprint = sealed_fingerprint
        instance.published = state == "published"
        instance.publishing = False
        # A published marker proves only the local namespace move. Recovery
        # must repeat the idempotent durable-journal handoff before cleanup.
        instance.journaled = False
        instance.detached = False
        instance.delete_pending = state == "delete_pending"
        instance.cancelled = state == "cancelled"
        instance.flush_closed = True
        instance.publish_failures = 0
        instance.pristine_view = None
        instance.seeded = True
        instance.modified = modified
        instance.created = bool(
            instance.original_base_digest is None
            and instance.expected_existing_fingerprint is None
        )
        instance.failed_mutation = False
        instance.failed_mutation_errno = None
        instance._lock = threading.RLock()
        if native is not None:
            instance.tree_journal = native.journal
            instance.tree_owner = document["tree_owner"]
            instance._tree_mutation = native.mutate
            instance._tree_release = native.release_later
        return state, instance

    def _document(self, state: str) -> dict[str, object]:
        return {
            "schema": MOUNT_STAGE_SCHEMA,
            "state": state,
            "token": self.token,
            "owner_pid": os.getpid(),
            "remote_path": self.remote_path,
            "original_remote_path": self.original_remote_path,
            "base_digest": self.base_digest,
            "original_base_digest": self.original_base_digest,
            "delete_after_ack": list(self.delete_after_ack)
            if self.delete_after_ack
            else None,
            "expected_existing_fingerprint": _fingerprint_document(
                self.expected_existing_fingerprint
            ),
            "modified": self.modified,
            "transport_provenance": self.transport_provenance,
            "stage_fingerprint": _fingerprint_document(self.sealed_fingerprint),
            "data_name": self.data_path.name,
            "updated_at_ns": time.time_ns(),
            **({"tree_journal": self.tree_journal.identity,
                "tree_owner": self.tree_owner,
                "tree_descriptor": self.tree_journal.descriptor(self.tree_owner)}
                if self.tree_journal is not None else {}),
        }

    def _capture_tree_owner_locked(self) -> str | None:
        """Give this close epoch its own root, distinct from upload ownership."""
        if self.tree_journal is None:
            return None
        if (self.tree_owner is not None
                and self.tree_journal.digest(self.tree_owner) == self.tree_journal.digest()):
            return None
        previous = self.tree_owner
        self.tree_owner = self._tree_mutation(lambda: self.tree_journal.retain(owner=f"mount:{self.token}", publication=False))
        return previous

    def _retire_tree_owner_locked(self, previous: str | None) -> None:
        if previous is not None:
            self._tree_mutation(lambda: self.tree_journal.release(previous))

    def _touch_tree_metadata_locked(self) -> None:
        # The inode owns only OS metadata. Logical bytes and size come from the
        # journal, so no hole-filled inode can masquerade as the complete file.
        now = time.time_ns() // 1000 * 1000
        os.utime(self.data_path, ns=(now, now), follow_symlinks=False)

    def _write_marker(self, state: str) -> None:
        if self.tree_journal is not None:
            # A replaced marker already owns its root even if directory fsync
            # returned an error. Never release that root as a failed capture.
            self._write_marker_transactionally(state)
            return
        write_private_file(
            self.marker_path,
            json.dumps(
                self._document(state),
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8"),
        )

    def _write_marker_transactionally(self, state: str) -> None:
        """Resolve an atomic marker write that can fail after replacement."""

        encoded = json.dumps(
            self._document(state),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        try:
            write_private_file(self.marker_path, encoded)
        except BaseException:
            if self._marker_matches(encoded):
                return
            raise

    def _marker_matches(self, expected: bytes) -> bool:
        """Read back one exact atomic marker after an ambiguous write error."""

        descriptor = -1
        try:
            descriptor = os.open(
                str(self.marker_path),
                os.O_RDONLY | _NOFOLLOW | _CLOEXEC,
            )
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_size != len(expected)
                or before.st_size > MAX_STAGE_MARKER_BYTES
            ):
                return False
            actual = os.read(descriptor, MAX_STAGE_MARKER_BYTES + 1)
            after = os.fstat(descriptor)
            return bool(
                actual == expected
                and before.st_dev == after.st_dev
                and before.st_ino == after.st_ino
                and before.st_size == after.st_size
                and before.st_mtime_ns == after.st_mtime_ns
            )
        except OSError:
            return False
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _record_capacity_rejection(self, growth_bytes: int, error: OSError) -> None:
        """Emit at most one low-disk event per shared staging volume."""

        self.stage_capacity.record_rejection(
            self.logger,
            path=self.remote_path,
            growth_bytes=growth_bytes,
            error=error,
        )

    def _reserve_growth_locked(
        self, growth_bytes: int, *, poison_on_failure: bool
    ) -> int:
        try:
            return self.stage_capacity.reserve(growth_bytes)
        except OSError as error:
            if poison_on_failure:
                self._poison_mutation_locked(error.errno)
            if error.errno == errno.ENOSPC:
                self._record_capacity_rejection(growth_bytes, error)
            raise

    def _pwrite_bounded_locked(
        self,
        data: memoryview,
        offset: int,
        *,
        poison_on_failure: bool,
    ) -> int:
        """Preflight and issue one at-most-1MiB stage growth syscall."""

        if len(data) > MOUNT_IO_BYTES:
            raise FabricMountError("A mounted write exceeded its syscall byte bound.")
        info = os.fstat(self.descriptor)
        current_size = int(info.st_size)
        logical_growth = max(0, offset + len(data) - current_size)
        allocated_bytes = int(getattr(info, "st_blocks", 0)) * 512
        # A pwrite into a sparse hole allocates local blocks without increasing
        # st_size. Conservatively charge its bounded payload whenever the inode
        # is observably sparse; ordinary fully-materialized overwrites remain
        # admission-free, while logical append charges only its new tail.
        if (
            current_size == 0
            or allocated_bytes < current_size
            or offset >= current_size
        ):
            growth = len(data)
        else:
            growth = logical_growth
        reserved = self._reserve_growth_locked(
            growth, poison_on_failure=poison_on_failure
        )
        try:
            return _portable_pwrite(self.descriptor, data, offset)
        except OSError as error:
            if poison_on_failure:
                self._poison_mutation_locked(error.errno)
            if error.errno == errno.ENOSPC:
                self._record_capacity_rejection(growth, error)
            raise
        finally:
            self.stage_capacity.release(reserved)

    def _begin_mutation_locked(self) -> None:
        """Publish the first edit intent before any user-visible byte mutation."""

        if self.modified:
            return
        self.modified = True
        try:
            self._write_marker_transactionally("open")
        except BaseException:
            # No user byte syscall has happened yet. Restore the pristine state
            # so a later retry must successfully publish its intent as well.
            self.modified = False
            raise

    def bind_remote_quota(
        self, capacity: _RemoteQuotaCapacity, *, base_size_bytes: int
    ) -> None:
        """Attach the active signed-quota fence to this retained session."""

        with self._lock:
            self.remote_quota = capacity
            self.base_size_bytes = base_size_bytes
            capacity.track_existing(
                self.mutation_id,
                base_size_bytes,
                self.size(),
            )

    def bind_stage_capacity(self, capacity: _LocalStageCapacity) -> None:
        """Attach the mount-wide local-capacity fence to this retained session."""

        if not isinstance(capacity, _LocalStageCapacity):
            raise TypeError("capacity must be a local stage capacity")
        with self._lock:
            self.stage_capacity = capacity

    def mark_transport_provenance(self, provenance: str) -> None:
        """Persist transport evidence before a scratch stage may be discarded."""

        with self._lock:
            if self.transport_provenance == provenance:
                return
            if (
                not self._valid_transport_provenance(
                    provenance,
                    self.remote_path,
                    original_remote_path=self.original_remote_path,
                )
                or (
                    self.transport_provenance is not None
                    and not (
                        self.transport_provenance
                        == _FUSE_T_SMB_APPLEDOUBLE_PROVENANCE
                        and provenance
                        == _FUSE_T_SMB_FINAL_APPLEDOUBLE_PROVENANCE
                    )
                )
                or not self.created
                or self.original_base_digest is not None
                or self.published
                or self.publishing
                or self.journaled
                or self.delete_pending
                or self.cancelled
            ):
                raise OSError(
                    errno.EBUSY,
                    "The mounted file cannot be marked as transport scratch.",
                )
            previous = self.transport_provenance
            self.transport_provenance = provenance
            try:
                self._write_marker_transactionally(
                    "ready"
                    if self.sealed or self.sealed_fingerprint is not None
                    else "open"
                )
            except BaseException:
                self.transport_provenance = previous
                raise

    def has_discardable_appledouble_bytes(self, *, any_metadata: bool = False) -> bool:
        """Validate one sealed sidecar inode without trusting its basename."""

        def read_descriptor(descriptor: int) -> tuple[bytes, FileFingerprint]:
            before = _descriptor_fingerprint(descriptor)
            if before.size_bytes > MAX_DISCARDABLE_APPLEDOUBLE_BYTES:
                return b"", before
            chunks: list[bytes] = []
            offset = 0
            while offset < before.size_bytes:
                chunk = _portable_pread(
                    descriptor,
                    before.size_bytes - offset,
                    offset,
                )
                if not chunk:
                    break
                chunks.append(chunk)
                offset += len(chunk)
            after = _descriptor_fingerprint(descriptor)
            if before != after or offset != before.size_bytes:
                return b"", after
            return b"".join(chunks), after

        with self._lock:
            if not self.sealed or self.sealed_fingerprint is None:
                return False
            try:
                if self.descriptor >= 0:
                    document, observed = read_descriptor(self.descriptor)
                elif self.published:
                    document, observed = self.workspace.with_regular_file_descriptor(
                        self.remote_path,
                        read_descriptor,
                    )
                else:
                    return False
            except (InvalidTask, OSError, UnsafePath):
                return False
            return bool(
                observed == self.sealed_fingerprint
                and _discardable_appledouble_v2(document, any_metadata=any_metadata)
            )

    def _reserve_remote_size_locked(self, projected_size: int) -> None:
        if self.remote_quota is not None:
            self.remote_quota.reserve(
                self.mutation_id,
                self.base_size_bytes,
                projected_size,
            )

    def _sync_remote_reservation_locked(self) -> None:
        if self.remote_quota is None:
            return
        current = (
            self.pristine_view.size_bytes
            if self.pristine_view is not None and not self.modified
            else self.size()
        )
        self.remote_quota.track_existing(
            self.mutation_id,
            self.base_size_bytes,
            current,
        )

    def release_remote_quota(self) -> None:
        if self.remote_quota is not None:
            self.remote_quota.release(self.mutation_id)

    def mark_delete_pending(self) -> None:
        """Fence publication before an explicit unlink enters its journal."""

        with self._lock:
            if self.cancelled:
                return
            if self.delete_pending:
                return
            # FUSE-T's SMB bridge can retain an O_RDWR description beyond the
            # client-side unlink. A pristine alias can be sealed here. A
            # modified alias is safe only after FLUSH persisted an exact inode
            # receipt; keep it logically open so a failed delete can restore the
            # ready epoch, but fence every later byte mutation with
            # ``delete_pending`` below. In both cases restart can replay only the
            # tombstone and the superseded PUT can never resurrect the path.
            pristine_open = bool(
                not self.sealed
                and not self.modified
                and self.pristine_view is not None
                and not self.published
                and not self.publishing
                and not self.journaled
                and not self.failed_mutation
            )
            flushed_open = bool(
                not self.sealed
                and self.modified
                and self.sealed_fingerprint is not None
                and not self.published
                and not self.publishing
                and not self.journaled
                and not self.failed_mutation
            )
            if not self.sealed and not pristine_open and not flushed_open:
                raise OSError(errno.EBUSY, "The mounted file is still open.")
            if flushed_open:
                current = _descriptor_fingerprint(self.descriptor)
                if current != self.sealed_fingerprint:
                    raise OSError(
                        errno.ESTALE,
                        "The flushed mounted file changed before deletion.",
                    )
            previous_sealed = self.sealed
            previous_fingerprint = self.sealed_fingerprint
            previous_flush_closed = self.flush_closed
            if pristine_open:
                self._fsync_data_locked()
                self.sealed_fingerprint = _descriptor_fingerprint(self.descriptor)
                self.sealed = True
                self.flush_closed = True
            self.delete_pending = True
            try:
                self._write_marker_transactionally("delete_pending")
            except BaseException:
                self.delete_pending = False
                self.sealed = previous_sealed
                self.sealed_fingerprint = previous_fingerprint
                self.flush_closed = previous_flush_closed
                raise

    def _poison_mutation_locked(self, error_code: int | None) -> None:
        if self.published or self.journaled:
            return
        self.failed_mutation = True
        if self.failed_mutation_errno is None:
            self.failed_mutation_errno = error_code or errno.EIO

    def _raise_if_poisoned_locked(self) -> None:
        if self.failed_mutation:
            raise OSError(
                self.failed_mutation_errno or errno.EIO,
                "The failed mounted write must be closed before retrying.",
            )

    def _fsync_data_locked(self) -> None:
        """Flush stage bytes or fence this handle from later publication."""

        if self.descriptor < 0:
            raise OSError(errno.EBADF, "The mounted write is already closed.")
        self._raise_if_poisoned_locked()
        try:
            os.fsync(self.descriptor)
        except OSError as error:
            # Delayed-allocation filesystems can accept pwrite and report the
            # real ENOSPC/EIO only here. Once that happens the byte image is
            # ambiguous, so no later FLUSH, RELEASE, or timer may publish it.
            self._poison_mutation_locked(error.errno)
            if error.errno == errno.ENOSPC:
                self._record_capacity_rejection(0, error)
            raise

    def restore_after_delete_failure(self) -> None:
        """Return a failed in-process unlink to its prior upload ownership."""

        with self._lock:
            if not self.delete_pending or self.cancelled:
                return
            pristine_open = bool(
                not self.modified
                and self.pristine_view is not None
                and self.sealed
            )
            previous_sealed = self.sealed
            previous_fingerprint = self.sealed_fingerprint
            previous_flush_closed = self.flush_closed
            self.delete_pending = False
            if pristine_open:
                self.sealed = False
                self.sealed_fingerprint = None
                self.flush_closed = False
            try:
                self._write_marker_transactionally(
                    "open" if pristine_open else "ready"
                )
            except BaseException:
                self.delete_pending = True
                self.sealed = previous_sealed
                self.sealed_fingerprint = previous_fingerprint
                self.flush_closed = previous_flush_closed
                raise

    def mark_cancelled(self) -> None:
        """Persist that a durable delete superseded this staged upload."""

        with self._lock:
            previous_pending = self.delete_pending
            previous_cancelled = self.cancelled
            previous_fingerprint = self.sealed_fingerprint
            if self.sealed_fingerprint is None:
                self.sealed_fingerprint = _descriptor_fingerprint(self.descriptor)
            self.delete_pending = False
            self.cancelled = True
            try:
                self._write_marker_transactionally("cancelled")
            except BaseException:
                self.delete_pending = previous_pending
                self.cancelled = previous_cancelled
                self.sealed_fingerprint = previous_fingerprint
                raise
            self.release_remote_quota()

    def _seed_from_locked(
        self,
        stream_view: Callable[..., Iterable[bytes]],
        *,
        after_seed: Callable[[int, _FileView], None] | None = None,
        retained_size: int | None = None,
    ) -> None:
        """Materialize the current pristine view while ``self._lock`` is held."""

        if self.seeded:
            return
        pristine = self.pristine_view
        if pristine is None:
            raise FabricMountError("The mounted write lost its pristine view.")
        expected_size = (
            pristine.size_bytes if retained_size is None
            else min(pristine.size_bytes, retained_size)
        )
        if not 0 <= expected_size <= MAX_LOCAL_UPLOAD_FILE_BYTES:
            raise OSError(
                errno.EFBIG, "The source exceeds Meshia's mounted-write limit."
            )
        offset = 0
        try:
            chunks = (stream_view(pristine) if expected_size == pristine.size_bytes
                      else stream_view(pristine, expected_size))
            for chunk in chunks:
                if not isinstance(chunk, bytes) or offset + len(chunk) > expected_size:
                    raise FabricMountError(
                        "The mounted-write seed violated its byte bound."
                    )
                view = memoryview(chunk)
                while view:
                    bounded = view[:MOUNT_IO_BYTES]
                    written = self._pwrite_bounded_locked(
                        bounded,
                        offset,
                        poison_on_failure=False,
                    )
                    if written <= 0:
                        raise OSError(errno.EIO, "The mounted-write seed made no progress.")
                    view = view[written:]
                    offset += written
            if offset != expected_size:
                raise OSError(errno.EIO, "The mounted-write seed ended early.")
            if after_seed is not None:
                after_seed(self.descriptor, pristine)
        except BaseException:
            os.ftruncate(self.descriptor, 0)
            raise
        if expected_size == pristine.size_bytes:
            self.seeded = True
            self.pristine_view = None
        # A prefix is not the original file. Keep the immutable view visible
        # until truncate_from durably records the edit intent. A marker failure
        # must leave reads and the next retry bound to the complete preimage.

    def seed_from(
        self,
        stream_view: Callable[[_FileView], Iterable[bytes]],
        *,
        after_seed: Callable[[int, _FileView], None] | None = None,
    ) -> None:
        """Materialize the current pristine view under the session lock."""

        with self._lock:
            self._seed_from_locked(stream_view, after_seed=after_seed)

    def with_pristine_local_metadata(
        self,
        operation: Callable[[_FileView], tuple[Any, FileFingerprint]],
        *,
        allow_mtime_change: bool = False,
    ) -> tuple[
        bool,
        Any,
        FileFingerprint | None,
        FileFingerprint | None,
    ]:
        """Apply metadata to a pristine local source and refresh its ctime fence."""

        with self._lock:
            pristine = self.pristine_view if not self.modified else None
            if pristine is None or pristine.local_fingerprint is None:
                return False, None, None, None
            result, current = operation(pristine)
            unchanged = (
                _same_file_storage(pristine.local_fingerprint, current)
                if allow_mtime_change
                else _same_file_bytes(pristine.local_fingerprint, current)
            )
            if not unchanged:
                raise OSError(
                    errno.ESTALE,
                    "The local mounted file changed during its metadata update.",
                )
            previous = pristine.local_fingerprint
            self.pristine_view = _FileView(
                pristine.remote_path,
                pristine.size_bytes,
                pristine.digest,
                current.mtime_ns,
                remote_source_path=pristine.remote_source_path,
                local_fingerprint=current,
            )
            if self.expected_existing_fingerprint is not None:
                self.expected_existing_fingerprint = current
            return True, result, previous, current

    def matches_published_inode(self, current: FileFingerprint | None) -> bool:
        with self._lock:
            return bool(
                self.published
                and self.sealed_fingerprint is not None
                and _same_file_bytes(self.sealed_fingerprint, current)
            )

    def prepare_empty_mutation(self) -> None:
        """Turn a pristine remote handle into an explicit empty local edit."""

        with self._lock:
            if self.sealed or self.delete_pending or self.cancelled:
                raise OSError(errno.EBADF, "The mounted write is already closed.")
            self._raise_if_poisoned_locked()
            self._resume_after_flush_locked()
            self._reserve_remote_size_locked(0)
            try:
                self._begin_mutation_locked()
            except BaseException:
                # Marker persistence precedes the byte syscall. If it fails,
                # discard the temporary shrink credit as well as ``modified``
                # so a concurrent writer cannot spend capacity we still own.
                self._sync_remote_reservation_locked()
                raise
            try:
                if self.tree_journal is not None:
                    self._tree_mutation(lambda: self.tree_journal.truncate(0))
                    self._touch_tree_metadata_locked()
                else:
                    os.ftruncate(self.descriptor, 0)
            except OSError as error:
                self._sync_remote_reservation_locked()
                self._poison_mutation_locked(error.errno)
                raise
            self.seeded = True
            self.pristine_view = None

    def pristine_read_view(self) -> _FileView | None:
        with self._lock:
            if self.tree_journal is not None:
                return self.staged_read_view() if not self.modified else None
            return self.pristine_view if not self.modified else None

    def staged_read_view(self) -> _FileView:
        """Snapshot the stage's bytes and modification time, never the read time.

        NSDocument compares file metadata before saving. Advancing mtime on
        every getattr makes our own unchanged stage look like an external edit.
        The same inode becomes the published working-set file, so its timestamp
        also remains continuous through flush, rename, and local publication.
        """

        with self._lock:
            if self.tree_journal is not None:
                info = os.fstat(self.descriptor)
                return _FileView(self.remote_path, self.size(),
                    self.base_digest if not self.modified else self.tree_journal.digest(
                        self.tree_owner if self.sealed or self.journaled else "current"),
                    int(info.st_mtime_ns), session=self)
            if self.pristine_view is not None and not self.modified:
                return self.pristine_view
            fingerprint = (
                self.sealed_fingerprint
                if (self.sealed or self.published)
                and self.sealed_fingerprint is not None
                else _descriptor_fingerprint(self.descriptor)
            )
            return _FileView(
                self.remote_path,
                fingerprint.size_bytes,
                None,
                fingerprint.mtime_ns,
                session=self,
            )

    def read(self, offset: int, size: int) -> bytes:
        with self._lock:
            if self.tree_journal is not None:
                return self.tree_journal.read(offset, size,
                    snapshot=self.tree_owner if self.sealed or self.journaled else "current")
            return _portable_pread(self.descriptor, size, offset)

    @property
    def anonymous_writable(self) -> bool:
        # Terminal namespace ownership stays terminal. Only a retained, fully
        # seeded local inode can accept descriptor-only edits without opening
        # a new upload intent or reading a superseded remote pathname.
        return bool((self.cancelled or self.detached) and self.seeded
                    and self.tree_journal is None and self.descriptor >= 0)

    def write_anonymous(self, offset: int, data: bytes) -> int:
        with self._lock:
            if not self.anonymous_writable:
                raise OSError(errno.EBADF, "The mounted write is already closed.")
            if offset < 0 or offset + len(data) > MAX_LOCAL_UPLOAD_FILE_BYTES:
                raise OSError(errno.EFBIG, "The mounted write exceeds Meshia's file limit.")
            self._raise_if_poisoned_locked()
            total = 0
            view = memoryview(data)
            while view:
                written = self._pwrite_bounded_locked(
                    view[:MOUNT_IO_BYTES], offset + total, poison_on_failure=False)
                if written <= 0:
                    raise OSError(errno.EIO, "The mounted write made no progress.")
                total += written
                view = view[written:]
            return total

    def truncate_anonymous(self, length: int) -> None:
        with self._lock:
            if not self.anonymous_writable:
                raise OSError(errno.EBADF, "The mounted write is already closed.")
            if not 0 <= length <= MAX_LOCAL_UPLOAD_FILE_BYTES:
                raise OSError(errno.EFBIG, "The mounted write exceeds Meshia's file limit.")
            self._raise_if_poisoned_locked()
            # Sparse growth follows the normal staged-inode contract; writes
            # that allocate its holes still pass bounded local admission.
            os.ftruncate(self.descriptor, length)

    def write_from(
        self,
        offset: int,
        data: bytes,
        stream_view: Callable[[_FileView], Iterable[bytes]],
        *,
        after_seed: Callable[[int, _FileView], None] | None = None,
    ) -> int:
        if offset < 0 or offset + len(data) > MAX_LOCAL_UPLOAD_FILE_BYTES:
            raise OSError(errno.EFBIG, "The mounted write exceeds Meshia's file limit.")
        with self._lock:
            if self.sealed or self.delete_pending or self.cancelled:
                raise OSError(errno.EBADF, "The mounted write is already closed.")
            self._raise_if_poisoned_locked()
            # POSIX zero-length writes are true no-ops. In particular, do not
            # strand a pristine handle in a seeded-but-unmodified state where
            # later Finder metadata callbacks have no authoritative inode.
            if not data:
                return 0
            self._resume_after_flush_locked()
            if self.tree_journal is not None:
                self._reserve_remote_size_locked(max(self.size(), offset + len(data)))
                try:
                    self._begin_mutation_locked()
                    for start in range(0, len(data), MOUNT_IO_BYTES):
                        chunk = data[start:start + MOUNT_IO_BYTES]
                        self._tree_mutation(lambda: self.tree_journal.write(offset + start, chunk))
                    self._touch_tree_metadata_locked()
                    self.pristine_view = None
                    return len(data)
                except BaseException as error:
                    self._poison_mutation_locked(getattr(error, "errno", None))
                    self._sync_remote_reservation_locked()
                    raise
            current_size = (
                self.pristine_view.size_bytes
                if not self.seeded and self.pristine_view is not None
                else int(os.fstat(self.descriptor).st_size)
            )
            self._reserve_remote_size_locked(
                max(current_size, offset + len(data))
            )
            try:
                replaces_pristine = (
                    not self.seeded and self.pristine_view is not None
                    and offset == 0 and len(data) >= self.pristine_view.size_bytes
                )
                if replaces_pristine:
                    if after_seed is not None:
                        after_seed(self.descriptor, self.pristine_view)
                else:
                    self._seed_from_locked(stream_view, after_seed=after_seed)
                self._begin_mutation_locked()
                if replaces_pristine:
                    # Every old byte is superseded. The new bytes still pass
                    # through the same durable intent, capacity and error fences.
                    self.seeded = True
                    self.pristine_view = None
            except BaseException:
                self._sync_remote_reservation_locked()
                raise
            view = memoryview(data)
            written_total = 0
            while view:
                bounded = view[:MOUNT_IO_BYTES]
                written = self._pwrite_bounded_locked(
                    bounded,
                    offset + written_total,
                    poison_on_failure=True,
                )
                if written <= 0:
                    self._poison_mutation_locked(errno.EIO)
                    raise OSError(errno.EIO, "The mounted write made no progress.")
                view = view[written:]
                written_total += written
            return written_total

    def truncate_from(
        self,
        length: int,
        stream_view: Callable[..., Iterable[bytes]],
        *,
        after_seed: Callable[[int, _FileView], None] | None = None,
    ) -> None:
        if not 0 <= length <= MAX_LOCAL_UPLOAD_FILE_BYTES:
            raise OSError(errno.EFBIG, "The mounted write exceeds Meshia's file limit.")
        with self._lock:
            if self.sealed or self.delete_pending or self.cancelled:
                raise OSError(errno.EBADF, "The mounted write is already closed.")
            self._raise_if_poisoned_locked()
            self._resume_after_flush_locked()
            self._reserve_remote_size_locked(length)
            if self.tree_journal is not None:
                try:
                    self._begin_mutation_locked()
                    self._tree_mutation(lambda: self.tree_journal.truncate(length))
                    self._touch_tree_metadata_locked()
                    self.pristine_view = None
                    return
                except BaseException as error:
                    self._poison_mutation_locked(getattr(error, "errno", None))
                    self._sync_remote_reservation_locked()
                    raise
            try:
                self._seed_from_locked(
                    stream_view, after_seed=after_seed, retained_size=length
                )
                self._begin_mutation_locked()
                self.seeded = True
                self.pristine_view = None
            except BaseException:
                try:
                    if not self.seeded:
                        os.ftruncate(self.descriptor, 0)
                finally:
                    self._sync_remote_reservation_locked()
                raise
            # ftruncate hole growth is sparse on the supported native filesystems
            # and does not consume the declared logical size. Charging it would
            # incorrectly reject sparse model/checkpoint files; the first pwrite
            # that materializes each range passes through the bounded guard.
            try:
                os.ftruncate(self.descriptor, length)
            except OSError as error:
                self._sync_remote_reservation_locked()
                self._poison_mutation_locked(error.errno)
                raise

    def size(self) -> int:
        with self._lock:
            if self.anonymous_writable:
                return int(os.fstat(self.descriptor).st_size)
            if self.tree_journal is not None:
                return self.tree_journal.descriptor(
                    self.tree_owner if self.sealed or self.journaled else "current")["total_bytes"]
            if self.pristine_view is not None and not self.modified:
                return self.pristine_view.size_bytes
            if (
                (self.sealed or self.published)
                and self.sealed_fingerprint is not None
            ):
                # Crash recovery intentionally does not reopen a locally
                # published inode. Its immutable close receipt is the exact
                # logical size and avoids fstat(EBADF) while quota/catalog
                # ownership is rebound to the recovered session.
                return self.sealed_fingerprint.size_bytes
            return int(os.fstat(self.descriptor).st_size)

    def fsync(self) -> None:
        with self._lock:
            self._fsync_data_locked()

    def mark_flushed(self) -> None:
        """Persist one close epoch while retaining a cancellable write handle."""

        with self._lock:
            # FLUSH is advisory and can race an explicit unlink after the
            # backend drops its namespace lock. Unlink owns the retired
            # stage; fsync(-1) raises ValueError (not OSError), which fusepy
            # maps to EINVAL and SMB presents as a permission failure.
            if self.descriptor < 0 or self.sealed or self.journaled:
                return
            self._fsync_data_locked()
            previous = self.sealed_fingerprint
            self.sealed_fingerprint = _descriptor_fingerprint(self.descriptor)
            prior_tree_owner = None
            try:
                prior_tree_owner = self._capture_tree_owner_locked()
                # Reuse v1 ``ready`` on disk for rollback compatibility. The
                # in-memory session remains unsealed, so a later write can
                # transactionally restore ``open`` before mutating bytes.
                self._write_marker("ready")
            except BaseException:
                self.sealed_fingerprint = previous
                if prior_tree_owner is not None:
                    failed_owner, self.tree_owner = self.tree_owner, prior_tree_owner
                    self._retire_tree_owner_locked(failed_owner)
                raise
            self._retire_tree_owner_locked(prior_tree_owner)

    def _resume_after_flush_locked(self) -> None:
        """Reopen durable crash semantics before accepting post-FLUSH bytes."""

        if self.sealed_fingerprint is None:
            return
        previous = self.sealed_fingerprint
        self.sealed_fingerprint = None
        self.flush_closed = False
        try:
            # The open marker must be durable before any later byte mutation.
            # A crash after this point is therefore preserved as an explicitly
            # incomplete write, never mispublished as the earlier FLUSH image.
            self._write_marker("open")
        except BaseException:
            self.sealed_fingerprint = previous
            raise

    def reopen_before_publish(self) -> None:
        """Reopen one sealed close epoch before namespace publication starts.

        FUSE-T's SMB bridge can close and immediately reopen an AppleDouble
        copy sidecar while the first close is still inside Meshia's short
        publish-settle window.  The staged inode is unchanged and has not left
        mount ownership, so that reopen is another description of the same
        mutation, not a competing generation.  Persist ``open`` before the
        caller exposes the new handle; a crash can then preserve incomplete
        bytes, never replay the earlier ``ready`` receipt after a later edit.
        """

        with self._lock:
            if (
                not self.sealed
                or self.sealed_fingerprint is None
                or self.published
                or self.publishing
                or self.journaled
                or self.delete_pending
                or self.cancelled
                or self.failed_mutation
                or self.descriptor < 0
            ):
                raise OSError(
                    errno.EBUSY,
                    "The mounted file is already publishing or reconciled.",
                )
            current = _descriptor_fingerprint(self.descriptor)
            if current != self.sealed_fingerprint:
                raise OSError(
                    errno.ESTALE,
                    "The mounted-write inode changed after it was sealed.",
                )
            previous_fingerprint = self.sealed_fingerprint
            previous_flush_closed = self.flush_closed
            self.sealed = False
            self.sealed_fingerprint = None
            # A reopen renews the sidecar discard grace from the next settle.
            self.discard_grace_deadline = None
            self.flush_closed = False
            try:
                self._write_marker_transactionally("open")
            except BaseException:
                self.sealed = True
                self.sealed_fingerprint = previous_fingerprint
                self.flush_closed = previous_flush_closed
                raise

    def with_descriptor(self, operation: Callable[[int], Any]) -> Any:
        """Apply one metadata operation while the staged inode is pinned."""

        with self._lock:
            if self.descriptor < 0:
                raise OSError(errno.EBADF, "The mounted write is already closed.")
            return operation(self.descriptor)

    def with_local_metadata_descriptor(
        self,
        operation: Callable[[int], Any],
        *,
        allow_mtime_change: bool = False,
    ) -> Any:
        """Apply inode-only metadata and refresh an existing close receipt.

        FUSE-T's SMB bridge can deliver named-stream metadata after the data
        handle's RELEASE.  At that point this session is sealed, but the exact
        staged descriptor is deliberately retained through the short publish
        settle window.  Quarantine changes ctime without changing file bytes;
        advance the receipt atomically so the later namespace move remains
        fenced to the same inode and byte-visible state.
        """

        with self._lock:
            if self.descriptor < 0:
                raise OSError(errno.EBADF, "The mounted write is already closed.")
            before = _descriptor_fingerprint(self.descriptor)
            if (self.sealed or self.sealed_fingerprint is not None) and (
                self.sealed_fingerprint is None
                or not _same_file_bytes(self.sealed_fingerprint, before)
            ):
                raise OSError(
                    errno.ESTALE,
                    "The mounted-write inode changed after it was sealed.",
                )

            def refresh_receipt() -> None:
                if self.published or self.journaled:
                    os.fsync(self.descriptor)
                else:
                    # Finder metadata can be the first operation to expose a
                    # delayed-allocation data failure. Before local namespace
                    # publication, fence that stage exactly like DATA fsync.
                    self._fsync_data_locked()
                after = _descriptor_fingerprint(self.descriptor)
                unchanged = (
                    _same_file_storage(before, after)
                    if allow_mtime_change
                    else _same_file_bytes(before, after)
                )
                if not unchanged:
                    raise OSError(
                        errno.ESTALE,
                        "A mounted metadata update changed the file bytes.",
                    )
                if self.sealed or self.sealed_fingerprint is not None:
                    self.sealed_fingerprint = after
                    self._write_marker(
                        "published"
                        if self.published
                        else "ready"
                        if self.sealed
                        else "ready"
                    )

            try:
                result = operation(self.descriptor)
            except BaseException as operation_error:
                try:
                    # A syscall can mutate inode metadata and still report an
                    # error. Preserve the refreshed close receipt before the
                    # original failure escapes and publication is rescheduled.
                    refresh_receipt()
                except BaseException as receipt_error:
                    raise receipt_error from operation_error
                raise
            refresh_receipt()
            return result

    def seal(self) -> None:
        with self._lock:
            if self.sealed:
                return
            self._fsync_data_locked()
            fingerprint = _descriptor_fingerprint(self.descriptor)
            previous = self.sealed_fingerprint
            self.sealed_fingerprint = fingerprint
            prior_tree_owner = None
            try:
                prior_tree_owner = self._capture_tree_owner_locked()
                # Persist the close receipt before exposing the in-memory
                # sealed state. If publication fails here, a retry may safely
                # rewrite the same exact receipt; a crash can recover a durable
                # ready marker even if this process never flips ``sealed``.
                self._write_marker("ready")
            except BaseException:
                self.sealed_fingerprint = previous
                if prior_tree_owner is not None:
                    failed_owner, self.tree_owner = self.tree_owner, prior_tree_owner
                    self._retire_tree_owner_locked(failed_owner)
                raise
            self.sealed = True
            self._retire_tree_owner_locked(prior_tree_owner)

    def rename(
        self,
        destination: str,
        *,
        destination_base_digest: str | None,
        destination_base_size: int,
        destination_existing_fingerprint: FileFingerprint | None,
        remote_size_for_identity: Callable[[str, str | None], int],
        preserve_transport_provenance: bool = False,
    ) -> None:
        with self._lock:
            if (
                self.published
                or self.publishing
                or self.delete_pending
                or self.cancelled
            ):
                raise OSError(errno.EBUSY, "The mounted write is already publishing.")
            if not self.seeded:
                raise FabricMountError("The mounted rename was not seeded.")
            next_delete = self.delete_after_ack
            if next_delete is not None and next_delete[0] == destination:
                # Writing the final destination supersedes an earlier need to
                # delete that same remote path.
                next_delete = None
            if (
                self.remote_path == self.original_remote_path
                and self.original_base_digest is not None
            ):
                source_delete = (
                    self.original_remote_path,
                    self.original_base_digest,
                )
            elif self.base_digest is not None and self.remote_path != destination:
                source_delete = (self.remote_path, self.base_digest)
            else:
                source_delete = None
            if source_delete is not None:
                if next_delete is not None and next_delete != source_delete:
                    # The durable mounted-write contract intentionally carries
                    # one dependent delete. A second occupied-remote hop would
                    # otherwise overwrite the first dependency and silently
                    # leave an earlier source behind.
                    raise OSError(
                        errno.EBUSY,
                        "Publish this mounted rename before moving it again.",
                    )
                next_delete = source_delete
            previous = (
                self.remote_path,
                self.base_digest,
                self.base_size_bytes,
                self.expected_existing_fingerprint,
                self.delete_after_ack,
                self.modified,
                self.transport_provenance,
            )
            try:
                # The signed catalog still charges every remote object that
                # this atomic handoff replaces. Recompute overwrite credit
                # from the exact current destination and exact dependent
                # delete identity on every hop. ``base_size_bytes`` is the
                # prior hop's composite quota baseline, so carrying it forward
                # would compound credit across a rename cycle (A -> temp -> B
                # -> A). A missing/mismatched dependency cannot safely grant
                # credit and therefore fails closed before the marker moves.
                quota_base_size = remote_size_for_identity(
                    destination,
                    destination_base_digest,
                )
                if quota_base_size != destination_base_size:
                    raise OSError(
                        errno.ESTALE,
                        "The mounted rename destination changed remotely; "
                        "refresh and retry.",
                    )
                if next_delete is not None:
                    quota_base_size += remote_size_for_identity(*next_delete)
                if self.remote_quota is not None:
                    self.remote_quota.reserve(
                        self.mutation_id,
                        quota_base_size,
                        self.size(),
                    )
                self.modified = True
                self.remote_path = destination
                self.base_digest = destination_base_digest
                self.base_size_bytes = quota_base_size
                self.expected_existing_fingerprint = (
                    destination_existing_fingerprint
                )
                self.delete_after_ack = next_delete
                # Ordinary namespace renames are explicit user-visible intent.
                # The backend opts into preservation only for one exact SMB
                # copy-pair temp-to-final transition; a second durable receipt
                # is still required before final-name suppression.
                if not preserve_transport_provenance:
                    self.transport_provenance = None
                marker_state = (
                    "ready"
                    if self.sealed or self.sealed_fingerprint is not None
                    else "open"
                )
                encoded = json.dumps(
                    self._document(marker_state),
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
                try:
                    write_private_file(self.marker_path, encoded)
                except BaseException:
                    # write_private_file can report a directory-fsync failure
                    # after its atomic replace has already committed. Read back
                    # that exact mutation before deciding whether to roll back
                    # in-memory identity; a landed marker is the authority.
                    if self._marker_matches(encoded):
                        return
                    raise
            except BaseException:
                (
                    self.remote_path,
                    self.base_digest,
                    self.base_size_bytes,
                    self.expected_existing_fingerprint,
                    self.delete_after_ack,
                    self.modified,
                    self.transport_provenance,
                ) = previous
                if self.remote_quota is not None:
                    self.remote_quota.track_existing(
                        self.mutation_id,
                        self.base_size_bytes,
                        self.size(),
                    )
                raise

    def stage_fingerprint(self) -> FileFingerprint:
        with self._lock:
            if self.tree_journal is not None:
                raise FabricMountError("A native tree must publish its root, never its metadata inode.")
            current = _descriptor_fingerprint(self.descriptor)
            if (
                self.sealed_fingerprint is not None
                and current != self.sealed_fingerprint
            ):
                raise FabricMountError(
                    "The mounted-write stage changed after it was closed."
                )
            return current

    def mark_published(self) -> None:
        with self._lock:
            # The exact inode has already moved into the visible namespace.
            # Reflect that irreversible fact before advancing the marker: if
            # the receipt rewrite fails, this process must retry journaling the
            # published inode rather than looking again for the vanished stage
            # path. Recovery can make the same deduction from the older ready
            # marker only after matching the destination inode byte-for-byte.
            self.published = True
            self._write_marker("published")

    def retire_marker(self) -> None:
        """Durably retire crash ownership after the journal accepts the write.

        A retained Finder read alias may keep ``descriptor`` alive long after
        the durable operation owns the mutation.  Its marker must not survive
        that handoff: a later namespace rename/unlink plus process crash would
        otherwise recover a stale published path.  Keep the anonymous inode
        readable, but persist removal of the marker before declaring the
        session journaled in memory.
        """

        with self._lock:
            try:
                self.marker_path.unlink()
            except FileNotFoundError:
                pass
            if os.name == "nt":
                # Python cannot portably open a Windows directory for fsync.
                # The unlink is best-effort durable there; a platform-native
                # directory flush can strengthen this when Windows mounting is
                # promoted beyond its current deferred release gate.
                return
            flags = (
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | _NOFOLLOW
                | _CLOEXEC
            )
            directory = os.open(str(self.marker_path.parent), flags)
            try:
                try:
                    os.fsync(directory)
                except OSError as error:
                    unsupported = {
                        errno.EINVAL,
                        getattr(errno, "ENOTSUP", errno.EINVAL),
                        getattr(errno, "EOPNOTSUPP", errno.EINVAL),
                    }
                    if error.errno not in unsupported:
                        raise
            finally:
                os.close(directory)

    def detach_pristine(self) -> None:
        """Retain a seeded, unchanged inode for aliases after replacement.

        There is no user mutation to recover. Remove only the private staging
        names, leaving the open descriptor readable until its last RELEASE.
        The old writable SMB alias must never publish over the new pathname.
        """

        with self._lock:
            if (
                self.modified or (not self.seeded and self.pristine_view is None) or self.publishing
                or self.published or self.journaled or self.delete_pending
                or self.cancelled or self.failed_mutation
            ):
                raise OSError(errno.EBUSY, "The rename destination is busy.")
            self.sealed = True
            self.detached = True
            self.release_remote_quota()
            try:
                self.retire_marker()
                self.data_path.unlink(missing_ok=True)
            except OSError as error:
                # Namespace replacement already succeeded. The old stage was
                # never modified, so its leftover marker cannot replay a PUT.
                # Keep the descriptor and retry private cleanup at last close.
                if self.logger is not None:
                    self.logger.record(
                        "fabric_mount_detached_pristine_cleanup_deferred",
                        path=self.remote_path, error=str(error),
                    )

    @contextmanager
    def reading(self):
        """Keep this description alive after a concurrent last CLOSE.

        Admission happens while the backend still owns its handle lookup;
        the network read itself runs without that namespace lock.
        """
        with self._lock:
            if self.descriptor < 0 or self._deferred_disposal is not None:
                raise OSError(errno.EBADF, "The mounted description is closed.")
            self._inflight_reads += 1
        try:
            yield
        finally:
            with self._lock:
                self._inflight_reads -= 1
                if not self._inflight_reads and self._deferred_disposal is not None:
                    action, self._deferred_disposal = self._deferred_disposal, None
                    getattr(self, action)()

    def finish(self) -> None:
        with self._lock:
            if self._inflight_reads:
                self._deferred_disposal = "finish"
                return
            cleanup_error: OSError | None = None
            try:
                os.close(self.descriptor)
            except OSError:
                # finish() remains idempotent for retained read aliases; only
                # artifact cleanup failures are actionable at this boundary.
                pass
            self.descriptor = -1
            try:
                data_removed = True
                if self.cancelled or self.detached or self.tree_journal is not None:
                    # Keep the cancellation marker when its private inode
                    # cannot be removed; restart must not reinterpret bytes.
                    try:
                        self.data_path.unlink()
                    except FileNotFoundError:
                        pass
                    except OSError as error:
                        cleanup_error = cleanup_error or error
                        data_removed = False
                if data_removed:
                    try:
                        self.marker_path.unlink()
                    except FileNotFoundError:
                        pass
                    except OSError as error:
                        cleanup_error = cleanup_error or error
                    if cleanup_error is None and self.tree_owner is not None:
                        self._tree_release(self.tree_owner)
                        self.tree_owner = None
            finally:
                # Local cleanup failure cannot retain remote capacity after a
                # durable handoff. release() is idempotent on every close path.
                self.release_remote_quota()
            if cleanup_error is not None:
                raise cleanup_error

    def abort(self) -> None:
        with self._lock:
            if self._inflight_reads:
                self._deferred_disposal = "abort"
                return
            cleanup_error: OSError | None = None
            try:
                try:
                    if self.descriptor >= 0:
                        os.close(self.descriptor)
                except OSError as error:
                    cleanup_error = error
                self.descriptor = -1
                data_removed = True
                try:
                    self.data_path.unlink()
                except FileNotFoundError:
                    pass
                except OSError as error:
                    cleanup_error = cleanup_error or error
                    data_removed = False
                if data_removed:
                    try:
                        self.marker_path.unlink()
                    except FileNotFoundError:
                        pass
                    except OSError as error:
                        cleanup_error = cleanup_error or error
                    if cleanup_error is None and self.tree_owner is not None:
                        self._tree_release(self.tree_owner)
                        self.tree_owner = None
            finally:
                self.release_remote_quota()
            if cleanup_error is not None:
                raise cleanup_error

    def preserve(self) -> None:
        """Close the inode but retain its marker and bytes for recovery."""

        with self._lock:
            if self._inflight_reads:
                self._deferred_disposal = "preserve"
                return
            if self.descriptor >= 0:
                try:
                    os.fsync(self.descriptor)
                finally:
                    os.close(self.descriptor)
                    self.descriptor = -1


_UNSET: Any = object()


@dataclass
class _DirectoryResolution:
    """Per-listdir prefetch that collapses the per-child visibility N+1.

    ``listdir`` filters every candidate name through the same resolution
    ``getattr`` uses, which otherwise issues three point reads per child. The
    ledgers here are fetched once for the whole child set; the resolver helpers
    on the backend consult them while this context is active and fall back to a
    point read for any path not in ``prefetched`` (so a rename source or a
    projected destination outside the listed directory still reads truth). The
    directory-rename overlay and manifest head, constant across one listing, are
    memoized on the backend's read epoch instead of here.
    """

    operations: dict[str, PendingOperation]
    remote_entries: dict[str, RemoteEntry]
    materialized: dict[str, MaterializedEntry]
    prefetched: frozenset[str]
    directory_children: frozenset[str]
    receipted_entries: dict[str, RemoteEntry | None]
    rename_sources: frozenset[tuple[str, str]]


class FabricMountBackend:
    """Thread-safe POSIX namespace projected from Fabric metadata and stages."""

    def __init__(
        self,
        database: FabricDatabase,
        coordinator: FabricSyncCoordinator,
        workspace: WorkspaceBoundary,
        workspace_name: str,
        *,
        rename_workspace: Callable[[str, str], str] | None = None,
        settle_seconds: float = MOUNT_SETTLE_SECONDS,
        appledouble_discard_grace_seconds: float = MOUNT_APPLEDOUBLE_DISCARD_GRACE_SECONDS,
        logger: NodeLogger = NULL_LOGGER,
        remote_quota: _RemoteQuotaCapacity | None = None,
        fuse_t_transport_backend: str | None = None,
    ) -> None:
        if len(split_relative(workspace_name)) != 1:
            raise ValueError("workspace_name must be one portable path component")
        if settle_seconds < 0:
            raise ValueError("settle_seconds must be non-negative")
        if fuse_t_transport_backend not in (None, "nfs", "smb"):
            raise ValueError("fuse_t_transport_backend must be nfs, smb, or None")
        self.database = database
        self.coordinator = coordinator
        self.workspace = workspace
        self.workspace_name = workspace_name
        self._rename_workspace = rename_workspace
        self.settle_seconds = settle_seconds
        if appledouble_discard_grace_seconds < 0:
            raise ValueError("appledouble_discard_grace_seconds must be non-negative")
        self.appledouble_discard_grace_seconds = appledouble_discard_grace_seconds
        self.logger = logger
        self._fuse_t_smb_transport = fuse_t_transport_backend == "smb"
        # SMB mirrors xattrs into ``._`` sidecars; store none of them by
        # default (owner decision 2026-09-03, see the env override above).
        self._discard_all_appledouble_sidecars = bool(
            self._fuse_t_smb_transport and mount_discards_appledouble_sidecars()
        )
        self._smb_copy_pair_evidence: dict[tuple[str, str], float] = {}
        self._smb_temp_final_pair_evidence: dict[
            tuple[str, str], tuple[tuple[str, str], float]
        ] = {}
        self._stage_capacity = _LocalStageCapacity(self.storage_root)
        self._remote_quota = remote_quota or _RemoteQuotaCapacity()
        self._remote_quota.attach_database(database)
        self._lock = threading.RLock()
        self._publication_condition = threading.Condition(self._lock)
        # Active only inside a listdir's child-visibility loop (under _lock);
        # the resolver helpers read prefetched ledgers from it instead of
        # issuing one point read per child. See _DirectoryResolution.
        self._listing_ctx: _DirectoryResolution | None = None
        # Backend read epoch (under _lock): the directory-rename overlay and
        # remote manifest head are constant across one read callback but are
        # read several times per resolution. Memoize them for the epoch's life
        # and drop them when it ends, so the next callback re-reads truth.
        self._read_epoch_depth = 0
        self._epoch_overlay: Any = _UNSET
        self._epoch_head: Any = _UNSET
        self._epoch_rename_sources: Any = _UNSET
        # Cleanup must exclude only operations whose namespace overlaps the
        # retired path. A backend-wide lock across filesystem reclamation made
        # an unrelated Finder open wait behind large-file cleanup. This compact
        # registry orders equal/ancestor paths while sibling paths proceed.
        self._cleanup_path_condition = threading.Condition(threading.Lock())
        self._cleanup_path_active: dict[int, tuple[str, ...]] = {}
        self._cleanup_path_owners: dict[int, int] = {}
        self._cleanup_path_next = 1
        self._handles: dict[int, _ReadHandle | _MountWriteSession] = {}
        # FUSE-T's SMB bridge may open several writable descriptions for one
        # create/copy inode.  They share one crash-described session, while
        # this per-handle set proves which descriptions have delivered their
        # close-time FLUSH.  A session-wide ready marker is not safe until no
        # writable alias remains unflushed.
        self._flushed_write_handles: set[int] = set()
        self._sessions: dict[str, _MountWriteSession] = {}
        self._timers: dict[str, threading.Timer] = {}
        self._flush_timers: dict[str, threading.Timer] = {}
        # Fabric persists files, not directories. The tiny empty-directory
        # overlay is stored in the authority-scoped journal so an OS/service
        # restart cannot resurrect a removed directory whose backing folder is
        # temporarily retained for safe open-inode retirement. Every row is
        # fenced to the exact remote head; an advance can reveal a concurrent
        # remote child rather than masking it.
        (
            self._removed_directories_head,
            removed_directories,
        ) = self.database.local_directory_tombstone_snapshot()
        self._removed_directories = set(removed_directories)
        self._next_handle = 1
        self._closed = False
        self._cleanup_fence_registered = False
        self._recovering_stages = True
        try:
            self._recover_stages()
        finally:
            self._recovering_stages = False
        # Recovery suppresses per-receipt timers while it drains the bounded
        # scan. Arm normal retries only for the explicitly bounded survivors.
        rearmed_deletes = 0
        with self._lock:
            for session in tuple(self._sessions.values()):
                if session.cancelled and session.journaled:
                    self._schedule_publish_retry_locked(
                        session,
                        count_failure=False,
                    )
                elif (
                    session.modified
                    and session.sealed
                    and not session.delete_pending
                    and not session.cancelled
                ):
                    self._schedule_publish_retry_locked(
                        session,
                        count_failure=False,
                    )
                elif (
                    session.delete_pending
                    and not session.cancelled
                    and not session.journaled
                ):
                    # The recovery replay above already tried this unlink and
                    # it did not journal: the engine is almost always still
                    # behind its own startup fence (staging_repair) when the
                    # mount recovers its receipts, so the replay is deferred
                    # -- and the deferral could not arm a timer because
                    # recovery suppresses them. Without this re-arm the
                    # receipt hides the path with no journal row, no timer,
                    # and no owner until the *next* restart, which defers it
                    # the same way. Live: 13 files stayed in the durable
                    # store across 12 restarts while the mount showed them
                    # deleted.
                    self._schedule_publish_retry_locked(
                        session,
                        count_failure=False,
                    )
                    if session.remote_path in self._timers:
                        rearmed_deletes += 1
        if rearmed_deletes:
            self.logger.record(
                "fabric_mount_recovered_deletes_rearmed",
                count=rearmed_deletes,
            )
        cleanup_fence_setter = getattr(
            self.coordinator, "set_mount_cleanup_fence", None
        )
        if callable(cleanup_fence_setter):
            cleanup_fence_setter(self._mount_cleanup_fence)
            self._cleanup_fence_registered = True

    def _remember_smb_copy_pair_locked(self, key: tuple[str, str]) -> None:
        """Keep bounded in-process evidence until its sidecar receipt owns it."""

        now = time.monotonic()
        expired = tuple(
            candidate
            for candidate, observed_at in self._smb_copy_pair_evidence.items()
            if now - observed_at > MOUNT_SMB_COPY_PAIR_EVIDENCE_SECONDS
        )
        for candidate in expired:
            self._smb_copy_pair_evidence.pop(candidate, None)
        self._smb_copy_pair_evidence.pop(key, None)
        self._smb_copy_pair_evidence[key] = now
        while len(self._smb_copy_pair_evidence) > MAX_SMB_COPY_PAIR_EVIDENCE:
            self._smb_copy_pair_evidence.pop(next(iter(self._smb_copy_pair_evidence)))
        parent, nonce = key
        sidecar = f"{parent + '/' if parent else ''}._.BC.T_{nonce}"
        session = self._sessions.get(sidecar)
        if session is None:
            return
        try:
            session.mark_transport_provenance(
                _FUSE_T_SMB_APPLEDOUBLE_PROVENANCE
            )
        except (FabricMountError, OSError, StateError) as error:
            # Failure to persist provenance must preserve the bytes as an
            # ordinary user file. Keep the bounded evidence for a later reopen
            # rather than converting an inference into deletion authority.
            self.logger.record(
                "fabric_mount_smb_copy_pair_provenance_failed",
                path=sidecar,
                error=str(error),
            )
        else:
            self._smb_copy_pair_evidence.pop(key, None)

    def _has_fresh_smb_copy_pair_locked(self, key: tuple[str, str]) -> bool:
        observed_at = self._smb_copy_pair_evidence.get(key)
        if observed_at is None:
            return False
        if (
            time.monotonic() - observed_at
            > MOUNT_SMB_COPY_PAIR_EVIDENCE_SECONDS
        ):
            self._smb_copy_pair_evidence.pop(key, None)
            return False
        return True

    @staticmethod
    def _final_sidecar_path(key: tuple[str, str]) -> str:
        parent, name = key
        return f"{parent + '/' if parent else ''}._{name}"

    def _mark_final_smb_sidecar_locked(
        self,
        key: tuple[str, str],
        *,
        expected_temp_key: tuple[str, str],
    ) -> bool:
        sidecar_path = self._final_sidecar_path(key)
        session = self._sessions.get(sidecar_path)
        if session is None:
            return False
        if _smb_copy_pair_key(
            session.original_remote_path,
            appledouble=True,
        ) != expected_temp_key:
            return False
        try:
            session.mark_transport_provenance(
                _FUSE_T_SMB_FINAL_APPLEDOUBLE_PROVENANCE
            )
        except (FabricMountError, OSError, StateError) as error:
            # Metadata suppression is never allowed to make the copy fail. A
            # missing receipt simply preserves the sidecar as ordinary bytes.
            self.logger.record(
                "fabric_mount_smb_final_pair_provenance_failed",
                path=sidecar_path,
                error=str(error),
            )
            return False
        return True

    def _remember_smb_temp_final_pair_locked(
        self,
        temp_key: tuple[str, str],
        final_key: tuple[str, str],
    ) -> None:
        """Bind a data-temp rename to its exact final same-directory name."""

        now = time.monotonic()
        expired = tuple(
            candidate
            for candidate, (_final, observed_at) in (
                self._smb_temp_final_pair_evidence.items()
            )
            if now - observed_at > MOUNT_SMB_COPY_PAIR_EVIDENCE_SECONDS
        )
        for candidate in expired:
            self._smb_temp_final_pair_evidence.pop(candidate, None)
        self._smb_temp_final_pair_evidence.pop(temp_key, None)
        self._smb_temp_final_pair_evidence[temp_key] = (final_key, now)
        while (
            len(self._smb_temp_final_pair_evidence)
            > MAX_SMB_COPY_PAIR_EVIDENCE
        ):
            self._smb_temp_final_pair_evidence.pop(
                next(iter(self._smb_temp_final_pair_evidence))
            )
        if self._mark_final_smb_sidecar_locked(
            final_key,
            expected_temp_key=temp_key,
        ):
            self._smb_temp_final_pair_evidence.pop(temp_key, None)

    def _matching_smb_temp_final_pair_locked(
        self,
        temp_key: tuple[str, str],
        final_key: tuple[str, str],
    ) -> bool:
        evidence = self._smb_temp_final_pair_evidence.get(temp_key)
        if evidence is None:
            return False
        candidate, observed_at = evidence
        if (
            time.monotonic() - observed_at
            > MOUNT_SMB_COPY_PAIR_EVIDENCE_SECONDS
        ):
            self._smb_temp_final_pair_evidence.pop(temp_key, None)
            return False
        return candidate == final_key

    def _appledouble_discard_deferred_locked(
        self,
        session: _MountWriteSession,
    ) -> bool:
        """Keep a discardable, unpublished sidecar reopenable for a grace.

        Returns True when the discard was deferred (a timer re-arms this
        path), False when the grace has lapsed and the caller may cancel.
        A sidecar that was already published (older runtime crash) is never
        deferred: it goes through the durable delete path.
        """

        grace = self.appledouble_discard_grace_seconds
        if session.published or self._closed or grace <= 0:
            return False
        now = time.monotonic()
        deadline = session.discard_grace_deadline
        if deadline is None:
            deadline = now + grace
            session.discard_grace_deadline = deadline
            self.logger.record(
                "fabric_mount_smb_appledouble_discard_deferred",
                path=session.remote_path,
                grace_seconds=grace,
            )
        if now >= deadline and not self._session_has_open_handle(session):
            return False
        remaining = max(0.05, deadline - now)
        if session.remote_path not in self._timers:
            timer = self._new_publish_timer(session.remote_path, remaining)
            self._timers[session.remote_path] = timer
            timer.start()
        self._publication_condition.notify_all()
        return True

    def _transport_appledouble_discardable(
        self,
        session: _MountWriteSession,
    ) -> bool:
        if (
            session.transport_provenance
            == _FUSE_T_SMB_APPLEDOUBLE_PROVENANCE
        ):
            return bool(
                _fuse_t_smb_appledouble_temp(session.remote_path)
                and session.has_discardable_appledouble_bytes(
                any_metadata=self._discard_all_appledouble_sidecars
            )
            )
        if (
            session.transport_provenance
            == _FUSE_T_SMB_FINAL_APPLEDOUBLE_PROVENANCE
            and _smb_final_copy_pair_key(
                session.remote_path,
                appledouble=True,
            )
            is not None
            and session.has_discardable_appledouble_bytes(
                any_metadata=self._discard_all_appledouble_sidecars
            )
        ):
            return True
        # A plain ``cp``/``rsync`` through the SMB bridge writes ``._name``
        # directly, with no copy-pair spelling to hold provenance. The bytes
        # themselves are still the authority: a sidecar that carries nothing
        # but zeroed FinderInfo and the advisory xattrs Meshia already drops
        # (provenance, last-used date, ...) has no user data to preserve, and
        # publishing it costs a full mutation chain per copied file.
        return bool(
            session.remote_path.rpartition("/")[2].startswith("._")
            and session.has_discardable_appledouble_bytes(
                any_metadata=self._discard_all_appledouble_sidecars
            )
        )

    @property
    def storage_root(self) -> Path:
        """Local filesystem used only for cache/stage capacity reporting."""

        return self.workspace.root

    def set_stage_capacity(self, capacity: _LocalStageCapacity) -> None:
        """Share one local-volume admission fence across workspace children."""

        if not isinstance(capacity, _LocalStageCapacity):
            raise TypeError("capacity must be a local stage capacity")
        with self._lock:
            self._stage_capacity = capacity
            for session in self._sessions.values():
                session.bind_stage_capacity(capacity)

    def set_remote_quota(self, capacity: _RemoteQuotaCapacity) -> None:
        """Share one catalog-owned quota fence through lazy activation."""

        if not isinstance(capacity, _RemoteQuotaCapacity):
            raise TypeError("capacity must be a remote quota capacity")
        with self._lock:
            previous = self._remote_quota
            self._remote_quota = capacity
            capacity.attach_database(self.database)
            for session in self._sessions.values():
                remote = self._resolve_remote_entry(session.remote_path)
                base_size = (
                    remote.size_bytes
                    if remote is not None and remote.digest == session.base_digest
                    else 0
                )
                if session.delete_after_ack is not None:
                    delete_path, delete_digest = session.delete_after_ack
                    delete_remote = self._resolve_remote_entry(delete_path)
                    if (
                        delete_remote is not None
                        and delete_remote.digest == delete_digest
                    ):
                        base_size += delete_remote.size_bytes
                session.bind_remote_quota(capacity, base_size_bytes=base_size)
        if previous is not capacity:
            previous.detach_database(self.database)

    def _remote_size_for_identity(self, path: str, digest: str | None) -> int:
        """Return exact acknowledged bytes for one rename delete dependency.

        Dependent-delete credit is safe only while a durable receipt or manifest
        still proves the same object identity. The server repeats admission at
        commit, but failing here avoids briefly advertising or reserving space
        that belongs to a changed/missing object.
        """

        remote = self._resolve_remote_entry(path)
        if digest is None and remote is None:
            return 0
        if remote is None or remote.digest != digest:
            raise OSError(
                errno.ESTALE,
                "A mounted rename object changed remotely; refresh and retry.",
            )
        return remote.size_bytes

    def statfs_capacity(self, _path: str = "/") -> tuple[int, int] | None:
        """Return this workspace's capacity for direct or catalog FUSE calls."""

        return self._remote_quota.snapshot()

    def local_stage_statfs(self) -> tuple[int, int]:
        """Return local total/safe bytes without touching remote child state."""

        return self._stage_capacity.snapshot()

    def can_close(self) -> bool:
        """Return whether no native file descriptor or private write is transient."""

        with self._lock:
            return not (
                self._handles
                or self._sessions
                or self._timers
                or self._flush_timers
            )

    def set_workspace_name(self, workspace_name: str) -> None:
        """Atomically refresh the server-owned root projection label."""

        try:
            valid = len(split_relative(workspace_name)) == 1
        except (InvalidTask, UnsafePath):
            valid = False
        if not valid:
            raise ValueError("workspace_name must be one portable path component")
        with self._lock:
            self.workspace_name = workspace_name

    @staticmethod
    def _root_component(path: str) -> str | None:
        if not isinstance(path, str) or not path.startswith("/") or path == "/":
            return None
        try:
            parts = split_relative(path[1:])
        except (InvalidTask, UnsafePath):
            return None
        return parts[0] if len(parts) == 1 else None

    @staticmethod
    def _recovery_cursor_path(root: Path) -> Path:
        return root / MOUNT_RECOVERY_CURSOR_NAME

    @staticmethod
    def _read_recovery_cursor_bytes(path: Path) -> bytes:
        descriptor = -1
        try:
            descriptor = os.open(str(path), os.O_RDONLY | _NOFOLLOW | _CLOEXEC)
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or (os.name != "nt" and stat.S_IMODE(before.st_mode) != 0o600)
                or (hasattr(os, "geteuid") and before.st_uid != os.geteuid())
                or before.st_size > MAX_RECOVERY_CURSOR_BYTES
            ):
                raise FabricMountError("The mount recovery cursor is not private.")
            raw = os.read(descriptor, MAX_RECOVERY_CURSOR_BYTES + 1)
            after = os.fstat(descriptor)
            if (
                len(raw) != before.st_size
                or before.st_dev != after.st_dev
                or before.st_ino != after.st_ino
                or before.st_size != after.st_size
                or before.st_mtime_ns != after.st_mtime_ns
            ):
                raise FabricMountError("The mount recovery cursor changed while read.")
            return raw
        except FileNotFoundError:
            raise
        except OSError as error:
            raise FabricMountError("The mount recovery cursor cannot be read.") from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _read_recovery_cursor(self, root: Path) -> str | None:
        path = self._recovery_cursor_path(root)
        try:
            raw = self._read_recovery_cursor_bytes(path)
        except FileNotFoundError:
            return None
        try:
            document = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise FabricMountError("The mount recovery cursor is invalid JSON.") from error
        if (
            not isinstance(document, Mapping)
            or set(document) != {"schema", "after"}
            or document.get("schema") != MOUNT_RECOVERY_CURSOR_SCHEMA
        ):
            raise FabricMountError("The mount recovery cursor has an unknown schema.")
        after = document.get("after")
        try:
            after_size = len(after.encode("utf-8")) if isinstance(after, str) else 0
        except UnicodeEncodeError as error:
            raise FabricMountError(
                "The mount recovery cursor has an invalid marker."
            ) from error
        if (
            not isinstance(after, str)
            or not after.endswith(".json")
            or not 1 <= after_size <= 255
            or after in (".", "..")
            or "/" in after
            or "\\" in after
            or "\x00" in after
        ):
            raise FabricMountError("The mount recovery cursor has an invalid marker.")
        return after

    def _write_recovery_cursor(self, root: Path, after: str) -> None:
        path = self._recovery_cursor_path(root)
        encoded = json.dumps(
            {"schema": MOUNT_RECOVERY_CURSOR_SCHEMA, "after": after},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        try:
            write_private_file(path, encoded)
        except BaseException:
            # write_private_file can fail after its atomic replacement. A byte-
            # exact readback distinguishes a landed cursor from a pre-commit
            # failure without ever mutating a stage receipt.
            try:
                if self._read_recovery_cursor_bytes(path) == encoded:
                    return
            except (FabricMountError, FileNotFoundError):
                pass
            raise

    def _clear_recovery_cursor(self, root: Path) -> None:
        try:
            self._recovery_cursor_path(root).unlink()
        except FileNotFoundError:
            return
        except OSError as error:
            self.logger.record(
                "fabric_mount_recovery_cursor_cleanup_failed",
                error=str(error),
            )

    def _recovery_batch(
        self,
        root: Path,
        after: str | None,
    ) -> tuple[tuple[str, ...], tuple[str, ...], bool]:
        """Return one fair, bounded startup ordering of every scanned receipt."""

        marker_names: list[str] = []
        scanned = 0
        truncated = False
        with os.scandir(root) as entries:
            for entry in entries:
                scanned += 1
                if scanned > MAX_RECOVERY_SCAN_ENTRIES:
                    truncated = True
                    break
                if not entry.name.endswith(".json"):
                    continue
                if len(marker_names) >= MAX_RECOVERY_MARKERS:
                    truncated = True
                    break
                marker_names.append(entry.name)
        marker_names.sort()
        if not marker_names:
            return (), (), truncated
        start = bisect.bisect_right(marker_names, after) if after is not None else 0
        ordered = marker_names[start:] + marker_names[:start]
        return tuple(ordered), tuple(marker_names), truncated

    def _delete_is_durably_owned(self, path: str) -> bool | None:
        """Return true/false ownership, or ``None`` when readback is unknown."""

        try:
            operation = self.database.get_latest_nonterminal_operation(path)
            if (
                operation is not None
                and operation.kind == "delete"
                and operation.path == path
            ):
                return True
            if operation is not None:
                return False
            # An absent row is evidence only inside an authoritative manifest. A
            # new/unadopted database has no namespace knowledge and must not erase a
            # delete_pending receipt merely because no head has been loaded yet.
            return (
                self.database.get_remote_manifest_head() is not None
                and self.database.get_remote_entry(path) is None
            )
        except (OSError, StateError, sqlite3.Error) as error:
            self.logger.record(
                "fabric_mount_delete_readback_failed",
                path=path,
                error=str(error),
            )
            return None

    def _remove_cancelled_visible_preimage(
        self,
        session: _MountWriteSession,
        *,
        tracked_handles_closed: bool = True,
    ) -> bool:
        """Remove only the exact local inode superseded by a durable delete."""

        expected = session.expected_existing_fingerprint
        if expected is None:
            return True
        try:
            evidence_query = getattr(
                self.workspace, "has_pending_fingerprint_removal", None
            )
            pending_retirement = bool(
                evidence_query(
                    session.remote_path,
                    expected_fingerprint=expected,
                )
                if callable(evidence_query)
                else False
            )
        except (InvalidTask, OSError, UnsafePath) as error:
            # Failure to inspect Meshia-owned retirement evidence is
            # ambiguous. Keep the cancellation receipt as a namespace fence;
            # treating a missing visible name as success could let generic
            # startup recovery resurrect its hidden preimage.
            self.logger.record(
                "fabric_mount_cancelled_preimage_evidence_failed",
                path=session.remote_path,
                error=str(error),
            )
            return False
        current = self._local_fingerprint(session.remote_path)
        if not pending_retirement and (current is None or current != expected):
            # A different inode is a legitimate later creation. It stays
            # hidden only while the deleted SMB description is still open.
            return True
        if not tracked_handles_closed:
            return False
        try:
            self.workspace.remove_file_by_fingerprint(
                session.remote_path,
                expected_fingerprint=expected,
                tracked_handles_closed=True,
            )
        except (InvalidTask, OSError, UnsafePath) as error:
            refreshed = self._local_fingerprint(session.remote_path)
            try:
                still_pending = bool(
                    evidence_query(
                        session.remote_path,
                        expected_fingerprint=expected,
                    )
                    if callable(evidence_query)
                    else False
                )
            except (InvalidTask, OSError, UnsafePath) as evidence_error:
                self.logger.record(
                    "fabric_mount_cancelled_preimage_evidence_failed",
                    path=session.remote_path,
                    error=str(evidence_error),
                )
                return False
            if not still_pending and (refreshed is None or refreshed != expected):
                # The atomic retirement primitive preserved a different
                # concurrent winner (or definitively removed the old inode).
                # The delete receipt owns only ``expected``; retire it so the
                # winner is exposed instead of hiding legitimate new work.
                self.logger.record(
                    "fabric_mount_cancelled_preimage_changed",
                    path=session.remote_path,
                )
                return True
            self.logger.record(
                "fabric_mount_cancelled_preimage_cleanup_failed",
                path=session.remote_path,
                error=str(error),
            )
            return False
        try:
            still_pending = bool(
                evidence_query(
                    session.remote_path,
                    expected_fingerprint=expected,
                )
                if callable(evidence_query)
                else False
            )
        except (InvalidTask, OSError, UnsafePath) as error:
            self.logger.record(
                "fabric_mount_cancelled_preimage_evidence_failed",
                path=session.remote_path,
                error=str(error),
            )
            return False
        if still_pending:
            self.logger.record(
                "fabric_mount_cancelled_preimage_cleanup_pending",
                path=session.remote_path,
            )
            return False
        refreshed = self._local_fingerprint(session.remote_path)
        if refreshed == expected:
            # A platform adapter may report success before the retained
            # pathname actually disappears. Never retire the session fence on
            # that claim alone; the next bounded retry repeats the exact CAS.
            self.logger.record(
                "fabric_mount_cancelled_preimage_cleanup_incomplete",
                path=session.remote_path,
            )
            return False
        return True

    def _retire_satisfied_delete(self, session: _MountWriteSession) -> None:
        """Close a pending unlink whose path is already gone.

        ENOENT is this delete's own goal state, so the session is retired as a
        durable cancellation exactly as a committed delete retires it. Without
        this, an SMB sidecar the transport removed underneath us kept its
        ``delete_pending`` timer alive at the retry cap indefinitely.
        """

        cleanup_error: OSError | None = None
        try:
            session.mark_cancelled()
        except OSError as error:
            cleanup_error = error
        with self._lock:
            session.publishing = False
            session.journaled = True
            session.publish_failures = 0
            timer = self._timers.pop(session.remote_path, None)
            if timer is not None and timer is not threading.current_thread():
                timer.cancel()
            flush_timer = self._flush_timers.pop(session.remote_path, None)
            if flush_timer is not None:
                flush_timer.cancel()
            retire = session.cancelled and not self._session_has_open_handle(session)
            if not session.cancelled:
                # The cancellation receipt did not commit. Keep the durable
                # delete_pending fence and the private bytes for restart
                # recovery, exactly as the committed-delete path does.
                if self._sessions.get(session.remote_path) is session:
                    self._sessions.pop(session.remote_path, None)
                try:
                    session.preserve()
                except OSError as error:
                    cleanup_error = cleanup_error or error
            self._publication_condition.notify_all()
        if retire and self._retire_cancelled_session(session):
            with self._lock:
                if self._sessions.get(session.remote_path) is session:
                    self._sessions.pop(session.remote_path, None)
                self._publication_condition.notify_all()
        self.logger.record(
            "fabric_mount_delete_retry_converged",
            path=session.remote_path,
            error=str(cleanup_error) if cleanup_error is not None else "",
        )

    def _retire_cancelled_session(self, session: _MountWriteSession) -> bool:
        """Retire cancellation evidence without exposing its stale preimage."""

        # `tracked_handles_closed=True` is authority only while the exact same
        # path gate excludes a concurrent open/create. Use a nonblocking claim:
        # several callers already hold backend state, so waiting behind an
        # operation that owns this gate and needs that state would invert locks.
        with self._cleanup_path_admission(
            session.remote_path, blocking=False
        ) as admitted:
            if not admitted:
                return False
            return self._retire_cancelled_session_admitted(session)

    def _retire_cancelled_session_admitted(
        self, session: _MountWriteSession
    ) -> bool:
        """Finish cancelled cleanup while exact-path admission is held."""

        if not self._remove_cancelled_visible_preimage(session):
            try:
                session.preserve()
            except OSError as error:
                self.logger.record(
                    "fabric_mount_cancelled_stage_preserve_failed",
                    path=session.remote_path,
                    marker=str(session.marker_path),
                    error=str(error),
                )
            return False
        try:
            session.abort()
        except OSError as error:
            self.logger.record(
                "fabric_mount_cancelled_stage_preserved",
                path=session.remote_path,
                marker=str(session.marker_path),
                error=str(error),
            )
            return False
        return True

    def _fail_recovery_session_admission(
        self,
        session: _MountWriteSession,
    ) -> None:
        """Close recovered inodes and fail loudly at the active-session bound."""

        sessions = (*self._sessions.values(), session)
        self._sessions.clear()
        for value in sessions:
            try:
                value.preserve()
            except OSError as error:
                self.logger.record(
                    "fabric_mount_recovery_stage_preserve_failed",
                    path=value.remote_path,
                    marker=str(value.marker_path),
                    error=str(error),
                )
        self.logger.record(
            "fabric_mount_recovery_attention_required",
            max_active_sessions=MAX_RECOVERY_ACTIVE_SESSIONS,
        )
        raise FabricMountError(
            "Mounted-write recovery exceeded its bounded active-session set; "
            "the Meshia service requires attention before mounting."
        )

    def _recover_stages(self) -> None:
        root = self.workspace.mount_staging_directory()
        try:
            after = self._read_recovery_cursor(root)
        except FabricMountError as error:
            after = None
            self.logger.record(
                "fabric_mount_recovery_cursor_ignored",
                error=str(error),
            )
        ordered, marker_names, scan_truncated = self._recovery_batch(root, after)
        if scan_truncated:
            self.logger.record(
                "fabric_mount_recovery_attention_required",
                max_entries=MAX_RECOVERY_SCAN_ENTRIES,
                max_markers=MAX_RECOVERY_MARKERS,
            )
            raise FabricMountError(
                "Mounted-write recovery exceeded its bounded receipt scan; "
                "the Meshia service requires attention before mounting."
            )

        # Scan once, then drain that explicit ordering in bounded work batches.
        # Invalid and incomplete receipts are visited at most once per process,
        # so they cannot starve a later valid receipt or create a recovery loop.
        for offset in range(0, len(ordered), MAX_RECOVERY_STAGES):
            selected = ordered[offset : offset + MAX_RECOVERY_STAGES]
            for name in selected:
                marker = root / name
                try:
                    state, session = _MountWriteSession.recover(
                        self.workspace,
                        marker,
                        stage_capacity=self._stage_capacity,
                        logger=self.logger,
                        tree_recovery=getattr(self.coordinator, "recover_native_journal", None),
                    )
                except (FabricMountError, InvalidTask, OSError, UnsafePath) as error:
                    self.logger.record(
                        "fabric_mount_stage_preserved",
                        marker=str(marker),
                        reason=str(error),
                    )
                    continue
                if state == "discarded":
                    self.logger.record(
                        "fabric_mount_pristine_stage_discarded",
                        marker=str(marker),
                    )
                    continue
                if state == "open" or session is None:
                    self.logger.record(
                        "fabric_mount_incomplete_stage_preserved",
                        marker=str(marker),
                    )
                    continue
                if state == "cancelled":
                    if self._retire_cancelled_session(session):
                        continue
                    # Keep the durable cancellation as an in-memory namespace
                    # fence when its exact old inode cannot yet be retired.
                    # Otherwise lookup or the watcher could reinterpret that
                    # stale preimage as a fresh local upload.
                    if session.remote_path in self._sessions:
                        session.preserve()
                        self.logger.record(
                            "fabric_mount_duplicate_cancelled_stage_preserved",
                            marker=str(marker),
                        )
                        continue
                    if len(self._sessions) >= MAX_RECOVERY_ACTIVE_SESSIONS:
                        self._fail_recovery_session_admission(session)
                    session.journaled = True
                    self._sessions[session.remote_path] = session
                    continue
                if session.remote_path in self._sessions:
                    if session.descriptor >= 0:
                        os.close(session.descriptor)
                        session.descriptor = -1
                    self.logger.record(
                        "fabric_mount_duplicate_stage_preserved",
                        marker=str(marker),
                    )
                    continue
                if len(self._sessions) >= MAX_RECOVERY_ACTIVE_SESSIONS:
                    self._fail_recovery_session_admission(session)
                self._sessions[session.remote_path] = session
                if state == "delete_pending":
                    path = session.remote_path
                    delete_owned = self._delete_is_durably_owned(path)
                    if delete_owned is True:
                        try:
                            session.mark_cancelled()
                        except OSError as error:
                            self.logger.record(
                                "fabric_mount_delete_cancellation_receipt_failed",
                                path=path,
                                error=str(error),
                            )
                            continue
                        session.journaled = True
                        if self._retire_cancelled_session(session):
                            self._sessions.pop(path, None)
                        continue
                    if delete_owned is None:
                        self.logger.record(
                            "fabric_mount_delete_recovery_unknown",
                            path=path,
                        )
                        continue
                    try:
                        self.unlink(self._virtual_path(path))
                    except (FabricMountError, OSError, StateError) as error:
                        self.logger.record(
                            "fabric_mount_delete_recovery_failed",
                            path=path,
                            error=str(error),
                        )
                else:
                    self._publish_path(session.remote_path)

            # A failed cursor write never blocks later batches in this process.
            # On crash the last durable cursor may repeat work, which all valid
            # upload/delete handoffs already make idempotent by durable identity.
            try:
                self._write_recovery_cursor(root, selected[-1])
            except (FabricMountError, OSError, StateError) as error:
                self.logger.record(
                    "fabric_mount_recovery_cursor_write_failed",
                    error=str(error),
                )

        remaining = any(
            os.path.lexists(root / name) for name in marker_names
        )
        if not remaining:
            self._clear_recovery_cursor(root)

    def _remote_path(self, path: str, *, allow_workspace: bool = False) -> str | None:
        if not isinstance(path, str) or not path.startswith("/"):
            raise OSError(errno.EINVAL, "Mounted paths must be absolute.")
        if path == "/":
            if allow_workspace:
                return None
            raise OSError(errno.EISDIR, "The Meshia root is a directory.")
        raw = path[1:]
        try:
            parts = split_relative(raw)
        except (InvalidTask, UnsafePath) as error:
            raise OSError(errno.EINVAL, str(error)) from error
        if parts[0] != self.workspace_name:
            raise OSError(errno.ENOENT, "The workspace does not exist.")
        if len(parts) == 1:
            if allow_workspace:
                return None
            raise OSError(errno.EISDIR, "The workspace root is a directory.")
        return "/".join(parts[1:])

    def _virtual_path(self, remote_path: str) -> str:
        return f"/{self.workspace_name}/{remote_path}"

    def _require_parent_directory(self, remote_path: str) -> None:
        parent, separator, _name = remote_path.rpartition("/")
        if not separator:
            return
        try:
            node = self.getattr(self._virtual_path(parent))
        except OSError as error:
            if error.errno == errno.ENOENT:
                raise OSError(
                    errno.ENOENT, "The mounted parent directory does not exist."
                ) from error
            raise
        if not node.is_directory:
            raise OSError(errno.ENOTDIR, "The mounted parent is not a directory.")

    def _manifest_time(self) -> int:
        head = self._cached_manifest_head()
        return head.refreshed_at_ns if head is not None else time.time_ns()

    def _manifest_identity(self) -> tuple[int, str | None] | None:
        head = self._cached_manifest_head()
        return (head.generation, head.digest) if head is not None else None

    def _refresh_removed_directories(self) -> None:
        if self._removed_directories_head != self._manifest_identity():
            (
                self._removed_directories_head,
                removed_directories,
            ) = self.database.local_directory_tombstone_snapshot()
            self._removed_directories = set(removed_directories)

    def _path_hidden_by_removed_directory(self, remote_path: str) -> bool:
        self._refresh_removed_directories()
        if not self._removed_directories:
            return False
        candidate = remote_path
        while candidate:
            if candidate in self._removed_directories:
                return True
            candidate = candidate.rpartition("/")[0]
        return False

    def _mark_directory_removed(
        self,
        remote_path: str,
        manifest_identity: tuple[int, str | None] | None,
        *,
        expected_scope_id: int | None = None,
    ) -> bool:
        generation, digest = (
            (None, None) if manifest_identity is None else manifest_identity
        )
        try:
            stored = self.database.mark_local_directory_removed(
                remote_path,
                expected_generation=generation,
                expected_manifest_digest=digest,
                expected_scope_id=expected_scope_id,
            )
        except StateError as error:
            raise OSError(errno.ENOSPC, str(error)) from error
        except ValueError as error:
            # ValueError is not an adapter error, so letting it out of the
            # backend means an untranslated escape the SMB bridge shows as a
            # permission failure. Name it as an invalid argument instead.
            raise OSError(errno.EINVAL, str(error)) from error
        # The journal compare-and-set and remote head read are one SQLite
        # transaction. A concurrent manifest advance therefore cannot land a
        # stale overlay that hides a new child.
        if not stored:
            (
                self._removed_directories_head,
                removed_directories,
            ) = self.database.local_directory_tombstone_snapshot()
            self._removed_directories = set(removed_directories)
            return False
        if self._removed_directories_head != manifest_identity:
            self._removed_directories.clear()
            self._removed_directories_head = manifest_identity
        self._removed_directories.add(remote_path)
        wake = getattr(self.coordinator, "wake", None)
        if callable(wake):
            wake()
        return True

    def _mark_directory_created(self, remote_path: str) -> None:
        self._refresh_removed_directories()
        self.database.forget_local_directory_tombstone(remote_path)
        self._removed_directories.discard(remote_path)
        clear_ack = getattr(
            self.coordinator,
            "clear_directory_delete_acknowledgement",
            None,
        )
        if callable(clear_ack):
            clear_ack(remote_path)

    def _local_fingerprint(self, path: str) -> FileFingerprint | None:
        try:
            return self.workspace.stat_fingerprint(path)
        except (OSError, UnsafePath):
            return None

    @contextmanager
    def _read_epoch(self) -> Iterator[None]:
        """Memoize per-callback metadata (overlay, manifest head) for one read.

        Wraps the database scope epoch so a getattr or listdir reads the active
        directory rename and manifest head at most once. Re-entrant: listdir's
        per-child getattrs share the outer epoch, and the memo is dropped when
        the outermost epoch exits so the next callback observes fresh truth.
        """

        with self.database.scope_read_epoch():
            self._read_epoch_depth += 1
            try:
                yield
            finally:
                self._read_epoch_depth -= 1
                if self._read_epoch_depth == 0:
                    self._epoch_overlay = _UNSET
                    self._epoch_head = _UNSET
                    self._epoch_rename_sources = _UNSET

    def _compute_directory_overlay(self) -> PendingOperation | None:
        operation = self.database.get_active_directory_rename()
        if (
            operation is None
            or not operation.directory_rename
            or operation.destination_path is None
        ):
            return None
        return operation

    def _directory_overlay(self) -> PendingOperation | None:
        # A single getattr consults the active directory rename several times
        # (once directly, once via _projected_path), and a listing consults it
        # once per child; it cannot change inside a read callback. Memoize it on
        # the read epoch so a resolution reads it once, not many times.
        if self._read_epoch_depth > 0:
            if self._epoch_overlay is _UNSET:
                self._epoch_overlay = self._compute_directory_overlay()
            return self._epoch_overlay
        return self._compute_directory_overlay()

    def _cached_manifest_head(self) -> Any | None:
        # Read on every getattr return path (via _manifest_time) and again in
        # the removed-directory check; constant across one read callback.
        if self._read_epoch_depth > 0:
            if self._epoch_head is _UNSET:
                self._epoch_head = self.database.get_remote_manifest_head()
            return self._epoch_head
        return self.database.get_remote_manifest_head()

    def _rename_source_is_hidden(self, remote_path: str, remote: RemoteEntry) -> bool:
        # A successful pre-publication rename already persisted this exact
        # source dependency in the private stage marker. Once handed off, the
        # existing transfer intent retains it until the destination ACK queues
        # a normal DELETE. Keep that same promise across both phases/restarts.
        if self._epoch_rename_sources is _UNSET:
            sources = frozenset(
                session.delete_after_ack for session in self._sessions.values()
                if session.delete_after_ack is not None
                and session.remote_path != session.delete_after_ack[0]
            )
            if self._read_epoch_depth > 0:
                self._epoch_rename_sources = sources
        else:
            sources = self._epoch_rename_sources
        identity = (remote_path, remote.digest)
        if identity in sources:
            return True
        ctx = self._listing_ctx
        if ctx is not None and remote_path in ctx.prefetched:
            return identity in ctx.rename_sources
        return identity in self.database.pending_rename_sources((remote_path,))

    def _resolve_operation(self, remote_path: str) -> PendingOperation | None:
        ctx = self._listing_ctx
        if ctx is not None and remote_path in ctx.prefetched:
            return ctx.operations.get(remote_path)
        return self.database.get_latest_nonterminal_operation(remote_path)

    def _resolve_remote_entry(self, remote_path: str) -> RemoteEntry | None:
        ctx = self._listing_ctx
        if ctx is not None and remote_path in ctx.prefetched:
            if remote_path in ctx.receipted_entries:
                return ctx.receipted_entries[remote_path]
            return ctx.remote_entries.get(remote_path)
        # A successful v2 commit can precede its ordered change-feed readback.
        # Use only the exact durable receipt for this path during that gap;
        # never advance the global cursor or treat arbitrary local bytes as
        # remotely stable. A receipted delete suppresses the older mirror row.
        receipted = self.database.get_receipted_entry(remote_path)
        if receipted is not None:
            entry = receipted.entry
            return entry if entry is not None and entry.kind == "file" else None
        return self.database.get_remote_entry(remote_path)

    def _resolve_materialized(self, remote_path: str) -> MaterializedEntry | None:
        ctx = self._listing_ctx
        if ctx is not None and remote_path in ctx.prefetched:
            return ctx.materialized.get(remote_path)
        return self.database.get_materialized(remote_path)

    def _projected_has_remote_children(self, projected: str) -> bool:
        # During a listing we enumerated this directory's direct children, so we
        # already know which are directories; only fall back to the point query
        # for a projected path outside the prefetched set.
        ctx = self._listing_ctx
        if ctx is not None and projected in ctx.prefetched:
            return projected in ctx.directory_children
        if self.database.is_remote_directory(projected) or bool(
            self.database.list_remote_children(projected, limit=1)
        ):
            return True
        return any(
            receipt.entry is not None and receipt.path.startswith(projected + "/")
            for receipt in self.database.list_receipted_entries(projected)
        )

    def _projected_path(self, remote_path: str) -> tuple[str, bool]:
        """Map one optimistic directory destination back to remote truth."""

        operation = self._directory_overlay()
        if operation is None or operation.destination_path is None:
            return remote_path, False
        source = operation.path
        destination = operation.destination_path
        if remote_path == source or remote_path.startswith(source + "/"):
            return remote_path, True
        if remote_path == destination or remote_path.startswith(destination + "/"):
            # Once the authoritative delta is local, read the destination
            # directly while retaining the overlay only to hide stale source
            # cache entries until their durable apply intents finish.
            if (
                self._resolve_remote_entry(remote_path) is not None
                or self.database.is_remote_directory(remote_path)
                or self.database.list_remote_children(remote_path, limit=1)
            ):
                return remote_path, False
            return source + remote_path[len(destination) :], False
        return remote_path, False

    def _path_has_pending_directory_mutation(self, remote_path: str) -> bool:
        operation = self._directory_overlay()
        if operation is None or operation.destination_path is None:
            return False
        return any(
            remote_path == prefix or remote_path.startswith(prefix + "/")
            for prefix in (operation.path, operation.destination_path)
        )

    def _await_directory_mutation_locked(self, *remote_paths: str) -> None:
        """Wait (bounded) for a directory-rename overlay covering these paths.

        Caller holds ``self._lock``; the wait releases it. Raises EBUSY only
        when the overlay outlives ``MOUNT_DIRECTORY_MUTATION_WAIT_SECONDS``.
        """

        def pending() -> bool:
            # Read the overlay fresh on every probe: the read-epoch memo would
            # otherwise pin the value seen at entry for the whole wait.
            operation = self._compute_directory_overlay()
            if operation is None or operation.destination_path is None:
                return False
            return any(
                path == prefix or path.startswith(prefix + "/")
                for path in remote_paths
                for prefix in (operation.path, operation.destination_path)
            )

        if not pending():
            return
        deadline = time.monotonic() + MOUNT_DIRECTORY_MUTATION_WAIT_SECONDS
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise OSError(errno.EBUSY, "The directory rename is still reconciling.")
            self._publication_condition.wait(timeout=min(remaining, 0.25))
            self._epoch_overlay = _UNSET
            if not pending():
                return

    def _has_open_writer_in_prefixes(self, *prefixes: str) -> bool:
        return any(
            any(path == prefix or path.startswith(prefix + "/") for prefix in prefixes)
            for path in self._sessions
        )

    def _flush_sealed_writes_in_prefixes(self, *prefixes: str) -> None:
        """Publish closed mounted writes before a directory-prefix rename.

        FUSE-T's SMB bridge maps a retryable ``EBUSY`` to a misleading macOS
        permission error.  A just-closed file can remain in the short settle
        window even though no application owns its handle, so drain only those
        sealed sessions here.  Truly open or already-publishing sessions stay
        fenced and are rejected by the normal writer check below.
        """

        self._discard_closed_sidecars_in_prefixes(*prefixes)
        with self._lock:
            paths = tuple(
                path
                for path, session in self._sessions.items()
                if session.sealed
                and not session.publishing
                and any(
                    path == prefix or path.startswith(prefix + "/")
                    for prefix in prefixes
                )
            )
            timers = tuple(self._timers.pop(path, None) for path in paths)
        for timer in timers:
            if timer is not None:
                timer.cancel()
        for path in paths:
            self._publish_path(path)

    def _discard_closed_sidecars_in_prefixes(self, *prefixes: str) -> None:
        """End only validated metadata grace before an explicit namespace move.

        Grace normally lets SMB reopen a sidecar for another xattr. Once its
        directory is being renamed or removed, retaining that closed scratch
        session would falsely fence the namespace. Use the existing durable
        cancellation path, and never retire an open or published user inode.
        """

        with self._lock:
            paths = []
            for path, session in self._sessions.items():
                if (
                    session.sealed
                    and not session.publishing
                    and not session.published
                    and not session.journaled
                    and not self._session_has_open_handle(session)
                    and any(path == prefix or path.startswith(prefix + "/") for prefix in prefixes)
                    and self._transport_appledouble_discardable(session)
                ):
                    session.discard_grace_deadline = 0.0
                    paths.append(path)
            timers = tuple(self._timers.pop(path, None) for path in paths)
        for timer in timers:
            if timer is not None:
                timer.cancel()
        for path in paths:
            # Reopening between locks resets the deadline and restores normal
            # grace; _publish_path rechecks handle ownership and sealed bytes.
            self._publish_path(path)

    def _retarget_open_reads(self, source: str, destination: str) -> None:
        """Keep already-open read descriptions valid across a prefix move."""

        for opened in self._handles.values():
            if not isinstance(opened, _ReadHandle):
                continue
            view = opened.view
            logical = view.remote_path
            if logical != source and not logical.startswith(source + "/"):
                continue
            opened.view = _FileView(
                destination + logical[len(source) :],
                view.size_bytes,
                view.digest,
                view.modified_ns,
                remote_source_path=view.remote_source_path or logical,
                local_fingerprint=view.local_fingerprint,
                session=view.session,
                native_tree=view.native_tree,
            )

    def _pending_view(self, path: str, operation: PendingOperation) -> _FileView | None:
        if operation.kind == "delete" and operation.path == path:
            return None
        if operation.kind == "rename":
            if operation.path == path:
                return None
            if operation.destination_path == path:
                source = self._resolve_remote_entry(operation.path)
                if source is None:
                    return None
                local = self._local_fingerprint(path)
                materialized = self._resolve_materialized(path)
                if (
                    local is not None
                    and materialized is not None
                    and materialized.state in ("dirty", "staging", "clean")
                    and materialized.clean_digest == source.digest
                    and materialized.stat_fingerprint == _fingerprint_text(local)
                ):
                    # A local safe-save rename has already moved the closed
                    # temp inode into the destination before its remote rename
                    # receipt arrives. Keep exposing that exact inode's mtime.
                    # Falling through to the remote source row substitutes the
                    # later source-PUT receipt timestamp for a moment; once the
                    # rename ACK retires, getattr snaps back to the inode time.
                    # NSDocument treats that self-created transition as an
                    # external edit and refuses its next normal save.
                    return _FileView(
                        path,
                        local.size_bytes,
                        source.digest,
                        local.mtime_ns,
                        local_fingerprint=local,
                    )
                return _FileView(
                    path,
                    source.size_bytes,
                    source.digest,
                    _modified_ns(source.modified, self._manifest_time()),
                    remote_source_path=operation.path,
                )
        if operation.kind == "put" and operation.path == path:
            local = self._local_fingerprint(path)
            if local is not None:
                return _FileView(
                    path,
                    local.size_bytes,
                    operation.staged_digest,
                    local.mtime_ns,
                    local_fingerprint=local,
                )
            pending_tree = getattr(self.coordinator, "pending_native_file", None)
            plan = pending_tree(operation) if callable(pending_tree) else None
            if plan is not None:
                return _FileView(path, plan.size_bytes, plan.sha256,
                    _modified_ns(plan.modified_at, self._manifest_time()),
                    native_tree=(plan.source_token, plan.tree_snapshot))
        return None

    def _file_view_exact(self, remote_path: str) -> _FileView | None:
        session = self._sessions.get(remote_path)
        if session is not None:
            # A durable, explicit unlink receipt owns the local namespace even
            # before its provider tombstone can be queued. Do not let the old
            # remote manifest row make an SMB deletion reappear in Finder.
            if session.delete_pending or session.cancelled:
                return None
            pristine = session.pristine_read_view()
            if pristine is not None:
                remote = self._resolve_remote_entry(remote_path)
                if (
                    self._fuse_t_smb_transport
                    and pristine.digest is not None
                    and self._resolve_operation(remote_path) is None
                    and remote is not None
                    and remote.digest != pristine.digest
                ):
                    # Browser saves replace the namespace while SMB retains
                    # old descriptions. Retire only an unchanged private stage;
                    # it must never publish over the browser's replacement.
                    session.detach_pristine()
                    self._sessions.pop(remote_path, None)
                    if not self._session_has_open_handle(session):
                        session.finish()
                    return self._file_view_exact(remote_path)
                return pristine
            if session.published:
                local = self._local_fingerprint(remote_path)
                if local is not None:
                    return _FileView(
                        remote_path,
                        local.size_bytes,
                        session.base_digest,
                        local.mtime_ns,
                        local_fingerprint=local,
                    )
                # A recovered ``published`` marker proves that the private
                # stage was moved into this path, but its descriptor is
                # intentionally closed during recovery. If the visible inode
                # subsequently disappears, do not fall through to size() and
                # turn a namespace miss into EBADF. Keep the marker/session as
                # durable reconciliation evidence while projecting absence.
                return None
            return session.staged_read_view()
        operation = self._resolve_operation(remote_path)
        if operation is not None:
            pending = self._pending_view(remote_path, operation)
            if (
                pending is not None
                or (operation.kind == "delete" and operation.path == remote_path)
                or (operation.kind == "rename" and operation.path == remote_path)
            ):
                return pending
        remote = self._resolve_remote_entry(remote_path)
        local = self._local_fingerprint(remote_path)
        materialized = self._resolve_materialized(remote_path)
        if (
            remote is not None
            and (
                local is None
                or materialized is not None
                and materialized.state == "clean"
                and materialized.clean_digest == remote.digest
                and materialized.stat_fingerprint == _fingerprint_text(local)
            )
            and self._rename_source_is_hidden(remote_path, remote)
        ):
            # A new source session/PUT has already won above. A new dirty
            # inode or different remote digest also remains visible; hide only
            # the exact acknowledged source (and its unchanged clean cache).
            return None
        if local is not None and (
            remote is None
            or materialized is not None
            and (
                materialized.state in ("dirty", "staging", "conflict")
                or materialized.state == "clean"
                and remote is not None
                and materialized.clean_digest == remote.digest
            )
        ):
            return _FileView(
                remote_path,
                local.size_bytes,
                materialized.clean_digest if materialized is not None else None,
                local.mtime_ns,
                local_fingerprint=local,
            )
        if remote is None:
            return None
        if (
            local is None
            and materialized is not None
            and self._unlink_receipt_owns_namespace(remote_path, remote)
        ):
            return None
        return _FileView(
            remote_path,
            remote.size_bytes,
            remote.digest,
            _modified_ns(remote.modified, self._manifest_time()),
            remote_source_path=remote_path,
        )

    def _unlink_receipt_owns_namespace(
        self, remote_path: str, remote: RemoteEntry
    ) -> bool:
        """Whether a stalled durable unlink still owns this path locally.

        ``unlink`` returns 0 once its delete is durable in the local journal,
        long before the authority acknowledges it. If that delete later lands
        in a terminal, unacknowledged state, falling through to the manifest
        mirror would silently contradict the success the caller was already
        given: the file reappears in the very next ``readdir`` and ``rmdir``
        fails ENOTEMPTY forever, with no errno anywhere to explain it. There
        is no syscall left to fail -- the honest repair is to keep the promise
        locally and let the durable conflict record drive reconciliation.

        This is deliberately narrow. The intent only owns the namespace while
        the entry it expected to remove is still the one on record; a remote
        writer that replaced those bytes wins, and its newer file becomes
        visible again.
        """

        # Cheap gate first: only a path this node actually mutated can carry a
        # stalled receipt, and only a path with no local inode is hidden.
        if remote.digest is None:
            return False
        intent = self.database.get_unresolved_delete_intent(remote_path)
        if intent is None:
            return False
        expected = intent.expected_source_digest
        return expected is None or expected == remote.digest

    def _file_view(self, remote_path: str) -> _FileView | None:
        projected, hidden = self._projected_path(remote_path)
        if hidden:
            return None
        view = self._file_view_exact(projected)
        if view is None or projected == remote_path:
            return view
        return _FileView(
            remote_path,
            view.size_bytes,
            view.digest,
            view.modified_ns,
            remote_source_path=projected,
            local_fingerprint=view.local_fingerprint,
            session=view.session,
            native_tree=view.native_tree,
        )

    def getattr(self, path: str) -> MountNode:
        with self._lock, self._read_epoch():
            if path == "/":
                return MountNode("/", True, 0, self._manifest_time())
            remote = self._remote_path(path, allow_workspace=True)
            if remote is None:
                return MountNode(path, True, 0, self._manifest_time())
            projected, hidden = self._projected_path(remote)
            if hidden:
                raise OSError(errno.ENOENT, "The mounted item was renamed.")
            if self._path_hidden_by_removed_directory(remote):
                raise OSError(errno.ENOENT, "The mounted directory was removed.")
            view = self._file_view(remote)
            if view is not None:
                return MountNode(
                    path, False, view.size_bytes, view.modified_ns, view.digest
                )
            operation = self._directory_overlay()
            if (
                operation is not None
                and operation.destination_path is not None
                and operation.destination_path.startswith(remote + "/")
            ):
                return MountNode(path, True, 0, self._manifest_time())
            if self._projected_has_remote_children(projected):
                return MountNode(path, True, 0, self._manifest_time())
            # A local directory is proven by one stat. Listing it first cost
            # O(children) under the backend lock for every re-stat of a
            # directory that is being filled (its files are not remote yet),
            # which is what convoyed eight parallel writers (2026-09-03).
            if self.workspace.directory_exists(projected):
                return MountNode(path, True, 0, self._manifest_time())
            try:
                local, _truncated = self.workspace.list(projected, max_entries=1)
            except (InvalidTask, OSError, UnsafePath):
                local = []
            if local:
                return MountNode(path, True, 0, self._manifest_time())
            raise OSError(errno.ENOENT, "The mounted item does not exist.")

    def getattr_handle(self, handle: int) -> MountNode:
        """Stat the open inode even after its namespace link was replaced."""
        with self._lock:
            opened = self._handles.get(handle)
            if opened is None:
                raise OSError(errno.EBADF, "The mounted handle is closed.")
            view = (opened.view if isinstance(opened, _ReadHandle)
                    else self._session_read_view(opened))
            if isinstance(opened, _ReadHandle) and opened.retired_local is not None:
                info = os.fstat(opened.retired_local.descriptor)
                size, modified = info.st_size, info.st_mtime_ns
            elif view.session is not None:
                current = self._session_read_view(view.session)
                size, modified = current.size_bytes, current.modified_ns
            else:
                size, modified = view.size_bytes, view.modified_ns
            return MountNode(f"/{self.workspace_name}/{view.remote_path}", False,
                             size, modified, view.digest)

    def listdir(self, path: str) -> tuple[str, ...]:
        # The batched resolution (listdir_entries) is reached only from the
        # FUSE readdir-plus prewarm,
        # as a wrapped side effect, so it can never fence a directory here.
        with self._lock:
            if path == "/":
                return (self.workspace_name,)
            node = self.getattr(path)
            if not node.is_directory:
                raise OSError(errno.ENOTDIR, "The mounted item is not a directory.")
            parent = self._remote_path(path, allow_workspace=True)
            projected_parent = parent
            if parent is not None:
                projected_parent, hidden = self._projected_path(parent)
                if hidden:
                    raise OSError(errno.ENOENT, "The mounted directory was renamed.")
            names: set[str] = set()
            for receipt in self.database.list_receipted_entries(projected_parent):
                if receipt.entry is not None:
                    child = _direct_child(projected_parent, receipt.path)
                    if child is not None:
                        names.add(child)
            after: str | None = None
            while len(names) < MAX_DIRECTORY_ENTRIES:
                page = self.database.list_remote_children(
                    projected_parent, after_name=after, limit=999
                )
                if not page:
                    break
                for child in page:
                    names.add(child.name)
                if len(page) < 999:
                    break
                after = page[-1].name
            if len(names) >= MAX_DIRECTORY_ENTRIES:
                raise OSError(errno.EOVERFLOW, "The mounted directory is too large.")

            for operation in self.database.list_operations(
                states=_NONTERMINAL_STATES, limit=10_000
            ):
                if operation.directory_rename:
                    continue
                for affected in (operation.path, operation.destination_path):
                    if affected is None:
                        continue
                    child = _direct_child(parent, affected)
                    if child is not None:
                        names.add(child)
            for staged in self._sessions:
                child = _direct_child(parent, staged)
                if child is not None:
                    names.add(child)
            try:
                local_entries, truncated = self.workspace.list(
                    projected_parent or ".", max_entries=10_000, recursive=False
                )
                if truncated:
                    raise OSError(
                        errno.EOVERFLOW, "The local mounted directory is too large."
                    )
                for local in local_entries:
                    names.add(local.rstrip("/"))
            except (InvalidTask, UnsafePath):
                pass

            directory_rename = self._directory_overlay()
            if (
                directory_rename is not None
                and directory_rename.destination_path is not None
            ):
                source_parent = directory_rename.path.rpartition("/")[0] or None
                source_child = _direct_child(parent, directory_rename.path)
                if parent == source_parent and source_child is not None:
                    names.discard(source_child)
                destination_child = _direct_child(
                    parent, directory_rename.destination_path
                )
                if destination_child is not None:
                    names.add(destination_child)

            visible: list[str] = []
            for name in sorted(names):
                child_path = f"{path.rstrip('/')}/{name}"
                try:
                    self.getattr(child_path)
                except OSError as error:
                    if error.errno != errno.ENOENT:
                        raise
                else:
                    visible.append(name)
            return tuple(visible)

    def listdir_entries(self, path: str) -> tuple[tuple[str, MountNode], ...]:
        """List a directory returning each visible child with its resolved node.

        The per-child visibility filter already resolves every name to a
        MountNode; returning those lets the FUSE layer prewarm its attribute
        cache from the listing (readdir-plus) instead of re-resolving each name
        in the getattr storm smbfs issues right after a readdir.
        """

        with self._lock, self._read_epoch():
            if path == "/":
                return (
                    (
                        self.workspace_name,
                        MountNode(
                            f"/{self.workspace_name}", True, 0, self._manifest_time()
                        ),
                    ),
                )
            node = self.getattr(path)
            if not node.is_directory:
                raise OSError(errno.ENOTDIR, "The mounted item is not a directory.")
            parent = self._remote_path(path, allow_workspace=True)
            projected_parent = parent
            if parent is not None:
                projected_parent, hidden = self._projected_path(parent)
                if hidden:
                    raise OSError(errno.ENOENT, "The mounted directory was renamed.")
            names: set[str] = set()
            # Direct child names the remote manifest already proves are
            # directories -- captured from the same page so the per-child
            # resolution never re-asks "does this have remote children?".
            remote_dir_names: set[str] = set()
            receipted_entries = self.database.list_receipted_entries(projected_parent)
            for receipt in receipted_entries:
                if receipt.entry is not None:
                    child = _direct_child(projected_parent, receipt.path)
                    if child is not None:
                        names.add(child)
                        child_path = f"{projected_parent}/{child}" if projected_parent else child
                        if receipt.path.startswith(child_path + "/"):
                            remote_dir_names.add(child)
            after: str | None = None
            while len(names) < MAX_DIRECTORY_ENTRIES:
                page = self.database.list_remote_children(
                    projected_parent, after_name=after, limit=999
                )
                if not page:
                    break
                for child in page:
                    names.add(child.name)
                    if child.is_directory:
                        remote_dir_names.add(child.name)
                if len(page) < 999:
                    break
                after = page[-1].name
            if len(names) >= MAX_DIRECTORY_ENTRIES:
                raise OSError(errno.EOVERFLOW, "The mounted directory is too large.")

            for operation in self.database.list_operations(
                states=_NONTERMINAL_STATES, limit=10_000
            ):
                if operation.directory_rename:
                    continue
                for affected in (operation.path, operation.destination_path):
                    if affected is None:
                        continue
                    child = _direct_child(parent, affected)
                    if child is not None:
                        names.add(child)
            for staged in self._sessions:
                child = _direct_child(parent, staged)
                if child is not None:
                    names.add(child)
            try:
                local_entries, truncated = self.workspace.list(
                    projected_parent or ".", max_entries=10_000, recursive=False
                )
                if truncated:
                    raise OSError(
                        errno.EOVERFLOW, "The local mounted directory is too large."
                    )
                for local in local_entries:
                    names.add(local.rstrip("/"))
            except (InvalidTask, UnsafePath):
                pass

            directory_rename = self._directory_overlay()
            if (
                directory_rename is not None
                and directory_rename.destination_path is not None
            ):
                source_parent = directory_rename.path.rpartition("/")[0] or None
                source_child = _direct_child(parent, directory_rename.path)
                if parent == source_parent and source_child is not None:
                    names.discard(source_child)
                destination_child = _direct_child(
                    parent, directory_rename.destination_path
                )
                if destination_child is not None:
                    names.add(destination_child)

            ordered_names = sorted(names)

            def _child_remote(name: str) -> str:
                return f"{parent}/{name}" if parent else name

            # One batched read of the three per-child ledgers, then resolve each
            # candidate's visibility from memory. getattr resolves the raw child
            # remote path (projected only differs under an active directory
            # rename, which then falls back to a point read), so prefetch by the
            # raw child paths.
            #
            # The prefetch is a pure optimization: with it, each child resolves
            # from memory; without it (resolution is None), each child falls
            # back to the exact per-child point reads this replaced. So a
            # failure to build it must degrade to the correct slow path, NEVER
            # fence the directory. An unhandled exception here would escape the
            # FUSE `_call` adapter uncaught and the SMB bridge would render it to
            # the user as a silent EACCES on the whole directory. Log the real
            # cause and continue with point reads instead.
            resolution: _DirectoryResolution | None = None
            try:
                child_remote_paths = [_child_remote(name) for name in ordered_names]
                operations, remotes, materialized, prefetched = (
                    self.database.prefetch_child_resolution(child_remote_paths)
                )
                resolution = _DirectoryResolution(
                    operations=operations,
                    remote_entries=remotes,
                    materialized=materialized,
                    prefetched=prefetched,
                    directory_children=frozenset(
                        _child_remote(name) for name in remote_dir_names
                    ),
                    receipted_entries={receipt.path: receipt.entry for receipt in receipted_entries},
                    rename_sources=self.database.pending_rename_sources(child_remote_paths),
                )
            except Exception as error:  # noqa: BLE001 - never fence on a perf path
                self.logger.record(
                    "fabric_mount_listdir_prefetch_failed",
                    path=path,
                    candidates=len(ordered_names),
                    error=f"{type(error).__name__}: {error}",
                    traceback=traceback.format_exc(),
                )

            visible: list[tuple[str, MountNode]] = []
            previous_ctx = self._listing_ctx
            self._listing_ctx = resolution
            try:
                for name in ordered_names:
                    child_path = f"{path.rstrip('/')}/{name}"
                    try:
                        child_node = self.getattr(child_path)
                    except OSError as error:
                        if error.errno != errno.ENOENT:
                            raise
                    else:
                        visible.append((name, child_node))
            finally:
                self._listing_ctx = previous_ctx
            return tuple(visible)

    def _new_handle(self, value: _ReadHandle | _MountWriteSession) -> int:
        handle = self._next_handle
        self._next_handle += 1
        self._handles[handle] = value
        return handle

    @staticmethod
    def _handle_references_session(
        opened: _ReadHandle | _MountWriteSession,
        session: _MountWriteSession,
    ) -> bool:
        return opened is session or (
            isinstance(opened, _ReadHandle) and opened.view.session is session
        )

    def _session_has_open_handle(self, session: _MountWriteSession) -> bool:
        """Return whether any FUSE description still pins this staged inode."""

        return any(
            self._handle_references_session(opened, session)
            for opened in self._handles.values()
        )

    @staticmethod
    def _handle_references_remote_path(
        opened: _ReadHandle | _MountWriteSession,
        remote_path: str,
    ) -> bool:
        if isinstance(opened, _MountWriteSession):
            return opened.remote_path == remote_path
        return remote_path in (
            opened.view.remote_path,
            opened.view.remote_source_path,
        )

    @staticmethod
    def _cleanup_paths_conflict(left: str, right: str) -> bool:
        return bool(
            left == right
            or not left
            or not right
            or left.startswith(right + "/")
            or right.startswith(left + "/")
        )

    @contextmanager
    def _cleanup_path_admission(
        self, *remote_paths: str, blocking: bool = True
    ) -> Iterator[bool]:
        normalized_paths = tuple(
            dict.fromkeys(
                "/".join(split_relative(path)) if path else ""
                for path in remote_paths
            )
        )
        token: int | None = None
        thread_id = threading.get_ident()
        with self._cleanup_path_condition:
            def conflicts() -> bool:
                return any(
                    self._cleanup_paths_conflict(path, active_path)
                    for active_token, active_paths in self._cleanup_path_active.items()
                    if self._cleanup_path_owners.get(active_token) != thread_id
                    for path in normalized_paths
                    for active_path in active_paths
                )

            if not blocking and conflicts():
                admitted = False
            else:
                while conflicts():
                    self._cleanup_path_condition.wait()
                token = self._cleanup_path_next
                self._cleanup_path_next += 1
                self._cleanup_path_active[token] = normalized_paths
                self._cleanup_path_owners[token] = thread_id
                admitted = True
        if not admitted:
            yield False
            return
        try:
            yield True
        finally:
            assert token is not None
            with self._cleanup_path_condition:
                self._cleanup_path_active.pop(token, None)
                self._cleanup_path_owners.pop(token, None)
                self._cleanup_path_condition.notify_all()

    @contextmanager
    def _mount_cleanup_fence(self, remote_path: str) -> Iterator[bool]:
        """Exclude open/create while proving one local inode has no handles."""

        normalized = "/".join(split_relative(remote_path))
        # Coordinator polls already own _coordinator_lock. Never wait for either
        # the path gate or backend state lock: a reverse-order Finder mutation
        # conservatively defers cleanup instead of forming a deadlock cycle.
        with self._cleanup_path_admission(normalized, blocking=False) as admitted:
            if not admitted:
                yield False
                return
            acquired = self._lock.acquire(blocking=False)
            if not acquired:
                yield False
                return
            try:
                handles_closed = bool(
                    not self._closed
                    and normalized not in self._sessions
                    and not any(
                        self._handle_references_remote_path(opened, normalized)
                        for opened in self._handles.values()
                    )
                )
            finally:
                self._lock.release()
            # Keep only the path-scoped gate across O(1) fingerprint+unlink.
            # Same-path admission is excluded; unrelated paths never wait on
            # hashing or this workspace's global state lock.
            yield handles_closed

    def _session_has_open_writer(self, session: _MountWriteSession) -> bool:
        """Return whether a writable FUSE description can still change bytes.

        FUSE-T's SMB bridge keeps both read aliases and the DATA description
        open after a close-time FLUSH.  Until the quiet FLUSH timer seals that
        description, only the actual writer can still mutate file bytes.
        """

        return any(opened is session for opened in self._handles.values())

    def _session_has_unflushed_writer(self, session: _MountWriteSession) -> bool:
        """Return whether one writable alias can still change session bytes."""

        return any(
            opened is session and handle not in self._flushed_write_handles
            for handle, opened in self._handles.items()
        )

    def _new_publish_timer(self, path: str, delay: float) -> threading.Timer:
        timer: threading.Timer
        timer = threading.Timer(
            delay,
            lambda: self._publish_path(path, expected_timer=timer),
        )
        timer.daemon = True
        return timer

    def _new_flush_publish_timer(
        self, path: str, delay: float | None = None
    ) -> threading.Timer:
        timer: threading.Timer
        timer = threading.Timer(
            self.settle_seconds if delay is None else delay,
            lambda: self._publish_flushed_path(path, expected_timer=timer),
        )
        timer.daemon = True
        return timer

    def defer_unlink(self, path: str) -> None:
        """Persist an explicit native unlink until mutation admission recovers.

        FUSE-T 1.2.7's SMB bridge acknowledges CLOSE even when the FUSE
        ``unlink`` callback returns a transient error. Persist a delete-only
        stage before acknowledging that callback, then reuse the bounded
        publication retry loop to enqueue its tombstone. A close without an
        unlink callback never enters this method and is not deletion evidence.
        """

        remote = self._remote_path(path)
        assert remote is not None
        with self._lock:
            self._await_directory_mutation_locked(remote)
            session = self._sessions.get(remote)
            if session is None:
                # FUSE-T can acknowledge an SMB unlink even when its callback
                # reports a transient error, so this path retains a local
                # tombstone for later publication. Keep that exceptional queue
                # under the same hard resource bound as ordinary/recovered
                # write sessions: every retained session owns an open stage
                # descriptor and, while authority is unavailable, one retry
                # timer. Without this fence a batch Finder delete could exhaust
                # both descriptors and native threads during an outage.
                self._wait_for_write_session_slot_locked(reason="deferred-delete")
                view = self._file_view(remote)
                remote_entry = self._resolve_remote_entry(remote)
                if view is None or remote_entry is None:
                    raise OSError(
                        errno.EAGAIN,
                        "The mounted delete cannot be deferred without "
                        "remote identity.",
                    )
                session = _MountWriteSession(
                    self.workspace,
                    remote,
                    base_digest=remote_entry.digest,
                    expected_existing_fingerprint=self._local_fingerprint(remote),
                    pristine_view=view,
                    created=False,
                    stage_capacity=self._stage_capacity,
                    remote_quota=self._remote_quota,
                    base_size_bytes=view.size_bytes,
                    logger=self.logger,
                )
                self._sessions[remote] = session
            if session.publishing:
                waited = self._wait_for_publication_locked(remote, session)
                if waited is None or waited.publishing:
                    raise OSError(errno.EBUSY, "The mounted file is still publishing.")
                session = waited
            try:
                session.mark_delete_pending()
            except BaseException:
                if (
                    self._sessions.get(remote) is session
                    and not self._session_has_open_handle(session)
                    and not session.modified
                    and not session.delete_pending
                ):
                    self._sessions.pop(remote, None)
                    session.abort()
                raise
            timer = self._timers.pop(remote, None)
            if timer is not None:
                timer.cancel()
            flush_timer = self._flush_timers.pop(remote, None)
            if flush_timer is not None:
                flush_timer.cancel()
            self._schedule_publish_retry_locked(session, count_failure=False)
            self._publication_condition.notify_all()

    def open(self, path: str, flags: int, *, create: bool = False) -> int:
        remote = self._remote_path(path)
        assert remote is not None
        with self._cleanup_path_admission(remote):
            return self._open_admitted(path, flags, create=create)

    def _note_access(self, remote_path: str) -> None:
        """Tell the coordinator this path was opened, for last-access eviction.

        Never fails an open and never blocks: the coordinator coalesces these
        in memory and stamps them from its own poll. Without this the cache's
        ``accessed_at_ns`` only ever moved when a file was WRITTEN, so reading
        a file a thousand times did nothing to protect it from eviction.
        """

        note = getattr(self.coordinator, "note_materialized_access", None)
        if not callable(note):
            return
        try:
            note(remote_path)
        except Exception:  # noqa: BLE001 - access accounting is best effort
            pass

    def _warm_remote_read(self, remote_path: str) -> None:
        """Start the object ticket for a remote file at open time.

        Opening is a strong hint that bytes are about to be read; issuing the
        ticket now hides the signed round trip behind the caller's first read.
        Never fails the open: the coordinator bounds and de-duplicates warms.
        """

        warm = getattr(self.coordinator, "warm_object_read", None)
        if not callable(warm):
            return
        try:
            warm(remote_path)
        except Exception:  # noqa: BLE001 - warming is best effort
            pass

    def _retire_superseded_session_locked(
        self,
        remote: str,
        session: "_MountWriteSession",
    ) -> None:
        """Drop a published-but-unjournaled attempt that a new write replaces.

        Called only for a session with no durable receipt (never journaled,
        not publishing, not delete-pending, not cancelled, not poisoned): the
        only thing owning it is a publish-retry timer. The caller is about to
        overwrite the same path, so the superseded bytes are exactly what the
        user is replacing. Cancel its timers, release the stage, and clear the
        registry so a fresh description can own the path.
        """

        for registry in (self._timers, self._flush_timers):
            timer = registry.pop(remote, None)
            if timer is not None:
                timer.cancel()
        if self._sessions.get(remote) is session:
            self._sessions.pop(remote, None)
        try:
            session.abort()
        except OSError:
            # The stage inode is already gone; the registry is authoritative.
            pass
        self.logger.record(
            "fabric_mount_superseded_unjournaled_write_retired",
            path=remote,
            publish_failures=session.publish_failures,
        )

    def _wait_for_write_session_slot_locked(self, *, reason: str) -> None:
        """Block (lock held, condition released) until a session slot frees.

        Publication retires sessions on timer threads that need ``_lock``;
        ``_publication_condition`` shares that lock, so waiting here lets them
        run. Past the deadline the historical EAGAIN is raised.
        """

        if len(self._sessions) < MAX_RECOVERY_ACTIVE_SESSIONS:
            return
        deadline = time.monotonic() + WRITE_SESSION_ADMISSION_WAIT_SECONDS
        self.logger.record(
            "fabric_mount_write_session_admission_wait",
            active_sessions=len(self._sessions),
            reason=reason,
        )
        while len(self._sessions) >= MAX_RECOVERY_ACTIVE_SESSIONS:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise OSError(
                    errno.EAGAIN,
                    f"The mounted {reason} admission bound is busy.",
                )
            self._publication_condition.wait(timeout=min(remaining, 0.25))

    def _wait_for_publication_locked(
        self, remote: str, session: "_MountWriteSession"
    ) -> "_MountWriteSession | None":
        """Wait (bounded) while ``session`` is mid-publication.

        Returns the session registered for ``remote`` afterwards (``None``
        once it retired), so the caller re-evaluates fresh state.
        """

        deadline = time.monotonic() + PUBLISH_REOPEN_WAIT_SECONDS
        current: _MountWriteSession | None = session
        while (
            current is not None
            and current.publishing
            and not current.delete_pending
            and not current.cancelled
            and not current.failed_mutation
        ):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            self._publication_condition.wait(timeout=min(remaining, 0.25))
            current = self._sessions.get(remote)
        return current

    def _await_pending_put_locked(
        self, remote: str, *, deadline: float | None = None
    ) -> None:
        """Wait (bounded) for a just-closed file's durable handoff.

        Native document saves commonly close a temporary file and immediately
        rename it over the destination.  The close can move ownership from the
        private mount session into either the local-transfer intent or the PUT
        journal before the rename callback arrives.  Returning EBUSY in that
        narrow handoff window is surfaced by FUSE-T/SMB as a permanent
        permission failure.  Release the backend lock while the synchronizer
        establishes the receipt, then let rename re-read every source and
        destination invariant from authoritative state.

        The wait remains bounded: large/offline uploads still fail closed and
        retain their durable source identity for a safe application retry.
        """

        def pending() -> bool:
            operation = self.database.get_latest_nonterminal_operation(remote)
            return bool(
                (operation is not None and operation.kind == "put")
                or self.database.get_local_transfer_intent(remote) is not None
            )

        if not pending():
            return
        deadline = (
            time.monotonic() + PUBLISH_REOPEN_WAIT_SECONDS
            if deadline is None
            else deadline
        )
        self.logger.record("fabric_mount_pending_put_rename_wait", path=remote)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise OSError(
                    errno.EBUSY,
                    "The mounted upload is still reconciling.",
                )
            self._publication_condition.wait(timeout=min(remaining, 0.25))
            if not pending():
                return

    def _await_pending_rename_destination_locked(
        self, remote: str, *, deadline: float
    ) -> None:
        """Wait briefly for an earlier exact-path mutation to release ``remote``.

        NSDocument's SMB safe-save choreography first renames the original to
        its backup name, then immediately renames the completed replacement
        over the original path.  The first callback publishes its local move
        before the durable rename receipt is acknowledged, so the second can
        observe that exact predecessor as still nonterminal.  Returning EBUSY
        in this narrow handoff window becomes a permanent Cocoa permission
        error.  Wait for the bounded journal handoff, then let the caller
        re-read both namespace and inode identity from scratch.

        Open write sessions remain a separate, immediate fence: this helper
        waits only on the indexed durable operation chain and never treats an
        actively writable destination as replaceable.
        """

        if self.database.get_latest_nonterminal_operation(remote) is None:
            return
        self.logger.record(
            "fabric_mount_pending_destination_rename_wait", path=remote
        )
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise OSError(
                    errno.EBUSY,
                    "The rename destination is still reconciling.",
                )
            self._publication_condition.wait(timeout=min(remaining, 0.25))
            if self.database.get_latest_nonterminal_operation(remote) is None:
                return

    def _open_admitted(self, path: str, flags: int, *, create: bool = False) -> int:
        # A brand-new write session opens its stage inode and writes its
        # crash receipt (two fsyncs) -- per-file disk work that used to run
        # under the backend lock, serializing every other mount callback
        # behind it. The admission decision stays under the lock; the
        # construction happens outside it; registration re-validates under
        # the lock and retries the whole admission if the path moved
        # meanwhile (another description won the same path, a directory
        # rename landed, the local inode changed).
        for _attempt in range(3):
            outcome = self._open_admitted_locked(path, flags, create=create)
            if isinstance(outcome, int):
                try:
                    self._pin_read_handle(outcome)
                except BaseException:
                    self._release_handle(outcome)
                    raise
                return outcome
            remote, pending = outcome
            session = self._construct_write_session(pending, flags)
            with self._lock:
                if (
                    self._sessions.get(remote) is None
                    and not self._closed
                    and not self._path_has_pending_directory_mutation(remote)
                    and self._local_fingerprint(remote) == pending.existing_local
                ):
                    self._sessions[remote] = session
                    self._register_new_session_locked(remote, pending)
                    return self._new_handle(session)
            session.abort()
        raise OSError(errno.EAGAIN, "The mounted file is being opened concurrently; retry.")

    def _pin_read_handle(self, handle: int) -> tuple[_FileView | None, FabricFileVersion | None]:
        # Holding the backend lock across control-plane IO would serialize
        # every file behind OPEN. Acquire outside it, then bind only to the
        # exact description still registered after the request completes.
        for _ in range(3):
            with self._lock:
                opened = self._handles.get(handle)
                if opened is None:
                    raise OSError(errno.EBADF, "The mounted handle is closed.")
                if not isinstance(opened, _ReadHandle):
                    return None, None
                view, previous = opened.view, opened.version
                if view.session is not None or view.local_fingerprint is not None:
                    if previous is not None:
                        self.coordinator.release_file_version(previous)
                        opened.version = None
                    return view, None
                if (previous is not None and previous.entry.digest == view.digest
                        and previous.entry.size_bytes == view.size_bytes):
                    return view, previous
            attempted_path = None
            try:
                if view.native_tree is not None:
                    candidate = self.coordinator.open_native_file_version(view.remote_path, *view.native_tree,
                        expected_digest=view.digest, expected_size=view.size_bytes)
                else:
                    attempted_path = self._remote_view_path(view)
                    candidate = self.coordinator.open_file_version(
                        attempted_path, expected_digest=view.digest,
                        expected_size=view.size_bytes,
                    )
            except (OSError, RemoteError) as error:
                # Safe-save can pin this reader to the old private inode while
                # the unlocked version lookup still uses its former pathname.
                # Retry only that exact handle transition, never an unchanged
                # stale remote version or an unrelated I/O failure.
                with self._lock:
                    stale_version = (
                        isinstance(error, OSError) and error.errno == errno.ESTALE
                        or isinstance(error, RemoteError) and error.status == 409
                        and error.remote_code == "FABRIC_FILE_HOLD_VERSION_STALE"
                    )
                    if (stale_version
                            and self._handles.get(handle) is opened
                            and opened.view is not view):
                        continue
                    if (stale_version and self._handles.get(handle) is opened
                            and opened.view is view and view.remote_source_path is not None
                            and view.remote_source_path != view.remote_path):
                        # A pending metadata rename exposes the source's exact
                        # version at its new name. Its ACK can consume the old
                        # path between our entry snapshot and hold acquisition.
                        # Follow only that same digest/size to the destination;
                        # an unrelated successor must still fail stale.
                        self._epoch_overlay = _UNSET
                        current = self._file_view(view.remote_path)
                        if (current is not None and current.digest == view.digest
                                and current.size_bytes == view.size_bytes
                                and attempted_path is not None
                                and self._remote_view_path(current) != attempted_path):
                            opened.view = current
                            continue
                raise
            with self._lock:
                if (self._handles.get(handle) is opened and opened.view is view
                        and opened.version is previous):
                    opened.version = candidate
                    if previous is not None:
                        self.coordinator.release_file_version(previous)
                    return view, candidate
            if candidate is not None:
                self.coordinator.release_file_version(candidate)
        raise OSError(errno.ESTALE, "The mounted file changed while retaining its version.")

    def _construct_write_session(
        self, pending: "_PendingWriteSession", flags: int
    ) -> "_MountWriteSession":
        factory = getattr(self.coordinator, "open_native_journal", None)
        native = (factory(pending.remote, expected_digest=pending.base_digest,
            expected_size=pending.base_size_bytes, discard_source=bool(flags & os.O_TRUNC))
            if callable(factory) and pending.existing_local is None
            and not pending.created and not flags & os.O_TRUNC else None)
        try:
            session = _MountWriteSession(
                self.workspace,
                pending.remote,
                base_digest=pending.base_digest,
                expected_existing_fingerprint=(None if pending.renamed_source else pending.existing_local),
                pristine_view=pending.pristine_view if not flags & os.O_TRUNC else None,
                created=pending.created,
                stage_capacity=self._stage_capacity,
                remote_quota=self._remote_quota,
                base_size_bytes=pending.base_size_bytes,
                logger=self.logger,
                transport_provenance=pending.transport_provenance,
                tree_journal=native.journal if native is not None else None,
                tree_mutation=native.mutate if native is not None else None,
                tree_release=native.release_later if native is not None else None,
            )
            try:
                if flags & os.O_TRUNC:
                    session.prepare_empty_mutation()
            except BaseException:
                session.abort()
                raise
            return session
        finally:
            if native is not None:
                native.finish_construction()

    def _register_new_session_locked(
        self, remote: str, pending: "_PendingWriteSession"
    ) -> None:
        session = self._sessions[remote]
        if session.modified:
            self._bind_in_place_readers_locked(session, pending.pristine_view)
        if pending.sidecar_key is not None and pending.transport_provenance is not None:
            self._smb_copy_pair_evidence.pop(pending.sidecar_key, None)
        if self._fuse_t_smb_transport and pending.created:
            data_key = _smb_copy_pair_key(remote, appledouble=False)
            if data_key is not None:
                self._remember_smb_copy_pair_locked(data_key)

    def _open_admitted_locked(
        self, path: str, flags: int, *, create: bool = False
    ) -> "int | tuple[str, _PendingWriteSession]":
        """Admit an open under the lock; a new write session is returned as a plan."""

        remote = self._remote_path(path)
        assert remote is not None
        writable = bool(flags & (os.O_WRONLY | os.O_RDWR))
        if writable:
            self._remote_quota.refresh_pending()
        with self._lock:
            if writable:
                self._await_directory_mutation_locked(remote)
            self._require_parent_directory(remote)
            view = self._file_view(remote)
            if (
                view is None
                and not self._path_hidden_by_removed_directory(remote)
                and self.database.is_remote_directory(remote)
            ):
                raise OSError(errno.EISDIR, "The mounted item is a directory.")
            if flags & os.O_EXCL and flags & os.O_CREAT and view is not None:
                raise OSError(errno.EEXIST, "The mounted file already exists.")
            if not writable:
                if view is None:
                    raise OSError(errno.ENOENT, "The mounted file does not exist.")
                handle = self._new_handle(_ReadHandle(view))
                self._note_access(view.remote_path)
                if view.session is None and view.local_fingerprint is None and view.native_tree is None:
                    self._warm_remote_read(view.remote_path)
                return handle
            existing = self._sessions.get(remote)
            if (existing is not None and existing.cancelled and existing.journaled
                    and flags & os.O_CREAT
                    and self._session_has_open_handle(existing)
                    and self._remove_cancelled_visible_preimage(
                        existing, tracked_handles_closed=False)):
                # Its terminal receipt and open private descriptor belong to
                # the old inode; a fresh create may own this pathname now.
                self._sessions.pop(remote, None)
                existing = None
            if existing is not None and existing.publishing:
                # Finder re-opens a file right after CLOSE (sidecar, attributes,
                # a second copy pass) while its bytes are being published.
                # Wait for the journal receipt instead of answering EBUSY.
                existing = self._wait_for_publication_locked(remote, existing)
                view = self._file_view(remote)
            if existing is not None:
                # SMB can reopen one copy/temp inode several times before its
                # first description closes, and can close/reopen an AppleDouble
                # sidecar during the short pre-publication settle window. Share
                # only the exact pre-journal session. Publication, journaling,
                # and retry ownership remain hard generation fences.
                if (
                    existing.published
                    and not existing.publishing
                    and not existing.journaled
                    and not existing.delete_pending
                    and not existing.cancelled
                    and not existing.failed_mutation
                ):
                    # The stage replaced the visible inode but its journal
                    # never landed, so only a backoff retry timer owns it and
                    # no durable receipt exists. Fencing here made every
                    # re-copy of that path fail for the whole retry window (up
                    # to MOUNT_PUBLISH_MAX_RETRY_SECONDS), which macOS SMB
                    # reports to Finder as a permission error. The caller is
                    # overwriting the path, so retire the superseded attempt
                    # and let a fresh description own the new bytes; nothing
                    # with a receipt is ever discarded here.
                    self._retire_superseded_session_locked(remote, existing)
                    existing = None
            if existing is not None:
                if (
                    existing.published
                    or existing.publishing
                    or existing.journaled
                    or existing.delete_pending
                    or existing.cancelled
                    or existing.failed_mutation
                ):
                    raise OSError(
                        errno.EBUSY,
                        "The mounted file is closing or reconciling.",
                    )
                # A publish that failed only arms a backoff retry timer; the
                # stage is intact, unpublished, and still mount-owned. Fencing
                # a new description on ``publish_failures`` alone made every
                # re-copy of that path fail for the whole backoff window (up to
                # MOUNT_PUBLISH_MAX_RETRY_SECONDS), which macOS SMB surfaces to
                # Finder as a permission error. The fresh bytes supersede the
                # pending ones, so reclaim the session below and let its
                # cancelled timer be replaced by the new close receipt. The
                # hard generation fences above still apply.
                if existing.sealed:
                    # release() seals the last description and arms exactly one
                    # settle timer. Keep that timer live until the marker has
                    # transactionally returned to ``open``: on any failure the
                    # old close receipt therefore still has a publisher. The
                    # backend lock also makes the timer callback and this
                    # downgrade mutually exclusive.
                    publish_timer = self._timers.get(remote)
                    if publish_timer is None:
                        raise OSError(
                            errno.EBUSY,
                            "The mounted file is closing or reconciling.",
                        )
                    existing.reopen_before_publish()
                    self._timers.pop(remote, None)
                    publish_timer.cancel()
                else:
                    flush_timer = self._flush_timers.pop(remote, None)
                    if flush_timer is not None:
                        flush_timer.cancel()
                # The reclaimed description owns publication again, so the
                # superseded attempt's backoff must not compound into the next
                # retry delay.
                existing.publish_failures = 0
                handle = self._new_handle(existing)
                try:
                    if flags & os.O_TRUNC:
                        before = self._session_read_view(existing)
                        existing.prepare_empty_mutation()
                        self._bind_in_place_readers_locked(existing, before)
                except BaseException:
                    self._handles.pop(handle, None)
                    raise
                return handle
            if view is None and not (create or flags & os.O_CREAT):
                raise OSError(errno.ENOENT, "The mounted file does not exist.")
            self._wait_for_write_session_slot_locked(reason="write-session")
            view = self._file_view(remote)
            base_digest = view.digest if view is not None else None
            existing_local = self._local_fingerprint(remote)
            remote_entry = self._resolve_remote_entry(remote) if view is None else None
            # The admission still rechecks the current local fingerprint.
            # Publication of a recreated name requires absence instead: the
            # old rename owns removal of its clean cache in the meantime.
            renamed_source = remote_entry is not None and self._rename_source_is_hidden(remote, remote_entry)
            sidecar_key = (
                _smb_copy_pair_key(remote, appledouble=True)
                if self._fuse_t_smb_transport and view is None
                else None
            )
            transport_provenance = (
                _FUSE_T_SMB_APPLEDOUBLE_PROVENANCE
                if sidecar_key is not None
                and self._has_fresh_smb_copy_pair_locked(sidecar_key)
                else None
            )
            return remote, _PendingWriteSession(
                remote=remote,
                base_digest=base_digest,
                existing_local=existing_local,
                pristine_view=view,
                created=view is None,
                base_size_bytes=view.size_bytes if view is not None else 0,
                sidecar_key=sidecar_key,
                transport_provenance=transport_provenance,
                renamed_source=renamed_source,
            )

    def _preserve_quarantine(self, descriptor: int, pristine: _FileView) -> None:
        if sys.platform != "darwin" or pristine.local_fingerprint is None:
            return

        def read_pinned(source_descriptor: int) -> tuple[bytes, FileFingerprint]:
            value = _darwin_get_quarantine_xattr(source_descriptor)
            return value, _descriptor_fingerprint(source_descriptor)

        try:
            value, current = self.workspace.with_regular_file_descriptor(
                pristine.remote_path,
                read_pinned,
            )
        except OSError as error:
            if error.errno == _ENOATTR:
                return
            raise
        if current != pristine.local_fingerprint:
            raise OSError(
                errno.ESTALE,
                "The local mounted file changed before metadata preservation.",
            )
        _darwin_set_quarantine_xattr(descriptor, value)

    def _ensure_session_seeded(self, session: _MountWriteSession) -> None:
        session.seed_from(
            self._stream_view,
            after_seed=self._preserve_quarantine,
        )

    @staticmethod
    def _session_read_view(session: _MountWriteSession) -> _FileView:
        if session.anonymous_writable:
            info = os.fstat(session.descriptor)
            return _FileView(session.remote_path, info.st_size, None,
                             info.st_mtime_ns, session=session)
        pristine = session.pristine_read_view()
        if pristine is not None:
            return pristine
        return _FileView(
            session.remote_path,
            session.size(),
            None,
            time.time_ns(),
            session=session,
        )

    def _bind_in_place_readers_locked(
        self, session: _MountWriteSession, before: _FileView | None
    ) -> None:
        """Keep descriptions of the edited inode on its mutable local bytes.

        A pristine reader can otherwise return the old immutable content after
        pwrite, refilling Linux's shared page cache with stale bytes even for the
        writer. Match the exact preimage; renamed/replaced descriptions retain
        their separately owned session or version.
        """
        if before is None or not session.modified:
            return
        for opened in self._handles.values():
            if not isinstance(opened, _ReadHandle):
                continue
            view = opened.view
            if view.session is not None:
                continue
            if (view.remote_path, view.size_bytes, view.digest, view.local_fingerprint, view.native_tree) != (
                before.remote_path, before.size_bytes, before.digest, before.local_fingerprint, before.native_tree
            ):
                continue
            opened.view = session.staged_read_view()
            if opened.version is not None:
                self.coordinator.release_file_version(opened.version)
                opened.version = None

    def _stream_view(self, view: _FileView, length: int | None = None) -> Iterator[bytes]:
        requested_size = view.size_bytes if length is None else length
        if type(requested_size) is not int or not 0 <= requested_size <= view.size_bytes:
            raise ValueError("The mounted seed prefix exceeds the source file.")
        if view.native_tree is not None:
            version = self.coordinator.open_native_file_version(view.remote_path,
                *view.native_tree, expected_digest=view.digest, expected_size=view.size_bytes)
            try:
                yield from version.stream(0, requested_size)
            finally:
                self.coordinator.release_file_version(version)
            return
        if view.session is not None:
            offset = 0
            while offset < requested_size:
                chunk = view.session.read(
                    offset, min(MOUNT_IO_BYTES, requested_size - offset)
                )
                if not chunk:
                    raise OSError(errno.EIO, "The mounted stage ended early.")
                offset += len(chunk)
                yield chunk
            return
        if view.local_fingerprint is not None:
            offset = 0
            while offset < requested_size:
                chunk = self.workspace.read_regular_range(
                    view.remote_path,
                    offset,
                    min(MOUNT_IO_BYTES, requested_size - offset),
                    view.local_fingerprint,
                )
                if not chunk:
                    raise OSError(errno.EIO, "The local mounted file ended early.")
                offset += len(chunk)
                yield chunk
            return
        source = self._remote_view_path(view)
        entry = self._resolve_remote_entry(source)
        if entry is None or entry.digest != view.digest or entry.size_bytes != view.size_bytes:
            raise OSError(errno.ESTALE, "The remote file advanced while it was opened for writing.")
        version = self.coordinator.open_file_version(source, expected_digest=view.digest,
                                                      expected_size=view.size_bytes)
        if version is not None:
            try:
                yield from version.stream(0, requested_size)
            finally:
                self.coordinator.release_file_version(version)
            return
        try:
            tree_reader = None
            if file_digest_algorithm(entry.blocks) == FABRIC_FILE_TREE_ALGORITHM:
                head = self.database.get_remote_manifest_head()
                if head is None:
                    raise OSError(errno.ESTALE, "The remote tree lost its manifest head.")
                tree_reader = self.coordinator._tree_reader(entry, head)
            # Partial reads already carry verified range receipts (and tree
            # ancestry) through the coordinator. A whole-file digest cannot be
            # recomputed from a prefix without downloading the discarded tail.
            digest = (FabricFileHasher(entry.blocks, tree_source=tree_reader)
                      if requested_size == view.size_bytes else None)
        except ValueError as error:
            raise OSError(errno.ESTALE, "The remote file has an invalid block identity.") from error
        streamed = 0
        chunks = (tree_reader.stream(0, requested_size) if tree_reader is not None else
            self.coordinator.stream(source, offset=0, length=requested_size))
        for chunk in chunks:
            if not isinstance(chunk, bytes) or streamed + len(chunk) > requested_size:
                raise OSError(errno.EIO, "The mounted seed exceeded its requested range.")
            try:
                if digest is not None:
                    digest.update(chunk)
            except ValueError as error:
                raise OSError(errno.ESTALE, "The remote file failed block verification.") from error
            streamed += len(chunk)
            yield chunk
        self._remote_view_path(view)
        try:
            verified_digest = digest.hexdigest() if digest is not None else view.digest
        except ValueError as error:
            raise OSError(errno.ESTALE, "The remote file failed block verification.") from error
        if (
            streamed != requested_size
            or view.digest is None
            or verified_digest != view.digest
        ):
            raise OSError(
                errno.ESTALE,
                "The remote file advanced while it was opened for writing.",
            )

    def _remote_view_path(self, view: _FileView) -> str:
        """Resolve a pinned read through either side of an in-flight rename."""

        candidates = (view.remote_source_path, view.remote_path)
        for candidate in dict.fromkeys(candidates):
            if candidate is None:
                continue
            current = self._resolve_remote_entry(candidate)
            if (
                current is not None
                and view.digest is not None
                and current.digest == view.digest
                and current.size_bytes == view.size_bytes
            ):
                return candidate
        raise OSError(errno.ESTALE, "The remote file advanced while it was open.")

    def _read_local_view(self, view: _FileView, offset: int, count: int) -> bytes:
        assert view.local_fingerprint is not None
        for candidate in dict.fromkeys((view.remote_path, view.remote_source_path)):
            if candidate is None:
                continue
            if self._local_fingerprint(candidate) == view.local_fingerprint:
                return self.workspace.read_regular_range(
                    candidate, offset, count, view.local_fingerprint
                )
        raise OSError(errno.ESTALE, "The local file moved or changed while it was open.")

    def _reload_read_view(self, handle: int, opened_identity: _FileView) -> _FileView:
        """Reload a handle retargeted while one range read was in flight."""

        with self._lock:
            opened = self._handles.get(handle)
            if isinstance(opened, _ReadHandle):
                refreshed = opened.view
            elif isinstance(opened, _MountWriteSession):
                refreshed = self._session_read_view(opened)
            else:
                raise OSError(errno.EBADF, "The mounted handle is closed.")
        if (
            refreshed.size_bytes != opened_identity.size_bytes
            or refreshed.digest != opened_identity.digest
            or refreshed.local_fingerprint != opened_identity.local_fingerprint
        ):
            raise OSError(errno.ESTALE, "The mounted file changed while it was open.")
        return refreshed

    def read(self, handle: int, offset: int, size: int) -> bytes:
        if offset < 0 or not 0 <= size <= MAX_MOUNT_READ_BYTES:
            raise OSError(errno.EINVAL, "The mounted read range is invalid.")
        # Take syscall ownership atomically with the descriptor lookup. CLOSE
        # may remove the handle before this thread enters the range iterator;
        # the read which already entered must still finish on its own version.
        with ExitStack() as ownership:
            version = None
            session_view = None
            retired_local = None
            with self._lock:
                opened = self._handles.get(handle)
                if isinstance(opened, _ReadHandle) and opened.retired_local is not None:
                    pinned = opened.retired_local
                    descriptor = os.dup(pinned.descriptor)
                    ownership.callback(os.close, descriptor)
                    retired_local = descriptor, pinned
                candidate_view = (opened.view if isinstance(opened, _ReadHandle)
                    else self._session_read_view(opened) if isinstance(opened, _MountWriteSession)
                    else None)
                session = candidate_view.session if candidate_view is not None else None
                if session is not None:
                    ownership.enter_context(session.reading())
                    session_view = self._session_read_view(session)
                if (not self._fuse_t_smb_transport and isinstance(opened, _ReadHandle)
                        and opened.version is not None and opened.view.session is None
                        and opened.view.local_fingerprint is None
                        and opened.version.entry.digest == opened.view.digest
                        and opened.version.entry.size_bytes == opened.view.size_bytes):
                    version = opened.version
                    ownership.enter_context(version.pool.reading(version))
            if retired_local is not None:
                descriptor, pinned = retired_local
                identity = pinned.identity

                def unchanged() -> bool:
                    info = os.fstat(descriptor)
                    return (stat.S_ISREG(info.st_mode)
                        and info.st_dev == identity.device_id and info.st_ino == identity.file_id
                        and info.st_size == identity.size_bytes and info.st_mtime_ns == identity.mtime_ns)

                # Rename/unlink legitimately changes ctime and link count.
                # A write through any other descriptor still invalidates this
                # retained preimage, before or during the bounded range read.
                with pinned.lock:
                    if not unchanged():
                        raise OSError(errno.ESTALE, "The replaced file changed while open.")
                    data = _portable_pread(descriptor, min(size, max(0, identity.size_bytes - offset)), offset)
                    if not unchanged():
                        raise OSError(errno.ESTALE, "The replaced file changed during read.")
                return data
            if session_view is not None:
                return (session.read(offset, min(size, session_view.size_bytes - offset))
                    if offset < session_view.size_bytes else b"")
            if version is not None:
                return b"".join(version.stream(offset, min(size, version.entry.size_bytes - offset))) if offset < version.entry.size_bytes else b""
        # SMB shares descriptions across macOS opens and uses pathname-current
        # stat sizes. A stale read poisons the vnode (subsequent CLOSE gets
        # EACCES), so retry a replacement with the current complete version.
        for attempt in range(3):
            try:
                return self._read_once(handle, offset, size)
            except OSError as error:
                if not self._fuse_t_smb_transport or error.errno != errno.ESTALE or attempt == 2:
                    raise
        raise AssertionError("unreachable")

    def _read_once(self, handle: int, offset: int, size: int) -> bytes:
        if offset < 0 or not 0 <= size <= MAX_MOUNT_READ_BYTES:
            raise OSError(errno.EINVAL, "The mounted read range is invalid.")
        with self._lock:
            opened = self._handles.get(handle)
            if opened is None:
                raise OSError(errno.EBADF, "The mounted handle is closed.")
            view = (
                opened.view
                if isinstance(opened, _ReadHandle)
                else self._session_read_view(opened)
            )
            if self._fuse_t_smb_transport and view.session is None and view.digest is not None:
                current = self._resolve_remote_entry(view.remote_path)
                if current is not None and current.digest != view.digest:
                    latest = self._file_view(view.remote_path)
                    if latest is not None and latest.digest == current.digest:
                        view = latest
                        if isinstance(opened, _ReadHandle):
                            opened.view = view
        version = None
        if isinstance(opened, _ReadHandle):
            view, version = self._pin_read_handle(handle)
        if offset >= view.size_bytes:
            return b""
        count = min(size, view.size_bytes - offset)
        if version is not None:
            return b"".join(version.stream(offset, count))
        opened_identity = view
        if view.session is not None:
            return view.session.read(offset, count)
        if view.local_fingerprint is not None:
            for attempt in range(2):
                try:
                    return self._read_local_view(view, offset, count)
                except (InvalidTask, OSError, UnsafePath):
                    if attempt != 0:
                        raise
                    view = self._reload_read_view(handle, opened_identity)
                    if view.session is not None:
                        return view.session.read(offset, count)
        for attempt in range(2):
            try:
                source = self._remote_view_path(view)
                data = bytearray()
                for chunk in self.coordinator.stream(
                    source, offset=offset, length=count
                ):
                    if len(data) + len(chunk) > count:
                        raise OSError(
                            errno.EIO,
                            "The Fabric range exceeded its requested bound.",
                        )
                    data.extend(chunk)
                if len(data) != count:
                    raise OSError(errno.EIO, "The Fabric range ended early.")
                # The coordinator resolves metadata lazily when its iterator advances.
                # Recheck after buffering. An atomic prefix move is allowed only when
                # the pinned digest is now present at the logical destination.
                self._remote_view_path(view)
                return bytes(data)
            except (InvalidTask, StateError, OSError):
                if attempt != 0:
                    raise
                view = self._reload_read_view(handle, opened_identity)
                if view.session is not None:
                    return view.session.read(offset, count)
        raise OSError(errno.ESTALE, "The remote file moved during its range read.")

    def write(self, handle: int, offset: int, data: bytes) -> int:
        with self._lock:
            opened = self._handles.get(handle)
            if not isinstance(opened, _MountWriteSession):
                raise OSError(errno.EBADF, "The mounted handle is not writable.")
            if opened.cancelled or opened.detached:
                return opened.write_anonymous(offset, data)
            before = self._session_read_view(opened) if data else None
            # A zero-byte POSIX write is a true no-op. Preserve an already
            # armed SMB close fence; only a real byte mutation reopens it.
            if data:
                self._flushed_write_handles.discard(handle)
                timer = self._flush_timers.pop(opened.remote_path, None)
                if timer is not None:
                    timer.cancel()
        written = opened.write_from(
            offset,
            data,
            self._stream_view,
            after_seed=self._preserve_quarantine,
        )
        if written:
            with self._lock:
                self._bind_in_place_readers_locked(opened, before)
        return written

    def command_write(
        self,
        path: str,
        data: bytes,
        expected_sha256: str | None = None,
        create_parents: bool = False,
    ) -> dict[str, Any]:
        """Replace through this mount's owner, acknowledging local durability only.

        The path admission fence excludes new opens, renames and remote cleanup;
        existing writable descriptions retain ownership and are never superseded.
        Remote-only CAS uses manifest metadata, while pending local bytes are
        hashed through the ordinary fingerprint-fenced reader (without hydration).
        """
        if not isinstance(data, bytes) or not isinstance(create_parents, bool):
            raise OSError(errno.EINVAL, "Invalid command write payload.")
        if expected_sha256 is not None and (
            not isinstance(expected_sha256, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", expected_sha256) is None
        ):
            raise OSError(errno.EINVAL, "Invalid expected SHA-256 digest.")
        remote = self._remote_path(path)
        assert remote is not None
        new_digest = hashlib.sha256(data).hexdigest()
        receipt = {
            "path": self._virtual_path(remote),
            "sha256": new_digest,
            "size_bytes": len(data),
            "mutation_id": None,
            "publication": "unchanged",
        }
        with self._cleanup_path_admission(remote):
            with self._lock:
                existing = self._sessions.get(remote)
                if existing is not None and self._session_has_open_writer(existing):
                    raise OSError(errno.EBUSY, "A mounted writer owns this file.")
            # Close-time settle is not a second writer. Hand its bytes to the
            # existing journal before comparing or superseding that generation.
            self._publish_path(remote)
            with self._lock:
                existing = self._sessions.get(remote)
                if existing is not None and existing.publishing:
                    existing = self._wait_for_publication_locked(remote, existing)
                if existing is not None:
                    raise OSError(errno.EBUSY, "The mounted file is reconciling.")
                view = self._file_view(remote)
            if expected_sha256 is not None:
                current_digest = None
                if view is not None:
                    if view.local_fingerprint is None and view.session is None:
                        self._remote_view_path(view)
                        current_digest = view.digest
                    else:
                        digest = hashlib.sha256()
                        for chunk in self._stream_view(view):
                            digest.update(chunk)
                        current_digest = digest.hexdigest()
                if current_digest != expected_sha256.removeprefix("sha256:"):
                    raise OSError(errno.ESTALE, "The file changed before command write.")
            if (
                view is not None
                and view.local_fingerprint is None
                and view.digest == new_digest
                and self.database.get_latest_nonterminal_operation(remote) is None
                and self.database.get_local_transfer_intent(remote) is None
            ):
                self._remote_view_path(view)
                return receipt
            if create_parents:
                parts = remote.split("/")[:-1]
                for index in range(1, len(parts) + 1):
                    parent = self._virtual_path("/".join(parts[:index]))
                    try:
                        self.mkdir(parent)
                    except OSError as error:
                        if error.errno != errno.EEXIST:
                            raise
                        if not self.getattr(parent).is_directory:
                            raise OSError(errno.ENOTDIR, "A parent is not a directory.")
            handle = self.open(path, os.O_RDWR | os.O_CREAT, create=True)
            with self._lock:
                session = self._handles[handle]
                assert isinstance(session, _MountWriteSession)
            try:
                if expected_sha256 is not None and view is not None:
                    if view.local_fingerprint is None and view.session is None:
                        self._remote_view_path(view)
                    elif self._local_fingerprint(remote) != view.local_fingerprint:
                        raise OSError(
                            errno.ESTALE, "The local file changed before command write."
                        )
                    # Never adopt a newer base observed while opening the stage.
                    # A later remote advance must conflict at the normal PUT CAS.
                    session.base_digest = view.digest
                # Typed command bytes are user data, never inferred SMB scratch
                # metadata. The next mutation marker persists this provenance.
                with session._lock:
                    session.transport_provenance = None
                self.truncate(path, 0, handle=handle)
                self.write(handle, 0, data)
                self.fsync(handle)
            except BaseException:
                # In particular, a remote deletion can make open(O_CREAT)
                # create a pristine stage before the second CAS check fails.
                # Never release that rejected stage as an empty-file mutation.
                session.failed_mutation = True
                raise
            finally:
                self.release(handle)
            self._publish_path(remote)
            with self._lock:
                if session.publishing:
                    self._wait_for_publication_locked(remote, session)
                if not session.journaled:
                    # Failed publication retains its crash receipt and retry;
                    # it is not evidence of either remote or journal success.
                    raise OSError(
                        errno.EAGAIN, "Command write is awaiting its durable journal."
                    )
            if self._session_write_is_durably_owned(session) is True:
                return {
                    **receipt,
                    "mutation_id": session.mutation_id,
                    "publication": "journaled",
                }
            # The coordinator may elide an identical PUT, or finish it before
            # this readback. Never invent a mutation receipt for that outcome.
            current = self.database.get_remote_entry(remote)
            if (
                current is not None
                and current.digest == new_digest
                and current.size_bytes == len(data)
                and self.database.get_latest_nonterminal_operation(remote) is None
                and self.database.get_local_transfer_intent(remote) is None
            ):
                return receipt
            raise OSError(errno.EAGAIN, "Command write durability could not be verified.")

    def truncate(self, path: str | None, length: int, *, handle: int | None = None) -> None:
        temporary_handle: int | None = None
        with self._lock:
            session: _MountWriteSession | None = None
            if handle is not None:
                value = self._handles.get(handle)
                session = value if isinstance(value, _MountWriteSession) else None
                if session is None:
                    raise OSError(errno.EBADF, "The mounted handle is not writable.")
                if session is not None:
                    if session.cancelled or session.detached:
                        session.truncate_anonymous(length)
                        return
                    self._flushed_write_handles.discard(handle)
            if session is None:
                if path is None:
                    raise OSError(errno.EBADF, "The mounted handle is unavailable.")
                remote = self._remote_path(path)
                assert remote is not None
                existing = self._sessions.get(remote)
                if existing is None:
                    temporary_handle = self.open(path, os.O_RDWR)
                    value = self._handles[temporary_handle]
                    assert isinstance(value, _MountWriteSession)
                    session = value
                else:
                    session = existing
                    self._flushed_write_handles.difference_update(
                        candidate
                        for candidate, opened in self._handles.items()
                        if opened is session
                    )
            timer = self._flush_timers.pop(session.remote_path, None)
            if timer is not None:
                timer.cancel()
            before = self._session_read_view(session)
        try:
            if length == 0:
                session.prepare_empty_mutation()
            else:
                session.truncate_from(
                    length,
                    self._stream_view,
                    after_seed=self._preserve_quarantine,
                )
            with self._lock:
                self._bind_in_place_readers_locked(session, before)
        finally:
            if temporary_handle is not None:
                self.release(temporary_handle)

    def fsync(self, handle: int) -> None:
        with self._lock:
            value = self._handles.get(handle)
            if isinstance(value, _MountWriteSession):
                try:
                    value.fsync()
                except BaseException:
                    # A prior SMB FLUSH may already have armed close-time
                    # publication. A client-visible data-fsync failure fences
                    # that exact session before the timer can seal it.
                    timer = (
                        self._flush_timers.pop(value.remote_path, None)
                        if self._sessions.get(value.remote_path) is value
                        else None
                    )
                    if timer is not None:
                        timer.cancel()
                    raise

    def flush(self, handle: int) -> None:
        """Publish an SMB close promptly while retaining a short write fence."""

        with self._lock:
            value = self._handles.get(handle)
            if not isinstance(value, _MountWriteSession):
                return
            if value.cancelled or value.detached:
                value.fsync()
                return
            if not value.modified:
                return
            if value.failed_mutation and not (
                value.published or value.journaled
            ):
                # release() owns exact cleanup after the native description is
                # consumed. Never turn a rejected edit into a partial or
                # zero-byte durable PUT from an advisory FLUSH.
                timer = self._flush_timers.pop(value.remote_path, None)
                if timer is not None:
                    timer.cancel()
                return
            self._flushed_write_handles.add(handle)
            if self._session_has_unflushed_writer(value):
                # A per-handle FLUSH is not a session-wide close receipt while
                # another writable SMB alias can still mutate the same inode.
                return
        # The seal fsyncs the staged bytes. That is per-session work under the
        # session's own lock; holding the backend lock across it made every
        # other mount callback wait out a disk sync per flushed file.
        try:
            value.mark_flushed()
        except BaseException:
            with self._lock:
                timer = self._flush_timers.pop(value.remote_path, None)
            if timer is not None:
                timer.cancel()
            raise
        with self._lock:
            if (
                value.journaled
                or self._handles.get(handle) is not value
                or self._sessions.get(value.remote_path) is not value
            ):
                # FUSE-T may issue another FLUSH (or a read/fsync) before the
                # matching RELEASE.  Publication must not invalidate that
                # still-open file description or enqueue the same bytes twice.
                return
            previous = self._flush_timers.pop(value.remote_path, None)
            if previous is not None:
                previous.cancel()
            timer = self._new_flush_publish_timer(value.remote_path)
            self._flush_timers[value.remote_path] = timer
            timer.start()

    def release(self, handle: int) -> None:
        try:
            self._release_handle(handle)
        finally:
            # A read-only description may be the sole reason a retained remote
            # cleanup could not reclaim its private inode. Wake the coordinator
            # immediately; the path fence will recheck all handles before
            # allowing last-link cleanup.
            wake = getattr(self.coordinator, "wake_mount_cleanup", None)
            if not callable(wake):
                wake = getattr(self.coordinator, "wake", None)
            if callable(wake):
                wake()

    def _release_handle(self, handle: int) -> None:
        finish: _MountWriteSession | None = None
        abort: _MountWriteSession | None = None
        with self._lock:
            value = self._handles.pop(handle, None)
            self._flushed_write_handles.discard(handle)
            if value is None:
                return
            if isinstance(value, _ReadHandle):
                if value.retired_local is not None:
                    os.close(value.retired_local.descriptor)
                    value.retired_local = None
                if value.version is not None:
                    self.coordinator.release_file_version(value.version)
                    value.version = None
                session = value.view.session
                if session is None or self._session_has_open_handle(session):
                    return
                if session.detached:
                    finish = session
                elif session.journaled:
                    if (
                        not session.cancelled
                        and self._sessions.get(session.remote_path) is session
                    ):
                        self._sessions.pop(session.remote_path, None)
                    finish = session
                elif self._sessions.get(session.remote_path) is not session:
                    return
                elif session.failed_mutation and not session.published:
                    self._sessions.pop(session.remote_path, None)
                    abort = session
                elif (
                    session.modified
                    and session.sealed
                    and not session.publishing
                    and session.remote_path not in self._timers
                ):
                    timer = self._new_publish_timer(
                        session.remote_path,
                        self.settle_seconds,
                    )
                    self._timers[session.remote_path] = timer
                    timer.start()
                if finish is None and abort is None:
                    return
            else:
                session = value
            if finish is None and abort is None:
                current_session = self._sessions.get(session.remote_path) is session
                if session.detached:
                    if self._session_has_open_handle(session):
                        return
                    finish = session
                elif session.journaled:
                    if not self._session_has_open_handle(session):
                        if current_session and not session.cancelled:
                            self._sessions.pop(session.remote_path, None)
                        finish = session
                elif not current_session:
                    return
                elif self._session_has_open_writer(session):
                    # The released alias can no longer change bytes, but a
                    # sibling writable description still owns the session. If
                    # all remaining writers already delivered FLUSH, arm the
                    # ordinary quiet-close fence; otherwise leave the crash
                    # marker open until their flush/release arrives.
                    if (
                        session.modified
                        and not session.failed_mutation
                        and not self._session_has_unflushed_writer(session)
                        and session.remote_path not in self._flush_timers
                    ):
                        try:
                            session.mark_flushed()
                        except BaseException:
                            timer = self._flush_timers.pop(
                                session.remote_path, None
                            )
                            if timer is not None:
                                timer.cancel()
                            raise
                        timer = self._new_flush_publish_timer(
                            session.remote_path
                        )
                        self._flush_timers[session.remote_path] = timer
                        timer.start()
                    return
                else:
                    flush_timer = self._flush_timers.pop(session.remote_path, None)
                    if flush_timer is not None:
                        flush_timer.cancel()
                if finish is not None:
                    pass
                elif session.failed_mutation and not (
                    session.published or session.journaled
                ):
                    if self._sessions.get(session.remote_path) is session:
                        self._sessions.pop(session.remote_path, None)
                    abort = session
                elif session.delete_pending:
                    # The explicit unlink receipt, not this now-anonymous SMB
                    # description, owns completion. Keep its retry timer and
                    # crash marker live; a late CLOSE must never discard the
                    # tombstone or republish the pristine stage.
                    return
                elif not session.modified:
                    if self._sessions.get(session.remote_path) is session:
                        self._sessions.pop(session.remote_path, None)
                    abort = session

                else:
                    try:
                        session.seal()
                    except BaseException as error:
                        if session.failed_mutation:
                            if self._sessions.get(session.remote_path) is session:
                                self._sessions.pop(session.remote_path, None)
                            # A failed close-time data fsync is not recoverable
                            # upload evidence. Retire it now so a retry timer or
                            # restart cannot publish an ambiguous replacement.
                            session.abort()
                            raise
                        # close(2) has consumed the native handle, but the
                        # private inode and its older crash marker still belong
                        # to this session. Retain that ownership and retry the
                        # close receipt instead of stranding an unsealed stage
                        # with neither a handle nor a timer.
                        session.flush_closed = True
                        self._schedule_flush_publish_retry_locked(session)
                        self.logger.record(
                            "fabric_mount_release_seal_failed",
                            path=session.remote_path,
                            error=str(error),
                        )
                        raise
            if abort is None and finish is None:
                if session.journaled:
                    if not self._session_has_open_handle(session):
                        if (
                            not session.cancelled
                            and self._sessions.get(session.remote_path) is session
                        ):
                            self._sessions.pop(session.remote_path, None)
                        finish = session
                elif session.publishing:
                    # The publisher owns finalization once it observes that this
                    # handle has gone away.  Scheduling another publisher here can
                    # otherwise race the same sealed stage.
                    return
                elif session.remote_path not in self._timers:
                    timer = self._new_publish_timer(
                        session.remote_path,
                        self.settle_seconds,
                    )
                    self._timers[session.remote_path] = timer
                    timer.start()
        if abort is not None:
            abort.abort()
        if finish is not None:
            if finish.cancelled:
                retired = self._retire_cancelled_session(finish)
                with self._lock:
                    if retired:
                        if self._sessions.get(finish.remote_path) is finish:
                            self._sessions.pop(finish.remote_path, None)
                    elif self._sessions.get(finish.remote_path) is finish:
                        self._schedule_publish_retry_locked(finish)
            else:
                finish.finish()

    def _schedule_flush_publish_retry_locked(
        self,
        session: _MountWriteSession,
    ) -> None:
        """Retry a failed close-receipt write without losing stage ownership."""

        session.publish_failures += 1
        if (
            self._closed
            or session.failed_mutation
            or self._sessions.get(session.remote_path) is not session
            or session.remote_path in self._flush_timers
            or session.remote_path in self._timers
        ):
            return
        base = max(self.settle_seconds, MOUNT_PUBLISH_RETRY_SECONDS)
        delay = min(
            MOUNT_PUBLISH_MAX_RETRY_SECONDS,
            base * (2 ** min(session.publish_failures - 1, 16)),
        )
        retry = self._new_flush_publish_timer(session.remote_path, delay)
        self._flush_timers[session.remote_path] = retry
        retry.start()

    def _publish_flushed_path(
        self,
        path: str,
        *,
        expected_timer: threading.Timer | None = None,
    ) -> None:
        with self._lock:
            timer = self._flush_timers.get(path)
            if expected_timer is not None and timer is not expected_timer:
                return
            timer = self._flush_timers.pop(path, None)
            if timer is not None and timer is not threading.current_thread():
                timer.cancel()
            session = self._sessions.get(path)
            if (
                session is None
                or not session.modified
                or session.failed_mutation
                or session.publishing
                or self._session_has_unflushed_writer(session)
            ):
                return
            try:
                session.flush_closed = True
                session.seal()
            except BaseException as error:
                session.flush_closed = False
                if not session.failed_mutation:
                    self._schedule_flush_publish_retry_locked(session)
                self.logger.record(
                    "fabric_mount_flush_publish_failed",
                    path=path,
                    error=str(error),
                )
                return
            session.publish_failures = 0
        self._publish_path(path)

    def _schedule_publish_retry_locked(
        self,
        session: _MountWriteSession,
        *,
        count_failure: bool = True,
        fenced: bool = False,
    ) -> None:
        """Retain one failed handoff and retry with capped exponential delay.

        ``fenced`` marks a delete the engine refused to *admit* (staging
        repair, watcher recovery, a publishing sibling) rather than one that
        failed. A fence lifts on its own and the retry then converges, so a
        fenced delete keeps its capped backoff and is never abandoned; the
        bounded budget applies only to deletes whose handoff genuinely fails.
        """

        if count_failure:
            session.publish_failures += 1
        if (
            self._closed
            or self._recovering_stages
            or session.failed_mutation
            or self._sessions.get(session.remote_path) is not session
            or session.remote_path in self._timers
        ):
            return
        if (
            session.delete_pending
            and not fenced
            and session.publish_failures >= MOUNT_DELETE_RETRY_MAX_ATTEMPTS
        ):
            # A delete whose handoff keeps failing (not merely fenced) will
            # not converge on a timer. Stop arming one: the durable
            # delete_pending marker still fences publication, still hides the
            # path from the namespace, and is replayed and re-armed on
            # restart, so the loop is abandoned without abandoning the
            # user's intent.
            self.logger.record(
                "fabric_mount_delete_retry_abandoned",
                path=session.remote_path,
                attempts=session.publish_failures,
            )
            return
        base = max(self.settle_seconds, MOUNT_PUBLISH_RETRY_SECONDS)
        delay = min(
            MOUNT_PUBLISH_MAX_RETRY_SECONDS,
            base * (2 ** min(session.publish_failures - 1, 16)),
        )
        timer = self._new_publish_timer(session.remote_path, delay)
        self._timers[session.remote_path] = timer
        timer.start()

    def _session_write_is_durably_owned(
        self,
        session: _MountWriteSession,
    ) -> bool | None:
        """Return exact durable ownership, or ``None`` when readback is unknown."""

        if session.tree_journal is not None:
            try:
                if not session.sealed or session.tree_owner is None:
                    return False
                return self.coordinator.native_tree_handoff_owned(session._document("ready"))
            except (OSError, StateError, sqlite3.Error, ValueError) as error:
                self.logger.record("fabric_mount_tree_handoff_readback_failed", path=session.remote_path,
                    mutation_id=session.mutation_id, error=str(error))
                return None
        if not session.published or session.sealed_fingerprint is None:
            return False
        try:
            operation = self.database.get_operation(session.mutation_id)
            if operation is not None:
                return bool(
                    operation.kind == "put"
                    and operation.path == session.remote_path
                    and operation.expected_source_digest == session.base_digest
                    and operation.staged_path is not None
                    and operation.staged_digest is not None
                    and operation.staged_size == session.sealed_fingerprint.size_bytes
                )
            intent = self.database.get_local_transfer_intent_by_id(
                session.mutation_id
            )
            if intent is None:
                return False
            dependency = (
                intent.delete_after_ack_path,
                intent.delete_after_ack_digest,
            )
            expected_dependency = (
                session.delete_after_ack
                if session.delete_after_ack is not None
                else (None, None)
            )
            current = self._local_fingerprint(session.remote_path)
            return bool(
                current is not None
                and intent.path == session.remote_path
                and intent.source_fingerprint == _fingerprint_text(current)
                and intent.expected_remote_digest == session.base_digest
                and dependency == expected_dependency
            )
        except (OSError, StateError, sqlite3.Error) as error:
            self.logger.record(
                "fabric_mount_publish_readback_failed",
                path=session.remote_path,
                mutation_id=session.mutation_id,
                error=str(error),
            )
            return None

    def _accept_durable_write_handoff(self, session: _MountWriteSession) -> None:
        """Retire mount ownership once its deterministic mutation is durable."""

        try:
            self._remote_quota.refresh_pending()
        except (OSError, StateError, sqlite3.Error) as error:
            # refresh_pending normally absorbs journal read errors and clears
            # its cached delta. Keep this boundary defensive: projection
            # telemetry can fail after the coordinator already durably owns
            # the mutation and must not strand the open-session reservation.
            self.logger.record(
                "fabric_mount_quota_projection_refresh_failed",
                path=session.remote_path,
                error=str(error),
            )
        finally:
            # The durable journal now contributes this mutation to pending
            # delta. Retaining its open-session reservation would double-count
            # the same growth after a successful refresh and leak capacity
            # indefinitely after a failed one. release() is idempotent with
            # finish()/abort() and preserves fail-closed pending_delta=None.
            session.release_remote_quota()
        try:
            session.retire_marker()
        except OSError as error:
            # The durable operation/transfer ID still prevents replay. Preserve
            # cleanup evidence for restart instead of scheduling another PUT.
            self.logger.record(
                "fabric_mount_journaled_marker_cleanup_failed",
                path=session.remote_path,
                marker=str(session.marker_path),
                error=str(error),
            )
        finish: _MountWriteSession | None = None
        with self._lock:
            session.publishing = False
            session.journaled = True
            session.publish_failures = 0
            still_open = self._session_has_open_handle(session)
            if self._sessions.get(session.remote_path) is session:
                self._sessions.pop(session.remote_path, None)
            if not still_open:
                finish = session
            self._publication_condition.notify_all()
        if finish is not None:
            try:
                finish.finish()
            except OSError as error:
                self.logger.record(
                    "fabric_mount_journaled_stage_cleanup_failed",
                    path=session.remote_path,
                    error=str(error),
                )

    def _publish_path(
        self,
        path: str,
        *,
        expected_timer: threading.Timer | None = None,
    ) -> None:
        discard: _MountWriteSession | None = None
        delete_published_temp = False
        retry_delete = False
        retry_cancelled_cleanup = False
        with self._lock:
            session = self._sessions.get(path)
            timer = self._timers.get(path)
            if expected_timer is not None and timer is not expected_timer:
                return
            timer = self._timers.pop(path, None)
            if timer is not None and timer is not threading.current_thread():
                timer.cancel()
            retry_delete = bool(
                session is not None
                and session.delete_pending
                and not session.cancelled
                and not session.publishing
            )
            retry_cancelled_cleanup = bool(
                session is not None
                and session.cancelled
                and session.journaled
                and not session.publishing
                and not self._session_has_open_handle(session)
            )
            if retry_cancelled_cleanup:
                assert session is not None
                session.publishing = True
            elif not retry_delete and (
                session is None
                or not session.modified
                or not session.sealed
                or session.failed_mutation
                or session.publishing
                # FUSE-T copies DATA and then named-stream xattrs while the
                # destination description remains open. Publishing here would
                # move/hash the inode before quarantine metadata arrives and
                # turns Finder's otherwise-valid copy into error -36.
                or (
                    self._session_has_open_writer(session)
                    and not session.flush_closed
                )
                # A merely published marker still needs its durable handoff,
                # but a journaled session must never enqueue the bytes twice.
                or session.journaled
                or session.delete_pending
                or session.cancelled
            ):
                return
            if (
                not retry_delete
                and not retry_cancelled_cleanup
                and self._transport_appledouble_discardable(session)
            ):
                if self._appledouble_discard_deferred_locked(session):
                    return
                if session.published:
                    # An older runtime may have crashed after moving this
                    # scratch inode into the visible namespace. Route that
                    # state through the ordinary durable delete path, which
                    # also supersedes any pre-commit PUT using the same path.
                    delete_published_temp = True
                else:
                    try:
                        # Persist cancellation before removing ownership from
                        # the backend. Recovery can then discard the stage
                        # after any process crash; it can never replay this
                        # scratch file as a workspace PUT.
                        session.mark_cancelled()
                    except BaseException as error:
                        self._schedule_publish_retry_locked(session)
                        self._publication_condition.notify_all()
                        self.logger.record(
                            "fabric_mount_smb_appledouble_cancel_failed",
                            path=session.remote_path,
                            error=str(error),
                        )
                        return
                    session.journaled = True
                    session.publish_failures = 0
                    self._sessions.pop(session.remote_path, None)
                    if not self._session_has_open_handle(session):
                        discard = session
                    self._publication_condition.notify_all()
            elif not retry_delete and not retry_cancelled_cleanup:
                session.publishing = True
        if retry_cancelled_cleanup:
            assert session is not None
            retired = self._retire_cancelled_session(session)
            with self._lock:
                session.publishing = False
                if retired:
                    session.publish_failures = 0
                    if self._sessions.get(path) is session:
                        self._sessions.pop(path, None)
                elif self._sessions.get(path) is session:
                    self._schedule_publish_retry_locked(session)
                self._publication_condition.notify_all()
            return
        if retry_delete:
            assert session is not None
            try:
                self.unlink(self._virtual_path(session.remote_path))
            except (FabricMountError, OSError, StateError, sqlite3.Error) as error:
                if isinstance(error, OSError) and error.errno == errno.ENOENT:
                    # Deleting what is already absent is the delete's own
                    # result, not a failure. Retrying it can never converge:
                    # every attempt re-reads the same missing path and
                    # reschedules, which is how one SMB sidecar
                    # (``._.Trashes``) held a timer forever at the retry cap.
                    self._retire_satisfied_delete(session)
                    return
                with self._lock:
                    if (
                        self._sessions.get(session.remote_path) is session
                        and session.delete_pending
                        and not session.cancelled
                    ):
                        session.publishing = False
                        self._schedule_publish_retry_locked(session)
                    self._publication_condition.notify_all()
                self.logger.record(
                    "fabric_mount_delete_retry_failed",
                    path=session.remote_path,
                    error=str(error),
                )
            return
        if delete_published_temp:
            try:
                self.unlink(self._virtual_path(session.remote_path))
            except (FabricMountError, OSError, StateError, sqlite3.Error) as error:
                with self._lock:
                    if (
                        self._sessions.get(session.remote_path) is session
                        and not session.delete_pending
                    ):
                        self._schedule_publish_retry_locked(session)
                    self._publication_condition.notify_all()
                self.logger.record(
                    "fabric_mount_smb_appledouble_published_cleanup_failed",
                    path=session.remote_path,
                    error=str(error),
                )
            return
        if discard is not None:
            try:
                discard.finish()
            except OSError as error:
                self.logger.record(
                    "fabric_mount_smb_appledouble_stage_cleanup_failed",
                    path=discard.remote_path,
                    error=str(error),
                )
            else:
                self.logger.record(
                    "fabric_mount_smb_appledouble_temp_discarded",
                    path=discard.remote_path,
                )
            return
        if session.journaled:
            # A cancelled scratch session may still have an SMB description
            # open. Its final RELEASE owns private-inode cleanup; there is no
            # namespace publication or remote mutation to perform here.
            return
        if session.tree_journal is not None and self._session_write_is_durably_owned(session) is True:
            # Recovery may reach a proven ACK after normal stage pruning.
            # Its exact receipt owns the bytes; no upload plan is required.
            self._accept_durable_write_handoff(session)
            return
        try:
            with self._lock:
                remote_entry = self._resolve_remote_entry(session.remote_path)
                if (
                    session.created and session.base_digest is None
                    and remote_entry is not None
                    and self._rename_source_is_hidden(session.remote_path, remote_entry)
                ):
                    # Wait until the destination ACK has queued the exact
                    # source DELETE. The existing path dependency then orders
                    # this new PUT after deletion and rebases its CAS to absent.
                    # Private bytes remain readable throughout this handoff.
                    raise StagingRepairPending("The renamed source deletion is not journaled yet.")

            def publish_local_namespace() -> None:
                if not session.published:
                    fingerprint = session.stage_fingerprint()
                    self.workspace.publish_mount_stage(
                        session.remote_path,
                        session.data_path,
                        expected_stage_fingerprint=fingerprint,
                        expected_existing_fingerprint=(
                            session.expected_existing_fingerprint
                        ),
                    )
                    session.mark_published()
                if session.delete_after_ack is not None:
                    source, source_digest = session.delete_after_ack
                    source_fingerprint = self._local_fingerprint(source)
                    materialized = self.database.get_materialized(source)
                    if source_fingerprint is not None:
                        if (
                            materialized is None
                            or materialized.state != "clean"
                            or materialized.clean_digest != source_digest
                            or materialized.content_sha256 is None
                        ):
                            raise OSError(
                                errno.EBUSY, "The rename source changed locally."
                            )
                        retired = self.workspace.retire_file(
                            source, require_retention_capacity=True,
                        )
                        if retired is not None:
                            if (
                                retired.initial.sha256 != materialized.content_sha256
                                or retired.initial.fingerprint.device_id != source_fingerprint.device_id
                                or retired.initial.fingerprint.file_id != source_fingerprint.file_id
                            ):
                                self.workspace.finish_retired_file(retired, preserve=True)
                                raise OSError(errno.EBUSY, "The rename source changed locally.")
                            # This is a clean cache preimage of an explicit
                            # rename, not a timed conflict candidate. Keep its
                            # exact inode until the coordinator's mount fence
                            # proves old descriptions closed; genuine drift is
                            # still promoted by ordinary quarantine maintenance.
                            preserved = self.workspace.finish_retired_file(
                                retired, preserve=False, retain_unchanged=True,
                            )
                            if preserved is not None:
                                raise OSError(errno.EBUSY, "The rename source changed locally.")

            if session.tree_journal is not None:
                modified_ns = session.sealed_fingerprint.mtime_ns
                modified_at = datetime.fromtimestamp(modified_ns // 1_000_000_000, timezone.utc).replace(
                    microsecond=modified_ns // 1000 % 1_000_000).isoformat().replace("+00:00", "Z")
                self.coordinator.stage_tree_snapshot(session.remote_path, journal=session.tree_journal,
                    snapshot=session.tree_owner, tree_mutation=session._tree_mutation,
                    expected_source_digest=session.base_digest, delete_after_ack=session.delete_after_ack,
                    mutation_id=session.mutation_id, modified_at=modified_at)
            else:
                self.coordinator.stage_file_provider_write(
                    session.remote_path,
                    expected_source_digest=session.base_digest,
                    delete_after_ack=session.delete_after_ack,
                    publish_local_namespace=publish_local_namespace,
                    mutation_id=session.mutation_id,
                )
        except StagingRepairPending as error:
            with self._lock:
                session.publishing = False
                self._schedule_publish_retry_locked(session)
                self._publication_condition.notify_all()
            self.logger.record(
                "fabric_mount_publish_deferred_for_staging_repair",
                path=session.remote_path,
                error=str(error),
            )
            return
        except BaseException as error:
            durable_owner = self._session_write_is_durably_owned(session)
            if durable_owner is True:
                self._accept_durable_write_handoff(session)
                self.logger.record(
                    "fabric_mount_publish_handoff_recovered",
                    path=session.remote_path,
                    mutation_id=session.mutation_id,
                    error=str(error),
                )
                return
            with self._lock:
                session.publishing = False
                self._schedule_publish_retry_locked(session)
                self._publication_condition.notify_all()
            if durable_owner is None:
                self.logger.record(
                    "fabric_mount_publish_handoff_unknown",
                    path=session.remote_path,
                    mutation_id=session.mutation_id,
                    error=str(error),
                )
            self.logger.record(
                "fabric_mount_publish_failed",
                path=session.remote_path,
                error=str(error),
            )
            return
        self._accept_durable_write_handoff(session)

    def flush_writes(self) -> None:
        with self._lock:
            paths = [
                path
                for path, session in self._sessions.items()
                if session.modified and session.sealed
            ]
        for path in paths:
            self._publish_path(path)

    def unlink(self, path: str) -> None:
        remote = self._remote_path(path)
        assert remote is not None
        with self._cleanup_path_admission(remote):
            self._unlink_admitted(path)

    def _unlink_admitted(self, path: str) -> None:
        remote = self._remote_path(path)
        assert remote is not None
        with self._lock:
            self._await_directory_mutation_locked(remote)
            session = self._sessions.get(remote)
            if session is not None and session.publishing:
                session = self._wait_for_publication_locked(remote, session)
                if session is not None and session.publishing:
                    raise OSError(errno.EBUSY, "The mounted file is still publishing.")
            if session is not None:
                remote_exists = self._resolve_remote_entry(remote) is not None
                transport_temp = self._transport_appledouble_discardable(session)
                if (
                    session.published
                    and not session.journaled
                    and not remote_exists
                    and not transport_temp
                ):
                    current = self._local_fingerprint(remote)
                    if not session.matches_published_inode(current) or current is None:
                        raise OSError(
                            errno.EBUSY,
                            "The pending mounted file changed before deletion.",
                        )
                    # Local publication won, but its durable journal handoff did
                    # not. Remove only that exact inode before discarding the
                    # recovery marker; otherwise a successful Finder unlink can
                    # leave an untracked file visible and later re-upload it.
                    self.workspace.native_unlink_file_by_fingerprint(
                        remote,
                        expected_fingerprint=current,
                    )
                if (
                    not remote_exists
                    and not session.journaled
                    and not session.delete_pending
                    and not (session.published and transport_temp)
                ):
                    # TemporaryFile unlinks before its first write. Persist a
                    # terminal receipt before removing the namespace, retaining
                    # the private inode until its final descriptor closes.
                    session.mark_cancelled()
                    session.journaled = True
                    timer = self._timers.pop(remote, None)
                    if timer is not None:
                        timer.cancel()
                    flush_timer = self._flush_timers.pop(remote, None)
                    if flush_timer is not None:
                        flush_timer.cancel()
                    self._sessions.pop(remote, None)
                    if not self._session_has_open_handle(session):
                        session.abort()
                    return
                if session.published and not session.journaled:
                    # The edited inode has already replaced the visible cache,
                    # but its upload journal did not land. A failed delete
                    # callback cannot relink that anonymous inode portably, so
                    # keep this brief state retryable instead of risking loss.
                    if not transport_temp:
                        raise OSError(
                            errno.EBUSY,
                            "The mounted upload is still reconciling.",
                        )
            view = self._file_view(remote)
            if view is None and session is not None and session.delete_pending:
                view = session.pristine_read_view()
                if view is None:
                    pending_remote = self._resolve_remote_entry(remote)
                    if pending_remote is not None:
                        view = _FileView(
                            remote,
                            pending_remote.size_bytes,
                            pending_remote.digest,
                            _modified_ns(
                                pending_remote.modified,
                                self._manifest_time(),
                            ),
                            remote_source_path=remote,
                        )
            if view is None:
                raise OSError(errno.ENOENT, "The mounted file does not exist.")

            delete_was_pending = bool(session is not None and session.delete_pending)
            if session is not None:
                # Persist the user's latest namespace intent before entering the
                # shared journal. A crash after the coordinator commits but
                # before local cleanup can then recover only as delete, never as
                # a replay of the superseded staged upload.
                session.mark_delete_pending()

            def publish_local_delete() -> None:
                # Resolve identity only after the coordinator has fenced any
                # off-loop remote publisher. The file visible when the delete
                # commits may be newer than the one Finder initially listed.
                local = self._local_fingerprint(remote)
                if local is None:
                    return
                # This is an explicit user unlink, not a remote winner being
                # applied over possibly-open local bytes. Match native unlink
                # semantics: remove the exact inode immediately and let any
                # already-open descriptor retain its anonymous lifetime. The
                # remote-delete quarantine is intentionally not used here;
                # doing so promoted every unchanged Finder deletion into a
                # false conflict file after the quarantine grace period.
                def remove() -> None:
                    self.workspace.native_unlink_file_by_fingerprint(
                        remote, expected_fingerprint=local
                    )
                if session is None:
                    self._replace_pristine_rename_destination(remote, remove)
                else:
                    remove()

            if session is not None:
                session.publishing = True
            try:
                self.coordinator.stage_file_provider_delete(
                    remote,
                    publish_local_namespace=publish_local_delete,
                )
            except BaseException as delete_error:
                delete_ownership = self._delete_is_durably_owned(remote)
                if delete_ownership is None:
                    if session is not None:
                        session.publishing = False
                        timer = self._timers.pop(remote, None)
                        if timer is not None:
                            timer.cancel()
                        flush_timer = self._flush_timers.pop(remote, None)
                        if flush_timer is not None:
                            flush_timer.cancel()
                        self._publication_condition.notify_all()
                    self.logger.record(
                        "fabric_mount_delete_handoff_unknown",
                        path=remote,
                        error=str(delete_error),
                    )
                    raise delete_error
                if delete_ownership is False:
                    if session is not None:
                        session.publishing = False
                        retryable = isinstance(delete_error, StagingRepairPending) or (
                            isinstance(delete_error, OSError)
                            and delete_error.errno
                            in (
                                errno.EAGAIN,
                                errno.EBUSY,
                                errno.ESTALE,
                                errno.EHOSTUNREACH,
                            )
                        )
                        if retryable and session.delete_pending:
                            # A fence, not a failure: the unlink returns 0 on
                            # the strength of the durable receipt, and the
                            # retry must outlive however long the engine
                            # stays fenced (a startup staging repair or a
                            # watcher recovery under a mass delete can hold
                            # for minutes). Abandoning it would leave the
                            # path hidden here yet alive in the durable store.
                            self._schedule_publish_retry_locked(
                                session, fenced=True
                            )
                            self._publication_condition.notify_all()
                            self.logger.record(
                                "fabric_mount_delete_deferred",
                                path=remote,
                                error=str(delete_error),
                            )
                            return
                        if not delete_was_pending:
                            try:
                                session.restore_after_delete_failure()
                            except (FabricMountError, OSError, StateError) as error:
                                # Preserve delete_pending if the rollback receipt
                                # itself cannot commit. It blocks upload publication
                                # and lets an explicit retry/restart finish safely.
                                self.logger.record(
                                    "fabric_mount_delete_rollback_receipt_failed",
                                    path=remote,
                                    error=str(error),
                                )
                        self._publication_condition.notify_all()
                    raise delete_error
                self.logger.record(
                    "fabric_mount_delete_handoff_recovered",
                    path=remote,
                    error=str(delete_error),
                )
            if session is not None:
                # The delete journal now owns the namespace intent. Retire the
                # older upload as a durable cancellation before dropping its
                # private bytes. Cleanup failure may retain the receipt, but its
                # state can never recover as an upload.
                cleanup_error: OSError | None = None
                try:
                    session.mark_cancelled()
                except OSError as error:
                    cleanup_error = error
                session.publishing = False
                session.journaled = True
                timer = self._timers.pop(remote, None)
                if timer is not None:
                    timer.cancel()
                flush_timer = self._flush_timers.pop(remote, None)
                if flush_timer is not None:
                    flush_timer.cancel()
                if session.cancelled:
                    if not self._session_has_open_handle(session):
                        if self._retire_cancelled_session(session):
                            if self._sessions.get(remote) is session:
                                self._sessions.pop(remote, None)
                        else:
                            cleanup_error = cleanup_error or OSError(
                                errno.EBUSY,
                                "The deleted local preimage is still retained.",
                            )
                            self._schedule_publish_retry_locked(session)
                    # A widened SMB O_RDWR/delete description can outlive the
                    # namespace callback. Keep both its private descriptor and
                    # its session-map namespace fence until the last RELEASE;
                    # fully seeded descriptors accept only anonymous local IO.
                    # The terminal receipt can never republish their bytes.
                else:
                    if self._sessions.get(remote) is session:
                        self._sessions.pop(remote, None)
                    # Cancellation receipt failure leaves the earlier durable
                    # delete_pending fence in place. Close the private inode but
                    # preserve both receipt and bytes for restart recovery.
                    try:
                        session.preserve()
                    except OSError as error:
                        cleanup_error = cleanup_error or error
                self._publication_condition.notify_all()
                if cleanup_error is not None:
                    self.logger.record(
                        "fabric_mount_deleted_stage_cleanup_failed",
                        path=remote,
                        error=str(cleanup_error),
                    )
            self._remote_quota.refresh_pending()

    def _await_closed_rename_destination_locked(self, destination: str) -> None:
        """Let a closed replacement target finish its existing durable handoff."""

        session = self._sessions.get(destination)
        if session is None or not session.modified:
            # A preceding rename can have left the session map while its
            # durable destination receipt is still pending. Resolve that exact
            # predecessor before using the destination's remote CAS preimage.
            deadline = time.monotonic() + PUBLISH_REOPEN_WAIT_SECONDS
            self._await_rename_destination_handoff_locked(destination, deadline=deadline)
            return
        if (
            not session.sealed
            or self._session_has_open_writer(session)
        ):
            return
        deadline = time.monotonic() + PUBLISH_REOPEN_WAIT_SECONDS
        # A cache writer can close its first result just before another writer
        # replaces it. The settle timer still owns those closed bytes; treating
        # that timer as a competing editor leaks EBUSY through SMB as EACCES.
        # Keep the existing publisher and receipt chain responsible for them.
        while self._sessions.get(destination) is session:
            if (
                not session.sealed or self._session_has_open_writer(session)
                or session.delete_pending or session.cancelled
                or session.failed_mutation
            ):
                raise OSError(errno.EBUSY, "The rename destination is busy.")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise OSError(errno.EBUSY, "The rename destination is still publishing.")
            self._publication_condition.wait(timeout=min(remaining, 0.25))
        if destination in self._sessions:
            raise OSError(errno.EBUSY, "The rename destination changed locally.")
        self._await_rename_destination_handoff_locked(destination, deadline=deadline)

    def _await_rename_destination_handoff_locked(self, destination: str, *, deadline: float) -> None:
        operation = self.database.get_latest_nonterminal_operation(destination)
        intent = self.database.get_local_transfer_intent(destination)
        predecessors = {value for value in (
            operation.mutation_id if operation is not None else None,
            intent.transfer_id if intent is not None else None,
        ) if value is not None}
        self._await_pending_put_locked(destination, deadline=deadline)
        self._await_pending_rename_destination_locked(destination, deadline=deadline)
        # A conflict leaves the nonterminal index just like an ACK. Only the
        # exact handoff observed above may fence this attempt; old unrelated
        # conflict history must not prevent an explicit later repair.
        for mutation_id in predecessors:
            observed = self.database.get_operation(mutation_id)
            if observed is not None and observed.state != "acked":
                raise OSError(errno.EBUSY, "The rename destination handoff did not complete.")

    def _replace_pristine_rename_destination(
        self, destination: str, replace: Callable[[], None]
    ) -> None:
        """A metadata-only O_RDWR alias is not a competing document edit."""

        session = self._sessions.get(destination)
        if session is None:
            pinned: list[tuple[_ReadHandle, int, FileFingerprint]] = []
            try:
                for opened in self._handles.values():
                    if not isinstance(opened, _ReadHandle) or opened.retired_local is not None:
                        continue
                    view = opened.view
                    if view.remote_path != destination or view.session is not None or view.local_fingerprint is None:
                        continue

                    def pin(descriptor: int) -> int:
                        if _descriptor_fingerprint(descriptor) != view.local_fingerprint:
                            raise OSError(errno.ESTALE, "The rename reader changed before replacement.")
                        retained = os.dup(descriptor)
                        # The boundary rechecks path identity after this
                        # callback; retain cleanup ownership even if that
                        # final validation rejects a concurrent replacement.
                        pinned.append((opened, retained, view.local_fingerprint))
                        return retained

                    self.workspace.with_regular_file_descriptor(destination, pin, share_delete=True)
                replace()
                for opened, descriptor, identity in pinned:
                    opened.retired_local = _RetiredLocalRead(descriptor, identity)
                pinned.clear()
            finally:
                for _opened, descriptor, _identity in pinned:
                    os.close(descriptor)
            return
        # write() drops the backend lock before taking this per-inode lock.
        # Hold it through the check and retirement so a racing actual write
        # either wins (and fences rename) or sees the retired alias as closed.
        with session._lock:
            if (
                session.modified or session.publishing or session.published
                or session.journaled or session.delete_pending
                or session.cancelled or session.failed_mutation
            ):
                raise OSError(errno.EBUSY, "The rename destination is busy.")
            original = self._session_read_view(session)
            self._ensure_session_seeded(session)
            # Seeding clears the lazy pristine view. Preserve its identity even
            # if the source receipt fails: a later retry must still recognize
            # older read aliases and pin them to this exact preimage.
            session.pristine_view = _FileView(
                destination, original.size_bytes, original.digest,
                original.modified_ns, remote_source_path=original.remote_source_path,
                local_fingerprint=original.local_fingerprint, session=session,
            )
            # Do not retire any alias unless the source's durable retarget
            # receipt succeeds. A failed rename leaves old handles writable.
            replace()
            session.detach_pristine()
            # Read aliases opened while the writer was still lazy may point
            # at its pristine pathname rather than its private descriptor.
            # Pin that exact preimage too; never redirect them to new bytes.
            for opened in self._handles.values():
                if not isinstance(opened, _ReadHandle):
                    continue
                view = opened.view
                if (
                    view.remote_path == destination
                    and view.size_bytes == original.size_bytes
                    and view.digest == original.digest
                    and view.local_fingerprint == original.local_fingerprint
                ):
                    opened.view = _FileView(
                        destination, view.size_bytes, view.digest,
                        view.modified_ns, remote_source_path=view.remote_source_path,
                        local_fingerprint=view.local_fingerprint, session=session,
                    )
            self._sessions.pop(destination)
            for registry in (self._timers, self._flush_timers):
                timer = registry.pop(destination, None)
                if timer is not None:
                    timer.cancel()
            if not self._session_has_open_handle(session):
                session.finish()

    def rename(self, source_path: str, destination_path: str) -> None:
        source_root = self._root_component(source_path)
        destination_root = self._root_component(destination_path)
        admission_paths = tuple(
            path
            for path in (
                "" if source_root is not None else self._remote_path(source_path),
                "" if destination_root is not None else self._remote_path(destination_path),
            )
            if path is not None
        )
        with self._cleanup_path_admission(*admission_paths):
            try:
                self._rename_admitted(source_path, destination_path)
            except OSError as error:
                if error.errno == errno.EBUSY:
                    self._record_rename_busy(source_path, destination_path, error)
                raise

    def _record_rename_busy(self, source_path: str, destination_path: str, error: OSError) -> None:
        """Bounded state evidence; never export user paths or exception text."""
        reasons = {
            "The rename destination is busy.": "destination_busy",
            "The rename destination is still publishing.": "destination_publishing",
            "The rename destination changed locally.": "destination_changed",
            "The rename destination handoff did not complete.": "destination_handoff_failed",
            "The rename destination has uncommitted local bytes.": "destination_dirty_cache",
            "The rename source changed locally.": "source_changed",
            "The rename source has pending local work.": "source_pending",
            "The rename source is being written.": "source_writer",
            "The rename source is not remotely stable.": "source_unstable",
            "The mounted write is already publishing.": "source_publishing",
            "The mounted file is still publishing.": "publication_pending",
            "The mounted upload is still reconciling.": "upload_pending",
            "The rename destination is still reconciling.": "destination_pending",
            "The directory rename is still reconciling.": "directory_pending",
            "The directory contains an open write.": "directory_writer",
        }
        try:
            source, destination = self._remote_path(source_path), self._remote_path(destination_path)
            with self._lock:
                source_session = self._sessions.get(source)
                destination_session = self._sessions.get(destination)
                self.logger.record(
                    "fabric_mount_rename_busy",
                    reason=reasons.get(error.strerror, "other_busy"),
                    source_cached=source is not None and self._local_fingerprint(source) is not None,
                    destination_cached=destination is not None and self._local_fingerprint(destination) is not None,
                    source_session=source_session is not None,
                    destination_session=destination_session is not None,
                    destination_modified=bool(destination_session and destination_session.modified),
                    destination_publishing=bool(destination_session and destination_session.publishing),
                    destination_open_writer=bool(destination_session and self._session_has_open_writer(destination_session)),
                    destination_open_reader=any(isinstance(opened, _ReadHandle)
                        and opened.view.remote_path == destination for opened in self._handles.values()),
                )
        except Exception:
            # Diagnostics must never change the original filesystem result.
            pass

    def _rename_admitted(self, source_path: str, destination_path: str) -> None:
        source_root = self._root_component(source_path)
        destination_root = self._root_component(destination_path)
        if source_root is not None or destination_root is not None:
            if (
                source_root is None
                or destination_root is None
                or source_root != self.workspace_name
            ):
                raise OSError(errno.EXDEV, "Workspace roots cannot be moved across namespaces.")
            if source_root == destination_root:
                return
            if self._rename_workspace is None:
                raise OSError(errno.EROFS, "Workspace naming authority is unavailable.")
            with self._lock:
                if self.workspace_name != source_root:
                    raise OSError(errno.ESTALE, "Workspace name changed; refresh and retry.")
            # The signed control-plane request can take seconds while offline.
            # Never hold the namespace lock across network I/O: reads and open
            # handles in this workspace must remain responsive during rename.
            updated = self._rename_workspace(source_root, destination_root)
            try:
                valid = len(split_relative(updated)) == 1
            except (InvalidTask, UnsafePath):
                valid = False
            if not valid:
                raise OSError(errno.EIO, "Meshia returned an invalid workspace name.")
            with self._lock:
                if self.workspace_name not in (source_root, updated):
                    raise OSError(errno.ESTALE, "Workspace name changed; refresh and retry.")
                self.workspace_name = updated
            return
        source = self._remote_path(source_path)
        destination = self._remote_path(destination_path)
        assert source is not None and destination is not None
        if source == destination:
            return
        with self._lock:
            self._await_closed_rename_destination_locked(destination)
        # Do not force an ordinary file save through upload before its rename;
        # the file-session path below retargets that stage atomically.  Prefix
        # moves, however, need every closed descendant staged before their one
        # manifest mutation can be journaled.
        if self.getattr(source_path).is_directory:
            self._flush_sealed_writes_in_prefixes(source, destination)
        with self._lock:
            self._await_directory_mutation_locked(source, destination)
            self._require_parent_directory(destination)
            source_node = self.getattr(source_path)
            if source_node.is_directory:
                if destination.startswith(source + "/"):
                    raise OSError(errno.EINVAL, "A directory cannot be moved inside itself.")
                if self._has_open_writer_in_prefixes(source, destination):
                    raise OSError(errno.EBUSY, "The directory contains an open write.")
                try:
                    self.getattr(destination_path)
                except OSError as error:
                    if error.errno != errno.ENOENT:
                        raise
                else:
                    raise OSError(
                        errno.ENOTEMPTY,
                        "The directory rename destination is not empty.",
                    )
                try:
                    self.coordinator.stage_metadata_directory_rename(
                        source,
                        destination,
                    )
                except StateError as error:
                    raise OSError(errno.EBUSY, str(error)) from error
                except InvalidTask as error:
                    if _is_local_only_directory_rename(error):
                        # A directory the engine has nothing to publish for
                        # (fresh ``mkdir`` with no file under it, no remote
                        # entry, no pending work) is renamed locally. FUSE-T
                        # rendered the previous EINVAL as "Permission denied"
                        # and the folder could never be renamed (2026-09-03).
                        self._rename_local_only_directory(source, destination)
                        return
                    raise OSError(errno.EINVAL, str(error)) from error
                self._retarget_open_reads(source, destination)
                return
            session = self._sessions.get(source)
            if session is not None and session.publishing:
                # Finder renames a just-closed file (temp -> final name) while
                # its bytes publish; wait for the receipt rather than EBUSY.
                session = self._wait_for_publication_locked(source, session)
            if session is not None:
                # Publication drops the backend lock while the coordinator
                # establishes its durable handoff. Retargeting the session in
                # that interval can move its marker to the destination after
                # the inode and journal have already committed at the source.
                # Fence before hydration, timer cancellation, or map mutation.
                if session.published or session.publishing:
                    raise OSError(
                        errno.EBUSY,
                        "The mounted write is already publishing.",
                    )
                self._ensure_session_seeded(session)
                destination_remote = self._resolve_remote_entry(destination)
                destination_local = self._local_fingerprint(destination)
                temp_data_key = (
                    _smb_copy_pair_key(source, appledouble=False)
                    if self._fuse_t_smb_transport
                    else None
                )
                final_data_key = (
                    _smb_final_copy_pair_key(destination, appledouble=False)
                    if self._fuse_t_smb_transport
                    else None
                )
                temp_sidecar_key = (
                    _smb_copy_pair_key(source, appledouble=True)
                    if self._fuse_t_smb_transport
                    else None
                )
                final_sidecar_key = (
                    _smb_final_copy_pair_key(destination, appledouble=True)
                    if self._fuse_t_smb_transport
                    else None
                )
                preserve_transport_provenance = bool(
                    temp_sidecar_key is not None
                    and final_sidecar_key is not None
                    and temp_sidecar_key[0] == final_sidecar_key[0]
                    and session.transport_provenance
                    == _FUSE_T_SMB_APPLEDOUBLE_PROVENANCE
                )
                # Keep the source map and its retry timers intact until the
                # retargeted crash marker is durable. Session.rename rolls its
                # own fields back if that marker write fails, so the original
                # path remains fully tracked and retryable.
                def retarget_source() -> None:
                    session.rename(
                        destination,
                        destination_base_digest=(
                            destination_remote.digest
                            if destination_remote is not None
                            else None
                        ),
                        destination_base_size=(
                            destination_remote.size_bytes
                            if destination_remote is not None
                            else 0
                        ),
                        destination_existing_fingerprint=destination_local,
                        remote_size_for_identity=self._remote_size_for_identity,
                        preserve_transport_provenance=preserve_transport_provenance,
                    )

                self._replace_pristine_rename_destination(destination, retarget_source)
                timer = self._timers.pop(source, None)
                if timer is not None:
                    timer.cancel()
                flush_timer = self._flush_timers.pop(source, None)
                if flush_timer is not None:
                    flush_timer.cancel()
                self._sessions.pop(source)
                self._sessions[destination] = session
                if (
                    temp_data_key is not None
                    and final_data_key is not None
                    and temp_data_key[0] == final_data_key[0]
                ):
                    self._remember_smb_temp_final_pair_locked(
                        temp_data_key,
                        final_data_key,
                    )
                elif (
                    preserve_transport_provenance
                    and temp_sidecar_key is not None
                    and final_sidecar_key is not None
                    and self._matching_smb_temp_final_pair_locked(
                        temp_sidecar_key,
                        final_sidecar_key,
                    )
                    and self._mark_final_smb_sidecar_locked(
                        final_sidecar_key,
                        expected_temp_key=temp_sidecar_key,
                    )
                ):
                    self._smb_temp_final_pair_evidence.pop(
                        temp_sidecar_key,
                        None,
                    )
                if session.sealed:
                    replacement = self._new_publish_timer(
                        destination,
                        self.settle_seconds,
                    )
                    self._timers[destination] = replacement
                    replacement.start()
                elif flush_timer is not None:
                    replacement = self._new_flush_publish_timer(destination)
                    self._flush_timers[destination] = replacement
                    replacement.start()
                return
            source_view_before_wait = self._file_view(source)
            if source_view_before_wait is None:
                raise OSError(errno.ENOENT, "The rename source does not exist.")
            source_local_before_wait = self._local_fingerprint(source)
            # A close may have retired the private session into the durable
            # transfer/PUT lane just before this rename arrived. Wait for that
            # exact handoff instead of leaking a transient EBUSY to Finder or
            # NSDocument, then validate the namespace again below. A genuinely
            # slow/offline upload remains fenced by the bounded helper.
            handoff_deadline = time.monotonic() + PUBLISH_REOPEN_WAIT_SECONDS
            self._await_pending_put_locked(source, deadline=handoff_deadline)
            if self._sessions.get(source) is not None:
                # The condition wait releases the backend lock. A concurrent
                # writer that acquired the path during that interval owns the
                # namespace now; never rename bytes out from under it.
                raise OSError(errno.EBUSY, "The rename source is being written.")
            # A preceding safe-save rename may have already moved the old
            # destination locally while its exact remote receipt is still in
            # flight.  Wait only for that durable chain; an actual open writer
            # remains fenced by the session checks before and after the wait.
            if destination not in self._sessions:
                self._await_pending_rename_destination_locked(
                    destination, deadline=handoff_deadline
                )
            if self._sessions.get(source) is not None:
                raise OSError(errno.EBUSY, "The rename source is being written.")
            if (
                self.database.get_latest_nonterminal_operation(source) is not None
                or self.database.get_local_transfer_intent(source) is not None
            ):
                raise OSError(errno.EBUSY, "The rename source has pending local work.")
            # Both waits release the namespace lock. Recheck parent and prefix
            # ownership so a directory mutation that won during that interval
            # cannot be overwritten by create_parents below.
            self._epoch_overlay = _UNSET
            if self._path_has_pending_directory_mutation(source) or (
                self._path_has_pending_directory_mutation(destination)
            ):
                raise OSError(
                    errno.EBUSY, "The directory rename is still reconciling."
                )
            self._require_parent_directory(destination)
            source_view = self._file_view(source)
            if source_view is None:
                raise OSError(errno.ENOENT, "The rename source does not exist.")
            local = self._local_fingerprint(source)
            source_changed = source_local_before_wait != local or (
                source_local_before_wait is None
                and (
                    source_view_before_wait.size_bytes != source_view.size_bytes
                    or source_view_before_wait.digest != source_view.digest
                )
            )
            if source_changed and not self._rename_source_cache_transition(
                source, source_view_before_wait, source_view, local
            ):
                raise OSError(errno.EBUSY, "The rename source changed locally.")
            if (
                self.database.list_remote_children(destination, limit=1)
                or self.database.is_remote_directory(destination)
                or self.workspace.directory_exists(destination)
            ):
                raise OSError(errno.EISDIR, "The rename destination is a directory.")
            if (
                self.database.get_latest_nonterminal_operation(destination)
                is not None
            ):
                raise OSError(errno.EBUSY, "The rename destination is busy.")
            # SMB can retain an unchanged O_RDWR description after its caller
            # only read the file. The same pristine-destination helper used by
            # private source sessions below fences actual writes and retires
            # that harmless alias; session presence alone is not a conflict.
            destination_remote = self._resolve_remote_entry(destination)
            destination_local = self._local_fingerprint(destination)
            destination_content_sha256 = None
            if destination_local is not None:
                destination_materialized = self.database.get_materialized(destination)
                if (
                    destination_remote is None
                    or destination_materialized is None
                    or destination_materialized.state != "clean"
                    or destination_materialized.clean_digest
                    != destination_remote.digest
                    or destination_materialized.stat_fingerprint
                    != _fingerprint_text(destination_local)
                    or destination_materialized.content_sha256 is None
                ):
                    raise OSError(
                        errno.EBUSY,
                        "The rename destination has uncommitted local bytes.",
                    )
                destination_content_sha256 = destination_materialized.content_sha256
            source_remote = self._resolve_remote_entry(
                source_view.remote_source_path or source
            )
            if source_remote is None or source_view.digest is None:
                raise OSError(errno.EBUSY, "The rename source is not remotely stable.")
            if local is not None:
                self._replace_pristine_rename_destination(
                    destination,
                    lambda: self.workspace.rename_file_by_fingerprint(
                        source,
                        destination,
                        expected_fingerprint=local,
                        expected_destination_fingerprint=destination_local,
                        expected_destination_sha256=(
                            f"sha256:{destination_content_sha256}"
                            if destination_content_sha256 is not None
                            else None
                        ),
                        create_parents=True,
                    ),
                )
                self.coordinator.stage_local_rename(source, destination)
            else:
                def retire_destination_cache() -> None:
                    # Retain old read descriptions before the coordinator
                    # retires this verified cache under its watcher fence.
                    # No source bytes need downloading or uploading.
                    self._replace_pristine_rename_destination(
                        destination,
                        lambda: self.workspace.remove_file(
                            destination,
                            expected_fingerprint=destination_local,
                            expected_sha256=f"sha256:{destination_content_sha256}",
                        ) if destination_local is not None else None,
                    )

                self.coordinator.stage_metadata_rename(
                    source,
                    destination,
                    expected_source_digest=source_remote.digest,
                    expected_destination_digest=(
                        destination_remote.digest
                        if destination_remote is not None
                        else None
                    ),
                    **({"retire_destination_cache": retire_destination_cache}
                        if destination_local is not None or destination in self._sessions else {}),
                )

    def _rename_source_cache_transition(
        self, path: str, before: _FileView, after: _FileView,
        local: FileFingerprint | None,
    ) -> bool:
        """Recognize only a verified cache transition of the same file value.

        A completed PUT makes its bytes evictable while rename waits for the
        receipt. Eviction and later hydration may change the cache inode without
        changing the file being renamed. A user's edit has no matching pristine
        cache fingerprint; an independent remote write has a different digest.
        """
        remote = self._resolve_remote_entry(path)
        materialized = self._resolve_materialized(path)
        if (
            before.digest is None or remote is None or materialized is None
            or before.digest != after.digest or before.digest != remote.digest
            or before.size_bytes != after.size_bytes or before.size_bytes != remote.size_bytes
            or materialized.clean_digest != remote.digest
        ):
            return False
        if local is None:
            return materialized.state == "absent" and materialized.bytes_on_disk == 0
        return (
            materialized.state == "clean"
            and materialized.stat_fingerprint == _fingerprint_text(local)
            and local.size_bytes == remote.size_bytes
            and materialized.content_sha256 is not None
        )

    def mkdir(self, path: str) -> None:
        remote = self._remote_path(path)
        assert remote is not None
        with self._lock:
            self._await_directory_mutation_locked(remote)
            self._require_parent_directory(remote)
            self._refresh_removed_directories()
            if (
                remote in self._removed_directories
                and self.workspace.directory_exists(remote)
            ):
                try:
                    public_entries, truncated = self.workspace.list(
                        remote, max_entries=1, recursive=False
                    )
                except (InvalidTask, OSError, UnsafePath):
                    public_entries, truncated = ["unknown"], True
                if not public_entries and not truncated:
                    # The physical folder is retained only because it contains
                    # hidden Meshia recovery evidence (or is truly empty).
                    # Reusing it is the atomic, zero-copy recreation path.
                    self.coordinator.stage_local_directory(remote)
                    self._mark_directory_created(remote)
                    return
            try:
                self.getattr(path)
            except OSError as error:
                if error.errno != errno.ENOENT:
                    raise
            else:
                raise OSError(errno.EEXIST, "The mounted item already exists.")
            try:
                # The parent was validated against the mounted namespace,
                # which includes remote-only directories. Materialize its
                # cache scaffold without requiring any remote child bytes.
                self.workspace.create_directory(remote, create_parents=True)
            except UnsafePath as error:
                raise OSError(
                    errno.EEXIST, "The mounted directory already exists."
                ) from error
            try:
                self.coordinator.stage_local_directory(remote)
            except BaseException:
                # Never acknowledge an unjournaled mkdir. Roll back only the
                # exact empty directory this callback created; parent cache
                # scaffolding and raced-in children remain untouched.
                try:
                    self.workspace.remove_empty_directory(remote)
                except (InvalidTask, OSError, UnsafePath):
                    pass
                raise
            self._mark_directory_created(remote)

    def _rename_local_only_directory(self, source: str, destination: str) -> None:
        """Rename a directory that exists only in the local namespace.

        Caller holds ``self._lock``. Nothing durable references ``source``:
        no remote entry, no pending operation. The destination was already
        verified absent by the caller.
        """

        try:
            self.workspace.create_directory(destination, create_parents=True)
        except UnsafePath as error:
            raise OSError(
                errno.EEXIST, "The mounted directory already exists."
            ) from error
        try:
            self.coordinator.stage_local_directory_rename(source, destination)
        except BaseException:
            try:
                self.workspace.remove_empty_directory(destination)
            except (InvalidTask, OSError, UnsafePath):
                pass
            raise
        self._mark_directory_created(destination)
        manifest_identity = self._manifest_identity()
        try:
            if self.workspace.directory_exists(source):
                self.workspace.remove_empty_directory(source)
        except InvalidTask:
            pass
        except OSError as error:
            if error.errno != errno.ENOENT:
                raise
        self._mark_directory_removed(source, manifest_identity)

    def rmdir(self, path: str) -> None:
        remote = self._remote_path(path)
        assert remote is not None
        self._discard_closed_sidecars_in_prefixes(remote)
        authority = self.database.current_authority()
        if authority is None:
            raise OSError(errno.ESTALE, "The workspace authority is unavailable.")
        for attempt in range(3):
            if self.database.current_authority() != authority:
                raise OSError(errno.ESTALE, "The workspace authority changed during directory removal.")
            if self._rmdir_once(path, remote, allow_missing=attempt > 0, expected_scope_id=authority.scope_id):
                return
        raise OSError(errno.EAGAIN, "The directory changed while removal was being journaled; retry.")

    def _rmdir_once(self, path: str, remote: str, *, allow_missing: bool, expected_scope_id: int) -> bool:
        with self._lock:
            self._await_directory_mutation_locked(remote)
            # A concurrent feed poll can advance the DB while this callback
            # removes its empty cache directory. Retry against a fresh head,
            # never the read-epoch memo, and recheck children each time.
            head = self.database.get_remote_manifest_head()
            manifest_identity = (head.generation, head.digest) if head is not None else None
            # A queued child delete remains in the authoritative manifest until
            # its receipt lands, but the mounted namespace already hides that
            # child. POSIX emptiness must follow the visible namespace or `rm
            # -r` spuriously fails during the normal reconciliation window.
            try:
                children = self.listdir(path)
            except OSError as error:
                if error.errno != errno.ENOENT or not allow_missing:
                    raise
                # The preceding attempt may already have removed a local-only
                # directory. Its durable delete still has to be journaled.
                children = ()
            if children:
                raise OSError(errno.ENOTEMPTY, "The mounted directory is not empty.")
            try:
                if self.workspace.directory_exists(remote):
                    self.workspace.remove_empty_directory(remote)
            except InvalidTask:
                # Another local reconciliation removed the already-observed
                # empty convenience directory first. Its desired state landed.
                pass
            except OSError as error:
                if error.errno == errno.ENOENT:
                    pass
                elif error.errno in (errno.ENOTEMPTY, errno.EEXIST):
                    # SMB can retain an unlinked inode until its delayed close.
                    # Workspace quarantine files are deliberately hidden from
                    # the mounted namespace and must not make an otherwise-
                    # empty directory impossible to remove. The bounded public
                    # listing filters only authenticated Meshia-reserved names;
                    # any real, truncated, or unreadable child still fails.
                    try:
                        public_entries, truncated = self.workspace.list(
                            remote,
                            max_entries=1,
                            recursive=False,
                        )
                    except (InvalidTask, OSError, UnsafePath):
                        public_entries, truncated = ["unknown"], True
                    if public_entries or truncated:
                        raise OSError(
                            errno.ENOTEMPTY,
                            "The mounted directory is not empty.",
                        ) from error
                else:
                    raise
            return self._mark_directory_removed(remote, manifest_identity, expected_scope_id=expected_scope_id)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            timers = tuple(self._timers.values())
            self._timers.clear()
            flush_timers = tuple(self._flush_timers.values())
            self._flush_timers.clear()
        for timer in (*timers, *flush_timers):
            timer.cancel()
        self.flush_writes()
        with self._lock:
            remaining = tuple(self._sessions.values())
            self._sessions.clear()
            handles = tuple(self._handles.values())
            self._handles.clear()
            self._flushed_write_handles.clear()
        sessions: dict[int, _MountWriteSession] = {}
        for value in (*remaining, *handles):
            if isinstance(value, _ReadHandle) and value.retired_local is not None:
                os.close(value.retired_local.descriptor)
                value.retired_local = None
            if isinstance(value, _ReadHandle) and value.version is not None:
                self.coordinator.release_file_version(value.version)
                value.version = None
            session = (
                value
                if isinstance(value, _MountWriteSession)
                else value.view.session
                if isinstance(value, _ReadHandle)
                else None
            )
            if session is not None:
                sessions[id(session)] = session
        for value in sessions.values():
            # Preserve only actual user work. A pristine O_RDWR bridge handle
            # has no recovery value and must not become a false upload later.
            try:
                if value.cancelled:
                    if not self._retire_cancelled_session(value):
                        value.preserve()
                elif value.journaled:
                    value.finish()
                elif value.failed_mutation:
                    value.abort()
                elif value.delete_pending:
                    # A graceful service stop is no less abrupt from Finder's
                    # perspective than a process crash. Preserve the explicit
                    # tombstone receipt for the next authority-scoped runtime.
                    value.preserve()
                elif value.modified:
                    value.preserve()
                else:
                    value.abort()
            except OSError:
                pass
        if self._cleanup_fence_registered:
            cleanup_fence_setter = getattr(
                self.coordinator, "set_mount_cleanup_fence", None
            )
            if callable(cleanup_fence_setter):
                cleanup_fence_setter(None)
            self._cleanup_fence_registered = False
        self._remote_quota.detach_database(self.database)

    def _with_local_metadata_descriptor(
        self,
        path: str,
        operation: Callable[[int], Any],
        *,
        require_writable_stage: bool = False,
        allow_mtime_change: bool = False,
    ) -> Any:
        remote = self._remote_path(path)
        assert remote is not None
        publication_deadline = (
            time.monotonic() + MOUNT_PUBLISH_MAX_RETRY_SECONDS
            if require_writable_stage
            else None
        )

        def acknowledge_metadata(
            previous: FileFingerprint, current: FileFingerprint
        ) -> None:
            rebase = getattr(
                self.coordinator,
                "acknowledge_local_metadata_change",
                None,
            )
            rebased = False
            if callable(rebase):
                try:
                    rebased = bool(
                        rebase(
                            remote,
                            previous_fingerprint=previous,
                            current_fingerprint=current,
                            allow_mtime_change=allow_mtime_change,
                        )
                    )
                except (OSError, StateError) as error:
                    # A durable owner with a third fingerprint proves that
                    # bytes advanced outside this pinned metadata syscall.
                    self.logger.record(
                        "fabric_mount_metadata_acknowledgement_failed",
                        path=remote,
                        error=str(error),
                    )
                    raise OSError(
                        errno.ESTALE,
                        "The mounted file changed during metadata acknowledgement.",
                    ) from error
            if not rebased:
                watcher = getattr(self.coordinator, "watch", None)
                acknowledge = getattr(watcher, "acknowledge_local_state", None)
                if callable(acknowledge):
                    try:
                        acknowledge({remote: current})
                    except Exception as error:
                        # The metadata is already safely attached to the exact
                        # local inode. A watcher-baseline refresh is only a
                        # duplicate-work optimization.
                        self.logger.record(
                            "fabric_mount_metadata_acknowledgement_failed",
                            path=remote,
                            error=str(error),
                        )

        while True:
            with self._lock:
                session = self._sessions.get(remote)
                if session is not None and session.modified:
                    if require_writable_stage and session.publishing:
                        # Publication temporarily owns the inode fingerprint
                        # while it snapshots bytes into the durable journal.
                        # Wait for that exact critical section instead of
                        # surfacing Finder error -36; success and retry paths
                        # both notify and the loop then resolves current state.
                        assert publication_deadline is not None
                        remaining = publication_deadline - time.monotonic()
                        if remaining <= 0:
                            raise OSError(
                                errno.EAGAIN,
                                "The mounted file is still publishing; retry metadata.",
                            )
                        self._publication_condition.wait(timeout=remaining)
                        continue
                    flush_timer: threading.Timer | None = None
                    publish_timer: threading.Timer | None = None
                    if require_writable_stage:
                        flush_timer = self._flush_timers.pop(remote, None)
                        if flush_timer is not None:
                            flush_timer.cancel()
                        publish_timer = self._timers.pop(remote, None)
                        if publish_timer is not None:
                            publish_timer.cancel()
                    try:
                        result = session.with_local_metadata_descriptor(
                            operation,
                            allow_mtime_change=allow_mtime_change,
                        )
                    except BaseException:
                        if (
                            session.failed_mutation
                            and not session.published
                            and not session.journaled
                            and not self._session_has_open_handle(session)
                        ):
                            if self._sessions.get(remote) is session:
                                self._sessions.pop(remote, None)
                            session.abort()
                        raise
                    finally:
                        # A named-stream callback after FLUSH or RELEASE owns a
                        # fresh close-settle window even when its syscall fails.
                        # Reset the same phase that was cancelled: an unsealed
                        # FLUSH candidate must not be stranded until SMB's much
                        # later lease RELEASE.
                        if (
                            (flush_timer is not None or publish_timer is not None)
                            and not self._closed
                            and self._sessions.get(remote) is session
                            and not session.publishing
                            and not session.failed_mutation
                            and not session.journaled
                            and remote not in self._timers
                            and remote not in self._flush_timers
                        ):
                            replacement = (
                                self._new_publish_timer(remote, self.settle_seconds)
                                if session.sealed
                                else self._new_flush_publish_timer(remote)
                            )
                            timers = (
                                self._timers if session.sealed else self._flush_timers
                            )
                            timers[remote] = replacement
                            replacement.start()
                    return result
                if self._file_view(remote) is None:
                    raise OSError(errno.ENOENT, "The mounted file does not exist.")
                if require_writable_stage:
                    materialized = self.database.get_materialized(remote)
                    if materialized is None or materialized.state == "absent":
                        raise OSError(
                            errno.EBUSY,
                            "The mounted file is still reconciling.",
                        )

            if session is not None:
                pristine = session.pristine_read_view()
                if pristine is None:
                    continue
                if pristine.local_fingerprint is not None:

                    def update_pristine(
                        _view: _FileView,
                    ) -> tuple[Any, FileFingerprint]:
                        def apply_pinned(
                            descriptor: int,
                        ) -> tuple[Any, FileFingerprint]:
                            result = operation(descriptor)
                            return result, _descriptor_fingerprint(descriptor)

                        return self.workspace.with_regular_file_descriptor(
                            remote,
                            apply_pinned,
                            allow_mtime_change=allow_mtime_change,
                        )

                    applied, result, previous, current = (
                        session.with_pristine_local_metadata(
                            update_pristine,
                            allow_mtime_change=allow_mtime_change,
                        )
                    )
                    if applied:
                        assert previous is not None and current is not None
                        acknowledge_metadata(previous, current)
                        return result
                    # A first write raced this metadata request. Resolve the
                    # session again and apply it to the now-authoritative stage.
                    continue
            observed: list[tuple[FileFingerprint, FileFingerprint]] = []

            def apply_local(descriptor: int) -> Any:
                if not require_writable_stage:
                    return operation(descriptor)
                before = _descriptor_fingerprint(descriptor)
                try:
                    return operation(descriptor)
                finally:
                    # As with a retained mount stage, sync then fingerprint
                    # even when the metadata syscall reports an error: some
                    # filesystems can mutate ctime before returning failure.
                    os.fsync(descriptor)
                    after = _descriptor_fingerprint(descriptor)
                    unchanged = (
                        _same_file_storage(before, after)
                        if allow_mtime_change
                        else _same_file_bytes(before, after)
                    )
                    if not unchanged:
                        raise OSError(
                            errno.ESTALE,
                            "A mounted metadata update changed the file bytes.",
                        )
                    observed.append((before, after))

            try:
                return self.workspace.with_regular_file_descriptor(
                    remote,
                    apply_local,
                    allow_mtime_change=allow_mtime_change,
                )
            except FileNotFoundError as error:
                code = errno.ENOTSUP if require_writable_stage else _ENOATTR
                raise OSError(
                    code,
                    "The remote-only file has no local extended-attribute inode.",
                ) from error
            finally:
                if require_writable_stage and observed:
                    previous, current = observed[-1]
                    acknowledge_metadata(previous, current)

    def getxattr(self, path: str, name: str, position: int = 0) -> bytes:
        if name != _MACOS_QUARANTINE_XATTR:
            raise OSError(_ENOATTR, "The extended attribute does not exist.")
        if self.getattr(path).is_directory:
            raise OSError(_ENOATTR, "Directories have no mounted attributes.")
        return bytes(
            self._with_local_metadata_descriptor(
                path,
                lambda descriptor: _darwin_get_quarantine_xattr(
                    descriptor, position
                ),
            )
        )

    def listxattr(self, path: str) -> list[str]:
        try:
            self.getxattr(path, _MACOS_QUARANTINE_XATTR)
        except OSError as error:
            if error.errno == _ENOATTR:
                return []
            raise
        return [_MACOS_QUARANTINE_XATTR]

    def set_times(self, path: str, times: Any | None = None) -> None:
        """Apply a client's modification identity to the exact local inode.

        FUSE-T's SMB server can acknowledge a cached create before its delayed
        WRITE reaches this process. The client consequently remembers the
        create-time mtime while the stage inode, created a little later, gets a
        different kernel mtime. NSDocument interprets that difference as an
        external edit and rejects its first save. Preserve the SMB timestamp on
        the stage/materialized inode and rebase its durable fingerprint without
        changing any bytes. Remote-only files stay metadata-synthetic and are
        not hydrated merely for a timestamp hint.
        """

        remote = self._remote_path(path)
        assert remote is not None
        if self.getattr(path).is_directory:
            return

        if times is not None and (
            not isinstance(times, (tuple, list)) or len(times) != 2
        ):
            raise OSError(errno.EINVAL, "The mounted timestamp is invalid.")

        def apply(descriptor: int) -> None:
            current = os.fstat(descriptor)
            if times is None:
                stamp = time.time_ns()
                atime_ns = mtime_ns = stamp
            else:
                atime, mtime = times

                def timestamp_ns(value: Any, fallback: int) -> int:
                    if value is None:
                        return fallback
                    if isinstance(value, bool) or not isinstance(
                        value, (int, float)
                    ):
                        raise OSError(errno.EINVAL, "The mounted timestamp is invalid.")
                    try:
                        seconds = float(value)
                    except (OverflowError, ValueError) as error:
                        raise OSError(
                            errno.EINVAL, "The mounted timestamp is invalid."
                        ) from error
                    if not math.isfinite(seconds) or seconds < 0:
                        raise OSError(
                            errno.EINVAL, "The mounted timestamp is invalid."
                        )
                    nanoseconds = seconds * 1_000_000_000
                    if nanoseconds > 2**63 - 1:
                        raise OSError(
                            errno.EINVAL, "The mounted timestamp is invalid."
                        )
                    return int(nanoseconds)

                atime_ns = timestamp_ns(atime, current.st_atime_ns)
                mtime_ns = timestamp_ns(mtime, current.st_mtime_ns)
            _set_descriptor_times_ns(descriptor, atime_ns, mtime_ns)

        try:
            self._with_local_metadata_descriptor(
                path,
                apply,
                require_writable_stage=True,
                allow_mtime_change=True,
            )
        except OSError as error:
            if (
                error.errno in (errno.EBUSY, errno.ENOTSUP)
                and self._local_fingerprint(remote) is None
            ):
                # A remote-only inode has no persistent local metadata to
                # update. Keep the existing synthetic timestamp and, most
                # importantly, do not download its bytes for this advisory op.
                return
            raise

    def setxattr(
        self,
        path: str,
        name: str,
        value: bytes,
        options: int,
        position: int = 0,
    ) -> None:
        if name != _MACOS_QUARANTINE_XATTR:
            raise OSError(errno.ENOTSUP, "The extended attribute is unsupported.")
        if self.getattr(path).is_directory:
            raise OSError(errno.ENOTSUP, "Directory xattrs are unsupported.")
        self._with_local_metadata_descriptor(
            path,
            lambda descriptor: _darwin_set_quarantine_xattr(
                descriptor,
                value,
                options=options,
                position=position,
            ),
            require_writable_stage=True,
        )

    def removexattr(self, path: str, name: str) -> None:
        if name != _MACOS_QUARANTINE_XATTR:
            raise OSError(_ENOATTR, "The extended attribute does not exist.")
        if self.getattr(path).is_directory:
            raise OSError(_ENOATTR, "Directories have no mounted attributes.")
        self._with_local_metadata_descriptor(
            path,
            _darwin_remove_quarantine_xattr,
            require_writable_stage=True,
        )


@dataclass(frozen=True)
class _PendingWriteSession:
    """Everything a new write session needs, decided under the backend lock."""

    remote: str
    base_digest: str | None
    existing_local: "FileFingerprint | None"
    pristine_view: "_FileView | None"
    created: bool
    base_size_bytes: int
    sidecar_key: tuple[str, str] | None
    transport_provenance: str | None
    renamed_source: bool = False


@dataclass(eq=False)
class _WorkspaceBackendRoute:
    """One workspace backend retained while visible or referenced by a handle."""

    backend: FabricMountBackend
    label: str
    visible: bool = True
    active_calls: int = 0
    open_handles: int = 0


class MultiWorkspaceMountBackend:
    """Route one native ``Meshia`` mount directly into workspace roots.

    Every child retains an independent Fabric authority, journal, bounded
    cache, staging ledger, watcher, and coordinator. This layer owns only the
    namespace map and global FUSE handles; it never copies bytes or introduces
    a second synchronization engine.

    Catalog replacement is atomic. Removed-account workspaces disappear for
    new lookups immediately, while already-open handles stay pinned to their
    original backend. Retired backends close after the last call and handle
    drain, preserving pending-write evidence during account cutover.
    """

    def __init__(
        self,
        storage_root: Path | str,
        workspaces: Mapping[str, FabricMountBackend] | None = None,
        *,
        logger: NodeLogger = NULL_LOGGER,
    ) -> None:
        self.storage_root = Path(storage_root).expanduser()
        self.logger = logger
        self._stage_capacity = _LocalStageCapacity(self.storage_root)
        self._lock = threading.RLock()
        # A signed root rename is a topology change. Serialize topology without
        # holding the namespace lock during its network request.
        self._topology_lock = threading.Lock()
        self._routes: dict[str, _WorkspaceBackendRoute] = {}
        self._folded_routes: dict[str, _WorkspaceBackendRoute] = {}
        self._retired: set[_WorkspaceBackendRoute] = set()
        self._handles: dict[int, tuple[_WorkspaceBackendRoute, int]] = {}
        self._next_handle = 1
        self._namespace_invalidator: Callable[[str], bool] | None = None
        self._compute_icon_sink: Callable[[Iterable[str]], tuple[str, ...]] | None = None
        # The last running set the catalog published. The catalog projects
        # (and publishes) during ``prepare_mount``, before any native mount has
        # attached, so a sink installed afterwards must be handed this set or
        # an already-running workspace stays untagged until the next catalog
        # generation moves -- up to a full refresh interval after startup.
        self._compute_running_labels: tuple[str, ...] = ()
        # Catalog-published content modification time per workspace label
        # (epoch ns). The root and every workspace folder answer getattr
        # without activating a runtime, so this is what their st_mtime shows
        # instead of "now" (which made every folder look modified at mount).
        self._workspace_modified_ns: dict[str, int] = {}
        self._closed = False
        self.replace_workspaces(workspaces or {})

    def set_namespace_invalidator(
        self, invalidator: Callable[[str], bool] | None
    ) -> None:
        """Install the mount-owned cache notification hook.

        The hook is lifecycle-scoped to one native mount.  Runtime polling may
        outlive an OS detach briefly, so replacement and removal are atomic and
        callers always invoke the captured callback outside the namespace lock.
        """

        with self._lock:
            self._namespace_invalidator = invalidator

    def set_compute_icon_sink(
        self, sink: Callable[[Iterable[str]], tuple[str, ...]] | None
    ) -> None:
        """Install the mount-owned running-compute icon hook.

        Lifecycle-scoped exactly like the namespace invalidator: one native
        mount owns it, replacement and removal are atomic, and the captured
        callback is always invoked outside the namespace lock.
        """

        with self._lock:
            self._compute_icon_sink = sink
            replay = self._compute_running_labels
        if sink is not None:
            # Replay the current running set so the mount is correct the
            # moment it attaches, instead of after the next catalog refresh.
            # The sink is idempotent, so an empty or unchanged set is free.
            sink(replay)

    def set_workspace_modified(self, modified: Mapping[str, int]) -> None:
        """Publish each workspace root's last content modification (epoch ns).

        Labels missing from ``modified`` keep no stamp and fall back to the
        mount's own clock, exactly as before M1790.
        """

        stamps = {
            str(label): int(stamp)
            for label, stamp in modified.items()
            if str(label) and isinstance(stamp, int) and not isinstance(stamp, bool) and stamp > 0
        }
        with self._lock:
            self._workspace_modified_ns = stamps

    def _workspace_root_modified_ns(self, label: str | None) -> int:
        with self._lock:
            if label is None:
                stamps = tuple(
                    stamp
                    for route_label, stamp in self._workspace_modified_ns.items()
                    if self._fold(route_label) in self._folded_routes
                )
                return max(stamps) if stamps else time.time_ns()
            stamp = self._workspace_modified_ns.get(label)
        return stamp if stamp else time.time_ns()

    def set_compute_running(self, labels: Iterable[str]) -> tuple[str, ...]:
        """Publish the workspace roots whose compute is running.

        Safe to call when no native mount is attached (the catalog advances
        whether or not the user has the folder open): the set is remembered
        for the next sink to install, and nothing else happens.
        """

        running = tuple(str(label) for label in labels if str(label))
        with self._lock:
            self._compute_running_labels = running
            sink = self._compute_icon_sink
        if sink is None:
            return ()
        return tuple(sink(running))

    def invalidate_workspace(
        self, workspace_name: str, changed_paths: Iterable[str] = ()
    ) -> int:
        """Notify the OS about one remotely changed workspace namespace.

        Invalidating the workspace directory makes newly-created root entries
        visible in an already-open Finder window.  Exact files and their
        immediate parents cover nested creates, deletes, renames, and metadata
        changes without constructing an unbounded full-manifest diff.
        """

        with self._lock:
            route = self._folded_routes.get(self._fold(workspace_name))
            invalidator = self._namespace_invalidator
            if (
                self._closed
                or route is None
                or not route.visible
                or invalidator is None
            ):
                return 0
            label = route.label

        root = f"/{label}"
        notifications: dict[str, None] = {root: None}
        for changed_path in changed_paths:
            try:
                parts = split_relative(changed_path)
            except (InvalidTask, UnsafePath):
                continue
            target = f"{root}/{'/'.join(parts)}"
            if len(parts) > 1:
                notifications[f"{root}/{'/'.join(parts[:-1])}"] = None
            notifications[target] = None
        return self._deliver_namespace_invalidations(invalidator, notifications)

    def _deliver_namespace_invalidations(
        self,
        invalidator: Callable[[str], bool],
        paths: Iterable[str],
    ) -> int:
        """Deliver a bounded, de-duplicated notification set outside locks."""

        delivered = 0
        for path in dict.fromkeys(paths):
            try:
                delivered += int(bool(invalidator(path)))
            except Exception as error:
                self.logger.record(
                    "fabric_mount_namespace_invalidation_failed",
                    path=path,
                    error=str(error),
                )
        return delivered

    @staticmethod
    def _fold(label: str) -> str:
        return label.casefold()

    @staticmethod
    def _validate_label(label: str) -> None:
        try:
            valid = len(split_relative(label)) == 1
        except (InvalidTask, UnsafePath):
            valid = False
        if not valid:
            raise ValueError("workspace labels must be portable path components")

    @staticmethod
    def _path_root(path: str) -> str | None:
        if path == "/":
            return None
        if not isinstance(path, str) or not path.startswith("/"):
            raise OSError(errno.EINVAL, "Mounted paths must be absolute.")
        try:
            parts = split_relative(path[1:])
        except (InvalidTask, UnsafePath) as error:
            raise OSError(errno.EINVAL, str(error)) from error
        return parts[0]

    @staticmethod
    def _canonical_path(path: str, route: _WorkspaceBackendRoute) -> str:
        root = MultiWorkspaceMountBackend._path_root(path)
        if root is None or root == route.label:
            return path
        suffix = path[len(root) + 1 :]
        return f"/{route.label}{suffix}"

    def _collect_close_locked(
        self, route: _WorkspaceBackendRoute
    ) -> FabricMountBackend | None:
        if route.visible or route.active_calls or route.open_handles:
            return None
        self._retired.discard(route)
        return route.backend

    @staticmethod
    def _close_backends(backends: Iterable[FabricMountBackend | None]) -> None:
        seen: set[int] = set()
        for backend in backends:
            if backend is None or id(backend) in seen:
                continue
            seen.add(id(backend))
            backend.close()

    def replace_workspaces(
        self, workspaces: Mapping[str, FabricMountBackend]
    ) -> None:
        """Atomically install a complete authenticated workspace projection."""

        prepared: dict[str, FabricMountBackend] = {}
        folded: dict[str, str] = {}
        for label, backend in workspaces.items():
            self._validate_label(label)
            key = self._fold(label)
            if key in folded:
                raise ValueError(
                    f"workspace labels {folded[key]!r} and {label!r} collide"
                )
            if backend.workspace_name != label:
                backend.set_workspace_name(label)
            share_capacity = getattr(backend, "set_stage_capacity", None)
            if callable(share_capacity):
                share_capacity(self._stage_capacity)
            prepared[label] = backend
            folded[key] = label

        to_close: list[FabricMountBackend | None] = []
        invalidator: Callable[[str], bool] | None = None
        changed_labels: tuple[str, ...] = ()
        with self._topology_lock:
            with self._lock:
                if self._closed:
                    raise StateError("The Meshia mount backend is closed.")
                previous_identities = {
                    label: id(route.backend) for label, route in self._routes.items()
                }
                reusable = {
                    id(route.backend): route
                    for route in (*self._routes.values(), *self._retired)
                }
                replacement: dict[str, _WorkspaceBackendRoute] = {}
                replacement_folded: dict[str, _WorkspaceBackendRoute] = {}
                retained: set[_WorkspaceBackendRoute] = set()
                for label, backend in prepared.items():
                    route = reusable.get(id(backend))
                    if route is None:
                        route = _WorkspaceBackendRoute(backend, label)
                    route.label = label
                    route.visible = True
                    replacement[label] = route
                    replacement_folded[self._fold(label)] = route
                    retained.add(route)
                    self._retired.discard(route)
                previous = set(self._routes.values())
                self._routes = replacement
                self._folded_routes = replacement_folded
                current_identities = {
                    label: id(route.backend) for label, route in replacement.items()
                }
                identity_changes = {
                    label
                    for label in previous_identities.keys() | current_identities.keys()
                    if previous_identities.get(label) != current_identities.get(label)
                }
                if identity_changes:
                    invalidator = self._namespace_invalidator
                    changed_labels = tuple(
                        sorted(identity_changes, key=str.casefold)
                    )
                for route in previous - retained:
                    route.visible = False
                    self._retired.add(route)
                    to_close.append(self._collect_close_locked(route))
        self._close_backends(to_close)
        if invalidator is not None:
            self._deliver_namespace_invalidations(
                invalidator,
                ("/", *(f"/{label}" for label in changed_labels)),
            )

    def _pin_path(self, path: str) -> tuple[_WorkspaceBackendRoute, str]:
        root = self._path_root(path)
        if root is None:
            raise OSError(errno.EISDIR, "The Meshia root is a directory.")
        with self._lock:
            if self._closed:
                raise OSError(errno.EIO, "The Meshia mount is closed.")
            route = self._folded_routes.get(self._fold(root))
            if route is None or not route.visible:
                raise OSError(errno.ENOENT, "The workspace does not exist.")
            route.active_calls += 1
            return route, self._canonical_path(path, route)

    def _unpin(self, route: _WorkspaceBackendRoute) -> None:
        with self._lock:
            route.active_calls -= 1
            close = self._collect_close_locked(route)
        self._close_backends((close,))

    def _path_call(self, path: str, operation: str, *args: Any, **kwargs: Any) -> Any:
        route, canonical = self._pin_path(path)
        try:
            return getattr(route.backend, operation)(canonical, *args, **kwargs)
        finally:
            self._unpin(route)

    def _reject_root_removal(self, path: str) -> None:
        root = self._path_root(path)
        if root is None or path != f"/{root}":
            return
        with self._lock:
            route = self._folded_routes.get(self._fold(root))
            if route is None or not route.visible:
                raise OSError(errno.ENOENT, "The workspace does not exist.")
        raise OSError(
            errno.EPERM,
            "Workspace roots are managed by Meshia and cannot be removed from the mount.",
        )

    def _validate_managed_directory_root(self, path: str) -> bool:
        """Validate mount/workspace roots without activating a lazy runtime."""

        root = self._path_root(path)
        if root is None:
            return True
        if path != f"/{root}":
            return False
        with self._lock:
            route = self._folded_routes.get(self._fold(root))
            if route is None or not route.visible:
                raise OSError(errno.ENOENT, "The workspace does not exist.")
        return True

    def statfs_capacity(self, path: str) -> tuple[int, int] | None:
        """Return remote quota/usage without starting any workspace runtime.

        The single native share reports the sum of every visible workspace at
        its root. A direct workspace query reports that workspace alone. Old
        persisted catalogs do not contain quota evidence; returning ``None``
        lets the FUSE adapter use its compatibility fallback until the first
        successful signed catalog refresh.
        """

        if path == "/":
            with self._lock:
                if self._closed:
                    raise OSError(errno.EIO, "The Meshia mount is closed.")
                backends = tuple(route.backend for route in self._routes.values())
        else:
            route, _canonical = self._pin_path(path)
            try:
                backends = (route.backend,)
            finally:
                self._unpin(route)
        capacities: list[tuple[int, int]] = []
        for backend in backends:
            capacity = getattr(backend, "statfs_capacity", None)
            value = capacity() if callable(capacity) else None
            if value is None:
                return None
            total_bytes, used_bytes = value
            if total_bytes < 1 or used_bytes < 0 or used_bytes > total_bytes:
                raise OSError(errno.EIO, "Meshia returned invalid workspace capacity.")
            capacities.append((total_bytes, used_bytes))
        total = sum(value for value, _used in capacities)
        used = sum(value for _total, value in capacities)
        if path == "/" and total > MAX_STATFS_BYTES:
            # Individual workspace quotas remain exact. Only the synthetic
            # aggregate share saturates, and used bytes saturate conservatively
            # so the mount never advertises more writable capacity than exists.
            total = MAX_STATFS_BYTES
            used = min(used, total)
        return total, used

    def local_stage_statfs(self) -> tuple[int, int]:
        """Read the shared staging volume once without activating children."""

        return self._stage_capacity.snapshot()

    def getattr(self, path: str) -> MountNode:
        if path == "/":
            return MountNode("/", True, 0, self._workspace_root_modified_ns(None))
        root = self._path_root(path)
        if root is not None and path == f"/{root}":
            with self._lock:
                route = self._folded_routes.get(self._fold(root))
                if route is None or not route.visible:
                    raise OSError(errno.ENOENT, "The workspace does not exist.")
                # Finder/Explorer probes every direct child while rendering the
                # mount. Keep that metadata-only operation lazy so a user with
                # many workspaces does not start every watcher/cache runtime.
                label = route.label
            return MountNode(
                f"/{label}", True, 0, self._workspace_root_modified_ns(label)
            )
        return self._path_call(path, "getattr")

    def listdir(self, path: str) -> tuple[str, ...]:
        if path == "/":
            with self._lock:
                if self._closed:
                    raise OSError(errno.EIO, "The Meshia mount is closed.")
                return tuple(
                    sorted(self._routes, key=lambda value: (value.casefold(), value))
                )
        return self._path_call(path, "listdir")

    def listdir_entries(self, path: str) -> tuple[tuple[str, MountNode], ...]:
        if path == "/":
            with self._lock:
                if self._closed:
                    raise OSError(errno.EIO, "The Meshia mount is closed.")
                labels = sorted(
                    self._routes, key=lambda value: (value.casefold(), value)
                )
                now = time.time_ns()
                stamps = dict(self._workspace_modified_ns)
                return tuple(
                    (label, MountNode(f"/{label}", True, 0, stamps.get(label) or now))
                    for label in labels
                )
        return self._path_call(path, "listdir_entries")

    def open(self, path: str, flags: int, *, create: bool = False) -> int:
        route, canonical = self._pin_path(path)
        try:
            local_handle = route.backend.open(canonical, flags, create=create)
            with self._lock:
                if self._closed:
                    route.backend.release(local_handle)
                    raise OSError(errno.EIO, "The Meshia mount is closed.")
                handle = self._next_handle
                self._next_handle += 1
                self._handles[handle] = (route, local_handle)
                route.open_handles += 1
                return handle
        finally:
            self._unpin(route)

    def _handle(self, handle: int) -> tuple[_WorkspaceBackendRoute, int]:
        with self._lock:
            value = self._handles.get(handle)
            if value is None:
                raise OSError(errno.EBADF, "The mounted handle is closed.")
            return value

    def read(self, handle: int, offset: int, size: int) -> bytes:
        route, local = self._handle(handle)
        return route.backend.read(local, offset, size)

    def getattr_handle(self, handle: int) -> MountNode:
        route, local = self._handle(handle)
        return route.backend.getattr_handle(local)

    def write(self, handle: int, offset: int, data: bytes) -> int:
        route, local = self._handle(handle)
        return route.backend.write(local, offset, data)

    def command_write(
        self,
        path: str,
        data: bytes,
        expected_sha256: str | None = None,
        create_parents: bool = False,
    ) -> dict[str, Any]:
        return self._path_call(
            path, "command_write", data,
            expected_sha256=expected_sha256, create_parents=create_parents,
        )

    def truncate(self, path: str | None, length: int, *, handle: int | None = None) -> None:
        if handle is not None:
            route, local = self._handle(handle)
            route.backend.truncate(
                self._canonical_path(path, route) if path is not None else None, length, handle=local
            )
            return
        self._path_call(path, "truncate", length)

    def fsync(self, handle: int) -> None:
        route, local = self._handle(handle)
        route.backend.fsync(local)

    def flush(self, handle: int) -> None:
        with self._lock:
            value = self._handles.get(handle)
        if value is None:
            # FUSE-T's SMB bridge flushes a handle it already released
            # (observed 153x in the first 11 s of a Finder folder drop). The
            # bytes are gone with the release; answering EBADF only makes the
            # client retry and slows the drop.
            return
        route, local = value
        route.backend.flush(local)

    def release(self, handle: int) -> None:
        with self._lock:
            value = self._handles.pop(handle, None)
        if value is None:
            return
        route, local = value
        try:
            route.backend.release(local)
        finally:
            with self._lock:
                route.open_handles -= 1
                close = self._collect_close_locked(route)
            self._close_backends((close,))

    def unlink(self, path: str) -> None:
        self._reject_root_removal(path)
        self._path_call(path, "unlink")

    def mkdir(self, path: str) -> None:
        self._path_call(path, "mkdir")

    def rmdir(self, path: str) -> None:
        self._reject_root_removal(path)
        self._path_call(path, "rmdir")

    def getxattr(self, path: str, name: str, position: int = 0) -> bytes:
        if self._validate_managed_directory_root(path):
            raise OSError(_ENOATTR, "The extended attribute does not exist.")
        return bytes(self._path_call(path, "getxattr", name, position))

    def listxattr(self, path: str) -> list[str]:
        if self._validate_managed_directory_root(path):
            return []
        return list(self._path_call(path, "listxattr"))

    def setxattr(
        self,
        path: str,
        name: str,
        value: bytes,
        options: int,
        position: int = 0,
    ) -> None:
        if self._validate_managed_directory_root(path):
            raise OSError(errno.ENOTSUP, "Directory xattrs are unsupported.")
        self._path_call(path, "setxattr", name, value, options, position)

    def removexattr(self, path: str, name: str) -> None:
        if self._validate_managed_directory_root(path):
            raise OSError(_ENOATTR, "The extended attribute does not exist.")
        self._path_call(path, "removexattr", name)

    def set_times(self, path: str, times: Any | None = None) -> None:
        """Forward one client timestamp to its selected workspace runtime."""

        if self._validate_managed_directory_root(path):
            return
        self._path_call(path, "set_times", times)

    def rename(self, source_path: str, destination_path: str) -> None:
        source_root = self._path_root(source_path)
        destination_root = self._path_root(destination_path)
        if source_root is None or destination_root is None:
            raise OSError(errno.EXDEV, "Workspace roots cannot leave Meshia.")
        source_is_root = source_path == f"/{source_root}"
        destination_is_root = destination_path == f"/{destination_root}"
        if not source_is_root and not destination_is_root:
            # A file/directory rename is child namespace work, not a catalog
            # change. Pin both names against one projection, then release the
            # routing lock just like every other child operation. Holding the
            # topology lock while a safe-save waits for its PUT receipt blocks
            # the engine's synchronous catalog push, and therefore the very
            # poll that must publish that receipt.
            with self._lock:
                source_route, source = self._pin_path(source_path)
                destination_route = self._folded_routes.get(
                    self._fold(destination_root)
                )
                destination = self._canonical_path(destination_path, source_route)
            try:
                if destination_route is not source_route:
                    raise OSError(errno.EXDEV, "Files cannot move across workspaces.")
                source_route.backend.rename(source, destination)
            finally:
                self._unpin(source_route)
            return
        with self._topology_lock:
            source_route, source = self._pin_path(source_path)
            try:
                with self._lock:
                    destination_route = self._folded_routes.get(
                        self._fold(destination_root)
                    )
                if source_is_root or destination_is_root:
                    if not source_is_root or not destination_is_root:
                        raise OSError(errno.EXDEV, "Workspace roots cannot be nested.")
                    if (
                        destination_route is not None
                        and destination_route is not source_route
                    ):
                        raise OSError(errno.EEXIST, "A workspace already uses that name.")
                    source_route.backend.rename(source, f"/{destination_root}")
                    updated = source_route.backend.workspace_name
                    invalidator: Callable[[str], bool] | None = None
                    previous_label = source_route.label
                    with self._lock:
                        if source_route.visible:
                            self._routes.pop(source_route.label, None)
                            self._folded_routes.pop(
                                self._fold(source_route.label), None
                            )
                            source_route.label = updated
                            self._routes[updated] = source_route
                            self._folded_routes[self._fold(updated)] = source_route
                            invalidator = self._namespace_invalidator
                    if invalidator is not None and previous_label != updated:
                        self._deliver_namespace_invalidations(
                            invalidator,
                            ("/", f"/{previous_label}", f"/{updated}"),
                        )
                    return
            finally:
                self._unpin(source_route)

    def close(self) -> None:
        with self._topology_lock:
            with self._lock:
                if self._closed:
                    return
                self._closed = True
                routes = set(self._routes.values()) | self._retired
                self._routes.clear()
                self._folded_routes.clear()
                self._retired.clear()
                self._handles.clear()
                self._namespace_invalidator = None
                for route in routes:
                    route.visible = False
        self._close_backends(route.backend for route in routes)


#: Refusals that are internal Meshia fences rather than ordinary POSIX
#: outcomes. macOS smbfs renders these to Finder as "you don't have
#: permission", so when one fires the user sees a failure with no explanation
#: -- and until now the service log recorded nothing at all, which cost three
#: rounds of hypothesis-driven debugging against live folder copies. They are
#: reported (rate limited by the adapter) instead of being silenced.
MOUNT_FENCE_ERRNOS = frozenset(
    {
        errno.EACCES,
        # EAGAIN is what FUSE-T's SMB client turns into a Finder "permission"
        # failure; it was silent in the service log (2026-09-02), so it is a
        # rate-limited fence record now, like EBUSY.
        errno.EAGAIN,
        errno.EBUSY,
        errno.EPERM,
    }
)

_QUIET_MOUNT_ERRNOS = frozenset(
    {
        errno.EEXIST,
        errno.EXDEV,
        errno.EINVAL,
        errno.EISDIR,
        errno.ENOENT,
        errno.ENOTDIR,
        errno.ENOTEMPTY,
        errno.ENOTSUP,
        errno.ENOSPC,
        _ENOATTR,
        errno.E2BIG,
        errno.ERANGE,
        errno.EHOSTUNREACH,
        errno.EROFS,
        errno.ESTALE,
    }
)

#: Every exception class a native adapter (FUSE, WinFsp, FSKit) converts into
#: one POSIX errno for the kernel. Anything else is a programming error.
MOUNT_ADAPTER_ERRORS: tuple[type[BaseException], ...] = (
    OSError,
    RemoteError,
    NetworkError,
    FabricMountError,
    InvalidTask,
    StateError,
    TransferError,
    UnsafePath,
    # Local capacity and cache failures reach the mount on the ordinary read
    # path -- hydrating a remote-only entry is exactly where the materialized
    # cache budget is enforced. They were absent here, so they escaped `_call`
    # uncaught: no errno translation, no log line, and FUSE-T's SMB bridge
    # rendered the unmapped failure to macOS as EACCES. Users then saw
    # "Permission denied" on a file whose permissions were fine, with total
    # silence in the service log.
    TransferError,
    FabricCacheError,
)


def mount_error_report(
    error: BaseException, *, operation: str
) -> tuple[int, dict[str, Any] | None]:
    """Map one backend failure to ``(errno, log_record)`` for a native adapter.

    Every native front end (fusepy on FUSE-T/libfuse/WinFsp and the FSKit
    bridge) shares this exact policy so an error looks the same to the user
    regardless of transport. ``log_record`` is ``None`` for ordinary,
    expected POSIX outcomes that must not spam the service log.
    """

    if isinstance(error, StagingQuotaExceeded) and not isinstance(
        error, StagingRepairPending
    ):
        # Local capacity, not permission. This reached the kernel as a generic
        # EIO (and over macOS smbfs as "you don't have permission"), which sent
        # the owner to check file permissions for a full cache. ENOSPC is the
        # honest code, and unlike a plain OSError(ENOSPC) -- which is quiet
        # because a real disk-full during a large copy would flood the log --
        # this one always records its reason, because it is a Meshia fence the
        # user cannot otherwise see. ``StagingRepairPending`` is deliberately
        # excluded: it is a transient repair, not "the disk has no room", and
        # keeps the classification it already had.
        return errno.ENOSPC, {
            "operation": operation,
            "error_code": type(error).__name__,
            "error": str(error),
            "fence": True,
        }
    if isinstance(error, OSError):
        number = error.errno or errno.EIO
        if number in _QUIET_MOUNT_ERRNOS:
            # A quiet errno on a per-file callback is an ordinary POSIX outcome.
            # The SAME errno on a whole-directory listing is not: an EACCES that
            # fences a readdir looks identical to a real permission denial and
            # hid a regression for a day. Also expose copy callback failures;
            # local disk capacity already has its own bounded diagnostic.
            if operation in _LISTING_OPERATIONS or (number != errno.ENOSPC and operation in {
                "write", "truncate", "flush", "fsync", "release"
            }):
                return number, {
                    "operation": operation,
                    "error_code": errno.errorcode.get(number, "EIO"),
                    "error": str(error),
                    "fence": True,
                }
            return number, None
        report = {
            "operation": operation,
            "error_code": errno.errorcode.get(number, "EIO"),
            "error": str(error),
        }
        if number in MOUNT_FENCE_ERRNOS:
            # A fence is expected to recur while it holds; the adapter keeps
            # one record per (operation, code) per minute so a busy copy
            # cannot flood the log.
            report["fence"] = True
        return number, report
    if isinstance(error, RemoteError):
        # A manifest entry with no durable backing object is an
        # authoritative content-integrity failure, not an empty file and
        # not a transient host outage. Keep ordinary retryable control/data
        # errors distinct so the native client can retry them naturally.
        number = (
            errno.EIO
            if error.status == 409 and error.remote_code == "FABRIC_CONTENT_MISSING"
            else errno.EHOSTUNREACH
            if error.retryable
            else errno.EIO
        )
        remote_code = (
            error.remote_code
            if isinstance(error.remote_code, str)
            and _REMOTE_ERROR_CODE_RE.fullmatch(error.remote_code)
            else type(error).__name__
        )
        return number, {
            "operation": operation,
            "error_code": remote_code,
            "remote_status": error.status,
            "error": (
                "Remote Fabric content is unavailable."
                if number == errno.EIO and remote_code == "FABRIC_CONTENT_MISSING"
                else "Remote Fabric request failed."
            ),
        }
    if isinstance(error, NetworkError):
        return errno.EHOSTUNREACH, {
            "operation": operation,
            "error_code": type(error).__name__,
            "error": "Remote Fabric transport is unavailable.",
        }
    if isinstance(error, (TransferError, FabricCacheError)):
        # A local-capacity refusal is "there is no room here", never "you may
        # not". ENOSPC/EAGAIN say that truthfully and macOS renders them as a
        # full disk or a busy resource instead of a permission problem. These
        # errnos are otherwise quiet, so the record is built here rather than
        # through the OSError branch: a read that cannot hydrate must always
        # name its reason and its path in the service log.
        number = (
            errno.EAGAIN
            if isinstance(error, StagingRepairPending)
            else errno.ENOSPC
            if isinstance(error, StagingQuotaExceeded)
            else errno.EIO
        )
        return number, {
            "operation": operation,
            "error_code": type(error).__name__,
            "error": str(error),
        }
    return errno.EIO, {
        "operation": operation,
        "error_code": type(error).__name__,
        "error": str(error),
    }


class FabricFuseOperations:
    """Small fusepy adapter; all policy remains in ``FabricMountBackend``."""

    def __init__(
        self,
        backend: FabricMountBackend,
        fuse_error: type[BaseException],
        *,
        publish_writes_on_flush: bool = False,
        notification_context: Callable[[], int | None] | None = None,
        notification_invalidator: Callable[[int, bytes], int] | None = None,
        break_metadata_only_smb_leases: bool = False,
        compute_icons: bool | None = None,
        native_mount_point: Path | None = None,
    ) -> None:
        self.backend = backend
        self.fuse_error = fuse_error
        self.publish_writes_on_flush = publish_writes_on_flush
        self._native_directory_watch = None
        if sys.platform == "darwin" and publish_writes_on_flush and native_mount_point is not None:
            from .native_directory_watch import NativeDirectoryWatch
            self._native_directory_watch = NativeDirectoryWatch(native_mount_point)
        self._notification_context = notification_context
        self._notification_invalidator = notification_invalidator
        # Keep a backend namespace mutation and its live SMB path-index update
        # in one order only where their paths can overlap. FUSE callbacks are
        # threaded, so an Open of a rename destination must not land between
        # the backend rename and lease-map retarget. A mount-wide lock made an
        # unrelated slow workspace/path stall every other Open and Create.
        # This tiny conflict registry orders equal/ancestor paths while sibling
        # paths and other workspace roots remain concurrent.
        self._smb_namespace_condition = threading.Condition(threading.Lock())
        self._smb_namespace_active: dict[int, tuple[str, ...]] = {}
        self._smb_namespace_next = 1
        self._notification_lock = threading.Lock()
        self._notification_fuse: int | None = None
        self._notifications_enabled = bool(
            notification_context is not None and notification_invalidator is not None
        )
        self._break_metadata_only_smb_leases = bool(
            break_metadata_only_smb_leases and self._notifications_enabled
        )
        self._live_open_paths: dict[int, str] = {}
        self._live_path_handles: dict[str, set[int]] = {}
        self._content_io_handles: set[int] = set()
        self._lease_break_candidates: dict[int, tuple[str, float]] = {}
        self._lease_break_path_candidates: dict[str, set[int]] = {}
        self._lease_break_timer: threading.Timer | None = None
        # Write-back nudge registry: path -> (attempts, timer). Armed on the
        # first content IO of an SMB write description, cancelled by the FLUSH
        # (or RELEASE) that shows the client delivered its cached bytes.
        self._writeback_nudges: dict[str, tuple[int, threading.Timer]] = {}
        self._writeback_nudges_enabled = bool(
            publish_writes_on_flush and self._notifications_enabled
        )
        # Attribute micro-cache: path -> (expires_monotonic, stat mapping or
        # None for a proven ENOENT). CPython dict operations are atomic and
        # entries are immutable tuples, so no lock is needed; a racing evict
        # only costs one extra backend call.
        self._attr_cache: dict[str, tuple[float, Mapping[str, Any] | None]] = {}
        # Directory listings, cached on exactly the invalidation discipline the
        # attribute cache already proves correct. readdir was uncached, so every
        # listing took the backend lock and hit SQLite -- a GIL-RELEASING call,
        # which is the operation that collapses under sync-engine contention
        # (measured: 4 us alone, 11-74 ms behind interpreter-bound threads).
        # Finder enumerates directories constantly, so this was a recurring
        # multi-millisecond cost on the hot path. Pure-Python dict hits never
        # yield the GIL and so are immune (measured 0.04 us under any load).
        self._dir_cache: dict[str, tuple[float, tuple[str, ...]]] = {}
        # A local CREATE changes the namespace before its remote manifest is
        # refreshed. Keep that directory identity beyond the attribute TTL:
        # reverting to manifest time lets another SMB client retain a cached
        # ENOENT until the next remote publication. Only directories use this
        # overlay; file timestamps still belong to their exact byte version.
        self._directory_time_lock = threading.Lock()
        self._directory_modified_ns: dict[str, int] = {}
        self._retired_directory_modified_ns = 0
        # Rate-limit state for fence-refusal diagnostics (op:code -> last log).
        self._fence_logged_ns: dict[str, int] = {}
        # readdir-plus circuit breaker: path -> (consecutive_failures,
        # open_until_monotonic). While open_until is in the future the prewarm
        # is skipped for that path.
        self._prewarm_trip: dict[str, tuple[int, float]] = {}
        self._attr_cache_enabled = bool(publish_writes_on_flush)
        # Running-compute folder icons. Custom-icon phantoms are macOS Finder
        # semantics carried over SMB, so they follow the same transport signal
        # as the write-back nudge and the attribute cache; Linux libfuse and
        # Windows WinFsp mounts pass False and synthesize nothing.
        self._compute_icons = ComputeIconPhantoms(
            enabled=(
                bool(publish_writes_on_flush)
                if compute_icons is None
                else bool(compute_icons)
            )
        )
        self._phantom_handles: dict[int, ComputeIconPhantom] = {}
        # Phantom handles live far above the backend's counter so the two
        # spaces can never collide, whatever the backend hands out.
        self._next_phantom_handle = 1 << 48
        # op -> [count, total_ns, max_ns] for the current stats window.
        self._op_stats: dict[str, list[int]] = {}
        self._op_stats_lock = threading.Lock()
        self._op_stats_window_started = time.monotonic()

    @staticmethod
    def _normalized_smb_namespace_path(path: str) -> str:
        normalized = path.rstrip("/")
        return normalized or "/"

    @classmethod
    def _smb_namespace_paths_conflict(cls, left: str, right: str) -> bool:
        left = cls._normalized_smb_namespace_path(left)
        right = cls._normalized_smb_namespace_path(right)
        return bool(
            left == right
            or left == "/"
            or right == "/"
            or left.startswith(right + "/")
            or right.startswith(left + "/")
        )

    @contextmanager
    def _ordered_smb_namespace(self, *paths: str) -> Iterator[None]:
        """Order only lease-index operations whose namespace can overlap."""

        with self._notification_lock:
            enabled = self._break_metadata_only_smb_leases
        if not enabled:
            yield
            return
        ordered_paths = tuple(
            dict.fromkeys(self._normalized_smb_namespace_path(path) for path in paths)
        )
        with self._smb_namespace_condition:
            while any(
                self._smb_namespace_paths_conflict(path, active_path)
                for active_paths in self._smb_namespace_active.values()
                for path in ordered_paths
                for active_path in active_paths
            ):
                self._smb_namespace_condition.wait()
            token = self._smb_namespace_next
            self._smb_namespace_next += 1
            self._smb_namespace_active[token] = ordered_paths
        try:
            yield
        finally:
            with self._smb_namespace_condition:
                self._smb_namespace_active.pop(token, None)
                self._smb_namespace_condition.notify_all()

    def _discard_lease_break_candidate_locked(self, handle: int) -> None:
        candidate = self._lease_break_candidates.pop(handle, None)
        if candidate is None:
            return
        path = candidate[0]
        path_candidates = self._lease_break_path_candidates.get(path)
        if path_candidates is None:
            return
        path_candidates.discard(handle)
        if not path_candidates:
            self._lease_break_path_candidates.pop(path, None)

    def _discard_path_lease_break_candidates_locked(self, path: str) -> None:
        for handle in tuple(self._lease_break_path_candidates.pop(path, ())):
            self._lease_break_candidates.pop(handle, None)

    def _arm_lease_break_timer_locked(self) -> None:
        if (
            not self._break_metadata_only_smb_leases
            or self._lease_break_timer is not None
            or not self._lease_break_candidates
        ):
            return
        deadline = min(
            candidate[1] for candidate in self._lease_break_candidates.values()
        )
        timer: threading.Timer
        timer = threading.Timer(
            max(0.0, deadline - time.monotonic()),
            lambda: self._break_metadata_only_leases(timer),
        )
        timer.daemon = True
        self._lease_break_timer = timer
        timer.start()

    def _record_smb_open(
        self,
        path: str,
        handle: int,
        *,
        metadata_candidate: bool,
        existing_only: bool = False,
    ) -> None:
        """Track an Open and arm a break only for a same-path overlap.

        FUSE-T 1.2.7's SMB server records DELETE disposition only on its cached
        Open and invokes FUSE Unlink only when that Open closes. A macOS
        metadata Open can retain the lease after rm(1) returns when another
        Open exists for the same inode. A lone Open already drains normally,
        so ordinary browsing must not cause lease churn. The bundled helper
        exposes its cache-breaker through ``fuse_invalidate_path``; using it
        does not infer deletion. It makes SMB resolve its own overlapping
        metadata Opens so explicit delete-on-close remains the sole unlink
        authority.
        """

        immediate = False
        with self._notification_lock:
            if not self._break_metadata_only_smb_leases:
                return
            if existing_only and self._live_open_paths.get(handle) != path:
                return
            self._live_open_paths[handle] = path
            path_handles = self._live_path_handles.setdefault(path, set())
            path_handles.add(handle)
            if not metadata_candidate:
                self._content_io_handles.add(handle)
            if path_handles & self._content_io_handles:
                # fuse_invalidate_path breaks every SMB Open for this path,
                # not just the metadata Open that motivated the timer. Never
                # interrupt an active copy/read to drain a metadata lease.
                self._discard_path_lease_break_candidates_locked(path)
                return
            if len(path_handles) >= 2:
                deadline = time.monotonic() + MOUNT_SMB_DELETE_LEASE_BREAK_SECONDS
                candidates = tuple(
                    live_handle
                    for live_handle in path_handles
                    if live_handle not in self._content_io_handles
                    and live_handle not in self._lease_break_candidates
                )
                available = max(
                    0,
                    MAX_SMB_DELETE_LEASE_BREAK_CANDIDATES
                    - len(self._lease_break_candidates),
                )
                if len(candidates) > available:
                    # Remain memory/thread bounded under an adversarial open
                    # burst. One path invalidation is sufficient to break all
                    # overlapping leases for this inode.
                    immediate = True
                    self._discard_path_lease_break_candidates_locked(path)
                else:
                    for live_handle in candidates:
                        self._lease_break_candidates[live_handle] = (
                            path,
                            deadline,
                        )
                        self._lease_break_path_candidates.setdefault(
                            path, set()
                        ).add(live_handle)
                self._arm_lease_break_timer_locked()
        if immediate:
            self.invalidate_path(path)

    def _mark_smb_content_io(self, handle: int | None) -> None:
        if handle is None:
            return
        with self._notification_lock:
            if handle in self._live_open_paths:
                self._content_io_handles.add(handle)
                self._discard_path_lease_break_candidates_locked(
                    self._live_open_paths[handle]
                )
            else:
                self._discard_lease_break_candidate_locked(handle)
            if not self._lease_break_candidates and self._lease_break_timer is not None:
                self._lease_break_timer.cancel()
                self._lease_break_timer = None

    def _release_smb_open(self, handle: int) -> None:
        rearm: tuple[str, int] | None = None
        with self._notification_lock:
            path = self._live_open_paths.pop(handle, None)
            self._content_io_handles.discard(handle)
            self._discard_lease_break_candidate_locked(handle)
            if path is not None:
                path_handles = self._live_path_handles.get(path)
                if path_handles is not None:
                    path_handles.discard(handle)
                    if not path_handles:
                        self._live_path_handles.pop(path, None)
                    elif len(path_handles) < 2:
                        self._discard_path_lease_break_candidates_locked(path)
                    elif not path_handles & self._content_io_handles:
                        # Resume ordinary metadata lease draining after the
                        # last content description releases this path.
                        rearm = (path, next(iter(path_handles)))
            if not self._lease_break_candidates and self._lease_break_timer is not None:
                self._lease_break_timer.cancel()
                self._lease_break_timer = None
        if rearm is not None:
            self._record_smb_open(
                rearm[0], rearm[1], metadata_candidate=True, existing_only=True,
            )

    @staticmethod
    def _renamed_smb_path(path: str, source: str, destination: str) -> str | None:
        """Map one exact file or directory descendant through a rename."""

        if path == source:
            return destination
        source_prefix = source.rstrip("/") + "/"
        if path.startswith(source_prefix):
            return destination.rstrip("/") + "/" + path[len(source_prefix) :]
        return None

    @staticmethod
    def _smb_path_is_at_or_below(path: str, root: str) -> bool:
        return path == root or path.startswith(root.rstrip("/") + "/")

    def _retarget_smb_opens_after_rename(
        self, source: str, destination: str
    ) -> None:
        """Retarget live SMB lease indexes after one successful rename.

        Source handles remain attached to the inode that moved, including all
        open descendants of a renamed directory. Handles below a replaced
        destination keep their backend lifetime but no longer name a live
        namespace path, so they are detached from path-based lease breaking.
        Candidate deadlines are preserved; only their paths and reverse index
        change.
        """

        if source == destination:
            return
        with self._notification_lock:
            if not self._break_metadata_only_smb_leases:
                return
            source_handles = {
                handle
                for handle, path in self._live_open_paths.items()
                if self._smb_path_is_at_or_below(path, source)
            }
            if not source_handles and not any(
                self._smb_path_is_at_or_below(path, destination)
                for path in self._live_open_paths.values()
            ):
                return

            updated_paths: dict[int, str] = {}
            for handle, path in self._live_open_paths.items():
                if handle in source_handles:
                    renamed = self._renamed_smb_path(path, source, destination)
                    assert renamed is not None
                    updated_paths[handle] = renamed
                elif not self._smb_path_is_at_or_below(path, destination):
                    updated_paths[handle] = path
            self._live_open_paths = updated_paths

            path_handles: dict[str, set[int]] = {}
            for handle, path in updated_paths.items():
                path_handles.setdefault(path, set()).add(handle)
            self._live_path_handles = path_handles

            candidates: dict[int, tuple[str, float]] = {}
            path_candidates: dict[str, set[int]] = {}
            for handle, (_old_path, deadline) in self._lease_break_candidates.items():
                path = updated_paths.get(handle)
                if path is None:
                    continue
                candidates[handle] = (path, deadline)
                path_candidates.setdefault(path, set()).add(handle)
            self._lease_break_candidates = candidates
            self._lease_break_path_candidates = path_candidates
            if not candidates and self._lease_break_timer is not None:
                self._lease_break_timer.cancel()
                self._lease_break_timer = None

    def _arm_writeback_nudge(self, path: str) -> None:
        """Ask the SMB client to deliver cached writes it is sitting on.

        macOS smbfs acknowledges close(2) while dirty pages and the SMB CLOSE
        itself stay cached for ~45-60 s. Publication cannot start until those
        bytes arrive. A path that saw content IO but no FLUSH within the nudge
        window gets a fuse_invalidate_path, which makes the client write its
        cached data through immediately. A FLUSH cancels the nudge; a quiet
        already-flushed description is never re-nudged.
        """

        if not self._writeback_nudges_enabled:
            return
        name = path.rsplit("/", 1)[-1]
        if name.startswith("._"):
            # AppleDouble sidecars are discard-managed; nudging them only
            # multiplies their own churn.
            return
        with self._notification_lock:
            if path in self._writeback_nudges:
                return
            timer = self._new_writeback_nudge_timer_locked(path, 1)
            self._writeback_nudges[path] = (1, timer)
        timer.start()

    def _new_writeback_nudge_timer_locked(
        self, path: str, attempt: int
    ) -> threading.Timer:
        timer: threading.Timer
        timer = threading.Timer(
            MOUNT_SMB_WRITEBACK_NUDGE_SECONDS,
            lambda: self._fire_writeback_nudge(path, timer),
        )
        timer.daemon = True
        return timer

    def _cancel_writeback_nudge(self, path: str | None) -> None:
        if path is None:
            return
        with self._notification_lock:
            entry = self._writeback_nudges.pop(path, None)
        if entry is not None:
            entry[1].cancel()

    def _fire_writeback_nudge(self, path: str, expected: threading.Timer) -> None:
        with self._notification_lock:
            entry = self._writeback_nudges.get(path)
            if entry is None or entry[1] is not expected:
                return
            attempt = entry[0]
            if attempt >= MOUNT_SMB_WRITEBACK_NUDGE_MAX_ATTEMPTS:
                self._writeback_nudges.pop(path, None)
            else:
                timer = self._new_writeback_nudge_timer_locked(path, attempt + 1)
                self._writeback_nudges[path] = (attempt + 1, timer)
                timer.start()
        self.invalidate_path(path)

    def _break_metadata_only_leases(self, timer: threading.Timer) -> None:
        paths: set[str] = set()
        with self._notification_lock:
            if self._lease_break_timer is not timer:
                return
            self._lease_break_timer = None
            if not self._break_metadata_only_smb_leases:
                self._lease_break_candidates.clear()
                return
            now = time.monotonic()
            for handle, (path, deadline) in tuple(
                self._lease_break_candidates.items()
            ):
                if deadline <= now:
                    self._discard_lease_break_candidate_locked(handle)
                    if not self._live_path_handles.get(path, set()) & self._content_io_handles:
                        paths.add(path)
            self._arm_lease_break_timer_locked()
        for path in sorted(paths):
            # Keep a new content Open from racing the native lease break
            # after the candidate snapshot. Recheck ownership inside the
            # same path gate used by Open/Create/Rename.
            with self._ordered_smb_namespace(path):
                with self._notification_lock:
                    active = self._live_path_handles.get(path, set())
                    if active & self._content_io_handles:
                        continue
                self.invalidate_path(path)

    def _capture_notification_context(self) -> None:
        with self._notification_lock:
            if not self._notifications_enabled or self._notification_fuse is not None:
                return
            provider = self._notification_context
        if provider is None:
            return
        try:
            pointer = provider()
        except (AttributeError, OSError, TypeError, ValueError):
            return
        if not isinstance(pointer, int) or pointer <= 0:
            return
        with self._notification_lock:
            if self._notifications_enabled and self._notification_fuse is None:
                self._notification_fuse = pointer

    def invalidate_path(self, path: str) -> bool:
        """Invalidate a FUSE-T path after remote manifest publication."""

        if self._native_directory_watch is not None:
            self._native_directory_watch.changed(path)

        with self._notification_lock:
            if not self._notifications_enabled:
                return False
            pointer = self._notification_fuse
            invalidator = self._notification_invalidator
        if pointer is None or invalidator is None:
            return False
        try:
            result = int(invalidator(pointer, path.encode("utf-8")))
        except (AttributeError, OSError, TypeError, ValueError) as error:
            self.backend.logger.record(
                "fabric_mount_namespace_invalidation_failed",
                path=path,
                error=str(error),
            )
            return False
        if result in (0, -errno.ENOENT):
            return True
        self.backend.logger.record(
            "fabric_mount_namespace_invalidation_failed",
            path=path,
            error_code=errno.errorcode.get(-result, "UNKNOWN"),
        )
        return False

    def disable_namespace_notifications(self) -> None:
        """Fence background invalidations before native unmount begins."""

        if self._native_directory_watch is not None:
            self._native_directory_watch.close()

        with self._notification_lock:
            self._notifications_enabled = False
            self._notification_fuse = None
            self._break_metadata_only_smb_leases = False
            self._live_open_paths.clear()
            self._live_path_handles.clear()
            self._content_io_handles.clear()
            self._lease_break_candidates.clear()
            self._lease_break_path_candidates.clear()
            if self._lease_break_timer is not None:
                self._lease_break_timer.cancel()
                self._lease_break_timer = None

    def __call__(self, operation: str, *args: Any) -> Any:
        """Honor fusepy's Operations dispatch contract without importing it."""

        function = getattr(self, operation, None)
        if not callable(function):
            raise self.fuse_error(errno.EFAULT)
        started = time.perf_counter_ns()
        try:
            return function(*args)
        finally:
            self._record_op_stat(operation, time.perf_counter_ns() - started)

    def _count_op(self, name: str) -> None:
        """Count an event (a cache hit, a miss) inside the op-stats window."""

        with self._op_stats_lock:
            stat = self._op_stats.get(name)
            if stat is None:
                self._op_stats[name] = [1, 0, 0]
            else:
                stat[0] += 1

    def _record_op_stat(self, operation: str, elapsed_ns: int) -> None:
        flush: dict[str, list[int]] | None = None
        window = 0.0
        with self._op_stats_lock:
            stat = self._op_stats.get(operation)
            if stat is None:
                self._op_stats[operation] = [1, elapsed_ns, elapsed_ns]
            else:
                stat[0] += 1
                stat[1] += elapsed_ns
                if elapsed_ns > stat[2]:
                    stat[2] = elapsed_ns
            now = time.monotonic()
            window = now - self._op_stats_window_started
            if window >= MOUNT_OP_STATS_WINDOW_SECONDS:
                flush = self._op_stats
                self._op_stats = {}
                self._op_stats_window_started = now
        if flush:
            fields = {
                name: f"{count}x mean={total // max(count, 1) // 1000}us max={peak // 1000}us"
                for name, (count, total, peak) in sorted(flush.items())
            }
            self.backend.logger.record(
                "fabric_mount_op_stats",
                window_seconds=round(window, 1),
                callbacks=sum(
                    count for name, (count, _total, _peak) in flush.items() if "." not in name
                ),
                attr_cache_size=len(self._attr_cache),
                **fields,
            )

    def _call(self, function: Any, *args: Any, **kwargs: Any) -> Any:
        self._capture_notification_context()
        try:
            return function(*args, **kwargs)
        except MOUNT_ADAPTER_ERRORS as error:
            number, report = mount_error_report(
                error, operation=getattr(function, "__name__", "unknown")
            )
            if report is not None and self._should_record_mount_failure(report):
                self.backend.logger.record("fabric_mount_operation_failed", **report)
            raise self.fuse_error(number) from error

    def _should_record_mount_failure(self, report: Mapping[str, Any]) -> bool:
        """Rate limit fence refusals to one per operation+code per minute."""

        if not report.get("fence"):
            return True
        key = f"{report.get('operation')}:{report.get('error_code')}"
        now_ns = time.monotonic_ns()
        last_ns = self._fence_logged_ns.get(key)
        if last_ns is not None and now_ns - last_ns < 60_000_000_000:
            return False
        if len(self._fence_logged_ns) > 256:
            self._fence_logged_ns.clear()
        self._fence_logged_ns[key] = now_ns
        return True

    def _touch_parent_attrs(self, path: str) -> None:
        """Advance a changed parent's identity without another backend stat.

        Evicting the parent made the SMB client's next re-stat (it re-stats
        the parent on nearly every operation) a backend call under the lock,
        once per created file. The directory's stat only changes its times;
        its listing is dropped because the names changed.
        """

        if not self._attr_cache_enabled:
            return
        parent = path.rsplit("/", 1)[0] or "/"
        with self._directory_time_lock:
            stamp = max(time.time_ns(), self._directory_modified_ns.get(parent, 0) + 1,
                        self._retired_directory_modified_ns + 1)
            self._directory_modified_ns[parent] = stamp
            if len(self._directory_modified_ns) > MOUNT_SMB_ATTR_CACHE_MAX_ENTRIES:
                # Keep metadata bounded during very broad offline mutations.
                # Retire an old exact hint into a mount-wide directory floor,
                # matching the existing global manifest timestamp semantics.
                retired = self._directory_modified_ns.pop(next(iter(self._directory_modified_ns)))
                self._retired_directory_modified_ns = max(self._retired_directory_modified_ns, retired)
        self._dir_cache.pop(parent, None)
        if self._native_directory_watch is not None:
            self._native_directory_watch.changed(path)
        entry = self._attr_cache.get(parent)
        if entry is None or entry[1] is None:
            return
        attrs = dict(entry[1])
        now = stamp / 1_000_000_000
        attrs["st_mtime"] = max(float(attrs.get("st_mtime", 0.0)), now)
        attrs["st_ctime"] = max(float(attrs.get("st_ctime", 0.0)), now)
        self._attr_cache[parent] = (entry[0], attrs)

    def _evict_attrs(self, path: str | None, *, parent: bool = False) -> None:
        if path is None or not self._attr_cache_enabled:
            return
        self._attr_cache.pop(path, None)
        # A path's own listing dies with it (it may be a directory), and the
        # listing that NAMES it dies whenever the caller says the parent
        # changed -- the same signal the attribute cache already trusts.
        self._dir_cache.pop(path, None)
        if parent:
            self._attr_cache.pop(path.rsplit("/", 1)[0] or "/", None)
            self._dir_cache.pop(path.rsplit("/", 1)[0] or "/", None)

    # -- running-compute folder icons ---------------------------------------

    def set_compute_running(self, labels: Iterable[str]) -> tuple[str, ...]:
        """Publish the set of workspace roots whose compute is running.

        Returns the labels whose state changed. Every changed root has its
        cached attributes dropped and its namespace invalidated so Finder
        re-reads the folder's FinderInfo (and therefore its icon) promptly
        instead of waiting out a cache. Idempotent: an unchanged set costs one
        set comparison and touches nothing.
        """

        changed = self._compute_icons.set_running(labels)
        if not changed:
            return ()
        for label in changed:
            for path in self._compute_icons.phantom_paths(label):
                self._evict_attrs(path)
            self._evict_attrs("/")
            # The root itself is what Finder re-stats for the icon flag; the
            # mount root carries the directory's AppleDouble sidecar.
            self.invalidate_path(f"/{label}")
            self.invalidate_path("/")
        self.backend.logger.record(
            "fabric_mount_compute_icons_changed",
            changed=",".join(changed),
            running=len(self._compute_icons.running_labels()),
        )
        return changed

    def _invalidate_compute_icon_path(self, path: str) -> None:
        """Drop caches for one workspace root after its tags changed.

        A user tag edit changes what getxattr must report for the root and for
        its AppleDouble sidecar, so both spellings are evicted and the root is
        invalidated for Finder to re-read.
        """

        label = self._compute_icons.root_label(path)
        if label is None:
            return
        for phantom_path in self._compute_icons.phantom_paths(label):
            self._evict_attrs(phantom_path)
        self._evict_attrs("/")
        self.invalidate_path(f"/{label}")

    def _phantom(self, path: str | None) -> ComputeIconPhantom | None:
        return self._compute_icons.classify(path) if path is not None else None

    @staticmethod
    def _phantom_stat(phantom: ComputeIconPhantom, timestamp_ns: int) -> dict[str, Any]:
        node = MountNode(
            f"/{phantom.label}/{phantom.kind.value}",
            False,
            phantom.size,
            timestamp_ns,
        )
        attrs = node.stat()
        # Phantoms are synthesized read-only: no writer, no owner semantics.
        attrs["st_mode"] = stat.S_IFREG | 0o444
        return attrs

    def getattr(self, path: str | None, fh: int | None = None) -> Mapping[str, Any]:
        if getattr(self, "flag_nullpath_ok", False) and fh not in (None, 0):
            phantom = self._phantom_handles.get(fh)
            if phantom is not None:
                return self._phantom_stat(phantom, 0)
            attrs = self._call(self.backend.getattr_handle, fh).stat()
            if path is None:
                attrs["st_nlink"] = 0
            return attrs
        if path is None:
            raise self.fuse_error(errno.EBADF)
        # Phantoms are resolved before the cache: their state changes with
        # compute, and set_compute_running has already dropped stale entries.
        phantom = self._phantom(path)
        if phantom is not None:
            return self._phantom_stat(
                phantom, self._compute_icons.root_timestamp_ns(phantom.label, 0)
            )
        if self._attr_cache_enabled:
            entry = self._attr_cache.get(path)
            if entry is not None:
                if entry[0] > time.monotonic():
                    self._count_op("getattr.hit")
                    if entry[1] is None:
                        raise self.fuse_error(errno.ENOENT)
                    return entry[1]
                self._count_op("getattr.expired")
            else:
                self._count_op("getattr.miss")
        try:
            node = self._call(self.backend.getattr, path)
        except self.fuse_error as error:
            if (
                self._attr_cache_enabled
                and getattr(error, "errno", None) == errno.ENOENT
            ):
                self._prune_attr_cache()
                self._attr_cache[path] = (
                    time.monotonic() + MOUNT_SMB_ATTR_CACHE_SECONDS,
                    None,
                )
            raise
        attrs = self._finalize_getattr_attrs(path, node)
        if self._attr_cache_enabled:
            self._prune_attr_cache()
            self._attr_cache[path] = (
                time.monotonic() + MOUNT_SMB_ATTR_CACHE_SECONDS,
                attrs,
            )
        return attrs

    def _prune_attr_cache(self) -> None:
        """Make room for one entry without wiping the working set.

        The cache used to ``clear()`` at its cap. Expired entries were never
        removed, so after one bulk copy (plus readdir-plus seeding whole
        listings) it sat at the cap and was wiped on nearly every insert --
        which is why a 15-file create loop measured ~200 backend getattrs per
        create instead of hits (2026-09-02, ``fabric_mount_op_stats``). Drop
        what has expired first; only if the live set itself is at the cap,
        drop the entries that expire soonest.
        """

        cache = self._attr_cache
        if len(cache) < MOUNT_SMB_ATTR_CACHE_MAX_ENTRIES:
            return
        now = time.monotonic()
        for key in [key for key, (expires, _attrs) in cache.items() if expires <= now]:
            cache.pop(key, None)
        if len(cache) < MOUNT_SMB_ATTR_CACHE_MAX_ENTRIES:
            return
        ordered = sorted(cache.items(), key=lambda item: item[1][0])
        for key, _entry in ordered[: len(ordered) // 2]:
            cache.pop(key, None)

    def _finalize_getattr_attrs(
        self, path: str, node: MountNode
    ) -> Mapping[str, Any]:
        """Turn a backend node into the exact stat mapping getattr caches.

        Shared by getattr and the readdir-plus prewarm so a cache entry seeded
        from a listing is byte-identical to one a later getattr would compute --
        including the running-compute directory timestamp bump.
        """

        attrs = node.stat()
        if node.is_directory and self._attr_cache_enabled:
            with self._directory_time_lock:
                local = self._directory_modified_ns.get(path, 0)
                stamp = max(local, self._retired_directory_modified_ns)
                if local and node.modified_ns >= local:
                    self._directory_modified_ns.pop(path, None)
            if stamp > node.modified_ns:
                attrs["st_mtime"] = attrs["st_ctime"] = stamp / 1_000_000_000
        if self._compute_icons.directory_finder_info(path) is not None:
            # Finder repaints a directory whose attributes moved and ignores
            # one whose have not, so a running root reports at least the
            # timestamp of its most recent compute transition.
            stamp = self._compute_icons.root_timestamp_ns(path.strip("/"), 0)
            if stamp:
                attrs = dict(attrs)
                seconds = stamp / 1_000_000_000
                attrs["st_mtime"] = max(float(attrs.get("st_mtime", 0.0)), seconds)
                attrs["st_ctime"] = max(float(attrs.get("st_ctime", 0.0)), seconds)
        return attrs

    def readdir(self, path: str, fh: int) -> list[str]:
        names: tuple[str, ...] | None = None
        if self._attr_cache_enabled:
            entry = self._dir_cache.get(path)
            if entry is not None and entry[0] > time.monotonic():
                names = entry[1]
        if names is None:
            entries = self._readdir_entries(path)
            names = tuple(name for name, _node in entries)
            if self._attr_cache_enabled:
                if len(self._dir_cache) >= MOUNT_SMB_ATTR_CACHE_MAX_ENTRIES:
                    self._dir_cache.clear()
                self._dir_cache[path] = (
                    time.monotonic() + MOUNT_SMB_ATTR_CACHE_SECONDS,
                    names,
                )
                # readdir-plus: seed the attribute cache from the listing that
                # already resolved every child, so the smbfs getattr-per-name
                # storm serves warm. Pure optimization -- never fatal.
                self._run_prewarm(path, entries)
        # Phantoms resolve by name only. Withholding them here is what keeps
        # folder copies, rsync, du, and every sync-driving scan blind to them.
        hidden = self._compute_icons.hidden_names(path)
        if hidden:
            names = tuple(name for name in names if name not in hidden)
        return [".", "..", *names]

    def _readdir_entries(self, path: str) -> tuple[tuple[str, MountNode | None], ...]:
        """Resolve a directory's children with the batched listing, fail-safe.

        The batched listdir_entries is the fast path (one page instead of a
        getattr-per-name N+1). But an exception of ANY non-adapter type raised
        anywhere inside it -- the range query, the scope/read epochs, the
        MultiWorkspaceMountBackend delegation, the per-child resolution -- would
        escape `_call` untranslated, and fusepy renders such an uncaught readdir
        exception as EINVAL, which FUSE-T presents to macOS as a silent EACCES on
        the whole directory. A directory listing must never be fenced by this
        optimization, so on ANY unexpected failure this logs the exact cause and
        falls back to the byte-identical 1.2.88 per-child listing. A legitimate
        POSIX outcome (ENOTDIR, ENOENT, ...) is a translated `fuse_error` and is
        re-raised unchanged -- it must reach the caller, not a fallback listing.
        """

        entries = getattr(self.backend, "listdir_entries", None)
        if callable(entries):
            try:
                return tuple(self._call(entries, path))
            except self.fuse_error as error:
                # ENOENT/ENOTDIR/EOVERFLOW are legitimate directory-level
                # answers and must reach the caller unchanged. Any OTHER errno
                # (EACCES/EIO/...) from a whole-directory listing is a
                # fence-class failure of the optimization, not a real permission
                # denial, so record it and fall back rather than re-raise a
                # quiet EACCES the way this regression did.
                number = getattr(error, "errno", None)
                if number in (errno.ENOENT, errno.ENOTDIR, errno.EOVERFLOW):
                    raise
                self._log_listdir_entries_failed(path, error, number)
            except Exception as error:  # noqa: BLE001 - never fence on the fast path
                self._log_listdir_entries_failed(path, error, None)
        # A backend without the richer surface, or a batched failure: the plain
        # listdir names still list correctly; readdir-plus has nothing to seed.
        return tuple((name, None) for name in self._call(self.backend.listdir, path))

    def _log_listdir_entries_failed(
        self, path: str, error: BaseException, number: int | None
    ) -> None:
        # Identifying facts go in their OWN short fields: NodeLogger hard-caps
        # every field at 256 chars and keeps the HEAD, so a full traceback is
        # truncated to its useless outermost frames. The type names the
        # exception; the tail carries the innermost frame and the exception line.
        self.backend.logger.record(
            "fabric_mount_listdir_entries_failed",
            path=path,
            exception_type=type(error).__name__,
            errno=number,
            message=str(error)[:200],
            traceback_tail=traceback.format_exc()[-250:],
        )

    def _run_prewarm(
        self, path: str, entries: tuple[tuple[str, MountNode | None], ...]
    ) -> None:
        """Seed the attribute cache, guarded by a per-path circuit breaker.

        A prewarm failure is never fatal to the listing. The identifying fields
        are short so they survive the log's per-field cap, and after repeated
        failures the breaker stops attempting the seed for a bounded window, so
        a persistently-failing optimization costs one record per window rather
        than one per readdir.
        """

        now = time.monotonic()
        failures, open_until = self._prewarm_trip.get(path, (0, 0.0))
        if now < open_until:
            return
        try:
            self._prewarm_child_attrs(path, entries)
        except Exception as error:  # noqa: BLE001 - best-effort, never fatal
            failures += 1
            self.backend.logger.record(
                "fabric_mount_readdir_prewarm_failed",
                path=path,
                exception_type=type(error).__name__,
                message=str(error)[:200],
                traceback_tail=traceback.format_exc()[-250:],
            )
            if failures >= MOUNT_PREWARM_TRIP_THRESHOLD:
                self._prewarm_trip[path] = (0, now + MOUNT_PREWARM_TRIP_SECONDS)
                self.backend.logger.record(
                    "fabric_mount_readdir_prewarm_circuit_open",
                    path=path,
                    seconds=int(MOUNT_PREWARM_TRIP_SECONDS),
                )
            else:
                self._prewarm_trip[path] = (failures, 0.0)
            return
        if path in self._prewarm_trip:
            del self._prewarm_trip[path]

    def _prewarm_child_attrs(
        self, path: str, entries: tuple[tuple[str, MountNode | None], ...]
    ) -> None:
        base = path.rstrip("/")
        expires = time.monotonic() + MOUNT_SMB_ATTR_CACHE_SECONDS
        for name, node in entries:
            if node is None:
                continue
            if len(self._attr_cache) >= MOUNT_SMB_ATTR_CACHE_MAX_ENTRIES:
                # Never evict the whole cache to prewarm; the storm that
                # follows will refill what it actually touches.
                break
            child_path = f"{base}/{name}"
            # A phantom resolves before the cache in getattr, so caching a
            # backend node for its path would never be consulted -- skip it.
            if self._phantom(child_path) is not None:
                continue
            self._attr_cache[child_path] = (
                expires,
                self._finalize_getattr_attrs(child_path, node),
            )

    def open(self, path: str, flags: int) -> int:
        phantom = self._phantom(path)
        if phantom is not None:
            if flags & (os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_TRUNC):
                raise self.fuse_error(errno.EACCES)
            handle = self._next_phantom_handle
            self._next_phantom_handle += 1
            self._phantom_handles[handle] = phantom
            return handle
        with self._ordered_smb_namespace(path):
            handle = int(self._call(self.backend.open, path, flags))
            self._record_smb_open(path, handle, metadata_candidate=True)
            return handle

    def create(self, path: str, mode: int, fi: Any | None = None) -> int:
        if self._phantom(path) is not None:
            raise self.fuse_error(errno.EACCES)
        with self._ordered_smb_namespace(path):
            handle = int(
                self._call(
                    self.backend.open, path, os.O_RDWR | os.O_CREAT, create=True
                )
            )
            self._evict_attrs(path)
            self._touch_parent_attrs(path)
            # A CREATE is content-bearing by definition, but still counts as the
            # overlapping Open that can keep a later delete description cached.
            self._record_smb_open(path, handle, metadata_candidate=False)
            return handle

    def read(self, path: str | None, size: int, offset: int, fh: int) -> bytes:
        phantom = self._phantom_handles.get(fh)
        if phantom is None and self._phantom(path) is not None:
            # A client may read without a phantom handle (or after a handle
            # was recycled); serve the same immutable bytes either way.
            phantom = self._phantom(path)
        if phantom is not None:
            if offset < 0 or size < 0:
                raise self.fuse_error(errno.EINVAL)
            return phantom.contents[offset : offset + size]
        self._mark_smb_content_io(fh)
        return bytes(self._call(self.backend.read, fh, offset, size))

    def write(self, path: str | None, data: bytes, offset: int, fh: int) -> int:
        if fh in self._phantom_handles or self._phantom(path) is not None:
            raise self.fuse_error(errno.EACCES)
        self._mark_smb_content_io(fh)
        if path is not None and self._writeback_nudges_enabled and path not in self._writeback_nudges:
            self._arm_writeback_nudge(path)
        written = int(self._call(self.backend.write, fh, offset, data))
        # The stage descriptor owns both size and modification identity. Never
        # synthesize half of its stat from this callback: SMB asks GetAttr for
        # CLOSE before RELEASE evicts the cache, and a fabricated wall-clock
        # mtime makes NSDocument report a false external edit. The next stat is
        # an O(1) descriptor lookup; no content bytes are read.
        self._evict_attrs(path)
        return written

    def truncate(self, path: str | None, length: int, fh: int | None = None) -> int:
        if self._phantom(path) is not None:
            raise self.fuse_error(errno.EACCES)
        self._mark_smb_content_io(fh)
        self._call(self.backend.truncate, path, length, handle=fh)
        self._evict_attrs(path)
        return 0

    def flush(self, path: str | None, fh: int) -> int:
        self._cancel_writeback_nudge(path)
        function = (
            self.backend.flush
            if self.publish_writes_on_flush
            else self.backend.fsync
        )
        self._call(function, fh)
        return 0

    def fsync(self, path: str | None, datasync: bool, fh: int) -> int:
        # A client that fsyncs has delivered its cached bytes: the write-back
        # nudge must not fire later and stall the SMB session with a needless
        # invalidation (measured: each fuse_invalidate_path freezes concurrent
        # CREATEs; 1.2.69 shipped the cancel only on FLUSH).
        self._cancel_writeback_nudge(path)
        self._call(self.backend.fsync, fh)
        return 0

    def release(self, path: str | None, fh: int) -> int:
        if self._phantom_handles.pop(fh, None) is not None:
            return 0
        self._evict_attrs(path)
        self._cancel_writeback_nudge(path)
        self._release_smb_open(fh)
        self._call(self.backend.release, fh)
        return 0

    def unlink(self, path: str) -> int:
        if self._phantom(path) is not None:
            # Synthesized entries have no storage to remove. Report the same
            # refusal a read-only entry would, never a phantom "success" that
            # would make a caller believe it deleted workspace content.
            raise self.fuse_error(errno.EPERM)
        self._evict_attrs(path, parent=True)
        self._cancel_writeback_nudge(path)
        self._call(self.backend.unlink, path)
        # Evict again on the way out. The pre-call eviction cannot hold: any
        # concurrent readdir of the parent that lands while the unlink is in
        # flight re-caches a listing that still names this child, and the
        # cache would then serve that stale name for a full TTL -- long enough
        # for the very next rmdir to fail ENOTEMPTY.
        self._evict_attrs(path, parent=True)
        self._touch_parent_attrs(path)
        return 0

    def rename(self, old: str, new: str) -> int:
        if self._phantom(old) is not None or self._phantom(new) is not None:
            raise self.fuse_error(errno.EPERM)
        self._evict_attrs(old, parent=True)
        self._evict_attrs(new, parent=True)
        self._cancel_writeback_nudge(old)
        with self._ordered_smb_namespace(old, new):
            self._call(self.backend.rename, old, new)
            self._retarget_smb_opens_after_rename(old, new)
        # Evict again after the namespace mutation. A slow safe-save rename can
        # release the backend lock while it waits for the just-closed source's
        # PUT receipt. A concurrent getattr/readdir-plus can then repopulate
        # either endpoint with the partly applied remote receipt timestamp.
        # That timestamp differs from the renamed local inode's stable mtime;
        # serving it at NSDocument save completion makes the next save report a
        # false external modification as soon as the cache expires. The first
        # eviction protects the mutation's preconditions; this one establishes
        # the completed rename as the new attribute identity boundary.
        self._evict_attrs(old, parent=True)
        self._evict_attrs(new, parent=True)
        self._touch_parent_attrs(old)
        self._touch_parent_attrs(new)
        return 0

    def mkdir(self, path: str, mode: int) -> int:
        self._evict_attrs(path, parent=True)
        self._call(self.backend.mkdir, path)
        self._touch_parent_attrs(path)
        return 0

    def _reject_link_operation(self, operation: str) -> NoReturn:
        # Fabric currently represents only regular files and directories.
        # Never copy target bytes or pretend a link was durably accepted.
        # In particular, link targets can name private paths outside Meshia:
        # do not resolve them or include callback arguments in diagnostics.
        try:
            self.backend.logger.record(
                "fabric_mount_link_unsupported",
                operation=operation,
                error_code="ENOTSUP",
                reason="Symbolic and hard links are not supported by Meshia storage.",
                action="Copy regular files and directories; link targets are not read or uploaded.",
            )
        except Exception:  # noqa: BLE001 - diagnostics cannot change the errno
            pass
        raise self.fuse_error(errno.ENOTSUP)

    def symlink(self, target: str, source: str) -> int:
        self._reject_link_operation("symlink")

    def readlink(self, path: str) -> str:
        self._reject_link_operation("readlink")

    def link(self, target: str, source: str) -> int:
        self._reject_link_operation("link")

    def rmdir(self, path: str) -> int:
        self._evict_attrs(path, parent=True)
        self._call(self.backend.rmdir, path)
        self._evict_attrs(path, parent=True)
        self._touch_parent_attrs(path)
        return 0

    def access(self, path: str, mode: int) -> int:
        self._call(self.backend.getattr, path)
        return 0

    def statfs(self, path: str) -> Mapping[str, int]:
        local_capacity = getattr(self.backend, "local_stage_statfs", None)
        local: tuple[int, int] | None = (
            self._call(local_capacity) if callable(local_capacity) else None
        )
        capacity = getattr(self.backend, "statfs_capacity", None)
        remote = self._call(capacity, path) if callable(capacity) else None
        if remote is not None:
            total_bytes, used_bytes = remote
            remote_free_bytes = max(0, total_bytes - used_bytes)
            available_bytes = remote_free_bytes
            if local is not None:
                _local_total, local_safe_bytes = local
                available_bytes = min(remote_free_bytes, local_safe_bytes)
            return {
                "f_bsize": MOUNT_IO_BYTES,
                "f_frsize": MOUNT_IO_BYTES,
                "f_blocks": max(1, (total_bytes + MOUNT_IO_BYTES - 1) // MOUNT_IO_BYTES),
                # bfree describes the remote volume; bavail is the subset this
                # edge can stage safely right now. Local disk pressure must not
                # masquerade as remotely-used workspace storage.
                "f_bfree": remote_free_bytes // MOUNT_IO_BYTES,
                "f_bavail": available_bytes // MOUNT_IO_BYTES,
                "f_files": MAX_DIRECTORY_ENTRIES,
                "f_ffree": MAX_DIRECTORY_ENTRIES,
                "f_namemax": 255,
            }
        storage_root = getattr(self.backend, "storage_root", None)
        if storage_root is None:
            storage_root = self.backend.workspace.root
        if local is None:
            usage = shutil.disk_usage(storage_root)
            local_total = int(usage.total)
            local_safe_bytes = max(0, int(usage.free) - MOUNT_MIN_FREE_BYTES)
        else:
            local_total, local_safe_bytes = local
        return {
            "f_bsize": MOUNT_IO_BYTES,
            "f_frsize": MOUNT_IO_BYTES,
            "f_blocks": local_total // MOUNT_IO_BYTES,
            "f_bfree": local_safe_bytes // MOUNT_IO_BYTES,
            "f_bavail": local_safe_bytes // MOUNT_IO_BYTES,
            "f_files": MAX_DIRECTORY_ENTRIES,
            "f_ffree": MAX_DIRECTORY_ENTRIES,
            "f_namemax": 255,
        }

    def chmod(self, path: str, mode: int) -> int:
        # Fabric is a per-user content projection rather than a POSIX metadata
        # store. macOS nevertheless finishes an ordinary Finder/``cp`` copy by
        # replaying the source mode through SMB. Rejecting that advisory call
        # makes a fully published byte copy look like a failed transfer. Keep
        # the stable synthetic mode returned by getattr, but acknowledge the
        # hint after proving the target still exists.
        self._call(self.backend.getattr, path)
        return 0

    def chown(self, path: str, uid: int, gid: int) -> int:
        # Never pretend that this current-user mount can transfer ownership.
        # SMB may restate the caller identity after a copy, which is harmless;
        # any genuinely different owner remains a permission error.
        # WinFsp has no POSIX getuid/getgid; match the synthetic identity in
        # MountNode.stat rather than failing a harmless metadata replay.
        current_uid = os.getuid() if hasattr(os, "getuid") else 0
        current_gid = os.getgid() if hasattr(os, "getgid") else 0
        if uid not in (-1, current_uid) or gid not in (-1, current_gid):
            raise self.fuse_error(errno.EPERM)
        self._call(self.backend.getattr, path)
        return 0

    def utimens(self, path: str, times: Any | None = None) -> int:
        # FUSE-T's SMB bridge acknowledges cached writes before their FUSE
        # callbacks arrive. Preserve the timestamp the client already exposed
        # so an immediate NSDocument open sees the same identity after delayed
        # writeback. The backend confines the change to an existing local
        # stage/materialization and rebases its durable fingerprint.
        self._evict_attrs(path)
        with self._ordered_smb_namespace(path):
            setter = getattr(self.backend, "set_times", None)
            if callable(setter):
                self._call(setter, path, times)
            else:
                self._call(self.backend.getattr, path)
        self._evict_attrs(path)
        return 0

    def _compute_icon_xattrs(self, path: str) -> dict[str, bytes] | None:
        """Synthesized xattrs for a running root or one of its phantoms."""

        directory = self._compute_icons.directory_xattrs(path)
        if directory is not None:
            return directory
        phantom = self._phantom(path)
        if phantom is not None:
            return phantom.xattrs()
        return None

    def getxattr(self, path: str, name: str, position: int = 0) -> bytes:
        synthesized = self._compute_icon_xattrs(path)
        if synthesized is not None:
            value = synthesized.get(name)
            if value is not None:
                if position:
                    return value[position:]
                return value
            if self._phantom(path) is not None:
                # A phantom has exactly the attributes above; anything else is
                # genuinely absent rather than delegated to a backend that has
                # never heard of this path.
                raise self.fuse_error(_ENOATTR)
        return bytes(self._call(self.backend.getxattr, path, name, position))

    def listxattr(self, path: str) -> list[str]:
        synthesized = self._compute_icon_xattrs(path)
        if synthesized is not None:
            if self._phantom(path) is not None:
                return sorted(synthesized)
            # A running workspace root keeps whatever the backend reports and
            # gains the custom-icon FinderInfo on top.
            names = list(self._call(self.backend.listxattr, path))
            return sorted({*names, *synthesized})
        return list(self._call(self.backend.listxattr, path))

    def setxattr(
        self, path: str, name: str, value: bytes, options: int, position: int = 0
    ) -> int:
        # Finder's quarantine marker is security-relevant and must follow the
        # exact staged inode through publication. Other known cosmetic hints can
        # be acknowledged because Fabric does not expose a portable metadata
        # namespace. Resource forks, ACLs, and application-owned xattrs remain
        # explicit ENOTSUP failures rather than being silently discarded.
        if (
            name == USER_TAGS_XATTR
            and self._compute_icons.directory_finder_info(path) is not None
        ):
            # The green tag is ours, but the tags around it are the user's.
            # Record what they set (minus our green) so turning compute off
            # leaves exactly their tags rather than wiping the folder clean.
            label = self._compute_icons.root_label(path)
            if label is not None:
                self._compute_icons.set_user_tags(label, decode_tags(value))
                self._invalidate_compute_icon_path(path)
            return 0
        if self._phantom(path) is not None or (
            name == FINDER_INFO_XATTR
            and self._compute_icons.directory_finder_info(path) is not None
        ):
            # Synthesized metadata is owned by compute state, not by clients.
            raise self.fuse_error(errno.EPERM)
        try:
            if name == _MACOS_QUARANTINE_XATTR:
                self._call(
                    self.backend.setxattr,
                    path,
                    name,
                    value,
                    options,
                    position,
                )
            elif _discardable_macos_xattr(name):
                self._call(self.backend.getattr, path)
            else:
                raise self.fuse_error(errno.ENOTSUP)
        except BaseException as error:
            self.backend.logger.record(
                "fabric_mount_xattr_set_failed",
                path=path,
                name=name,
                size_bytes=len(value),
                options=options,
                position=position,
                error_type=type(error).__name__,
                error=str(error),
            )
            raise
        return 0

    def removexattr(self, path: str, name: str) -> int:
        if (
            name == USER_TAGS_XATTR
            and self._compute_icons.directory_finder_info(path) is not None
        ):
            label = self._compute_icons.root_label(path)
            if label is not None:
                self._compute_icons.set_user_tags(label, ())
                self._invalidate_compute_icon_path(path)
            return 0
        if self._phantom(path) is not None or (
            name == FINDER_INFO_XATTR
            and self._compute_icons.directory_finder_info(path) is not None
        ):
            raise self.fuse_error(errno.EPERM)
        if name == _MACOS_QUARANTINE_XATTR:
            self._call(self.backend.removexattr, path, name)
        elif _discardable_macos_xattr(name):
            self._call(self.backend.getattr, path)
        else:
            raise self.fuse_error(_ENOATTR)
        return 0


def _winfsp_library_candidates() -> tuple[Path, ...]:
    try:  # Imported lazily so POSIX installs never require the Windows module.
        import winreg  # type: ignore[import-not-found]

        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\WinFsp",
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_32KEY,
        ) as key:
            install_dir = str(winreg.QueryValueEx(key, "InstallDir")[0])
    except (ImportError, OSError, TypeError, ValueError):
        return ()
    machine = platform.machine().lower()
    preferred = (
        "a64" if machine in ("arm64", "aarch64") else "x64"
        if sys.maxsize > 0xFFFFFFFF
        else "x86"
    )
    architectures = (preferred,) + tuple(
        value for value in ("a64", "x64", "x86") if value != preferred
    )
    return tuple(
        Path(install_dir) / "bin" / f"winfsp-{architecture}.dll"
        for architecture in architectures
    )


def detect_fuse_runtime() -> FuseRuntime | None:
    candidates: list[Path] = []
    explicit = os.environ.get("MESHIA_FUSE_LIBRARY") or os.environ.get(
        "FUSE_LIBRARY_PATH"
    )
    if explicit:
        candidates.append(Path(explicit).expanduser())
    if sys.platform == "darwin":
        candidates.extend(
            Path(value)
            for value in (
                f"/Library/Application Support/fuse-t/lib/libfuse-t-{FUSE_T_TRANSPORT_VERSION}.dylib",
                "/usr/local/lib/libfuse-t.dylib",
                "/opt/homebrew/lib/libfuse-t.dylib",
                "/usr/local/lib/libfuse.dylib",
                "/opt/homebrew/lib/libfuse.dylib",
            )
        )
    elif sys.platform == "win32":
        candidates.extend(_winfsp_library_candidates())
    else:
        candidates.extend(
            Path(value)
            for value in (
                "/lib/libfuse.so.2",
                "/usr/lib/libfuse.so.2",
                "/lib64/libfuse.so.2",
                "/usr/lib64/libfuse.so.2",
                "/lib/x86_64-linux-gnu/libfuse.so.2",
                "/usr/lib/x86_64-linux-gnu/libfuse.so.2",
                "/lib/aarch64-linux-gnu/libfuse.so.2",
                "/usr/lib/aarch64-linux-gnu/libfuse.so.2",
            )
        )
        for pattern in (
            "/lib/*-linux-gnu/libfuse.so.2",
            "/usr/lib/*-linux-gnu/libfuse.so.2",
        ):
            candidates.extend(Path(value) for value in sorted(glob.glob(pattern)))
    for candidate in candidates:
        try:
            if candidate.is_file():
                resolved = candidate.resolve(strict=True)
                return FuseRuntime(
                    resolved,
                    "fuse-t"
                    if "fuse-t" in resolved.name
                    else "winfsp"
                    if "winfsp" in resolved.name.lower()
                    else "fuse",
                )
        except OSError:
            continue
    return None


def select_macos_fuse_backend(
    runtime: FuseRuntime, *, macos_version: str | None = None
) -> str | None:
    """Choose one deterministic FUSE-T bridge without probing live mounts.

    FUSE-T's NFS bridge is retained on macOS 13-25, where it is the established
    path. macOS 26's NFS client can hand FUSE-T an empty NFSv4 file handle and
    crash its helper before the filesystem sees a callback, so Tahoe and later
    use FUSE-T's bundled SMB bridge. FSKit is deliberately not an automatic
    fallback: enabling its third-party extension is user-election state and an
    unavailable extension can leave the mount helper waiting indefinitely.

    A non-FUSE-T runtime owns its own backend selection (for example macFUSE's
    VFS/FSKit choice), so do not pass it a FUSE-T-specific option.
    """

    if sys.platform != "darwin" or runtime.kind != "fuse-t":
        return None
    version = platform.mac_ver()[0] if macos_version is None else macos_version
    try:
        major = int(version.split(".", 1)[0])
    except (AttributeError, TypeError, ValueError):
        # Preserve the established NFS path when a restricted runtime cannot
        # report the product version.  Never guess FSKit or SMB from Darwin's
        # unrelated kernel version.
        major = 0
    return "smb" if major >= 26 else "nfs"


def _macos_extended_attribute_options(
    runtime: FuseRuntime, transport_backend: str | None
) -> dict[str, bool]:
    """Select the native xattr bridge without weakening Fabric authority.

    The SMB helper accepted earlier in ``FabricFuseMount.start`` is pinned to
    FUSE-T 1.2.7. Its SMB server returns ``STATUS_IO_DEVICE_ERROR`` after a
    successful zero-length extended-attribute callback, which makes Finder
    abort otherwise-valid copies with error -36. Disable only that broken
    named-stream bridge. Meshia's xattr implementation remains available to
    the established NFS transport and non-FUSE-T runtimes, and this option has
    no effect on remote namespace invalidation or content publication.
    """

    if (
        runtime.kind == "fuse-t"
        and transport_backend == "smb"
        and FUSE_T_TRANSPORT_VERSION == "1.2.7"
    ):
        return {"nonamedattr": True}
    return {"namedattr": True}


_WINDOWS_DRIVE_ROOT_RE = re.compile(r"^[A-Za-z]:[\\/]?$")


def select_mount_point(default_posix_path: Path | str) -> Path:
    """Select a stable native location without hiding the local working set."""

    explicit = os.environ.get("MESHIA_MOUNT_POINT")
    if explicit:
        return Path(explicit).expanduser()
    if sys.platform != "win32":
        return Path(default_posix_path).expanduser()
    # M: is memorable; the bounded fallback keeps existing/network drives intact.
    for letter in "MNOPQRSTUVWXYZLKJIHGFED":
        candidate = Path(f"{letter}:\\")
        if not candidate.exists():
            return candidate
    raise FabricMountError("No free drive letter is available for the Meshia mount.")


_FUSE_T_VERSIONED_HELPER_RE = re.compile(
    r"^/Library/Application Support/fuse-t/bin/go-nfsv4-[A-Za-z0-9._-]+(?:\s|$)"
)
_FUSE_T_STABLE_HELPERS = (
    "/usr/local/bin/go-nfsv4",
    "/opt/homebrew/bin/go-nfsv4",
    "/Library/Application Support/fuse-t/bin/go-nfsv4",
)


def _exact_fuse_t_helper_command(command: str, mount_point: Path) -> bool:
    """Recognize only FUSE-T's exact per-mount helper command."""

    known_executable = _FUSE_T_VERSIONED_HELPER_RE.match(command) is not None or any(
        command == helper or command.startswith(f"{helper} ")
        for helper in _FUSE_T_STABLE_HELPERS
    )
    return bool(
        known_executable
        and command.endswith(f" {mount_point}")
    )


def _find_fuse_t_helper_pid(mount_point: Path) -> int | None:
    """Find this process's one exact FUSE-T helper without broad process kills."""

    if sys.platform != "darwin":
        return None
    try:
        result = subprocess.run(
            ["/bin/ps", "-axo", "pid=,ppid=,command="],
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0 or len(result.stdout) > 8 * 1024 * 1024:
        return None
    matches: list[int] = []
    for line in result.stdout.splitlines():
        fields = line.strip().split(None, 2)
        if len(fields) != 3:
            continue
        try:
            pid, parent_pid = int(fields[0]), int(fields[1])
        except ValueError:
            continue
        if (
            pid > 1
            and parent_pid == os.getpid()
            and _exact_fuse_t_helper_command(fields[2], mount_point)
        ):
            matches.append(pid)
    return matches[0] if len(matches) == 1 else None


def _fuse_t_helper_still_exact(pid: int, mount_point: Path) -> bool:
    """Revalidate PID ownership and argv immediately before signalling it."""

    try:
        result = subprocess.run(
            ["/bin/ps", "-p", str(pid), "-o", "ppid=", "-o", "command="],
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    fields = result.stdout.strip().split(None, 1)
    if result.returncode != 0 or len(fields) != 2:
        return False
    try:
        parent_pid = int(fields[0])
    except ValueError:
        return False
    return parent_pid == os.getpid() and _exact_fuse_t_helper_command(
        fields[1], mount_point
    )


def _stop_fuse_t_helper(pid: int, mount_point: Path) -> bool:
    """Stop one detached FUSE-T helper so its libfuse loop can unwind."""

    if not _fuse_t_helper_still_exact(pid, mount_point):
        return False
    try:
        os.kill(pid, signal.SIGTERM)
    except (OSError, ValueError):
        return False
    deadline = time.monotonic() + MOUNT_HELPER_TERM_SECONDS
    while time.monotonic() < deadline:
        if not _fuse_t_helper_still_exact(pid, mount_point):
            return True
        time.sleep(0.05)
    # The mount is already detached before this helper is called. Revalidate
    # the exact child and argv again so PID reuse can never broaden SIGKILL.
    if not _fuse_t_helper_still_exact(pid, mount_point):
        return True
    try:
        os.kill(pid, signal.SIGKILL)
    except (OSError, ValueError):
        return False
    return True


def _run_bounded_mount_command(
    command: list[str], *, timeout_seconds: float = MOUNT_UNMOUNT_TIMEOUT_SECONDS
) -> bool:
    """Run one fixed mount helper without ever waiting on a wedged child.

    A native unmount can enter an uninterruptible kernel wait.  The usual
    ``subprocess.run(timeout=...)`` path kills and then waits for that child,
    which can wedge the Meshia service too.  Poll explicitly; on expiry, ask
    the child to stop and hand reaping to a daemon thread so the parent remains
    able to publish recovery state and exit.  The private mount receipt blocks
    repeated attempts until restart recovery can prove the old boot is gone.
    """

    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, ValueError):
        return False
    deadline = time.monotonic() + max(0.0, timeout_seconds)
    while time.monotonic() < deadline:
        result = process.poll()
        if result is not None:
            return result == 0
        time.sleep(0.05)
    result = process.poll()
    if result is not None:
        return result == 0
    try:
        process.kill()
    except OSError:
        pass

    def reap() -> None:
        try:
            process.wait()
        except OSError:
            pass

    threading.Thread(
        target=reap,
        name="meshia-unmount-reaper",
        daemon=True,
    ).start()
    return False


def read_mount_state(path: Path | str) -> dict[str, object] | None:
    """Read a bounded private mount receipt without scanning any filesystem."""

    source = Path(path)
    try:
        descriptor = os.open(str(source), os.O_RDONLY | _NOFOLLOW | _CLOEXEC)
    except OSError:
        return None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_MOUNT_STATE_BYTES:
            return None
        raw = os.read(descriptor, MAX_MOUNT_STATE_BYTES + 1)
        if len(raw) != info.st_size:
            return None
    except OSError:
        return None
    finally:
        os.close(descriptor)
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(document, dict) or document.get("schema") != MOUNT_STATE_SCHEMA:
        return None
    mount_point = document.get("mount_point")
    owner_pid = document.get("owner_pid")
    transport_backend = document.get("transport_backend")
    if (
        not isinstance(mount_point, str)
        or not mount_point
        or len(mount_point) > 1_024
        or "\x00" in mount_point
        or isinstance(owner_pid, bool)
        or not isinstance(owner_pid, int)
        or owner_pid < 1
        or transport_backend not in (None, "nfs", "smb")
    ):
        return None
    return document


def mount_state_path_present(path: Path | str) -> bool:
    """Fail closed when a private mount receipt exists but cannot be parsed.

    ``lstat`` never follows a substituted symlink and the receipt lives outside
    the mounted namespace, so this check remains bounded even when the native
    mount itself is stuck in an uninterruptible kernel wait.  Errors other than
    a proven absence count as present: startup must not adopt a mount merely
    because its private safety receipt is unreadable.
    """

    try:
        os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError:
        return True
    return True


def _mount_receipt_predates_current_boot(receipt: Mapping[str, object]) -> bool:
    """Prove that a legacy receipt cannot belong to this kernel boot.

    Native mounts cannot survive a host restart.  This lets the first service
    start after a reboot retire an otherwise-valid receipt without probing the
    old mount point.  If the platform boot time cannot be read exactly, the
    answer remains false and startup keeps failing closed.
    """

    started_at_ns = receipt.get("started_at_ns")
    if (
        isinstance(started_at_ns, bool)
        or not isinstance(started_at_ns, int)
        or started_at_ns < 1
    ):
        return False
    boot_seconds: int | None = None
    boot_microseconds = 0
    if sys.platform == "darwin":
        try:
            result = subprocess.run(
                ["/usr/sbin/sysctl", "-n", "kern.boottime"],
                check=False,
                capture_output=True,
                text=True,
                timeout=2,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        if result.returncode != 0 or len(result.stdout) > 256:
            return False
        match = re.search(r"sec\s*=\s*(\d+),\s*usec\s*=\s*(\d+)", result.stdout)
        if match is None:
            return False
        boot_seconds = int(match.group(1))
        boot_microseconds = int(match.group(2))
    elif sys.platform.startswith("linux"):
        try:
            with open("/proc/stat", encoding="utf-8") as source:
                for line_number, line in enumerate(source):
                    if line_number >= 256:
                        break
                    match = re.fullmatch(r"btime (\d+)\n?", line)
                    if match is not None:
                        boot_seconds = int(match.group(1))
                        break
        except OSError:
            return False
    if boot_seconds is None:
        return False
    boot_time_ns = boot_seconds * 1_000_000_000 + boot_microseconds * 1_000
    return started_at_ns < boot_time_ns


def _decode_mount_registry_path(value: str) -> str:
    """Decode the octal escapes used by POSIX mount registries."""

    return re.sub(
        r"\\([0-7]{3})",
        lambda match: chr(int(match.group(1), 8)),
        value,
    )


_DARWIN_MOUNT_PATH_ALIASES = (
    ("/etc", "/private/etc"),
    ("/tmp", "/private/tmp"),
    ("/var", "/private/var"),
)


def _mount_registry_path_aliases(value: Path | str) -> set[str]:
    """Return lexical OS-registry aliases without touching a mounted path.

    macOS exposes ``/etc``, ``/tmp``, and ``/var`` as symlinks into
    ``/private``. Its mount registry reports the resolved spelling even when a
    caller selected the public spelling. ``realpath`` would resolve that, but
    can block on the very dead network mount this health path must diagnose.
    Expanding only Apple's stable root aliases keeps the check bounded and
    avoids treating unrelated path prefixes as equivalent.
    """

    normalized = os.path.normpath(str(Path(value).expanduser()))
    aliases = {normalized}
    if sys.platform != "darwin":
        return aliases
    for public, private in _DARWIN_MOUNT_PATH_ALIASES:
        for source, destination in ((public, private), (private, public)):
            if normalized == source:
                aliases.add(destination)
            elif normalized.startswith(f"{source}/"):
                aliases.add(destination + normalized[len(source) :])
    return aliases


def _mounted_paths_from_registry() -> set[str] | None:
    """Read mount names from an OS registry without touching mounted paths."""

    if sys.platform == "win32":
        from .windows_mount import mounted_drive_paths
        # Directory mounts use a reparse point and need the path-specific
        # bounded probe in mount_registration_state below.
        return mounted_drive_paths()
    if sys.platform == "darwin":
        # mount(8) itself blocks on a dead NFS/SMB mount. The bounded capture
        # never waits on that wedged child, so this probe answers ``None``
        # (unknown) in the exact failure mode it exists to diagnose instead
        # of joining the hang.
        output = run_bounded_capture(
            ["/sbin/mount"],
            timeout_seconds=MOUNT_REGISTRY_PROBE_TIMEOUT_SECONDS,
            max_output_bytes=MAX_MOUNT_REGISTRY_BYTES,
        )
        if output is None:
            return None
        paths: set[str] = set()
        for line in output.splitlines():
            separator = line.rfind(" on ")
            options = line.rfind(" (")
            if separator < 0 or options <= separator + 4:
                continue
            paths.add(
                os.path.normpath(
                    _decode_mount_registry_path(line[separator + 4 : options])
                )
            )
        return paths
    if sys.platform.startswith("linux"):
        try:
            with open("/proc/self/mountinfo", encoding="utf-8") as source:
                document = source.read(MAX_MOUNT_REGISTRY_BYTES + 1)
        except OSError:
            return None
        if len(document.encode("utf-8", errors="replace")) > MAX_MOUNT_REGISTRY_BYTES:
            return None
        paths = set()
        for line in document.splitlines():
            fields = line.split()
            if len(fields) >= 5:
                paths.add(
                    os.path.normpath(_decode_mount_registry_path(fields[4]))
                )
        return paths
    return None


def _linux_meshia_mount_identity(mount_point: Path | str) -> tuple[int, str, str, str] | None:
    """Identify one exact account-owned Meshia FUSE mount without statting it."""
    try:
        with open("/proc/self/mountinfo", encoding="utf-8") as source:
            document = source.read(MAX_MOUNT_REGISTRY_BYTES + 1)
    except OSError:
        return None
    if len(document.encode("utf-8", errors="replace")) > MAX_MOUNT_REGISTRY_BYTES:
        return None
    target = os.path.normpath(str(mount_point))
    found = []
    for line in document.splitlines():
        fields = line.split()
        if len(fields) < 10 or os.path.normpath(_decode_mount_registry_path(fields[4])) != target:
            continue
        try:
            separator = fields.index("-", 6)
            kind, name, options = fields[separator + 1:separator + 4]
            if (kind != "fuse.meshia" or name != "meshia"
                    or f"user_id={os.getuid()}" not in options.split(",")):
                return None
            found.append((int(fields[0]), fields[2], _decode_mount_registry_path(fields[3]), target))
        except (ValueError, IndexError):
            return None
    return found[0] if len(found) == 1 and found[0][0] > 0 else None


def mount_registration_state(mount_point: Path | str) -> bool | None:
    """Return whether the OS registry still contains one mount.

    This deliberately never stats the mounted namespace.  A disconnected or
    wedged network filesystem can make that probe block indefinitely, whereas
    the bounded OS registry read remains a safe service/status health check.
    ``None`` means the registry was unavailable, so callers must stay
    conservative rather than declaring a healthy mount detached.
    """

    if sys.platform == "win32":
        from .windows_mount import mount_registration_state as windows_registration
        return windows_registration(mount_point, timeout_seconds=MOUNT_REGISTRY_PROBE_TIMEOUT_SECONDS)
    paths = _mounted_paths_from_registry()
    if paths is None:
        return None
    return not _mount_registry_path_aliases(mount_point).isdisjoint(paths)


def _receipt_owner_is_live(receipt: Mapping[str, object]) -> bool:
    """Keep a receipt unless its saved owner is proven absent or exited."""

    owner_pid = receipt.get("owner_pid")
    if (
        isinstance(owner_pid, bool)
        or not isinstance(owner_pid, int)
        or owner_pid < 1
    ):
        return True
    if sys.platform == "win32":
        from .windows_mount import process_definitely_exited
        return not process_definitely_exited(owner_pid)
    if sys.platform != "darwin" and not sys.platform.startswith("linux"):
        return True
    try:
        os.kill(owner_pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return True
    return True


def _mount_receipt_is_proven_detached(receipt: Mapping[str, object]) -> bool:
    """Prove a dead receipt no longer names an OS-registered mount."""

    if _receipt_owner_is_live(receipt):
        return False
    if sys.platform == "win32":
        # Directory mounts are reparse points, not enumerable drive letters.
        # Reuse the bounded path-specific probe for both kinds; unknown is
        # never absence. This only retires the receipt, never an OS mount.
        return mount_registration_state(str(receipt["mount_point"])) is False
    paths = _mounted_paths_from_registry()
    if paths is None:
        return False
    return _mount_registry_path_aliases(str(receipt["mount_point"])).isdisjoint(paths)


def is_meshia_mount(mount_point: Path | str) -> bool:
    """Verify the mounted location, including its Windows volume label."""

    if not os.path.ismount(mount_point):
        return False
    if sys.platform != "win32" or os.name != "nt":
        return True
    try:  # pragma: no cover - exercised on Windows hosts
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetVolumeInformationW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.LPWSTR,
            wintypes.DWORD,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.LPWSTR,
            wintypes.DWORD,
        ]
        kernel32.GetVolumeInformationW.restype = wintypes.BOOL
        volume_name = ctypes.create_unicode_buffer(64)
        root = str(mount_point)
        if _WINDOWS_DRIVE_ROOT_RE.fullmatch(root):
            root = root[:2] + "\\"
        if not kernel32.GetVolumeInformationW(
            root, volume_name, len(volume_name), None, None, None, None, 0
        ):
            return False
        return volume_name.value == MOUNT_NAME
    except (AttributeError, OSError, ValueError):
        return False


class _NodeLogForwardHandler(logging.Handler):
    """Forward Python ERROR logging records into the structured node log.

    fusepy logs an uncaught FUSE callback exception to logging.getLogger("fuse")
    and returns EINVAL, which FUSE-T renders to macOS as EACCES. The service
    plist points stderr at /dev/null, so that traceback -- the one thing that
    names such a failure -- was discarded. Forwarding ERROR+ records into the
    bounded, rotated NodeLogger keeps them. emit() is fully guarded so a logging
    failure can never disturb the FUSE callback that produced it.
    """

    def __init__(self, logger: NodeLogger) -> None:
        super().__init__(level=logging.ERROR)
        self._logger = logger

    def emit(self, record: logging.LogRecord) -> None:
        try:
            trace = ""
            exception_type = ""
            exception_message = ""
            if record.exc_info:
                trace = "".join(traceback.format_exception(*record.exc_info))[-4000:]
                exception_type = type(record.exc_info[1]).__name__
                exception_message = str(record.exc_info[1])
            self._logger.record(
                "python_logging_error",
                logger=record.name,
                level=record.levelname,
                message=record.getMessage()[:1000],
                traceback=trace,
                # NodeLogger bounds each field to 256 characters. Preserve
                # the cause separately; the old traceback field retained
                # only fusepy's wrapper frame and discarded the actual error.
                exception_type=exception_type,
                exception_message=exception_message,
                traceback_tail=trace[-240:],
            )
        except Exception:  # noqa: BLE001 - logging must never raise into a callback
            pass


def _forward_python_logging_to_node(logger: NodeLogger) -> None:
    """Route Python ERROR logs into node.log, once, via the root logger.

    Idempotent -- a second mount does not stack handlers. Attached to the root
    logger so fusepy's "fuse" logger (and any other library) reaches the bounded
    node log by propagation instead of the process stderr the plist discards.
    """

    root = logging.getLogger()
    if any(isinstance(handler, _NodeLogForwardHandler) for handler in root.handlers):
        return
    root.addHandler(_NodeLogForwardHandler(logger))


class _WindowsFuseLoop:
    """Own one WinFsp loop pointer only between its init/destroy callbacks."""

    def __init__(self, library: Any) -> None:
        self._context = library.fuse_get_context
        self._exit = library.fuse_exit
        # fusepy declares fuse_get_context's platform ABI, including its
        # POINTER(fuse_context) return. Do not replace it with a guessed layout.
        self._exit.argtypes = [ctypes.c_void_p]
        self._exit.restype = None
        self._lock = threading.Lock()
        self._pointer: int | None = None
        self._stop_requested = False

    def init(self, _path: str) -> None:
        context = self._context()
        pointer = context.contents.fuse if context else None
        if not pointer:
            raise FabricMountError("The Windows mount loop did not provide its native identity.")
        with self._lock:
            self._pointer = int(pointer)
            if self._stop_requested:
                self._exit(ctypes.c_void_p(self._pointer))

    def destroy(self, _path: str) -> None:
        with self._lock:
            self._pointer = None

    def stop(self) -> None:
        with self._lock:
            self._stop_requested = True
            if self._pointer is not None:
                # WinFsp fuse_exit only signals LoopEvent and sets exited; it
                # never waits for destroy. Holding the lock prevents a racing
                # destroy callback from freeing the pointer before this call.
                self._exit(ctypes.c_void_p(self._pointer))


class FabricFuseMount:
    """Own one fusepy loop and a bounded, safely-unmounted backend."""

    def __init__(
        self,
        backend: FabricMountBackend,
        mount_point: Path | str,
        *,
        state_path: Path | str | None = None,
        logger: NodeLogger = NULL_LOGGER,
        windows_workspace_security: str | None = None,
    ) -> None:
        self.backend = backend
        self.mount_point = Path(mount_point).expanduser()
        self.state_path = Path(state_path).expanduser() if state_path is not None else None
        self.logger = logger
        self.windows_workspace_security = windows_workspace_security
        self.runtime: FuseRuntime | None = None
        self.transport_backend: str | None = None
        self._helper_pid: int | None = None
        self._thread: threading.Thread | None = None
        self._error: BaseException | None = None
        self._mount_ready = False
        self._linux_mount_identity: tuple[int, str, str, str] | None = None
        self._next_registration_check = 0.0
        self._detached_for_process_exit = False
        self._operations: FabricFuseOperations | None = None
        self._windows_loop: _WindowsFuseLoop | None = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def detached_for_process_exit(self) -> bool:
        """Whether OS ownership ended while the callback loop is still draining.

        FUSE-T can detach its SMB/NFS client and stop the exact helper before
        fusepy's blocking callback returns. Callers must then leave backend
        handles open until process exit, but this is not a live or orphaned
        mount and should not turn an otherwise-clean service stop into failure.
        """

        return self._detached_for_process_exit

    def require_registered(self) -> None:
        """Fail when a formerly-ready mount vanished from the OS registry."""

        if not self._mount_ready:
            return
        now = time.monotonic()
        if now < self._next_registration_check:
            return
        registered = mount_registration_state(self.mount_point)
        self._next_registration_check = now + MOUNT_REGISTRATION_CHECK_SECONDS
        if registered is False:
            self.logger.record(
                "fabric_mount_detached",
                mount_point=str(self.mount_point),
            )
            raise StateError(
                "The native Meshia mount was disconnected outside Meshia; "
                "the service will recreate it."
            )

    def _refresh_fuse_t_helper(self) -> None:
        """Retain only the exact live FUSE-T child for this mount."""

        if self._helper_pid is not None and _fuse_t_helper_still_exact(
            self._helper_pid, self.mount_point
        ):
            return
        self._helper_pid = _find_fuse_t_helper_pid(self.mount_point)

    def _foreign_mount_owner(self) -> int | None:
        """PID of another live process whose receipt now claims our mount point."""

        if self.state_path is None:
            return None
        try:
            receipt = read_mount_state(self.state_path)
        except OSError:
            return None
        if receipt is None:
            return None
        owner = receipt.get("owner_pid")
        if (
            isinstance(owner, bool)
            or not isinstance(owner, int)
            or owner < 1
            or owner == os.getpid()
        ):
            return None
        try:
            os.kill(owner, 0)
        except ProcessLookupError:
            return None
        except PermissionError:
            pass
        except OSError:
            return None
        return owner

    def _retire_owned_mount_receipt(self) -> None:
        """Remove only this process's receipt after the OS mount is detached."""

        if self.state_path is None:
            return
        try:
            receipt = read_mount_state(self.state_path)
            if receipt is not None and receipt.get("owner_pid") == os.getpid():
                self.state_path.unlink()
        except OSError:
            pass

    def start(self, *, timeout_seconds: float | None = None) -> bool:
        if self.running:
            return True
        self._error = None
        if self.state_path is not None:
            existing_receipt = read_mount_state(self.state_path)
            if (
                existing_receipt is not None
                and _mount_receipt_predates_current_boot(existing_receipt)
            ):
                try:
                    self.state_path.unlink()
                except OSError as error:
                    raise FabricMountError(
                        "A pre-restart Meshia mount receipt could not be retired."
                    ) from error
                self.logger.record(
                    "fabric_mount_receipt_retired_after_restart",
                    mount_point=str(existing_receipt["mount_point"]),
                )
                existing_receipt = None
            if (
                existing_receipt is not None
                and _mount_receipt_is_proven_detached(existing_receipt)
            ):
                try:
                    self.state_path.unlink()
                except OSError as error:
                    raise FabricMountError(
                        "A detached Meshia mount receipt could not be retired."
                    ) from error
                self.logger.record(
                    "fabric_mount_receipt_retired_after_detach",
                    mount_point=str(existing_receipt["mount_point"]),
                )
                existing_receipt = None
            if existing_receipt is not None or mount_state_path_present(self.state_path):
                raise FabricMountError(
                    "A previous or invalid Meshia mount receipt is still present. "
                    "Stop the prior service, or restart the host if the native "
                    "mount cannot be detached; Meshia will not adopt it."
                )
        runtime = detect_fuse_runtime()
        if runtime is None:
            self.logger.record(
                "fabric_mount_runtime_unavailable",
                install_hint=mount_runtime_help(),
            )
            return False
        initial_registration = mount_registration_state(self.mount_point)
        if initial_registration is True:
            raise FabricMountError(
                f"The Meshia mount point {self.mount_point} is already registered by "
                "the operating system (a stale or foreign mount is still attached); "
                "Meshia will not stack or adopt another mount there. Run "
                "`meshia-node status` for the recovery step."
            )
        if initial_registration is None:
            # The registry did not answer, which on macOS means mount(8) is
            # blocked on a dead network mount. A stat/ismount of the mount
            # point would join that uninterruptible wait, so fail closed.
            raise FabricMountError(
                f"The operating system could not confirm that {self.mount_point} is "
                "free (the mount registry did not answer in time); Meshia will not "
                "start a second file server on top of a possibly attached mount."
            )
        windows_drive = sys.platform == "win32" and _WINDOWS_DRIVE_ROOT_RE.fullmatch(
            str(self.mount_point)
        )
        if sys.platform == "win32" and not windows_drive:
            # WinFsp owns creation/removal of a directory mount point. Creating
            # it first makes its native mount call fail with an occupied path.
            ensure_private_dir(self.mount_point.parent)
            if os.path.lexists(self.mount_point):
                raise FabricMountError("The Windows directory mount point is occupied.")
        elif not windows_drive:
            ensure_private_dir(self.mount_point)
            if any(self.mount_point.iterdir()) and not os.path.ismount(self.mount_point):
                raise FabricMountError("The Meshia mount point is not empty.")
        self.runtime = runtime
        self.transport_backend = select_macos_fuse_backend(runtime)
        os.environ["FUSE_LIBRARY_PATH"] = str(runtime.library_path)
        if (
            sys.platform == "darwin"
            and runtime.kind == "fuse-t"
            and self.transport_backend == "smb"
        ):
            helper_state = self.state_path or (
                self.mount_point.parent / ".meshia-mount-state"
            )
            os.environ["FUSE_NFSSRV_PATH"] = str(
                _write_fuse_t_transport_helper(helper_state)
            )
        try:
            import fuse as fuse_module
        except (ImportError, OSError) as error:
            raise FabricMountError("The Python FUSE adapter is unavailable.") from error
        # fusepy reports an uncaught callback exception only through
        # logging.getLogger("fuse"); route it (and any library ERROR log) into
        # the bounded node log so it can never again vanish to the plist's
        # /dev/null stderr.
        _forward_python_logging_to_node(self.logger)
        FUSE = fuse_module.FUSE
        FuseOSError = fuse_module.FuseOSError
        notification_context: Callable[[], int | None] | None = None
        notification_invalidator: Callable[[int, bytes], int] | None = None
        if (
            sys.platform == "darwin"
            and runtime.kind == "fuse-t"
            and self.transport_backend == "smb"
        ):
            fuse_library = getattr(fuse_module, "_libfuse", None)
            if (
                fuse_library is not None
                and hasattr(fuse_library, "fuse_get_context")
                and hasattr(fuse_library, "fuse_invalidate_path")
            ):
                fuse_library.fuse_invalidate_path.argtypes = [
                    ctypes.c_void_p,
                    ctypes.c_char_p,
                ]
                fuse_library.fuse_invalidate_path.restype = ctypes.c_int

                def current_fuse_pointer() -> int | None:
                    context = fuse_library.fuse_get_context()
                    if not context:
                        return None
                    value = context.contents.fuse
                    return int(value) if value else None

                def invalidate_fuse_path(pointer: int, path: bytes) -> int:
                    return int(
                        fuse_library.fuse_invalidate_path(
                            ctypes.c_void_p(pointer), path
                        )
                    )

                notification_context = current_fuse_pointer
                notification_invalidator = invalidate_fuse_path
        operations = FabricFuseOperations(
            self.backend,
            FuseOSError,
            publish_writes_on_flush=self.transport_backend == "smb",
            native_mount_point=self.mount_point,
            notification_context=notification_context,
            notification_invalidator=notification_invalidator,
            break_metadata_only_smb_leases=(
                runtime.kind == "fuse-t"
                and self.transport_backend == "smb"
                and FUSE_T_TRANSPORT_VERSION == "1.2.7"
            ),
        )
        if sys.platform == "win32":
            try:
                self._windows_loop = _WindowsFuseLoop(fuse_module._libfuse)
            except AttributeError as error:
                raise FabricMountError("The Windows FUSE lifecycle API is unavailable.") from error
            operations.init = self._windows_loop.init
            operations.destroy = self._windows_loop.destroy
        self._operations = operations
        if sys.platform == "linux":
            # Handle callbacks and local-only retained aliases both use the
            # existing descriptor-stat surface, independent of pathname.
            operations.flag_nullpath_ok = True
        install_invalidator = getattr(
            self.backend, "set_namespace_invalidator", None
        )
        if callable(install_invalidator):
            install_invalidator(
                operations.invalidate_path
                if notification_invalidator is not None
                else None
            )
        install_compute_icons = getattr(self.backend, "set_compute_icon_sink", None)
        if callable(install_compute_icons):
            install_compute_icons(operations.set_compute_running)
        common_options: dict[str, object] = {
            "foreground": True,
            "nothreads": False,
            "fsname": "meshia",
        }
        if sys.platform == "darwin":
            # libfuse otherwise rewrites unlink-on-open into a synthetic
            # ``.fuse_hidden*`` rename followed by a later unlink.  Those two
            # callbacks are not one user namespace mutation and can race the
            # remote manifest CAS.  Meshia read handles already own an
            # immutable remote view or a retained local descriptor. Linux
            # retains libfuse names only inside its request adapter instead.
            common_options["hard_remove"] = True
        if sys.platform == "darwin":
            platform_options: dict[str, object] = {
                "volname": MOUNT_NAME,
                # Name the native volume metadata consistently. FUSE-T 1.2.7
                # still owns its internal Guest loopback SMB source, which the
                # non-browsable option below keeps out of Finder's locations.
                "location": MOUNT_NAME,
                # The SMB transport's native URL is an internal Guest loopback
                # session. Keep that server out of Finder's Locations/Computer
                # lists while retaining the ordinary ~/Meshia mount directory.
                "nobrowse": True,
                # Keep mmap and ordinary kernel readahead available for model
                # weights. The page cache is memory-pressure managed; verified
                # persistent ranges remain bounded by Fabric's disk cache.
                #
                # Attribute caching stays ON in the transport, bounded to one
                # second. With ``noattrcache`` the macOS SMB client re-stats
                # the whole ancestor chain on nearly every operation: ~300
                # getattr callbacks per create, which is the floor under a
                # bulk copy even with the sync engine in another process
                # (2026-09-02, fabric_mount_op_stats: 94% server-cache hits at
                # 265 us each under the storm's own GIL contention). One
                # second is the staleness class the server-side attribute cache
                # already accepts, and remote publications still invalidate
                # through fuse_invalidate_path. Do not pass ``nomtime``: the
                # SMB client's SetInfo mtime is the identity NSDocument saw
                # before delayed writeback, and the adapter must receive it to
                # keep the eventual local inode identical.
                "attrcache-timeout": MOUNT_SMB_TRANSPORT_ATTR_CACHE_SECONDS,
                "nfc": True,
                "rwsize": MOUNT_IO_BYTES,
            }
            platform_options.update(
                _macos_extended_attribute_options(runtime, self.transport_backend)
            )
            if self.transport_backend is not None:
                platform_options["backend"] = self.transport_backend
        elif sys.platform == "win32":
            platform_options = {
                "volname": MOUNT_NAME,
                # WinFsp's -1 identity maps namespace entries to the caller,
                # rather than fabricating a second Windows account boundary.
                "uid": -1,
                "gid": -1,
            }
            if self.windows_workspace_security is not None:
                platform_options.update({
                    "FileSecurity": self.windows_workspace_security,
                    "ExactFileSystemName": "MeshiaWorkspace",
                    # WinFsp disk devices reject AppContainer traversal before
                    # the per-file DACL is evaluated. Its local MUP transport
                    # accepts the same exact workspace SID without changing
                    # driver/device ACLs. Network volumes require a drive mount.
                    "VolumePrefix": "/meshia-private/" + uuid.uuid4().hex,
                })
        else:
            platform_options = {
                "subtype": "meshia",
                "big_writes": True,
                "max_read": MOUNT_IO_BYTES,
            }

        def run() -> None:
            try:
                if sys.platform == "linux":
                    from .linux_fuse import run_linux_fuse
                    run_linux_fuse(fuse_module, operations, str(self.mount_point),
                                   **common_options, **platform_options)
                    return
                FUSE(
                    operations,
                    # WinFsp recognizes only "Z:" as a drive mount. "Z:\\"
                    # enters its directory-mount preflight and is rejected.
                    # Keep the rooted Path for kernel IO and registry checks.
                    str(self.mount_point)[:2] if windows_drive else str(self.mount_point),
                    **common_options,
                    **platform_options,
                )
            except BaseException as error:  # pragma: no cover - runtime boundary
                self._error = error
            finally:
                if self._windows_loop is not None:
                    self._windows_loop.destroy("/")

        applied_interval = tune_interpreter_for_mount_callbacks()
        if applied_interval is not None:
            self.logger.record(
                "fabric_mount_gil_interval_tuned", interval=applied_interval
            )
        self._thread = threading.Thread(target=run, name="meshia-fuse", daemon=True)
        self._thread.start()
        selected_timeout = (
            timeout_seconds
            if timeout_seconds is not None
            else MOUNT_SMB_START_TIMEOUT_SECONDS
            if self.transport_backend == "smb"
            else MOUNT_START_TIMEOUT_SECONDS
        )
        deadline = time.monotonic() + selected_timeout
        fuse_t_helper = sys.platform == "darwin" and runtime.kind == "fuse-t"
        next_helper_discovery = 0.0
        while time.monotonic() < deadline:
            now = time.monotonic()
            if fuse_t_helper and now >= next_helper_discovery:
                # FUSE-T starts its loopback helper before the native SMB/NFS
                # mount necessarily becomes visible. Capture that exact child
                # while startup is pending so a failed native mount can still
                # be cleaned up without a broad process match.
                self._refresh_fuse_t_helper()
                next_helper_discovery = now + MOUNT_HELPER_DISCOVERY_SECONDS
            # Never stat the new mount while waiting for it: a POSIX ismount
            # can block inside the kernel and prevent this loop from reaching
            # its deadline or cleanup. The existing bounded registry probe
            # also handles WinFsp drive roots and directory junctions without
            # traversing them. Unknown is not ready; a live helper alone is
            # not evidence that the OS attached this exact mount path.
            registered = mount_registration_state(self.mount_point)
            if registered is True and self.running:
                if fuse_t_helper:
                    self._refresh_fuse_t_helper()
                if self.state_path is not None:
                    try:
                        write_private_file(
                            self.state_path,
                            json.dumps(
                                {
                                    "schema": MOUNT_STATE_SCHEMA,
                                    "owner_pid": os.getpid(),
                                    "mount_point": str(self.mount_point),
                                    "runtime": runtime.kind,
                                    "transport_backend": self.transport_backend,
                                    "started_at_ns": time.time_ns(),
                                },
                                sort_keys=True,
                                separators=(",", ":"),
                            ).encode("utf-8"),
                        )
                    except BaseException as error:
                        # A live native mount without its private ownership
                        # receipt cannot be distinguished from an orphan on the
                        # next service start. Tear down this exact mount/helper
                        # before returning the receipt error to the caller.
                        self.logger.record(
                            "fabric_mount_receipt_publish_failed",
                            mount_point=str(self.mount_point),
                            error=str(error),
                        )
                        self.close()
                        raise FabricMountError(
                            "The Meshia mount ownership receipt could not be published."
                        ) from error
                self.logger.record(
                    "fabric_mount_started",
                    mount_point=str(self.mount_point),
                    runtime=runtime.kind,
                    transport_backend=self.transport_backend,
                )
                self._mount_ready = True
                if sys.platform.startswith("linux"):
                    self._linux_mount_identity = _linux_meshia_mount_identity(self.mount_point)
                return True
            if not self.running:
                break
            time.sleep(0.05)
        if fuse_t_helper:
            # The helper may have appeared between the last bounded poll and a
            # FUSE error/timeout. One final exact lookup closes that race.
            self._refresh_fuse_t_helper()
        error = self._error
        # A failed start owns the thread and helper it created. Tear them down
        # before returning control so callers cannot accidentally leave a
        # loopback SMB/NFS server behind. close() revalidates PID parentage and
        # argv immediately before signalling and bounds every wait.
        self.close()
        if error is not None:
            raise FabricMountError(f"The Meshia mount failed: {error}") from error
        raise FabricMountError("The Meshia mount did not become ready in time.")

    def close(self) -> bool:
        # Stop callbacks before closing or publishing their backend sessions.
        # Reversing this order leaves a small window where the FUSE loop can
        # accept a new write after backend cleanup has already run.
        thread = self._thread
        self._detached_for_process_exit = False
        operations = self._operations
        remove_invalidator = getattr(
            self.backend, "set_namespace_invalidator", None
        )
        if callable(remove_invalidator):
            remove_invalidator(None)
        remove_compute_icons = getattr(self.backend, "set_compute_icon_sink", None)
        if callable(remove_compute_icons):
            remove_compute_icons(None)
        if operations is not None:
            operations.disable_namespace_notifications()
        if thread is None:
            # Startup can fail before a FUSE thread exists (missing runtime,
            # stale receipt, unsafe mount point). Never probe the mounted
            # namespace from that cleanup path: a dead native mount can block
            # the probe in an uninterruptible kernel wait.
            self.backend.close()
            return True
        foreign_owner = self._foreign_mount_owner()
        if foreign_owner is not None:
            # The receipt at our state path now names another live process:
            # a newer worker or service mounted here after ours was released
            # (an installer swap, `mount --release` followed by a restart).
            # Unmounting by path would tear down THEIR mount -- which is
            # exactly what emptied ~/Meshia during the 2026-09-02 install.
            # Stop our own callbacks, touch nothing at the OS level.
            self.logger.record(
                "fabric_mount_close_skipped_foreign_owner",
                mount_point=str(self.mount_point),
                owner_pid=foreign_owner,
            )
            self._mount_ready = False
            if thread is not None and thread.is_alive():
                return False
            self.backend.close()
            return True
        unmount_succeeded = False
        posix_registry = sys.platform == "darwin" or sys.platform.startswith(
            "linux"
        )
        initial_registry = (
            mount_registration_state(self.mount_point) if posix_registry else None
        )
        proven_detached = False
        normal_attempted = not (posix_registry and initial_registry is False)
        if normal_attempted and sys.platform.startswith("linux") and self._mount_ready:
            # The receipt can still name us after another mount replaces ours
            # at this path. Both ordinary and lazy unmount act by path: require
            # the identity captured at readiness before issuing either command.
            # Missing/unknown identity is not permission to remove a mount.
            normal_attempted = bool(
                self._linux_mount_identity is not None
                and _linux_meshia_mount_identity(self.mount_point) == self._linux_mount_identity
            )
            if not normal_attempted:
                self.logger.record(
                    "fabric_mount_close_skipped_unverified_identity",
                    mount_point=str(self.mount_point),
                )
        # A preflight absence can race a new/unrelated mount at the same path.
        # Skip the command in that state and require a fresh post-attempt
        # absence readback before cleaning any helper or receipt.
        if normal_attempted:
            try:
                if sys.platform == "win32":
                    # WinFsp fuse_unmount only frees a channel; passing NULL
                    # cannot stop the loop created by fuse_main_real. Signal
                    # this mount's exact native loop and verify its teardown.
                    if self._windows_loop is not None:
                        self._windows_loop.stop()
                else:
                    command = ["/sbin/umount", str(self.mount_point)]
                    if sys.platform != "darwin":
                        helper = shutil.which("fusermount3") or shutil.which(
                            "fusermount"
                        )
                        command = [
                            helper or "fusermount",
                            "-u",
                            str(self.mount_point),
                        ]
                    unmount_succeeded = _run_bounded_mount_command(command)
            except (AttributeError, OSError, ValueError):
                pass
        if posix_registry:
            # A bounded umount can time out after the kernel has already
            # detached. Refresh the OS authority before touching the helper or
            # receipt; the pre-attempt observation cannot resolve that race.
            refreshed_registry = mount_registration_state(self.mount_point)
            proven_detached = refreshed_registry is False
            if (
                not unmount_succeeded
                and normal_attempted
                and refreshed_registry is True
                and sys.platform == "darwin"
                and self._mount_ready
            ):
                # The ordinary detach was definitively unsuccessful and the
                # exact owned mount remains registered. Try one bounded native
                # force detach, then require both command success and a second
                # authoritative absence readback. Unknown/still-mounted state
                # deliberately keeps helper, backend, and receipt alive.
                force_succeeded = _run_bounded_mount_command(
                    ["/sbin/umount", "-f", str(self.mount_point)]
                )
                forced_registry = mount_registration_state(self.mount_point)
                proven_detached = bool(
                    force_succeeded and forced_registry is False
                )
                if proven_detached:
                    unmount_succeeded = True
            if (
                sys.platform.startswith("linux")
                and not unmount_succeeded
                and normal_attempted
                and refreshed_registry is True
                and self._mount_ready
                and self._linux_mount_identity is not None
                and self.state_path is not None
            ):
                # A user's cwd/open handle can keep a revoked mount busy.
                # Detach this mount from the namespace without killing that
                # unrelated process. Never apply the fallback to a replacement
                # at the same path or to an unproved/missing ownership receipt.
                receipt = read_mount_state(self.state_path)
                if (
                    receipt is not None
                    and receipt.get("owner_pid") == os.getpid()
                    and receipt.get("mount_point") == str(self.mount_point)
                    and _linux_meshia_mount_identity(self.mount_point) == self._linux_mount_identity
                ):
                    helper = shutil.which("fusermount3") or shutil.which("fusermount")
                    detached = _run_bounded_mount_command(
                        [helper or "fusermount", "-u", "-z", str(self.mount_point)]
                    )
                    proven_detached = bool(
                        detached and mount_registration_state(self.mount_point) is False
                    )
                    if proven_detached:
                        unmount_succeeded = True
                        self.logger.record("fabric_mount_busy_detached", mount_point=str(self.mount_point))
        if sys.platform != "win32" and not unmount_succeeded and not proven_detached:
            self.logger.record(
                "fabric_mount_unmount_not_confirmed",
                mount_point=str(self.mount_point),
            )
        if (
            thread is not None
            and sys.platform == "darwin"
            and self.runtime is not None
            and self.runtime.kind == "fuse-t"
            and self._helper_pid is not None
            and proven_detached
        ):
            # FUSE-T's built-in SMB/NFS client can detach before fusepy's
            # blocking loop sees its private monitor-channel shutdown. Give the
            # normal path a brief chance, then stop only the exact child helper.
            # This avoids exiting the Meshia process under a live local network
            # server, which macOS presents as an interrupted-server dialog.
            if thread.is_alive():
                thread.join(timeout=MOUNT_HELPER_SETTLE_SECONDS)
            if _stop_fuse_t_helper(self._helper_pid, self.mount_point):
                self.logger.record(
                    "fabric_mount_helper_stopped",
                    mount_point=str(self.mount_point),
                    helper_pid=self._helper_pid,
                )
        if thread is not None:
            thread.join(timeout=MOUNT_THREAD_STOP_SECONDS)
        if sys.platform == "win32":
            # A void fuse_exit return proves only that shutdown was requested.
            # Registry absence and an exited callback thread are both required
            # before releasing this mount's receipt or backend sessions.
            proven_detached = mount_registration_state(self.mount_point) is False
        if thread is not None and thread.is_alive():
            # A successful OS detach ends mount ownership even if FUSE-T's
            # private callback loop takes longer to observe its monitor-channel
            # shutdown. Keep the backend open until process exit, but do not
            # leave a same-boot orphan receipt that prevents the replacement
            # service from mounting. Ambiguous or failed detach keeps the
            # receipt and therefore continues to fail closed.
            if sys.platform != "win32" and proven_detached:
                self._retire_owned_mount_receipt()
                self._detached_for_process_exit = True
            # Do not close SQLite or write sessions under a still-live callback.
            # Process exit will close descriptors and recovery markers retain
            # any sealed/pending bytes for the next service start. Retain the
            # thread handle so a later close attempt can retry the unmount
            # instead of falsely treating the mount as stopped.
            self.logger.record("fabric_mount_stop_deferred", mount_point=str(self.mount_point))
            return False
        if (posix_registry or sys.platform == "win32") and not proven_detached:
            # Even if the callback thread happened to stop, a live or unknown
            # registry cannot authorize teardown of the exact transport helper
            # or its recovery receipt. A later close can retry from this state.
            self.logger.record(
                "fabric_mount_stop_deferred",
                mount_point=str(self.mount_point),
            )
            return False
        self._thread = None
        self._operations = None
        self._windows_loop = None
        self._helper_pid = None
        self._mount_ready = False
        self._linux_mount_identity = None
        self._detached_for_process_exit = False
        self.backend.close()
        self._retire_owned_mount_receipt()
        return True


__all__ = [
    "FabricFuseMount",
    "FabricFuseOperations",
    "FabricMountBackend",
    "FabricMountError",
    "FuseRuntime",
    "MOUNT_RUNTIME_HELP",
    "MOUNT_RUNTIME_HELP_LINUX",
    "MOUNT_RUNTIME_HELP_WINDOWS",
    "MOUNT_ADAPTER_ERRORS",
    "MultiWorkspaceMountBackend",
    "MountNode",
    "mount_error_report",
    "detect_fuse_runtime",
    "is_meshia_mount",
    "mount_runtime_help",
    "mount_registration_state",
    "mount_state_path_present",
    "read_mount_state",
    "select_macos_fuse_backend",
    "select_mount_point",
]

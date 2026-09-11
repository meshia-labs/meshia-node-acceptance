"""An offline control plane that re-implements the server's own verification.

This is deliberately *not* a stub: signature checking, canonical string
construction, strict low-S DER parsing, clock skew, generation binding and
sequence consumption are re-derived here from ``web/lib/connected-host-auth.ts``
so the tests prove interop rather than self-consistency.
"""

from __future__ import annotations

import base64
import bisect
import copy
import hashlib
import json
import math
import re
import secrets
import socket
import threading
import time
import unicodedata
import urllib.parse
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I
)
BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
POSITIVE_RE = re.compile(r"^[1-9][0-9]{0,15}$")
RAW_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
MAX_CLOCK_SKEW_SECONDS = 60
SIGNED_REQUEST_LIMIT = 180
SIGNED_REQUEST_WINDOW_SECONDS = 60
ENROLLMENT_PROOF_PREFIX = "meshia.connected-host-enrollment-proof.v1"
ALLOWED_CAPABILITIES = frozenset(
    {
        "executor",
        "filesystem",
        "outside_workspace",
        "task_network",
        "gpu_utilization",
        "key_protection",
        "release_tier",
        "machine_family",
        "apple_chip",
        "cpu_logical",
        "memory_bytes",
        "gpu_family",
        "gpu_count",
        "app_protocol",
    }
)
CAPABILITY_VALUE_RE = re.compile(r"^[A-Za-z0-9 ._:+()-]+$")
PERSONAL_PROFILE = {"workspace": "read_write", "outside_workspace": "none", "network": "deny"}
COMPUTE_PROFILE = {
    "workspace": "read_write",
    "outside_workspace": "none",
    "network": "deny",
    "exec": "workspace",
}
LEGACY_FULL_EXEC_PROFILE = {
    "workspace": "read_write",
    "outside_workspace": "read_write",
    "network": "deny",
    "exec": "workspace",
}
NATIVE_WORKSPACE_PROFILE = {"workspace": "read_write", "outside_workspace": "none", "network": "allow", "exec": "workspace"}
NATIVE_FULL_PROFILE = {"workspace": "read_write", "outside_workspace": "read_write", "network": "allow", "exec": "host"}
ACCEPTED_PROFILES = (PERSONAL_PROFILE, COMPUTE_PROFILE, NATIVE_WORKSPACE_PROFILE, NATIVE_FULL_PROFILE)

# ---------------------------------------------------------------- task env

TASK_ENVIRONMENT_SCHEMA = "meshia.connected_host.task_environment.v1"
SEAL_CONTEXT_PREFIX = "meshia-node-task-env-v1"
# Ported from `web/lib/env-vars.ts` (the key CHECK on
# security.user_environment_variables is `^[A-Z][A-Z0-9_]{0,127}$`).
ENV_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}\Z")  # \Z: `$` would allow a trailing newline
# Ported from `web/lib/env-key-policy.ts`. Only the prefixes matter for the
# node path; the full backend-credential key list is a server-side concern.
RESERVED_ENV_PREFIXES = (
    "MESHIA_",
    "MESH_",
    "RUNPOD_",
    "MODAL_",
    "CLOUDFLARE_",
    "OBJECT_STORE_",
    "SUPABASE_",
    "DAEMON_",
    "SESSION_",
)
# Ported from `web/lib/customer-runtime-env-policy.ts`.
MIN_SECRET_VALUE_LENGTH = 8

# ---------------------------------------------------------------- fabric v2

FABRIC_MANIFEST_SCHEMA = "meshia.connected_host.fabric_manifest.v1"
FABRIC_MANIFEST_BLOCKS_SCHEMA = "meshia.connected_host.fabric_manifest_blocks.v1"
FABRIC_RANGE_SCHEMA = "meshia.connected_host.fabric_range.v1"
FABRIC_CHANGES_SCHEMA = "meshia.connected_host.fabric_changes.v1"
FABRIC_BLOCK_WRITE_SCHEMA = "meshia.connected_host_fabric_block_write_batch.v1"
FABRIC_BLOCK_READ_SCHEMA = "meshia.connected_host_fabric_block_read_batch.v1"
FABRIC_BLOCK_VERIFY_SCHEMA = "meshia.connected_host_fabric_block_verification.v1"
FABRIC_LEGACY_OBJECT_CAS_KIND = "object_cas_v1"
FABRIC_CONNECTED_HOST_OBJECT_CAS_KIND = "connected_host_object_cas_v1"
FABRIC_MUTATION_SCHEMA = "meshia.connected_host.fabric_mutation.v1"
FABRIC_MUTATION_STATUS_SCHEMA = "meshia.connected_host.fabric_mutation_status.v1"
FABRIC_RECOMMENDED_BLOCK_BYTES = 4 * 1024 * 1024
FABRIC_MAX_BLOCK_BYTES = 64 * 1024 * 1024
FABRIC_MAX_BLOCK_TICKETS = 64
FABRIC_MAX_BLOCK_WRITE_TICKETS = 4
FABRIC_MAX_BLOCK_VERIFICATIONS = 4
FABRIC_MAX_MUTATION_BLOCKS = 8_192
FABRIC_MAX_CHANGE_PAGE = 256
FABRIC_MAX_MANIFEST_BLOCK_PAGE = 2_048
FABRIC_MAX_RESPONSE_BYTES = 1_250_000
FABRIC_MAX_VERIFICATION_OPERATIONS = 64
FABRIC_VERIFICATION_OPERATION_TTL_SECONDS = 2 * 60 * 60
FABRIC_DEFAULT_TICKET_TTL_SECONDS = 5 * 60
FABRIC_MAX_WRITE_TICKET_TTL_SECONDS = 15 * 60
FABRIC_MAX_READ_TICKET_TTL_SECONDS = 5 * 60
FABRIC_BLOCK_VERIFICATION_FAILURE_CODES = frozenset(
    {
        "CONNECTED_HOST_FABRIC_BLOCK_MISSING",
        "CONNECTED_HOST_FABRIC_BLOCK_SIZE_METADATA_MISSING_OR_MISMATCHED",
        "CONNECTED_HOST_FABRIC_BLOCK_SIZE_MISMATCH",
        "CONNECTED_HOST_FABRIC_BLOCK_SHA256_MISMATCH",
        "CONNECTED_HOST_FABRIC_BLOCK_PROVIDER_PROOF_MISMATCH",
    }
)


def fabric_mutation_request_digest(
    *,
    session_id: str,
    mutation_id: str,
    base_generation: int,
    base_manifest_digest: str | None,
    mutation: dict[str, Any],
) -> str:
    """Cross-language canonical v2 mutation request digest used by the fake."""

    encoded = json.dumps(
        {
            "schema": "meshiafabric.connected_host_path_mutation_request.v2",
            "session_id": session_id,
            "mutation_id": mutation_id,
            "base_generation": base_generation,
            "base_manifest_digest": base_manifest_digest,
            "mutation": mutation,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
PORTABLE_FORBIDDEN_CHARS = frozenset('<>:"|?*')
MESHIA_RESERVED_TEMP_PATH_SEGMENT_RE = re.compile(
    r"^\..+\.meshia-(?:rename-)?[0-9a-f]{32}(?:\.owner)?$", re.I
)
PORTABLE_RESERVED_STEMS = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        "CLOCK$",
        "CONIN$",
        "CONOUT$",
        *(
            f"COM{suffix}"
            for suffix in ("1", "2", "3", "4", "5", "6", "7", "8", "9", "¹", "²", "³")
        ),
        *(
            f"LPT{suffix}"
            for suffix in ("1", "2", "3", "4", "5", "6", "7", "8", "9", "¹", "²", "³")
        ),
    }
)


@dataclass(frozen=True)
class DirectBlockTicket:
    operation: str
    sha256: str
    size_bytes: int
    expires_at: float


class FabricResponseLost(Exception):
    """The fake committed a direct object but intentionally sent no response."""


@dataclass
class FabricVerificationOperation:
    host_id: str
    host_generation: int
    expires_at: float
    targets: dict[str, int] = field(default_factory=dict)
    verified: dict[str, int] = field(default_factory=dict)


def _json_copy(value: Any) -> Any:
    """Return detached JSON-shaped state, matching an HTTP serialization boundary."""

    return copy.deepcopy(value)


class Rejected(Exception):
    def __init__(
        self,
        status: int,
        code: str,
        message: str = "",
        *,
        details: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(message or code)
        self.status = status
        self.code = code
        self.details = dict(details or {})
        self.headers = dict(headers or {})


def is_strict_low_s_p256(signature: bytes) -> bool:
    """Byte-for-byte port of `isStrictLowSP256Signature`."""
    if len(signature) < 8 or len(signature) > 72:
        return False
    if signature[0] != 0x30 or signature[1] != len(signature) - 2:
        return False
    offset = 2

    def read_integer() -> int | None:
        nonlocal offset
        if offset >= len(signature) or signature[offset] != 0x02:
            return None
        offset += 1
        if offset >= len(signature):
            return None
        length = signature[offset]
        offset += 1
        if not length or length > 33 or offset + length > len(signature):
            return None
        value = signature[offset : offset + length]
        offset += length
        if value[0] & 0x80:
            return None
        if length > 1 and value[0] == 0 and not (value[1] & 0x80):
            return None
        normalized = value[1:] if value[0] == 0 else value
        if not normalized or len(normalized) > 32:
            return None
        return int.from_bytes(normalized, "big")

    r = read_integer()
    s = read_integer()
    return (
        offset == len(signature)
        and r is not None
        and s is not None
        and 0 < r < P256_ORDER
        and 0 < s <= P256_ORDER // 2
    )


def rfc3986(value: str) -> str:
    return urllib.parse.quote(value, safe="", encoding="utf-8")


def canonical_path_and_query(raw_path: str) -> str:
    path, _, query = raw_path.partition("?")
    segments = path.split("/")
    normalized: list[str] = []
    for index, segment in enumerate(segments):
        if not segment:
            if index == 0 or (index == len(segments) - 1 and len(segments) == 2):
                normalized.append("")
                continue
            raise Rejected(400, "PATH_NONCANONICAL")
        decoded = urllib.parse.unquote(segment)
        if decoded in (".", "..") or rfc3986(decoded) != segment:
            raise Rejected(400, "PATH_NONCANONICAL")
        normalized.append(segment)
    joined = "/".join(normalized) or "/"
    pairs = sorted(
        (rfc3986(key), rfc3986(value))
        for key, value in urllib.parse.parse_qsl(query, keep_blank_values=True)
    )
    tail = "&".join(f"{key}={value}" for key, value in pairs)
    return f"{joined}?{tail}" if tail else joined


@dataclass
class Host:
    id: str
    public_key_pem: str
    generation: int = 0
    status: str = "pending_proof"
    session_id: str = ""
    challenge: str = ""
    audience: str = ""
    origin: str = ""
    capabilities: dict[str, str] = field(default_factory=dict)
    consumed: set[tuple[int, int]] = field(default_factory=set)
    owner_email: str = "owner@example.com"
    owner_id: str = "11111111-1111-4111-8111-111111111111"


@dataclass(frozen=True)
class PairingGrant:
    session_id: str
    owner_id: str
    owner_email: str
    expires_at: float


@dataclass
class Command:
    id: str
    command_type: str
    payload: dict[str, Any]
    claim_token: str = ""
    status: str = "queued"
    result: dict[str, Any] = field(default_factory=dict)
    error_code: str | None = None


class FakeControlPlane:
    """Threaded loopback HTTP control plane with real signature verification."""

    def __init__(self, audience: str = "meshia-local") -> None:
        self.safe_errors = []
        self.audience = audience
        self.hosts: dict[str, Host] = {}
        self.pairings: dict[str, PairingGrant] = {}
        self.enrollment_claims: dict[str, tuple[dict[str, Any], str]] = {}
        self.attachments: dict[str, dict[str, Any]] = {}
        self.commands: list[Command] = []
        self.completed: dict[str, Command] = {}
        self.fabric_files: dict[str, bytes] = {}
        self.fabric_file_blocks: dict[str, dict[str, Any]] = {}
        self.fabric_tombstones: dict[str, str] = {}
        self.fabric_cas: dict[str, bytes] = {}
        self.fabric_cas_metadata: dict[str, dict[str, str]] = {}
        self.fabric_verification_operations: dict[
            tuple[str, str], FabricVerificationOperation
        ] = {}
        self.fabric_block_verify_failures: dict[str, str] = {}
        # No manifest exists until the first publish/mutation. Production uses
        # the explicit generation-zero/null base for that bootstrap commit.
        self.fabric_generation = 0
        self.fabric_manifest_available = False
        self.fabric_change_history: dict[int, dict[str, Any]] = {}
        self.fabric_mutation_receipts: dict[
            tuple[str, str], tuple[str, str, int, dict[str, Any]]
        ] = {}
        self.fabric_force_full_manifest = False
        # Production defers only descriptors whose inline block layout would
        # exceed one megabyte. Tests can force that exact wire shape for named
        # non-empty files without allocating tens of thousands of blocks.
        self.fabric_deferred_manifest_paths: set[str] = set()
        self.fabric_change_hook: Callable[[dict[str, Any]], dict[str, Any]] | None = None
        self.fabric_blocks_hook: Callable[[dict[str, Any]], dict[str, Any]] | None = None
        self.fabric_mutate_hook: Callable[[dict[str, Any]], dict[str, Any]] | None = None
        self.fabric_mutate_request_hook: (
            Callable[[Host, dict[str, Any]], None] | None
        ) = None
        self.fabric_direct_put_hook: Callable[[dict[str, Any]], dict[str, Any]] | None = None
        self.fabric_drop_direct_put_response_once = False
        self.fabric_direct_put_attempts: dict[str, int] = {}
        self.fabric_counters: dict[str, int] = {
            "manifest_requests": 0,
            "read_requests": 0,
            "range_bytes": 0,
            "change_requests": 0,
            "block_control_requests": 0,
            "write_ticket_count": 0,
            "max_write_ticket_batch": 0,
            "read_ticket_count": 0,
            "verified_blocks": 0,
            "direct_put_requests": 0,
            "direct_put_bytes": 0,
            "max_direct_put_body_bytes": 0,
            "direct_get_requests": 0,
            "direct_get_bytes": 0,
            "mutation_requests": 0,
            "mutation_replays": 0,
            "mutation_status_requests": 0,
        }
        self.manifest_page_hook: Callable[[dict[str, Any], int], dict[str, Any]] | None = None
        self.read_hook: Callable[[dict[str, Any]], dict[str, Any]] | None = None
        self.publish_hook: Callable[[dict[str, Any]], dict[str, Any]] | None = None
        self.enrollment_requests: list[dict[str, Any]] = []
        self.signed_requests: list[dict[str, Any]] = []
        self.oauth_access_tokens: dict[str, str] = {}
        # The live access mode reported on every heartbeat. `None` models an older
        # control plane that omits the field entirely.
        #
        # The production route derives this narrow value from the authoritative
        # attachment permission profile after renewing the lease; the underlying
        # heartbeat RPC itself intentionally remains migration-free.
        self.access_mode: str | None = "limited"
        self.workspace_name = "Research Workspace"
        # M725 account-scoped workspace authority.  The singular fields above
        # remain the compatibility view of the enrollment session; this
        # registry lets integration tests exercise the production catalog,
        # batch-lease, and revision-fenced rename protocols without replacing
        # the established attach/heartbeat endpoints.
        self.account_catalog_generation = 1
        self.account_workspaces: dict[str, dict[str, Any]] = {}
        self.workspace_rename_receipts: dict[
            tuple[str, str, str], tuple[dict[str, Any], dict[str, Any]]
        ] = {}
        # Workspace-configured environment variables, as the control plane would
        # hold them for the attached session. Tests assign this directly.
        self.workspace_env: dict[str, str] = {}
        # Values of the control plane's own backend credentials. The real policy
        # reads these out of `process.env`; here they are set explicitly so a
        # test can prove an aliased secret is refused.
        self.control_plane_secrets: list[str] = []
        self.task_environment_requests: list[dict[str, Any]] = []
        self.time_offset = 0.0
        self.pairing_time_offset = 0.0
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._state_lock = threading.RLock()
        self._signed_rate_windows: dict[str, tuple[int, float]] = {}
        self._direct_block_tickets: dict[str, DirectBlockTicket] = {}
        self._fabric_digests: dict[int, str] = {}
        self._fabric_manifest_ids: dict[int, str] = {}
        # Immutable per-head layouts let the fake enforce the same authority
        # boundary as production when a mutation reuses target blocks. A digest
        # merely existing in CAS is insufficient proof: it must be an exact
        # digest/size member of both the supplied base head and current target.
        self._fabric_block_snapshots: dict[
            int, dict[str, dict[str, Any]]
        ] = {}
        self.origin = ""

    # ------------------------------------------------------------------ server

    def start(self) -> str:
        plane = self
        server = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(plane))
        self._server = server
        self.origin = f"http://127.0.0.1:{server.server_address[1]}"
        self._thread = threading.Thread(target=server.serve_forever, daemon=True)
        self._thread.start()
        return self.origin

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)



    # ----------------------------------------------------------------- helpers

    def mint_pairing_code(
        self,
        session_id: str | None = None,
        *,
        account_id: str = "11111111-1111-4111-8111-111111111111",
        account_email: str = "owner@example.com",
    ) -> str:
        if not UUID_RE.fullmatch(account_id):
            raise AssertionError("fake pairing accounts require UUID identifiers")
        if not isinstance(account_email, str) or "@" not in account_email:
            raise AssertionError("fake pairing accounts require an email address")
        code = "mesh_" + base64.urlsafe_b64encode(secrets.token_bytes(24)).decode().rstrip("=")
        self.pairings[code] = PairingGrant(
            session_id=session_id or str(uuid.uuid4()),
            owner_id=account_id,
            owner_email=account_email,
            expires_at=self.now() + self.pairing_time_offset + 20 * 60,
        )
        return code

    def enqueue(self, command_type: str, payload: dict[str, Any]) -> str:
        command = Command(id=str(uuid.uuid4()), command_type=command_type, payload=payload)
        self.commands.append(command)
        return command.id






    @property
    def manifest_digest(self) -> str:
        with self._state_lock:
            return self._manifest_digest_unlocked()

    def _manifest_digest_unlocked(self) -> str:
        joiner = hashlib.sha256()
        for path in sorted(self.fabric_files.keys() | self.fabric_tombstones.keys()):
            joiner.update(path.encode("utf-8"))
            if path in self.fabric_files:
                joiner.update(b"\0file\0")
                joiner.update(hashlib.sha256(self.fabric_files[path]).digest())
            else:
                joiner.update(b"\0tombstone\0")
                joiner.update(bytes.fromhex(self.fabric_tombstones[path]))
        return joiner.hexdigest()

    @staticmethod
    def _fabric_path(value: Any) -> str:
        if not isinstance(value, str) or not value:
            raise Rejected(400, "UNSAFE_PATH")
        try:
            utf8_bytes = len(value.encode("utf-8"))
            utf16_units = len(value.encode("utf-16-le")) // 2
        except UnicodeEncodeError:
            raise Rejected(400, "UNSAFE_PATH") from None
        if utf8_bytes > 4_096 or utf16_units > 1_024:
            raise Rejected(400, "UNSAFE_PATH")
        if (
            value != unicodedata.normalize("NFC", value)
            or value.startswith(("/", "~"))
            or "\\" in value
            or (len(value) > 1 and value[1] == ":" and value[0].isalpha())
        ):
            raise Rejected(400, "UNSAFE_PATH")
        parts = value.split("/")
        if any(not part or part in (".", "..") or "\0" in part for part in parts):
            raise Rejected(400, "UNSAFE_PATH")
        for part in parts:
            if (
                len(part.encode("utf-8")) > 255
                or part[-1] in (" ", ".")
                or any(
                    character in PORTABLE_FORBIDDEN_CHARS
                    or ord(character) < 32
                    or ord(character) == 127
                    for character in part
                )
                or part.lower() == ".meshia"
                or MESHIA_RESERVED_TEMP_PATH_SEGMENT_RE.fullmatch(part) is not None
                or part.split(".", 1)[0].upper() in PORTABLE_RESERVED_STEMS
            ):
                raise Rejected(400, "UNSAFE_PATH")
        return value

    @staticmethod
    def _assert_portable_fabric_namespace(paths: Any) -> None:
        """Mirror the production manifest's whole-namespace portability check."""

        canonical_prefixes: dict[str, str] = {}
        live_by_portable_path: dict[str, str] = {}
        path_list = list(paths)
        for path in path_list:
            segments = path.split("/")
            for index in range(1, len(segments) + 1):
                prefix = "/".join(segments[:index])
                portable_prefix = unicodedata.normalize("NFC", prefix.lower())
                prior = canonical_prefixes.get(portable_prefix)
                if prior is not None and prior != prefix:
                    raise Rejected(409, "FABRIC_MUTATION_PATH_CONFLICT")
                canonical_prefixes[portable_prefix] = prefix
            portable_path = unicodedata.normalize("NFC", path.lower())
            if portable_path in live_by_portable_path:
                raise Rejected(409, "FABRIC_MUTATION_PATH_CONFLICT")
            live_by_portable_path[portable_path] = path

        for path in path_list:
            segments = path.split("/")
            for index in range(1, len(segments)):
                portable_ancestor = unicodedata.normalize(
                    "NFC", "/".join(segments[:index]).lower()
                )
                if portable_ancestor in live_by_portable_path:
                    raise Rejected(409, "FABRIC_MUTATION_PATH_CONFLICT")

    def _seed_file_blocks_locked(self, data: bytes) -> dict[str, Any]:
        chunks = [
            data[offset : offset + FABRIC_RECOMMENDED_BLOCK_BYTES]
            for offset in range(0, len(data), FABRIC_RECOMMENDED_BLOCK_BYTES)
        ]
        if not chunks:
            chunks = [b""]
        offset = 0
        blocks: list[dict[str, Any]] = []
        for index, chunk in enumerate(chunks):
            digest = hashlib.sha256(chunk).hexdigest()
            self.fabric_cas[digest] = chunk
            self.fabric_cas_metadata[digest] = self._canonical_block_metadata(
                digest, len(chunk)
            )
            blocks.append(
                {
                    "index": index,
                    "offset_bytes": offset,
                    "size_bytes": len(chunk),
                    "sha256": digest,
                }
            )
            offset += len(chunk)
        return {
            "version": 1,
            "algorithm": "sha256",
            "block_size_bytes": FABRIC_RECOMMENDED_BLOCK_BYTES if data else 1,
            "block_count": len(blocks),
            "total_bytes": len(data),
            # Seeded/pod-origin fixtures intentionally exercise the legacy CAS
            # reader. Newly verified connected-host writes use the exclusive
            # connected-host prefix below.
            "storage": {"kind": FABRIC_LEGACY_OBJECT_CAS_KIND},
            "blocks": blocks,
        }

    @staticmethod
    def _canonical_block_metadata(digest: str, size: int) -> dict[str, str]:
        return {
            "content-encoding": "identity",
            "content-length": str(size),
            "content-type": "application/octet-stream",
            "etag": f'"{digest[:32]}"',
            "x-amz-checksum-sha256": base64.b64encode(
                bytes.fromhex(digest)
            ).decode("ascii"),
            "x-amz-meta-meshia-sha256": digest,
            "x-amz-meta-meshia-size-bytes": str(size),
        }

    def _verify_canonical_block_locked(self, block: Mapping[str, Any]) -> bytes:
        digest = str(block["sha256"])
        expected_size = int(block["size_bytes"])
        data = self.fabric_cas.get(digest)
        metadata = self.fabric_cas_metadata.get(digest)
        if data is None or metadata is None:
            raise Rejected(409, "CONNECTED_HOST_FABRIC_BLOCK_MISSING")
        size_metadata = metadata.get("x-amz-meta-meshia-size-bytes")
        content_length = metadata.get("content-length")
        if size_metadata is None or content_length != str(expected_size):
            raise Rejected(
                409,
                "CONNECTED_HOST_FABRIC_BLOCK_SIZE_METADATA_MISSING_OR_MISMATCHED",
            )
        if size_metadata != str(expected_size) or len(data) != expected_size:
            raise Rejected(409, "CONNECTED_HOST_FABRIC_BLOCK_SIZE_MISMATCH")
        if (
            metadata.get("x-amz-meta-meshia-sha256") != digest
            or hashlib.sha256(data).hexdigest() != digest
        ):
            raise Rejected(409, "CONNECTED_HOST_FABRIC_BLOCK_SHA256_MISMATCH")
        if (
            metadata.get("content-encoding", "identity") != "identity"
            or metadata.get("content-type") != "application/octet-stream"
            or metadata.get("x-amz-checksum-sha256")
            != base64.b64encode(bytes.fromhex(digest)).decode("ascii")
            or not metadata.get("etag")
            or any(
                ord(character) < 32 or ord(character) == 127
                for character in metadata.get("etag", "")
            )
        ):
            raise Rejected(409, "CONNECTED_HOST_FABRIC_BLOCK_PROVIDER_PROOF_MISMATCH")
        return data

    def _descriptor_locked(self, path: str) -> dict[str, Any]:
        data = self.fabric_files[path]
        return {
            "path": path,
            "size_bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "modified_at": None,
            "blocks": _json_copy(self.fabric_file_blocks[path]),
        }

    def _manifest_descriptor_locked(self, path: str) -> dict[str, Any]:
        descriptor = self._descriptor_locked(path)
        serialized_size = len(
            json.dumps(descriptor, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        )
        if descriptor["size_bytes"] == 0 or (
            path not in self.fabric_deferred_manifest_paths
            and serialized_size <= 1_000_000
        ):
            return descriptor
        blocks = descriptor["blocks"]
        return {
            **descriptor,
            "blocks": {
                **blocks,
                "blocks_complete": False,
                "blocks": [],
            },
        }

    def _advance_fabric_locked(
        self, previous_digest: str, entries: list[dict[str, Any]]
    ) -> tuple[int, str]:
        self.fabric_generation += 1
        digest = self._manifest_digest_unlocked()
        self._fabric_digests[self.fabric_generation] = digest
        self._fabric_manifest_ids[self.fabric_generation] = str(uuid.uuid4())
        self._fabric_block_snapshots[self.fabric_generation] = _json_copy(
            self.fabric_file_blocks
        )
        self.fabric_change_history[self.fabric_generation] = {
            "manifest_generation": self.fabric_generation,
            "manifest_digest": digest,
            "previous_manifest_digest": previous_digest,
            "published_at": None,
            "entries": _json_copy(entries),
        }
        return self.fabric_generation, digest



    def now(self) -> float:
        return time.time() + self.time_offset


    # ------------------------------------------------------------ verification

    def authenticate(
        self, method: str, raw_path: str, headers: Any, body: bytes, allow_disconnected: bool = False
    ) -> Host:
        host_id = (headers.get("x-meshia-host-id") or "").strip()
        algorithm = (headers.get("x-meshia-key-algorithm") or "").strip()
        signature_text = (headers.get("x-meshia-signature") or "").strip()
        if not UUID_RE.match(host_id):
            raise Rejected(401, "HOST_ID_INVALID")
        if algorithm != "p256-sha256":
            raise Rejected(400, "ALGORITHM_UNSUPPORTED")
        if not signature_text or len(signature_text) > 256 or not BASE64URL_RE.match(signature_text):
            raise Rejected(401, "SIGNATURE_INVALID")
        padding = "=" * (-len(signature_text) % 4)
        signature = base64.urlsafe_b64decode(signature_text + padding)
        if not is_strict_low_s_p256(signature):
            raise Rejected(401, "SIGNATURE_INVALID", "non-canonical signature")
        # Match production's per-host 180/60s signed-auth limiter. It runs
        # after cheap host/signature syntax checks but before timestamp, DB,
        # or cryptographic verification, and uses the fake's controllable
        # clock so retry scheduling tests never sleep.
        now = self.now()
        with self._state_lock:
            count, reset_at = self._signed_rate_windows.get(
                host_id, (0, now + SIGNED_REQUEST_WINDOW_SECONDS)
            )
            if now >= reset_at:
                count, reset_at = 0, now + SIGNED_REQUEST_WINDOW_SECONDS
            count += 1
            self._signed_rate_windows[host_id] = (count, reset_at)
            if count > SIGNED_REQUEST_LIMIT:
                retry_after = max(1, math.ceil(reset_at - now))
                raise Rejected(
                    429,
                    "RATE_LIMITED",
                    "Connected-host request rate exceeded.",
                    details={"retry_after_seconds": retry_after},
                    headers={"Retry-After": str(retry_after)},
                )
        for name, code in (
            ("x-meshia-timestamp", "TIMESTAMP_INVALID"),
            ("x-meshia-host-generation", "GENERATION_INVALID"),
            ("x-meshia-sequence", "SEQUENCE_INVALID"),
        ):
            if not POSITIVE_RE.match((headers.get(name) or "").strip()):
                raise Rejected(401, code)
        timestamp = int(headers["x-meshia-timestamp"])
        claimed_generation = int(headers["x-meshia-host-generation"])
        sequence = int(headers["x-meshia-sequence"])
        if abs(self.now() - timestamp) > MAX_CLOCK_SKEW_SECONDS:
            raise Rejected(401, "TIMESTAMP_OUT_OF_RANGE")
        host = self.hosts.get(host_id)
        allowed = ("connected", "disconnected") if allow_disconnected else ("connected",)
        if host is None or host.status not in allowed or host.generation < 1:
            raise Rejected(403, "HOST_REVOKED")
        if claimed_generation != host.generation:
            raise Rejected(409, "HOST_GENERATION_STALE")
        if host.audience != self.audience or host.origin != self.origin:
            raise Rejected(403, "DEPLOYMENT_BINDING_MISMATCH")
        canonical = "\n".join(
            (
                "meshia-device-request-v1",
                self.audience,
                self.origin,
                method.upper(),
                canonical_path_and_query(raw_path),
                str(timestamp),
                str(sequence),
                hashlib.sha256(body).hexdigest(),
            )
        ).encode("utf-8")
        public_key = serialization.load_pem_public_key(host.public_key_pem.encode("ascii"))
        try:
            public_key.verify(signature, canonical, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature as error:
            raise Rejected(401, "SIGNATURE_INVALID") from error
        with self._state_lock:
            if (host.generation, sequence) in host.consumed:
                raise Rejected(409, "SEQUENCE_REPLAYED")
            host.consumed.add((host.generation, sequence))
            self.signed_requests.append(
                {
                    "method": method.upper(),
                    "path": canonical_path_and_query(raw_path),
                    "sequence": sequence,
                    "generation": host.generation,
                    "body": body,
                }
            )
        return host

    # -------------------------------------------------------------- operations

    def enroll(self, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        self.enrollment_requests.append(payload)
        code = payload.get("pairing_code", "")
        prior_claim = self.enrollment_claims.get(str(code))
        if prior_claim is not None:
            prior_payload, host_id = prior_claim
            host = self.hosts.get(host_id)
            identity_fields = (
                "installation_id",
                "enrollment_idempotency_key",
                "public_key",
            )
            if (
                host is None
                or host.status != "pending_proof"
                or any(payload.get(field) != prior_payload.get(field) for field in identity_fields)
            ):
                raise Rejected(401, "PAIRING_CODE_INVALID")
            return 202, {
                "host_id": host.id,
                "proof_challenge": host.challenge,
                "proof_algorithm": "p256-sha256",
                "proof_format": "der-base64url",
                "reused": True,
                "deployment_audience": host.audience,
            }
        if (
            not re.match(r"^mesh_[A-Za-z0-9_-]{32}$", str(code))
            or code not in self.pairings
            or self.pairings[str(code)].expires_at
            <= self.now() + self.pairing_time_offset
        ):
            raise Rejected(401, "PAIRING_CODE_INVALID")
        if payload.get("key_algorithm") != "p256-sha256":
            raise Rejected(400, "ALGORITHM_UNSUPPORTED")
        if payload.get("public_key_format") != "spki-pem":
            raise Rejected(400, "PUBLIC_KEY_FORMAT_UNSUPPORTED")
        for name, limit in (("display_name", 96), ("platform", 64), ("architecture", 64)):
            value = payload.get(name)
            if not isinstance(value, str) or not 1 <= len(value.strip()) <= limit:
                raise Rejected(400, "BAD_REQUEST", f"{name} is invalid")
        for name in ("installation_id", "enrollment_idempotency_key"):
            if not UUID_RE.match(str(payload.get(name, ""))):
                raise Rejected(400, "BAD_REQUEST", f"{name} must be a UUID")
        capabilities = payload.get("capabilities") or {}
        if len(capabilities) > len(ALLOWED_CAPABILITIES):
            raise Rejected(400, "CAPABILITIES_INVALID")
        for key, value in capabilities.items():
            if (
                key not in ALLOWED_CAPABILITIES
                or not isinstance(value, str)
                or not 1 <= len(value) <= 96
                or not CAPABILITY_VALUE_RE.match(value)
            ):
                raise Rejected(400, "CAPABILITIES_INVALID", f"capability {key} rejected")
        for key, maximum in (("cpu_logical", 1024), ("memory_bytes", 2**51), ("gpu_count", 256)):
            raw = capabilities.get(key)
            if raw is None:
                continue
            if not re.match(r"^(0|[1-9][0-9]{0,18})$", raw) or int(raw) > maximum:
                raise Rejected(400, "CAPABILITIES_INVALID", f"{key} out of range")
        if capabilities.get("machine_family") not in (
            None,
            "apple_silicon",
            "x86_64",
            "arm64",
            "unknown",
        ):
            raise Rejected(400, "CAPABILITIES_INVALID", "machine_family")
        if capabilities.get("gpu_family") not in (
            None,
            "apple_integrated",
            "nvidia",
            "amd",
            "intel",
            "none",
            "unknown",
        ):
            raise Rejected(400, "CAPABILITIES_INVALID", "gpu_family")
        try:
            key = serialization.load_pem_public_key(str(payload.get("public_key", "")).encode())
        except Exception as error:
            raise Rejected(400, "PUBLIC_KEY_INVALID") from error
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
            raise Rejected(400, "PUBLIC_KEY_INVALID")
        grant = self.pairings[str(code)]
        host = Host(
            id=str(uuid.uuid4()),
            public_key_pem=payload["public_key"],
            session_id=grant.session_id,
            challenge=base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("="),
            audience=self.audience,
            origin=self.origin,
            capabilities=dict(capabilities),
            owner_email=grant.owner_email,
            owner_id=grant.owner_id,
        )
        self.hosts[host.id] = host
        self.enrollment_claims[str(code)] = (dict(payload), host.id)
        return 202, {
            "host_id": host.id,
            "proof_challenge": host.challenge,
            "proof_algorithm": "p256-sha256",
            "proof_format": "der-base64url",
            "reused": False,
            "deployment_audience": host.audience,
        }

    def prove(self, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        host = self.hosts.get(str(payload.get("host_id", "")))
        # Production proof completion is idempotent so a client can recover
        # when the server commits the proof but the HTTPS response is lost.
        if host is None or host.status not in {"pending_proof", "connected", "disconnected"}:
            raise Rejected(401, "ENROLLMENT_PROOF_EXPIRED")
        signature_text = str(payload.get("signature", ""))
        if not BASE64URL_RE.match(signature_text) or len(signature_text) > 256:
            raise Rejected(401, "ENROLLMENT_PROOF_INVALID")
        signature = base64.urlsafe_b64decode(signature_text + "=" * (-len(signature_text) % 4))
        if not is_strict_low_s_p256(signature):
            raise Rejected(401, "ENROLLMENT_PROOF_INVALID")
        proof = "\n".join((ENROLLMENT_PROOF_PREFIX, host.id, host.challenge)).encode("utf-8")
        try:
            serialization.load_pem_public_key(host.public_key_pem.encode()).verify(
                signature, proof, ec.ECDSA(hashes.SHA256())
            )
        except InvalidSignature as error:
            raise Rejected(401, "ENROLLMENT_PROOF_INVALID") from error
        if host.status == "pending_proof":
            host.generation += 1
            # The established fixture exposes enrolled hosts as connected;
            # replay preserves that generation/status instead of minting a new
            # authority. Attachment tests exercise the later attach transition.
            host.status = "connected"
        return 201, {
            "host_id": host.id,
            "generation": host.generation,
            "key_algorithm": "p256-sha256",
            "session_id": host.session_id,
            "account_id": host.owner_id,
            "account_email": host.owner_email,
        }

    def attach(self, host: Host, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        permissions = payload.get("permissions")
        if permissions not in ACCEPTED_PROFILES:
            raise Rejected(400, "PERMISSION_PROFILE_INVALID")
        if payload.get("session_id") != host.session_id:
            raise Rejected(404, "SESSION_NOT_FOUND")
        if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", str(payload.get("mount_name", ""))):
            raise Rejected(400, "BAD_REQUEST")
        attachment = {
            "id": str(uuid.uuid4()),
            "host_id": host.id,
            "host_generation": host.generation,
            "session_id": host.session_id,
            "status": "active",
            "mount_name": payload["mount_name"],
            "permissions": dict(permissions),
            "lease_expires_at": self.now() + 90,
        }
        self.attachments[attachment["id"]] = attachment
        self.access_mode = "full" if permissions.get("exec") == "host" else "limited" if permissions == NATIVE_WORKSPACE_PROFILE else "files"
        host.status = "connected"
        grant = self._object_edge_document(host.session_id, attachment["id"])
        return 201, {
            "attachment": attachment,
            "reused": False,
            "workspace_name": self.workspace_name,
            "account_id": host.owner_id,
            "account_email": host.owner_email,
            **({"object_edge": grant} if grant is not None else {}),
        }

    @staticmethod
    def _lease_timestamp(expires_at: float) -> str:
        return (
            datetime.fromtimestamp(expires_at, tz=timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z")
        )

    @staticmethod
    def _exact_workspace_payload(payload: dict[str, Any], allowed: set[str]) -> None:
        if not isinstance(payload, dict) or set(payload) - allowed:
            raise Rejected(400, "BAD_REQUEST")

    @staticmethod
    def _object_edge_flag(payload: dict[str, Any]) -> bool:
        flag = payload.get("object_edge")
        if flag is not None and not isinstance(flag, bool):
            raise Rejected(400, "BAD_REQUEST")
        return bool(flag)

    # Optional Meshia object edge: tests install ``object_edge_grant`` (a
    # callable taking session_id and attachment_id, returning the wire grant
    # document) to hand every attach/heartbeat receipt a scoped token.
    object_edge_grant: Any = None

    def _object_edge_document(self, session_id: str, attachment_id: str) -> dict[str, Any] | None:
        factory = self.object_edge_grant
        if factory is None:
            return None
        return factory(session_id, attachment_id)

    @staticmethod
    def _positive_workspace_integer(value: Any) -> int:
        if type(value) is not int or value < 1 or value > 2**53 - 1:
            raise Rejected(400, "BAD_REQUEST")
        return value

    def _ensure_account_workspace_locked(self, host: Host) -> dict[str, Any]:
        workspace = self.account_workspaces.get(host.session_id)
        if workspace is None:
            workspace = {
                "session_id": host.session_id,
                "owner_id": host.owner_id,
                "name": self.workspace_name,
                "name_revision": 1,
                "binding_generation": 1,
                "quota_bytes": 100 * 1024**3,
                "used_bytes": 0,
            }
            self.account_workspaces[host.session_id] = workspace
        return workspace

    def _account_document(self, host: Host) -> dict[str, Any]:
        return {
            "id": host.owner_id,
            "email": host.owner_email,
            "catalog_generation": self.account_catalog_generation,
        }

    def workspace_catalog(
        self, host: Host, payload: dict[str, Any]
    ) -> tuple[int, dict[str, Any]]:
        self._exact_workspace_payload(
            payload,
            {"known_generation", "snapshot_generation", "after_session_id", "limit"},
        )
        limit = payload.get("limit", 100)
        if type(limit) is not int or not 1 <= limit <= 200:
            raise Rejected(400, "BAD_REQUEST")
        known_generation = payload.get("known_generation")
        snapshot_generation = payload.get("snapshot_generation")
        after_session_id = payload.get("after_session_id")
        if known_generation is not None:
            known_generation = self._positive_workspace_integer(known_generation)
        if snapshot_generation is not None:
            snapshot_generation = self._positive_workspace_integer(snapshot_generation)
        if after_session_id is not None:
            if not isinstance(after_session_id, str) or not UUID_RE.fullmatch(after_session_id):
                raise Rejected(400, "BAD_REQUEST")
            if snapshot_generation is None:
                raise Rejected(400, "BAD_REQUEST")

        with self._state_lock:
            self._ensure_account_workspace_locked(host)
            generation = self.account_catalog_generation
            if snapshot_generation is not None and snapshot_generation != generation:
                raise Rejected(409, "CATALOG_CHANGED")
            account = self._account_document(host)
            if (
                after_session_id is None
                and snapshot_generation is None
                and known_generation == generation
            ):
                return 200, {
                    "schema": "meshia.connected_host.workspace_catalog.v1",
                    "account": account,
                    "unchanged": True,
                    "snapshot_generation": generation,
                    "workspaces": [],
                    "next_after_session_id": None,
                }

            owned = sorted(
                (
                    workspace
                    for workspace in self.account_workspaces.values()
                    if workspace["owner_id"] == host.owner_id
                    and (after_session_id is None or workspace["session_id"] > after_session_id)
                ),
                key=lambda workspace: workspace["session_id"],
            )
            page = owned[:limit]
            has_more = len(owned) > limit
            workspaces: list[dict[str, Any]] = []
            now = self.now()
            for workspace in page:
                active = next(
                    (
                        attachment
                        for attachment in self.attachments.values()
                        if attachment.get("host_id") == host.id
                        and attachment.get("host_generation") == host.generation
                        and attachment.get("session_id") == workspace["session_id"]
                        and attachment.get("status") == "active"
                        and float(attachment.get("lease_expires_at", 0)) > now
                    ),
                    None,
                )
                workspaces.append(
                    {
                        "session_id": workspace["session_id"],
                        "name": workspace["name"],
                        "name_revision": workspace["name_revision"],
                        "access": "read_write",
                        "storage": {
                            "state": "ready",
                            "binding_generation": workspace["binding_generation"],
                            "quota_bytes": workspace["quota_bytes"],
                            "used_bytes": workspace["used_bytes"],
                        },
                        "attachment": (
                            None
                            if active is None
                            else {
                                "id": active["id"],
                                "lease_expires_at": self._lease_timestamp(
                                    float(active["lease_expires_at"])
                                ),
                            }
                        ),
                    }
                )
            return 200, {
                "schema": "meshia.connected_host.workspace_catalog.v1",
                "account": account,
                "unchanged": False,
                "snapshot_generation": generation,
                "workspaces": workspaces,
                "next_after_session_id": page[-1]["session_id"] if has_more else None,
            }

    def attach_workspaces(
        self, host: Host, payload: dict[str, Any]
    ) -> tuple[int, dict[str, Any]]:
        self._exact_workspace_payload(
            payload, {"catalog_generation", "workspace_ids", "access_mode", "object_edge"}
        )
        object_edge_requested = self._object_edge_flag(payload)
        access_mode = payload.get("access_mode", "limited")
        if access_mode not in ("files", "limited", "full"):
            raise Rejected(400, "BAD_REQUEST")
        generation = self._positive_workspace_integer(payload.get("catalog_generation"))
        workspace_ids = payload.get("workspace_ids")
        if (
            not isinstance(workspace_ids, list)
            or not 1 <= len(workspace_ids) <= 32
            or any(
                not isinstance(item, str) or not UUID_RE.fullmatch(item)
                for item in workspace_ids
            )
            or len(set(workspace_ids)) != len(workspace_ids)
        ):
            raise Rejected(400, "BAD_REQUEST")

        with self._state_lock:
            self._ensure_account_workspace_locked(host)
            if generation != self.account_catalog_generation:
                raise Rejected(409, "CATALOG_CHANGED")
            targets: list[dict[str, Any]] = []
            for session_id in workspace_ids:
                workspace = self.account_workspaces.get(session_id)
                if workspace is None or workspace["owner_id"] != host.owner_id:
                    raise Rejected(404, "WORKSPACE_NOT_FOUND")
                targets.append(workspace)

            expires_at = self.now() + 90
            receipts: list[dict[str, Any]] = []
            for workspace in targets:
                profile = (
                    COMPUTE_PROFILE
                    if access_mode == "full" and workspace["session_id"] == host.session_id
                    else PERSONAL_PROFILE
                )
                attachment = next(
                    (
                        candidate
                        for candidate in self.attachments.values()
                        if candidate.get("host_id") == host.id
                        and candidate.get("host_generation") == host.generation
                        and candidate.get("session_id") == workspace["session_id"]
                        and candidate.get("status") == "active"
                    ),
                    None,
                )
                reused = attachment is not None
                if attachment is None:
                    attachment = {
                        "id": str(uuid.uuid4()),
                        "host_id": host.id,
                        "host_generation": host.generation,
                        "session_id": workspace["session_id"],
                        "owner_id": host.owner_id,
                        "status": "active",
                        "mount_name": "workspace",
                        "permissions": dict(profile),
                        "lease_expires_at": expires_at,
                    }
                    self.attachments[attachment["id"]] = attachment
                else:
                    attachment["permissions"] = dict(profile)
                    attachment["lease_expires_at"] = expires_at
                receipt = {
                    "session_id": workspace["session_id"],
                    "workspace_name": workspace["name"],
                    "name_revision": workspace["name_revision"],
                    "attachment": {
                        "id": attachment["id"],
                        "lease_expires_at": self._lease_timestamp(expires_at),
                    },
                    "workspace_storage": {
                        "state": "ready",
                        "generation": workspace["binding_generation"],
                        "quota_bytes": workspace["quota_bytes"],
                        "used_bytes": workspace["used_bytes"],
                    },
                    "reused": reused,
                }
                if object_edge_requested:
                    grant = self._object_edge_document(workspace["session_id"], attachment["id"])
                    if grant is not None:
                        receipt["object_edge"] = grant
                receipts.append(receipt)
            host.status = "connected"
            return 201, {
                "schema": "meshia.connected_host.workspace_attachments.v1",
                "account": self._account_document(host),
                "attachments": receipts,
            }

    def heartbeat_workspaces(
        self, host: Host, payload: dict[str, Any]
    ) -> tuple[int, dict[str, Any]]:
        self._exact_workspace_payload(
            payload, {"attachments", "known_catalog_generation", "object_edge"}
        )
        object_edge_requested = self._object_edge_flag(payload)
        pairs = payload.get("attachments")
        known = payload.get("known_catalog_generation")
        if known is not None:
            known = self._positive_workspace_integer(known)
        if not isinstance(pairs, list) or not 1 <= len(pairs) <= 200:
            raise Rejected(400, "BAD_REQUEST")
        normalized: list[tuple[str, str]] = []
        for pair in pairs:
            if not isinstance(pair, dict) or set(pair) != {"attachment_id", "session_id"}:
                raise Rejected(400, "BAD_REQUEST")
            attachment_id = pair.get("attachment_id")
            session_id = pair.get("session_id")
            if (
                not isinstance(attachment_id, str)
                or not UUID_RE.fullmatch(attachment_id)
                or not isinstance(session_id, str)
                or not UUID_RE.fullmatch(session_id)
            ):
                raise Rejected(400, "BAD_REQUEST")
            normalized.append((attachment_id, session_id))
        if (
            len({pair[0] for pair in normalized}) != len(normalized)
            or len({pair[1] for pair in normalized}) != len(normalized)
        ):
            raise Rejected(400, "BAD_REQUEST")

        with self._state_lock:
            self._ensure_account_workspace_locked(host)
            resolved: list[tuple[dict[str, Any], dict[str, Any]]] = []
            for attachment_id, session_id in normalized:
                attachment = self.attachments.get(attachment_id)
                workspace = self.account_workspaces.get(session_id)
                if (
                    attachment is None
                    or attachment.get("host_id") != host.id
                    or attachment.get("host_generation") != host.generation
                    or attachment.get("session_id") != session_id
                    or attachment.get("status") != "active"
                    or workspace is None
                    or workspace.get("owner_id") != host.owner_id
                ):
                    raise Rejected(409, "ATTACHMENT_INACTIVE")
                resolved.append((attachment, workspace))

            expires_at = self.now() + 90
            receipts: list[dict[str, Any]] = []
            for attachment, workspace in resolved:
                attachment["lease_expires_at"] = expires_at
                receipt = {
                    "attachment_id": attachment["id"],
                    "session_id": workspace["session_id"],
                    "lease_expires_at": self._lease_timestamp(expires_at),
                    "workspace_name": workspace["name"],
                    "name_revision": workspace["name_revision"],
                    "access_mode": "limited",
                }
                if object_edge_requested:
                    grant = self._object_edge_document(workspace["session_id"], attachment["id"])
                    if grant is not None:
                        receipt["object_edge"] = grant
                receipts.append(receipt)
            return 200, {
                "schema": "meshia.connected_host.workspace_heartbeat.v1",
                "account": self._account_document(host),
                "catalog_changed": known is not None and known != self.account_catalog_generation,
                "attachments": receipts,
            }

    def account_connection(self, host: Host, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        if set(payload) != {"access_token"} or self.oauth_access_tokens.get(payload.get("access_token")) != host.owner_email:
            raise Rejected(401, "DEVICE_CONNECTION_DENIED")
        return 200, {"linked": True, "host_id": host.id, "generation": host.generation}

    def heartbeat(self, host: Host, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        if "attachments" in payload:
            return self.heartbeat_workspaces(host, payload)
        attachment_id = str(payload.get("attachment_id", ""))
        if attachment_id not in self.attachments:
            raise Rejected(409, "ATTACHMENT_INACTIVE")
        self.attachments[attachment_id]["lease_expires_at"] = self.now() + 90
        body = {"attachment_id": attachment_id, "lease_seconds": 90}
        if self.access_mode is not None:
            body["access_mode"] = self.access_mode
        body["workspace_name"] = self.workspace_name
        body["account_id"] = host.owner_id
        body["account_email"] = host.owner_email
        grant = self._object_edge_document(host.session_id, attachment_id)
        if grant is not None:
            body["object_edge"] = grant
        return 200, body

    def workspace(self, host: Host, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        attachment_id = str(payload.get("attachment_id", ""))
        attachment = self.attachments.get(attachment_id)
        if (
            attachment is None
            or attachment.get("host_id") != host.id
            or payload.get("session_id") != host.session_id
        ):
            raise Rejected(409, "ATTACHMENT_INACTIVE")
        expected_name = payload.get("expected_name")
        new_name = payload.get("new_name")
        if expected_name != self.workspace_name:
            raise Rejected(409, "WORKSPACE_RENAME_CONFLICT")
        if not isinstance(new_name, str) or not new_name or len(new_name) > 100:
            raise Rejected(400, "WORKSPACE_NAME_INVALID")
        with self._state_lock:
            workspace = self._ensure_account_workspace_locked(host)
            if workspace["name"] != new_name:
                workspace["name"] = new_name
                workspace["name_revision"] += 1
                self.account_catalog_generation += 1
            self.workspace_name = new_name
        return 200, {
            "workspace_id": host.session_id,
            "workspace_name": self.workspace_name,
            "changed": True,
        }

    def workspace_rename(
        self, host: Host, session_id: str, payload: dict[str, Any]
    ) -> tuple[int, dict[str, Any]]:
        self._exact_workspace_payload(
            payload,
            {"attachment_id", "expected_name_revision", "name", "idempotency_key"},
        )
        attachment_id = payload.get("attachment_id")
        expected_revision = self._positive_workspace_integer(
            payload.get("expected_name_revision")
        )
        name = payload.get("name")
        idempotency_key = payload.get("idempotency_key")
        if (
            not UUID_RE.fullmatch(session_id)
            or not isinstance(attachment_id, str)
            or not UUID_RE.fullmatch(attachment_id)
        ):
            raise Rejected(400, "BAD_REQUEST")
        if (
            not isinstance(name, str)
            or not name
            or len(name) > 100
            or name != name.strip()
            or name in (".", "..")
            or name.endswith(".")
            or any(character in '<>:"/\\|?*' for character in name)
            or re.fullmatch(
                r"(?:CON|PRN|AUX|NUL|CLOCK\$|CONIN\$|CONOUT\$|COM[1-9]|LPT[1-9])(?:\..*)?",
                name,
                re.IGNORECASE,
            )
        ):
            raise Rejected(400, "WORKSPACE_NAME_INVALID")
        if (
            not isinstance(idempotency_key, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{7,159}", idempotency_key)
        ):
            raise Rejected(400, "IDEMPOTENCY_KEY_INVALID")

        request = {
            "host_id": host.id,
            "host_generation": host.generation,
            "attachment_id": attachment_id,
            "expected_name_revision": expected_revision,
            "name": name,
        }
        receipt_key = (host.owner_id, session_id, idempotency_key)
        with self._state_lock:
            attachment = self.attachments.get(attachment_id)
            workspace = self.account_workspaces.get(session_id)
            if (
                attachment is None
                or attachment.get("host_id") != host.id
                or attachment.get("host_generation") != host.generation
                or attachment.get("session_id") != session_id
                or attachment.get("status") != "active"
                or float(attachment.get("lease_expires_at", 0)) <= self.now()
            ):
                raise Rejected(409, "ATTACHMENT_INACTIVE")
            existing = self.workspace_rename_receipts.get(receipt_key)
            if existing is not None:
                prior_request, prior_receipt = existing
                if prior_request != request:
                    raise Rejected(409, "WORKSPACE_RENAME_IDEMPOTENCY_CONFLICT")
                return 200, _json_copy(prior_receipt)
            if workspace is None or workspace.get("owner_id") != host.owner_id:
                raise Rejected(404, "WORKSPACE_NOT_FOUND")
            if workspace["name_revision"] != expected_revision:
                raise Rejected(409, "WORKSPACE_RENAME_CONFLICT")

            changed = workspace["name"] != name
            if changed:
                workspace["name"] = name
                workspace["name_revision"] += 1
                self.account_catalog_generation += 1
                if session_id == host.session_id:
                    self.workspace_name = name
            receipt = {
                "schema": "meshia.connected_host.workspace_rename.v1",
                "session_id": session_id,
                "name": workspace["name"],
                "name_revision": workspace["name_revision"],
                "catalog_generation": self.account_catalog_generation,
                "changed": changed,
            }
            self.workspace_rename_receipts[receipt_key] = (
                _json_copy(request),
                _json_copy(receipt),
            )
            return 200, receipt

    def metrics(self, host: Host, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        if str(payload.get("attachment_id", "")) not in self.attachments:
            raise Rejected(409, "ATTACHMENT_INACTIVE")
        sequence = payload.get("sample_sequence")
        if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
            raise Rejected(400, "METRICS_INVALID", "sample_sequence")
        cpu = payload.get("task_cpu_percent")
        if cpu is not None and (not isinstance(cpu, (int, float)) or cpu < 0 or cpu > 100):
            raise Rejected(400, "METRICS_INVALID", "task_cpu_percent")
        if payload.get("gpu") != []:
            raise Rejected(400, "METRICS_INVALID", "gpu")
        observed = str(payload.get("observed_at", ""))
        if not observed.endswith("Z"):
            raise Rejected(400, "METRICS_INVALID", "observed_at")
        return 202, {"accepted": True, "sample_sequence": sequence}

    def claim_apps(self, host: Host, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        # Ordinary protocol fixtures have no app work. Disposable install
        # acceptance may override this lane without stealing command claims.
        return 200, {"commands": [], "app_supervision": []}

    def complete_app_batch(self, host: Host, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        completions = payload.get("completions") if isinstance(payload, dict) else None
        if (not isinstance(payload, dict) or set(payload) != {"completions"} or not isinstance(completions, list)
                or not 1 <= len(completions) <= 4 or any(not isinstance(item, dict)
                or set(item) != {"command_id", "claim_token", "status", "result", "error_code"}
                or not isinstance(item.get("command_id"), str) for item in completions)
                or len({item["command_id"] for item in completions}) != len(completions)):
            raise Rejected(400, "COMPLETION_INVALID")
        results = []
        for item in completions:
            command_id = item["command_id"]
            try:
                status, _ = self.complete(host, command_id, {key: value for key, value in item.items() if key != "command_id"})
                results.append({"command_id": command_id, "status": "acknowledged", "http_status": status})
            except Rejected as error:
                results.append({"command_id": command_id, "status": "rejected", "http_status": error.status, "code": error.code})
        return 200, {"completions": results}

    def claim(self, host: Host, *, app_lane: bool = False) -> tuple[int, dict[str, Any] | None]:
        attachment = next((item for item in self.attachments.values()
            if item.get("host_id") == host.id and item.get("host_generation") == host.generation
            and item.get("session_id") == host.session_id and item.get("status") == "active"), None)
        for command in self.commands:
            if command.status == "queued" and (command.command_type in ("app_control", "app_http")) == app_lane:
                command.status = "claimed"
                command.claim_token = str(uuid.uuid4())
                return 200, {
                    "command": {
                        "id": command.id,
                        "claim_token": command.claim_token,
                        "command_type": command.command_type,
                        "payload": command.payload,
                        "host_id": host.id,
                        "host_generation": host.generation,
                        "session_id": host.session_id,
                        "attachment_id": attachment["id"] if attachment else None,
                        "access_mode": self.access_mode,
                        "supervision_seconds": 15,
                    }
                }
        return 204, None

    def supervise(self, host: Host, active: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        command = next((item for item in self.commands if item.id == active.get("id")), None)
        allowed = bool(command and command.claim_token == active.get("claim_token")
            and command.status == "claimed" and self.access_mode == "full" and host.status == "connected")
        return 200, {"supervision": {"continue": allowed, **({"supervision_seconds": 15} if allowed else {})}}

    def complete(self, host: Host, command_id: str, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        for command in self.commands:
            if command.id != command_id:
                continue
            if command.status == "completed":
                raise Rejected(409, "COMMAND_LEASE_LOST")
            if payload.get("claim_token") != command.claim_token:
                raise Rejected(409, "COMMAND_LEASE_LOST")
            if payload.get("status") not in ("succeeded", "failed", "canceled"):
                raise Rejected(400, "COMPLETION_INVALID")
            command.status = "completed"
            command.result = payload.get("result") or {}
            command.error_code = payload.get("error_code")
            self.completed[command.id] = command
            return 200, {"command": {"id": command.id, "status": command.status}}
        raise Rejected(404, "COMMAND_NOT_FOUND")

    # -------------------------------------------------------------- task env

    def _sanitize_workspace_env(self, names: list[str]) -> dict[str, str]:
        """The server-side policy, ported from the web control plane.

        Two independent filters, in the same order the real code applies them:
        a key-level allowlist (``env-key-policy.ts``) and the value-level
        control-plane-secret comparison (``customer-runtime-env-policy.ts``).
        The value comparison is the one that matters here — it is what stops a
        customer renaming one of our credentials and having it delivered to a
        machine we do not control.
        """
        wanted = set(names)
        output: dict[str, str] = {}
        for key, value in self.workspace_env.items():
            if key not in wanted:
                continue  # named delivery: never more than the task asked for
            if not ENV_KEY_RE.match(key):
                continue
            if any(key.startswith(prefix) for prefix in RESERVED_ENV_PREFIXES):
                continue
            if not isinstance(value, str):
                continue
            # `containsControlPlaneSecretValue`: substring, not equality, so
            # wrapping or prefixing a secret does not get through either.
            candidate = value.strip()
            if candidate and any(
                secret and len(secret) >= MIN_SECRET_VALUE_LENGTH and secret in candidate
                for secret in self.control_plane_secrets
            ):
                continue
            output[key] = value
        return output

    def task_environment(self, host: Host, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        self.task_environment_requests.append(dict(payload))
        attachment_id = str(payload.get("attachment_id", ""))
        if attachment_id not in self.attachments:
            raise Rejected(409, "ATTACHMENT_INACTIVE")
        # Same predicate `enqueue_connected_host_command_445` uses to gate exec:
        # absence of the key reads as denial. Workspace variables are only ever
        # consumed by a process, and a personal-tier attachment cannot run one —
        # so without this, pairing a laptop under the "no exec" option would
        # still let it pull every named workspace secret, because the node's own
        # refusal is client-side and the host owns its signing key.
        profile = self.attachments[attachment_id].get("permissions") or {}
        if profile.get("exec") != "workspace":
            # 409 and not 403: the node treats any 403 on a signed route as
            # revocation and disconnects. Denying delivery must not kill a
            # healthy personal-tier connection.
            raise Rejected(409, "CONNECTED_HOST_EXEC_DENIED")
        if payload.get("recipient_algorithm") != "x25519":
            raise Rejected(400, "RECIPIENT_ALGORITHM_UNSUPPORTED")
        raw_recipient = str(payload.get("recipient_public_key", ""))
        if not BASE64URL_RE.match(raw_recipient):
            raise Rejected(400, "RECIPIENT_KEY_INVALID")
        recipient_bytes = base64.urlsafe_b64decode(
            raw_recipient + "=" * (-len(raw_recipient) % 4)
        )
        if len(recipient_bytes) != 32:
            raise Rejected(400, "RECIPIENT_KEY_INVALID")
        names = payload.get("names")
        if not isinstance(names, list) or not all(isinstance(entry, str) for entry in names):
            raise Rejected(400, "ENV_NAMES_INVALID")
        if len(names) > 64:
            raise Rejected(400, "ENV_NAMES_INVALID")

        delivered = self._sanitize_workspace_env([str(entry) for entry in names])
        sender_private = X25519PrivateKey.generate()
        sender_public = sender_private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        shared = sender_private.exchange(X25519PublicKey.from_public_bytes(recipient_bytes))
        context = "\n".join(
            (
                SEAL_CONTEXT_PREFIX,
                host.id,
                str(host.generation),
                attachment_id,
                raw_recipient,
            )
        ).encode("utf-8")
        key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=hashlib.sha256(recipient_bytes + sender_public).digest(),
            info=context,
        ).derive(shared)
        nonce = secrets.token_bytes(12)
        # `cryptography` returns ciphertext||tag; the wire layout is
        # nonce||tag||ciphertext to match `encryptValue` in web/lib/env-vars.ts.
        sealed_body = AESGCM(key).encrypt(
            nonce, json.dumps(delivered, sort_keys=True).encode("utf-8"), context
        )
        ciphertext, tag = sealed_body[:-16], sealed_body[-16:]
        return 200, {
            "schema": TASK_ENVIRONMENT_SCHEMA,
            "sender_public_key": base64.urlsafe_b64encode(sender_public).decode().rstrip("="),
            "sealed_base64": base64.b64encode(nonce + tag + ciphertext).decode("ascii"),
            "names": sorted(delivered),
        }


    # ---------------------------------------------------------------- fabric


    def _require_fabric_attachment(self, host: Host, payload: dict[str, Any]) -> dict[str, Any]:
        attachment = self.attachments.get(str(payload.get("attachment_id", "")))
        if (
            attachment is None
            or attachment.get("status") != "active"
            or attachment.get("host_id") != host.id
            or attachment.get("host_generation") != host.generation
            or float(attachment.get("lease_expires_at", 0)) <= self.now()
            or attachment.get("permissions") not in ACCEPTED_PROFILES
        ):
            raise Rejected(409, "FABRIC_ATTACHMENT_INACTIVE")
        if payload.get("workspace") != "workspace":
            raise Rejected(400, "FABRIC_WORKSPACE_INVALID")
        return attachment

    @staticmethod
    def _exact_keys(payload: dict[str, Any], allowed: set[str]) -> None:
        if set(payload) - allowed:
            raise Rejected(400, "BAD_REQUEST", "Fabric request contains unknown fields.")

    @staticmethod
    def _integer(value: Any, *, minimum: int, maximum: int, code: str) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
            raise Rejected(400, code)
        return value

    @staticmethod
    def _raw_digest(value: Any, code: str = "FABRIC_DIGEST_INVALID") -> str:
        if not isinstance(value, str) or not RAW_SHA256_RE.fullmatch(value):
            raise Rejected(400, code)
        return value

    @classmethod
    def _block_descriptors(
        cls, value: Any, *, maximum: int
    ) -> tuple[int, list[dict[str, Any]]]:
        if not isinstance(value, list) or not value or len(value) > maximum:
            status = 413 if isinstance(value, list) and len(value) > maximum else 400
            raise Rejected(status, "FABRIC_BLOCKS_INVALID")
        unique: dict[str, dict[str, Any]] = {}
        for candidate in value:
            if not isinstance(candidate, dict) or set(candidate) != {"sha256", "size_bytes"}:
                raise Rejected(400, "FABRIC_BLOCKS_INVALID")
            digest = cls._raw_digest(candidate.get("sha256"), "FABRIC_BLOCKS_INVALID")
            size = cls._integer(
                candidate.get("size_bytes"),
                minimum=0,
                maximum=FABRIC_MAX_BLOCK_BYTES,
                code="FABRIC_BLOCKS_INVALID",
            )
            if size == 0 and digest != EMPTY_SHA256:
                raise Rejected(400, "FABRIC_BLOCKS_INVALID")
            prior = unique.get(digest)
            if prior is not None:
                raise Rejected(
                    400,
                    "FABRIC_BLOCK_DESCRIPTOR_DUPLICATE"
                    if prior["size_bytes"] == size
                    else "FABRIC_BLOCK_DESCRIPTOR_CONFLICT",
                )
            unique[digest] = {"sha256": digest, "size_bytes": size}
        return len(value), [unique[digest] for digest in sorted(unique)]

    def _target_verification_blocks_locked(
        self,
        host: Host,
        mutation_id: str,
        blocks: list[dict[str, Any]],
    ) -> FabricVerificationOperation:
        """Establish production's durable mutation/object authority fence.

        The real route does this before returning bearer PUT URLs as well as
        before recording a successful HEAD verification. Keeping the fake's
        fence at ticket issuance is important: otherwise another host could
        mint URLs for the same session/mutation before either upload is
        verified, and ticket-only workloads would evade the durable bounds.
        """

        now = self.now()
        for stale_scope, stale in tuple(self.fabric_verification_operations.items()):
            if stale.expires_at <= now:
                self.fabric_verification_operations.pop(stale_scope, None)
        verification_scope = (host.session_id, mutation_id)
        verification = self.fabric_verification_operations.get(verification_scope)
        if verification is None:
            active = sum(
                1
                for scope, operation_state in self.fabric_verification_operations.items()
                if scope[0] == host.session_id
                and operation_state.host_id == host.id
                and operation_state.host_generation == host.generation
            )
            if active >= FABRIC_MAX_VERIFICATION_OPERATIONS:
                raise Rejected(502, "CONNECTED_HOST_FABRIC_BLOCKS_FAILED")
            verification = FabricVerificationOperation(
                host_id=host.id,
                host_generation=host.generation,
                expires_at=now + FABRIC_VERIFICATION_OPERATION_TTL_SECONDS,
            )
            self.fabric_verification_operations[verification_scope] = verification
        elif (
            verification.host_id != host.id
            or verification.host_generation != host.generation
        ):
            raise Rejected(502, "CONNECTED_HOST_FABRIC_BLOCKS_FAILED")
        new_targets = {
            block["sha256"]: block["size_bytes"]
            for block in blocks
            if block["sha256"] not in verification.targets
        }
        if any(
            verification.targets.get(block["sha256"], block["size_bytes"])
            != block["size_bytes"]
            for block in blocks
        ) or len(verification.targets) + len(new_targets) > FABRIC_MAX_MUTATION_BLOCKS:
            raise Rejected(502, "CONNECTED_HOST_FABRIC_BLOCKS_FAILED")
        verification.targets.update(new_targets)
        return verification

    @staticmethod
    def _ticket_ttl(value: Any, *, maximum: int) -> int:
        if value is None:
            return FABRIC_DEFAULT_TICKET_TTL_SECONDS
        if isinstance(value, bool) or not isinstance(value, int) or not 30 <= value <= maximum:
            raise Rejected(400, "FABRIC_BLOCK_TTL_INVALID")
        return value

    def _mint_direct_ticket_locked(
        self,
        operation: str,
        descriptor: dict[str, Any],
        ttl_seconds: int,
        *,
        content_encoding_identity: bool = False,
    ) -> dict[str, Any]:
        if operation not in {"GET", "PUT"}:
            raise AssertionError("unsupported direct block operation")
        token = secrets.token_urlsafe(32)
        expiry = self.now() + ttl_seconds
        digest = descriptor["sha256"]
        size = descriptor["size_bytes"]
        self._direct_block_tickets[token] = DirectBlockTicket(
            operation, digest, size, expiry
        )
        expires_at = datetime.fromtimestamp(expiry, timezone.utc).isoformat().replace("+00:00", "Z")
        ticket = {
            **descriptor,
            "url": f"{self.origin}/__fabric-blocks/{token}",
            "headers": (
                {
                    **(
                        {"content-encoding": "identity"}
                        if content_encoding_identity
                        else {}
                    ),
                    "content-length": str(size),
                    "content-type": "application/octet-stream",
                    "if-none-match": "*",
                    "x-amz-checksum-sha256": base64.b64encode(
                        bytes.fromhex(digest)
                    ).decode("ascii"),
                    "x-amz-meta-meshia-sha256": digest,
                    "x-amz-meta-meshia-size-bytes": str(size),
                }
                if operation == "PUT"
                else {}
            ),
            "expires_at": expires_at,
        }
        if operation == "PUT":
            ticket["method"] = "PUT"
        return ticket

    def fabric_manifest(self, host: Host, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        self._exact_keys(
            payload,
            {
                "attachment_id",
                "workspace",
                "manifest_id",
                "manifest_digest",
                "manifest_generation",
                "after_path",
                "offset",
                "limit",
            },
        )
        with self._state_lock:
            self._require_fabric_attachment(host, payload)
            self.fabric_counters["manifest_requests"] += 1
            if not self.fabric_manifest_available:
                raise Rejected(409, "FABRIC_MANIFEST_UNAVAILABLE")
            offset = self._integer(
                payload.get("offset", 0), minimum=0, maximum=250_000, code="BAD_REQUEST"
            )
            limit = self._integer(
                payload.get("limit", 1000), minimum=1, maximum=1_000, code="BAD_REQUEST"
            )
            raw_after_path = payload.get("after_path")
            after_path = None if raw_after_path is None else self._fabric_path(raw_after_path)
            cursor_fields = ("manifest_id", "manifest_digest", "manifest_generation")
            cursor_field_count = sum(field in payload for field in cursor_fields)
            if (
                (after_path is None) != (offset == 0)
                or (after_path is None and cursor_field_count != 0)
                or (after_path is not None and cursor_field_count != len(cursor_fields))
            ):
                raise Rejected(409, "FABRIC_MANIFEST_CURSOR_INVALID")
            manifest_id = self._fabric_manifest_ids.get(self.fabric_generation)
            manifest_digest = self._manifest_digest_unlocked()
            if manifest_id is None:
                raise Rejected(503, "FABRIC_MANIFEST_PAGE_INVALID")
            if after_path is not None:
                try:
                    cursor_generation = self._integer(
                        payload.get("manifest_generation"),
                        minimum=1,
                        maximum=2_147_483_647,
                        code="FABRIC_MANIFEST_CURSOR_INVALID",
                    )
                    cursor_digest = self._raw_digest(
                        payload.get("manifest_digest"),
                        "FABRIC_MANIFEST_CURSOR_INVALID",
                    )
                except Rejected:
                    raise Rejected(409, "FABRIC_MANIFEST_CURSOR_INVALID") from None
                if (
                    not isinstance(payload.get("manifest_id"), str)
                    or not UUID_RE.fullmatch(payload["manifest_id"])
                    or payload["manifest_id"] != manifest_id
                    or cursor_digest != manifest_digest
                    or cursor_generation != self.fabric_generation
                ):
                    raise Rejected(409, "FABRIC_MANIFEST_CURSOR_INVALID")
            paths = sorted(self.fabric_files)
            start = 0 if after_path is None else bisect.bisect_right(paths, after_path)
            if start != offset:
                raise Rejected(409, "FABRIC_MANIFEST_CURSOR_INVALID")
            files: list[dict[str, Any]] = []
            response_bytes = 512
            for path in paths[start : start + limit]:
                descriptor = self._manifest_descriptor_locked(path)
                descriptor_bytes = len(
                    json.dumps(descriptor, ensure_ascii=False, separators=(",", ":")).encode(
                        "utf-8"
                    )
                ) + 1
                if response_bytes + descriptor_bytes > FABRIC_MAX_RESPONSE_BYTES:
                    if not files:
                        raise Rejected(503, "FABRIC_DESCRIPTOR_TOO_LARGE")
                    break
                files.append(descriptor)
                response_bytes += descriptor_bytes
            next_offset = offset + len(files)
            truncated = next_offset < len(paths)
            page = {
                "schema": FABRIC_MANIFEST_SCHEMA,
                "workspace": "workspace",
                "manifest_id": manifest_id,
                "manifest_digest": manifest_digest,
                "manifest_generation": self.fabric_generation,
                "offset": offset,
                "limit": limit,
                "total_files": len(paths),
                "truncated": truncated,
                "next_offset": next_offset,
                "next_after_path": files[-1]["path"] if truncated and files else None,
                "files": files,
            }
        if self.manifest_page_hook:
            page = self.manifest_page_hook(page, offset)
        return 200, page

    def fabric_read(self, host: Host, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        range_keys = {
            "offset_bytes",
            "length_bytes",
            "manifest_generation",
            "manifest_digest",
        }
        has_range_field = any(key in payload for key in range_keys)
        self._exact_keys(
            payload,
            {"attachment_id", "workspace", "path"}
            | (range_keys if has_range_field else set()),
        )
        with self._state_lock:
            self._require_fabric_attachment(host, payload)
            self.fabric_counters["read_requests"] += 1
            path = self._fabric_path(payload.get("path"))
            if has_range_field:
                generation = self._integer(
                    payload.get("manifest_generation"),
                    minimum=1,
                    maximum=(1 << 53) - 1,
                    code="FABRIC_RANGE_INVALID",
                )
                manifest_digest = self._raw_digest(
                    payload.get("manifest_digest"), "FABRIC_RANGE_INVALID"
                )
                if (
                    generation != self.fabric_generation
                    or manifest_digest != self._manifest_digest_unlocked()
                ):
                    # Check the immutable head before path membership so a file
                    # removed or shortened after H cannot turn a stale H range
                    # into a misleading 404/400 response.
                    raise Rejected(409, "FABRIC_MANIFEST_CHANGED")
            if path not in self.fabric_files:
                raise Rejected(404, "FABRIC_FILE_NOT_FOUND")
            data = self.fabric_files[path]
            digest = hashlib.sha256(data).hexdigest()
            has_offset = "offset_bytes" in payload
            has_length = "length_bytes" in payload
            if has_range_field and not (has_offset and has_length):
                raise Rejected(400, "FABRIC_RANGE_INVALID")
            if has_offset:
                offset = self._integer(
                    payload["offset_bytes"],
                    minimum=0,
                    maximum=(1 << 53) - 1,
                    code="FABRIC_RANGE_INVALID",
                )
                length = self._integer(
                    payload["length_bytes"],
                    minimum=1,
                    maximum=1_048_576,
                    code="FABRIC_RANGE_INVALID",
                )
                if offset >= len(data) or offset + length > len(data):
                    raise Rejected(400, "FABRIC_RANGE_INVALID")
                content = data[offset : offset + length]
                self.fabric_counters["range_bytes"] += len(content)
                document = {
                    "schema": FABRIC_RANGE_SCHEMA,
                    "workspace": "workspace",
                    "path": path,
                    "file_size_bytes": len(data),
                    "offset_bytes": offset,
                    "length_bytes": len(content),
                    "file_sha256": digest,
                    "range_sha256": hashlib.sha256(content).hexdigest(),
                    "content_base64": base64.b64encode(content).decode("ascii"),
                    "manifest_digest": manifest_digest,
                    "manifest_generation": generation,
                }
            else:
                document = {
                    "schema": "meshia.connected_host.fabric_read.v1",
                    "workspace": "workspace",
                    "path": path,
                    "size_bytes": len(data),
                    "sha256": digest,
                    "content_base64": base64.b64encode(data).decode("ascii"),
                    "manifest_digest": self._manifest_digest_unlocked(),
                    "manifest_generation": self.fabric_generation,
                }
        if self.read_hook:
            document = self.read_hook(document)
        return 200, document

    def fabric_changes(self, host: Host, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        self._exact_keys(
            payload,
            {
                "attachment_id",
                "workspace",
                "after_generation",
                "after_manifest_digest",
                "limit",
            },
        )
        with self._state_lock:
            self._require_fabric_attachment(host, payload)
            self.fabric_counters["change_requests"] += 1
            if not self.fabric_manifest_available:
                raise Rejected(409, "FABRIC_MANIFEST_UNAVAILABLE")
            after = self._integer(
                payload.get("after_generation"),
                minimum=1,
                maximum=(1 << 53) - 2,
                code="FABRIC_CURSOR_INVALID",
            )
            after_digest = self._raw_digest(
                payload.get("after_manifest_digest"), "FABRIC_CURSOR_INVALID"
            )
            limit = self._integer(
                payload.get("limit", 128),
                minimum=1,
                maximum=FABRIC_MAX_CHANGE_PAGE,
                code="BAD_REQUEST",
            )
            common = {
                "schema": FABRIC_CHANGES_SCHEMA,
                "workspace": "workspace",
                "after_generation": after,
                "after_manifest_digest": after_digest,
                "limit": limit,
            }

            def full_refresh() -> dict[str, Any]:
                return {
                    **common,
                    "unchanged": False,
                    "requires_full_manifest": True,
                    "truncated": False,
                    "next_generation": after,
                    "next_manifest_digest": after_digest,
                    "changes": [],
                }

            current_digest = self._manifest_digest_unlocked()
            if self.fabric_force_full_manifest:
                response = full_refresh()
            elif after > self.fabric_generation:
                response = full_refresh()
            elif after == self.fabric_generation:
                if after_digest != current_digest:
                    response = full_refresh()
                else:
                    response = {
                        **common,
                        "unchanged": True,
                        "requires_full_manifest": False,
                        "truncated": False,
                        "next_generation": after,
                        "next_manifest_digest": after_digest,
                        "changes": [],
                    }
            elif self._fabric_digests.get(after) != after_digest:
                response = full_refresh()
            else:
                changes: list[dict[str, Any]] = []
                expected_previous = after_digest
                next_generation = after
                response_bytes = 512
                response_limited = False
                for generation in range(
                    after + 1, min(self.fabric_generation, after + limit) + 1
                ):
                    change = self.fabric_change_history.get(generation)
                    if (
                        change is None
                        or change.get("manifest_generation") != generation
                        or change.get("previous_manifest_digest") != expected_previous
                    ):
                        changes = []
                        break
                    copied_change = _json_copy(change)
                    change_bytes = len(
                        json.dumps(
                            copied_change, ensure_ascii=False, separators=(",", ":")
                        ).encode("utf-8")
                    ) + 1
                    if response_bytes + change_bytes > FABRIC_MAX_RESPONSE_BYTES:
                        response_limited = bool(changes)
                        if not changes:
                            changes = []
                        break
                    changes.append(copied_change)
                    response_bytes += change_bytes
                    expected_previous = str(change["manifest_digest"])
                    next_generation = generation
                if not changes:
                    response = full_refresh()
                else:
                    response = {
                        **common,
                        "unchanged": False,
                        "requires_full_manifest": False,
                        "truncated": response_limited
                        or next_generation < self.fabric_generation,
                        "next_generation": next_generation,
                        "next_manifest_digest": expected_previous,
                        "changes": changes,
                    }
        if self.fabric_change_hook:
            response = self.fabric_change_hook(response)
        return 200, response

    def fabric_blocks(
        self,
        host: Host,
        payload: dict[str, Any],
        *,
        content_encoding_identity: bool = False,
    ) -> tuple[int, dict[str, Any]]:
        operation = payload.get("operation")
        with self._state_lock:
            # Production's signed verify wire deliberately carries neither an
            # attachment claim nor provider-specific upload receipts. Durable
            # mutation targets established at write-ticket issuance are the
            # authority for this exact host generation and mutation UUID.
            attachment = (
                None
                if operation == "verify"
                else self._require_fabric_attachment(host, payload)
            )
            self.fabric_counters["block_control_requests"] += 1
            if operation == "manifest_blocks":
                self._exact_keys(
                    payload,
                    {
                        "attachment_id",
                        "workspace",
                        "operation",
                        "path",
                        "manifest_generation",
                        "manifest_digest",
                        "block_offset",
                        "block_limit",
                    },
                )
                path = self._fabric_path(payload.get("path"))
                generation = self._integer(
                    payload.get("manifest_generation"),
                    minimum=1,
                    maximum=(1 << 53) - 1,
                    code="BAD_REQUEST",
                )
                manifest_digest = self._raw_digest(
                    payload.get("manifest_digest"), "FABRIC_DIGEST_INVALID"
                )
                block_offset = self._integer(
                    payload.get("block_offset", 0),
                    minimum=0,
                    maximum=131_071,
                    code="BAD_REQUEST",
                )
                block_limit = self._integer(
                    payload.get("block_limit", FABRIC_MAX_MANIFEST_BLOCK_PAGE),
                    minimum=1,
                    maximum=FABRIC_MAX_MANIFEST_BLOCK_PAGE,
                    code="BAD_REQUEST",
                )
                if (
                    generation != self.fabric_generation
                    or manifest_digest != self._manifest_digest_unlocked()
                ):
                    raise Rejected(409, "FABRIC_BLOCK_READ_CURSOR_STALE")
                if path not in self.fabric_files:
                    raise Rejected(404, "FABRIC_FILE_NOT_FOUND")
                descriptor = self._descriptor_locked(path)
                layout = descriptor["blocks"]
                if (
                    layout.get("storage", {}).get("kind")
                    not in {
                        FABRIC_LEGACY_OBJECT_CAS_KIND,
                        FABRIC_CONNECTED_HOST_OBJECT_CAS_KIND,
                    }
                    or layout.get("blocks_complete") is False
                    or not isinstance(layout.get("blocks"), list)
                    or len(layout["blocks"]) != layout.get("block_count")
                ):
                    raise Rejected(409, "FABRIC_BLOCK_READ_UNSUPPORTED")
                block_count = layout["block_count"]
                if block_offset >= block_count:
                    raise Rejected(400, "FABRIC_BLOCK_CURSOR_INVALID")
                blocks = _json_copy(
                    layout["blocks"][block_offset : block_offset + block_limit]
                )
                next_block_offset = block_offset + len(blocks)
                response = {
                    "schema": FABRIC_MANIFEST_BLOCKS_SCHEMA,
                    "workspace": "workspace",
                    "operation": "manifest_blocks",
                    "path": path,
                    "file_size_bytes": descriptor["size_bytes"],
                    "file_sha256": descriptor["sha256"],
                    "manifest_digest": manifest_digest,
                    "manifest_generation": generation,
                    "block_size_bytes": layout["block_size_bytes"],
                    "block_count": block_count,
                    "total_bytes": layout["total_bytes"],
                    "storage": _json_copy(layout["storage"]),
                    **(
                        {"chunking": _json_copy(layout["chunking"])}
                        if "chunking" in layout
                        else {}
                    ),
                    "block_offset": block_offset,
                    "block_limit": block_limit,
                    "next_block_offset": next_block_offset,
                    "truncated": next_block_offset < block_count,
                    "blocks": blocks,
                }
            elif operation == "write_batch":
                assert attachment is not None
                self._exact_keys(
                    payload,
                    {
                        "attachment_id",
                        "workspace",
                        "operation",
                        "mutation_id",
                        "blocks",
                        "ttl_seconds",
                    },
                )
                mutation_id = str(payload.get("mutation_id", ""))
                if not UUID_RE.fullmatch(mutation_id):
                    raise Rejected(400, "BAD_REQUEST", "mutation_id must be a UUID")
                requested, blocks = self._block_descriptors(
                    payload.get("blocks"), maximum=FABRIC_MAX_BLOCK_WRITE_TICKETS
                )
                ttl = self._ticket_ttl(
                    payload.get("ttl_seconds"), maximum=FABRIC_MAX_WRITE_TICKET_TTL_SECONDS
                )
                remaining = int(float(attachment["lease_expires_at"]) - self.now()) - 5
                if remaining < 30:
                    raise Rejected(409, "FABRIC_ATTACHMENT_LEASE_TOO_SHORT")
                ttl = min(ttl, remaining)
                self._target_verification_blocks_locked(host, mutation_id, blocks)
                tickets = [
                    self._mint_direct_ticket_locked(
                        "PUT", block, ttl, content_encoding_identity=content_encoding_identity
                    )
                    for block in blocks
                ]
                self.fabric_counters["write_ticket_count"] += len(tickets)
                self.fabric_counters["max_write_ticket_batch"] = max(
                    self.fabric_counters["max_write_ticket_batch"], len(tickets)
                )
                response = {
                    "schema": FABRIC_BLOCK_WRITE_SCHEMA,
                    "operation": "write_batch",
                    "mutation_id": mutation_id,
                    "requested_block_count": requested,
                    "unique_block_count": len(blocks),
                    "recommended_block_bytes": FABRIC_RECOMMENDED_BLOCK_BYTES,
                    "tickets": tickets,
                }
            elif operation == "verify":
                self._exact_keys(
                    payload,
                    {"operation", "mutation_id", "blocks"},
                )
                if not UUID_RE.fullmatch(str(payload.get("mutation_id", ""))):
                    raise Rejected(400, "BAD_REQUEST", "mutation_id must be a UUID")
                _requested, blocks = self._block_descriptors(
                    payload.get("blocks"), maximum=FABRIC_MAX_BLOCK_VERIFICATIONS
                )
                verification = self._target_verification_blocks_locked(
                    host, str(payload["mutation_id"]), blocks
                )
                for block in blocks:
                    injected = self.fabric_block_verify_failures.get(block["sha256"])
                    if injected is not None:
                        if injected not in FABRIC_BLOCK_VERIFICATION_FAILURE_CODES:
                            raise AssertionError("invalid fake Fabric verification failure code")
                        raise Rejected(409, injected)
                    self._verify_canonical_block_locked(block)
                for block in blocks:
                    verification.verified[block["sha256"]] = block["size_bytes"]
                self.fabric_counters["verified_blocks"] += len(blocks)
                response = {
                    "schema": FABRIC_BLOCK_VERIFY_SCHEMA,
                    "verified_block_count": len(blocks),
                    "verified_bytes": sum(block["size_bytes"] for block in blocks),
                    "blocks": blocks,
                }
            elif operation == "read_batch":
                assert attachment is not None
                self._exact_keys(
                    payload,
                    {
                        "attachment_id",
                        "workspace",
                        "operation",
                        "path",
                        "manifest_generation",
                        "manifest_digest",
                        "blocks",
                        "ttl_seconds",
                    },
                )
                path = self._fabric_path(payload.get("path"))
                generation = self._integer(
                    payload.get("manifest_generation"),
                    minimum=1,
                    maximum=(1 << 53) - 1,
                    code="FABRIC_BLOCK_READ_CURSOR_STALE",
                )
                digest = self._raw_digest(
                    payload.get("manifest_digest"), "FABRIC_BLOCK_READ_CURSOR_STALE"
                )
                if (
                    generation != self.fabric_generation
                    or digest != self._manifest_digest_unlocked()
                ):
                    raise Rejected(409, "FABRIC_BLOCK_READ_CURSOR_STALE")
                if path not in self.fabric_files:
                    raise Rejected(404, "FABRIC_FILE_NOT_FOUND")
                requested, blocks = self._block_descriptors(
                    payload.get("blocks"), maximum=FABRIC_MAX_BLOCK_TICKETS
                )
                referenced = {
                    block["sha256"]: block["size_bytes"]
                    for block in self.fabric_file_blocks[path]["blocks"]
                }
                if any(referenced.get(block["sha256"]) != block["size_bytes"] for block in blocks):
                    raise Rejected(409, "FABRIC_BLOCK_NOT_REFERENCED")
                ttl = self._ticket_ttl(
                    payload.get("ttl_seconds"), maximum=FABRIC_MAX_READ_TICKET_TTL_SECONDS
                )
                remaining = int(float(attachment["lease_expires_at"]) - self.now()) - 5
                if remaining < 30:
                    raise Rejected(409, "FABRIC_ATTACHMENT_LEASE_TOO_SHORT")
                ttl = min(ttl, remaining)
                tickets = [self._mint_direct_ticket_locked("GET", block, ttl) for block in blocks]
                self.fabric_counters["read_ticket_count"] += len(tickets)
                response = {
                    "schema": FABRIC_BLOCK_READ_SCHEMA,
                    "operation": "read_batch",
                    "requested_block_count": requested,
                    "unique_block_count": len(blocks),
                    "tickets": tickets,
                }
            else:
                raise Rejected(400, "FABRIC_BLOCK_OPERATION_INVALID")
        if self.fabric_blocks_hook:
            response = self.fabric_blocks_hook(response)
        return 200, response

    def fabric_direct_put(
        self, token: str, headers: Any, body: bytes
    ) -> tuple[int, bytes, dict[str, str]]:
        with self._state_lock:
            ticket = self._direct_block_tickets.get(token)
            if ticket is None or ticket.operation != "PUT" or ticket.expires_at <= self.now():
                raise Rejected(403, "FABRIC_BLOCK_TICKET_INVALID")
            checksum = base64.b64encode(bytes.fromhex(ticket.sha256)).decode("ascii")
            if (
                headers.get("Content-Encoding") != "identity"
                or headers.get("Content-Length") != str(ticket.size_bytes)
                or headers.get("Content-Type") != "application/octet-stream"
                or headers.get("If-None-Match") != "*"
                or headers.get("x-amz-checksum-sha256") != checksum
                or headers.get("x-amz-meta-meshia-sha256") != ticket.sha256
                or headers.get("x-amz-meta-meshia-size-bytes")
                != str(ticket.size_bytes)
                or len(body) != ticket.size_bytes
                or hashlib.sha256(body).hexdigest() != ticket.sha256
            ):
                raise Rejected(400, "FABRIC_BLOCK_UPLOAD_MISMATCH")
            self.fabric_counters["direct_put_requests"] += 1
            self.fabric_direct_put_attempts[ticket.sha256] = (
                self.fabric_direct_put_attempts.get(ticket.sha256, 0) + 1
            )
            self.fabric_counters["direct_put_bytes"] += len(body)
            self.fabric_counters["max_direct_put_body_bytes"] = max(
                self.fabric_counters["max_direct_put_body_bytes"], len(body)
            )
            # The canonical CAS path is immutable. Both an exact replay and a
            # same-key concurrent loser receive the provider's ordinary 412;
            # signed exact-HEAD verification decides whether the object is good.
            if ticket.sha256 in self.fabric_cas:
                return 412, b"", {}
            self.fabric_cas[ticket.sha256] = bytes(body)
            self.fabric_cas_metadata[ticket.sha256] = self._canonical_block_metadata(
                ticket.sha256, ticket.size_bytes
            )
            receipt = {
                "sha256": ticket.sha256,
                "size_bytes": ticket.size_bytes,
                "outcome": "stored",
            }
            if self.fabric_direct_put_hook is not None:
                self.fabric_direct_put_hook(_json_copy(receipt))
            if self.fabric_drop_direct_put_response_once:
                self.fabric_drop_direct_put_response_once = False
                raise FabricResponseLost
        return 200, b"", {}

    def fabric_direct_upload_size(self, token: str) -> int:
        with self._state_lock:
            ticket = self._direct_block_tickets.get(token)
            if ticket is None or ticket.operation != "PUT" or ticket.expires_at <= self.now():
                raise Rejected(403, "FABRIC_BLOCK_TICKET_INVALID")
            return ticket.size_bytes

    def fabric_direct_get(self, token: str) -> tuple[int, bytes]:
        with self._state_lock:
            ticket = self._direct_block_tickets.get(token)
            if ticket is None or ticket.operation != "GET" or ticket.expires_at <= self.now():
                raise Rejected(403, "FABRIC_BLOCK_TICKET_INVALID")
            data = self.fabric_cas.get(ticket.sha256)
            if (
                data is None
                or len(data) != ticket.size_bytes
                or hashlib.sha256(data).hexdigest() != ticket.sha256
            ):
                raise Rejected(404, "FABRIC_BLOCK_NOT_FOUND")
            self.fabric_counters["direct_get_requests"] += 1
            self.fabric_counters["direct_get_bytes"] += len(data)
            return 200, bytes(data)

    def _normalize_mutation_expectation(self, value: Any) -> dict[str, Any]:
        if not isinstance(value, dict) or set(value) != {"kind", "digest"}:
            raise Rejected(400, "FABRIC_MUTATION_PRECONDITION_INVALID")
        kind = value.get("kind")
        digest = value.get("digest")
        if kind == "absent" and digest is None:
            return {"kind": "absent", "digest": None}
        if kind in {"file", "tombstone"}:
            return {
                "kind": kind,
                "digest": self._raw_digest(
                    digest, "FABRIC_MUTATION_PRECONDITION_INVALID"
                ),
            }
        raise Rejected(400, "FABRIC_MUTATION_PRECONDITION_INVALID")

    def _expectation_matches_locked(self, path: str, value: Any) -> bool:
        expectation = self._normalize_mutation_expectation(value)
        kind = expectation["kind"]
        digest = expectation["digest"]
        data = self.fabric_files.get(path)
        if kind == "absent" and digest is None:
            return data is None
        if kind == "file":
            return data is not None and hashlib.sha256(data).hexdigest() == digest
        if kind == "tombstone":
            return data is None and self.fabric_tombstones.get(path) == digest
        raise AssertionError("unreachable normalized Fabric mutation expectation")

    def _normalize_put_descriptor(
        self, value: Any
    ) -> tuple[int, str, dict[str, Any]]:
        """Validate and canonicalize a put descriptor without reading CAS bytes."""

        if not isinstance(value, dict) or set(value) != {
            "kind",
            "size_bytes",
            "sha256",
            "modified_at",
            "blocks",
        }:
            raise Rejected(400, "FABRIC_MUTATION_DESCRIPTOR_INVALID")
        if value.get("kind") != "file" or value.get("modified_at") is not None:
            raise Rejected(400, "FABRIC_MUTATION_DESCRIPTOR_INVALID")
        size = self._integer(
            value.get("size_bytes"),
            minimum=0,
            maximum=1 << 40,
            code="FABRIC_MUTATION_DESCRIPTOR_INVALID",
        )
        digest = self._raw_digest(value.get("sha256"), "FABRIC_MUTATION_DESCRIPTOR_INVALID")
        block_map = value.get("blocks")
        allowed_block_keys = {
            "version",
            "algorithm",
            "block_size_bytes",
            "block_count",
            "total_bytes",
            "storage",
            "blocks",
        }
        if not isinstance(block_map, dict) or set(block_map) != allowed_block_keys:
            raise Rejected(400, "FABRIC_MUTATION_DESCRIPTOR_INVALID")
        storage = block_map.get("storage")
        raw_blocks = block_map.get("blocks")
        if (
            block_map.get("version") != 1
            or block_map.get("algorithm") != "sha256"
            or storage != {"kind": FABRIC_CONNECTED_HOST_OBJECT_CAS_KIND}
            or not isinstance(raw_blocks, list)
            or not 1 <= len(raw_blocks) <= FABRIC_MAX_MUTATION_BLOCKS
            or block_map.get("block_count") != len(raw_blocks)
            or block_map.get("total_bytes") != size
        ):
            raise Rejected(400, "FABRIC_MUTATION_DESCRIPTOR_INVALID")
        block_size = self._integer(
            block_map.get("block_size_bytes"),
            minimum=1,
            maximum=FABRIC_MAX_BLOCK_BYTES,
            code="FABRIC_MUTATION_DESCRIPTOR_INVALID",
        )
        expected_offset = 0
        normalized: list[dict[str, Any]] = []
        for index, raw in enumerate(raw_blocks):
            if not isinstance(raw, dict) or set(raw) != {
                "index",
                "offset_bytes",
                "size_bytes",
                "sha256",
            }:
                raise Rejected(400, "FABRIC_MUTATION_DESCRIPTOR_INVALID")
            block_digest = self._raw_digest(
                raw.get("sha256"), "FABRIC_MUTATION_DESCRIPTOR_INVALID"
            )
            block_bytes = self._integer(
                raw.get("size_bytes"),
                minimum=0,
                maximum=FABRIC_MAX_BLOCK_BYTES,
                code="FABRIC_MUTATION_DESCRIPTOR_INVALID",
            )
            if raw.get("index") != index or raw.get("offset_bytes") != expected_offset:
                raise Rejected(400, "FABRIC_MUTATION_DESCRIPTOR_INVALID")
            normalized.append(
                {
                    "index": index,
                    "offset_bytes": expected_offset,
                    "size_bytes": block_bytes,
                    "sha256": block_digest,
                }
            )
            expected_offset += block_bytes
        empty_descriptor = [
            {
                "index": 0,
                "offset_bytes": 0,
                "size_bytes": 0,
                "sha256": EMPTY_SHA256,
            }
        ]
        if (
            expected_offset != size
            or (size == 0 and (block_size != 1 or normalized != empty_descriptor))
        ):
            raise Rejected(400, "FABRIC_MUTATION_DESCRIPTOR_INVALID")
        normalized_map = {
            "version": 1,
            "algorithm": "sha256",
            "block_size_bytes": block_size,
            "block_count": len(normalized),
            "total_bytes": size,
            "storage": {"kind": FABRIC_CONNECTED_HOST_OBJECT_CAS_KIND},
            "blocks": normalized,
        }
        return size, digest, normalized_map

    def _put_descriptor_locked(
        self,
        value: Any,
        *,
        verification_scope: tuple[str, str, int, str] | None = None,
        reusable_blocks: Mapping[str, int] | None = None,
    ) -> tuple[bytes, dict[str, Any]]:
        size, digest, normalized_map = self._normalize_put_descriptor(value)
        normalized = normalized_map["blocks"]
        if verification_scope is not None:
            verification_key = (verification_scope[0], verification_scope[3])
            verification = self.fabric_verification_operations.get(verification_key)
            reusable = reusable_blocks or {}
            needs_upload_proof = [
                block
                for block in normalized
                if reusable.get(block["sha256"]) != block["size_bytes"]
            ]
            if needs_upload_proof and (
                verification is None
                or verification.host_id != verification_scope[1]
                or verification.host_generation != verification_scope[2]
                or verification.expires_at <= self.now()
                or any(
                    verification.verified.get(block["sha256"])
                    != block["size_bytes"]
                    for block in needs_upload_proof
                )
            ):
                if verification is not None and verification.expires_at <= self.now():
                    self.fabric_verification_operations.pop(verification_key, None)
                raise Rejected(409, "FABRIC_MUTATION_BLOCKS_NOT_VERIFIED")
        content: list[bytes] = []
        for block in normalized:
            content.append(self._verify_canonical_block_locked(block))
        data = b"".join(content)
        if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
            raise Rejected(400, "FABRIC_MUTATION_DESCRIPTOR_INVALID")
        return data, normalized_map

    def _normalize_mutation_request(
        self, payload: dict[str, Any]
    ) -> tuple[int, str | None, dict[str, Any]]:
        """Return the exact semantic snake-case request used by the v2 digest."""

        base_generation = self._integer(
            payload.get("base_generation"),
            minimum=0,
            maximum=(1 << 53) - 2,
            code="FABRIC_MUTATION_BASE_INVALID",
        )
        base_digest = payload.get("base_manifest_digest")
        if base_generation == 0:
            if base_digest is not None:
                raise Rejected(400, "FABRIC_MUTATION_BASE_INVALID")
        else:
            base_digest = self._raw_digest(base_digest, "FABRIC_MUTATION_BASE_INVALID")

        value = payload.get("mutation")
        if not isinstance(value, dict):
            raise Rejected(400, "FABRIC_MUTATION_OPERATION_INVALID")
        operation = value.get("operation")
        if operation == "put":
            if set(value) != {"operation", "path", "expected_source", "descriptor"}:
                raise Rejected(400, "BAD_REQUEST")
            size, digest, blocks = self._normalize_put_descriptor(value.get("descriptor"))
            mutation = {
                "operation": "put",
                "path": self._fabric_path(value.get("path")),
                "expected_source": self._normalize_mutation_expectation(
                    value.get("expected_source")
                ),
                "descriptor": {
                    "kind": "file",
                    "size_bytes": size,
                    "sha256": digest,
                    "modified_at": None,
                    "blocks": blocks,
                },
            }
        elif operation == "delete":
            if set(value) != {"operation", "path", "expected_source"}:
                raise Rejected(400, "BAD_REQUEST")
            mutation = {
                "operation": "delete",
                "path": self._fabric_path(value.get("path")),
                "expected_source": self._normalize_mutation_expectation(
                    value.get("expected_source")
                ),
            }
        elif operation == "rename":
            if set(value) != {
                "operation",
                "source_path",
                "destination_path",
                "expected_source",
                "expected_destination",
            }:
                raise Rejected(400, "BAD_REQUEST")
            mutation = {
                "operation": "rename",
                "source_path": self._fabric_path(value.get("source_path")),
                "destination_path": self._fabric_path(value.get("destination_path")),
                "expected_source": self._normalize_mutation_expectation(
                    value.get("expected_source")
                ),
                "expected_destination": self._normalize_mutation_expectation(
                    value.get("expected_destination")
                ),
            }
        else:
            raise Rejected(400, "FABRIC_MUTATION_OPERATION_INVALID")
        return base_generation, base_digest, mutation

    @staticmethod
    def _mutation_request_digest(
        host: Host,
        mutation_id: str,
        base_generation: int,
        base_digest: str | None,
        mutation: dict[str, Any],
    ) -> str:
        return fabric_mutation_request_digest(
            session_id=host.session_id,
            mutation_id=mutation_id,
            base_generation=base_generation,
            base_manifest_digest=base_digest,
            mutation=mutation,
        )

    def fabric_mutate(self, host: Host, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        self._exact_keys(
            payload,
            {
                "attachment_id",
                "workspace",
                "mutation_id",
                "base_generation",
                "base_manifest_digest",
                "mutation",
                "request_digest",
            },
        )
        if self.fabric_mutate_request_hook is not None:
            self.fabric_mutate_request_hook(host, _json_copy(payload))
        with self._state_lock:
            self._require_fabric_attachment(host, payload)
            self.fabric_counters["mutation_requests"] += 1
            mutation_id = str(payload.get("mutation_id", ""))
            if not UUID_RE.fullmatch(mutation_id):
                raise Rejected(400, "BAD_REQUEST", "mutation_id must be a UUID")
            base_generation, base_digest, mutation = self._normalize_mutation_request(payload)
            request_digest = self._raw_digest(
                payload.get("request_digest"), "FABRIC_MUTATION_REQUEST_DIGEST_INVALID"
            )
            # Match production idempotency scope: an attachment is a renewable
            # transport lease, not part of the durable workspace mutation.
            # Replaying the same session/mutation after reconnect must therefore
            # bind to the original receipt instead of conflicting merely because
            # ``attachment_id`` rotated.
            recomputed_digest = self._mutation_request_digest(
                host, mutation_id, base_generation, base_digest, mutation
            )
            if request_digest != recomputed_digest:
                raise Rejected(400, "FABRIC_MUTATION_REQUEST_DIGEST_INVALID")
            replay = self.fabric_mutation_receipts.get((host.session_id, mutation_id))
            if replay is not None:
                if (
                    replay[0] != request_digest
                    or replay[1] != host.id
                    or replay[2] != host.generation
                ):
                    raise Rejected(409, "FABRIC_MUTATION_IDEMPOTENCY_CONFLICT")
                receipt = _json_copy(replay[3])
                receipt["replayed"] = True
                receipt["path_index_deferred"] = True
                self.fabric_counters["mutation_replays"] += 1
                return 200, receipt

            if base_generation > self.fabric_generation or (
                base_generation > 0
                and self._fabric_digests.get(base_generation) != base_digest
            ):
                raise Rejected(409, "FABRIC_MUTATION_BASE_DIVERGED")
            operation = mutation.get("operation")
            previous_digest = self._manifest_digest_unlocked()
            entries: list[dict[str, Any]]
            if operation == "put":
                if set(mutation) != {"operation", "path", "expected_source", "descriptor"}:
                    raise Rejected(400, "BAD_REQUEST")
                path = self._fabric_path(mutation.get("path"))
                if not self._expectation_matches_locked(path, mutation.get("expected_source")):
                    raise Rejected(409, "FABRIC_MUTATION_PATH_CONFLICT")
                self._assert_portable_fabric_namespace(self.fabric_files.keys() | {path})
                prior = self.fabric_files.get(path)
                expected_source = mutation["expected_source"]
                base_layout = (
                    self._fabric_block_snapshots.get(base_generation, {}).get(path)
                    if base_generation > 0
                    else None
                )
                current_layout = self.fabric_file_blocks.get(path)
                reusable_blocks: dict[str, int] = {}
                if (
                    prior is not None
                    and expected_source.get("kind") == "file"
                    and expected_source.get("digest")
                    == hashlib.sha256(prior).hexdigest()
                    and isinstance(base_layout, dict)
                    and isinstance(current_layout, dict)
                ):
                    base_members = {
                        block["sha256"]: block["size_bytes"]
                        for block in base_layout.get("blocks", [])
                        if isinstance(block, dict)
                        and isinstance(block.get("sha256"), str)
                        and isinstance(block.get("size_bytes"), int)
                    }
                    current_members = {
                        block["sha256"]: block["size_bytes"]
                        for block in current_layout.get("blocks", [])
                        if isinstance(block, dict)
                        and isinstance(block.get("sha256"), str)
                        and isinstance(block.get("size_bytes"), int)
                    }
                    reusable_blocks = {
                        digest: size
                        for digest, size in base_members.items()
                        if current_members.get(digest) == size
                    }
                data, blocks = self._put_descriptor_locked(
                    mutation.get("descriptor"),
                    verification_scope=(
                        host.session_id,
                        host.id,
                        host.generation,
                        mutation_id,
                    ),
                    reusable_blocks=reusable_blocks,
                )
                self.fabric_files[path] = data
                self.fabric_file_blocks[path] = blocks
                self.fabric_tombstones.pop(path, None)
                descriptor = self._descriptor_locked(path)
                entries = [
                    {
                        "kind": "file",
                        **descriptor,
                        "previous_sha256": (
                            hashlib.sha256(prior).hexdigest() if prior is not None else None
                        ),
                    }
                ]
                touched_paths = [path]
                entry_sha256: str | None = descriptor["sha256"]
            elif operation == "delete":
                if set(mutation) != {"operation", "path", "expected_source"}:
                    raise Rejected(400, "BAD_REQUEST")
                path = self._fabric_path(mutation.get("path"))
                if not self._expectation_matches_locked(path, mutation.get("expected_source")):
                    raise Rejected(409, "FABRIC_MUTATION_PATH_CONFLICT")
                prior = self.fabric_files.pop(path, None)
                if prior is None:
                    raise Rejected(409, "FABRIC_MUTATION_PATH_CONFLICT")
                self.fabric_file_blocks.pop(path, None)
                entry_sha256 = hashlib.sha256(prior).hexdigest()
                self.fabric_tombstones[path] = entry_sha256
                entries = [
                    {
                        "path": path,
                        "kind": "tombstone",
                        "size_bytes": 0,
                        "sha256": entry_sha256,
                        "modified_at": None,
                    }
                ]
                touched_paths = [path]
            elif operation == "rename":
                if set(mutation) != {
                    "operation",
                    "source_path",
                    "destination_path",
                    "expected_source",
                    "expected_destination",
                }:
                    raise Rejected(400, "BAD_REQUEST")
                source = self._fabric_path(mutation.get("source_path"))
                destination = self._fabric_path(mutation.get("destination_path"))
                if source == destination:
                    raise Rejected(409, "FABRIC_MUTATION_RENAME_SAME_PATH")
                if not self._expectation_matches_locked(
                    source, mutation.get("expected_source")
                ) or not self._expectation_matches_locked(
                    destination, mutation.get("expected_destination")
                ):
                    raise Rejected(409, "FABRIC_MUTATION_PATH_CONFLICT")
                source_data = self.fabric_files.get(source)
                source_blocks = self.fabric_file_blocks.get(source)
                if source_data is None or source_blocks is None:
                    raise Rejected(409, "FABRIC_MUTATION_LEGACY_RENAME_UNSUPPORTED")
                destination_data = self.fabric_files.get(destination)
                candidate_paths = (self.fabric_files.keys() - {source, destination}) | {
                    destination
                }
                self._assert_portable_fabric_namespace(candidate_paths)
                self.fabric_files[destination] = self.fabric_files.pop(source)
                self.fabric_file_blocks[destination] = self.fabric_file_blocks.pop(source)
                entry_sha256 = hashlib.sha256(source_data).hexdigest()
                self.fabric_tombstones[source] = entry_sha256
                self.fabric_tombstones.pop(destination, None)
                entries = [
                    {
                        "path": source,
                        "kind": "tombstone",
                        "size_bytes": 0,
                        "sha256": entry_sha256,
                        "modified_at": None,
                    },
                    {
                        "kind": "file",
                        **self._descriptor_locked(destination),
                        "previous_sha256": (
                            hashlib.sha256(destination_data).hexdigest()
                            if destination_data is not None
                            else None
                        ),
                    },
                ]
                touched_paths = [source, destination]
            else:
                raise Rejected(400, "FABRIC_MUTATION_OPERATION_INVALID")

            self.fabric_manifest_available = True
            generation, digest = self._advance_fabric_locked(previous_digest, entries)
            receipt = {
                "schema": FABRIC_MUTATION_SCHEMA,
                "workspace": "workspace",
                "mutation_id": mutation_id,
                "request_digest": request_digest,
                "operation": operation,
                "touched_paths": touched_paths,
                "entry_sha256": entry_sha256,
                "manifest_id": self._fabric_manifest_ids[generation],
                "manifest_digest": digest,
                "manifest_generation": generation,
                "replayed": False,
                "path_index_deferred": False,
            }
            self.fabric_mutation_receipts[(host.session_id, mutation_id)] = (
                request_digest,
                host.id,
                host.generation,
                _json_copy(receipt),
            )
            verification_scope = (
                host.session_id,
                mutation_id,
            )
            self.fabric_verification_operations.pop(verification_scope, None)
        if self.fabric_mutate_hook:
            receipt = self.fabric_mutate_hook(receipt)
        return 200, receipt

    def fabric_mutation_status(
        self, host: Host, payload: dict[str, Any]
    ) -> tuple[int, dict[str, Any]]:
        self._exact_keys(
            payload, {"attachment_id", "workspace", "mutation_id", "request_digest"}
        )
        with self._state_lock:
            self._require_fabric_attachment(host, payload)
            self.fabric_counters["mutation_status_requests"] += 1
            mutation_id = str(payload.get("mutation_id", ""))
            if not UUID_RE.fullmatch(mutation_id):
                raise Rejected(400, "BAD_REQUEST", "mutation_id must be a UUID")
            request_digest = self._raw_digest(
                payload.get("request_digest"), "FABRIC_MUTATION_REQUEST_DIGEST_INVALID"
            )
            stored = self.fabric_mutation_receipts.get((host.session_id, mutation_id))
            common = {
                "schema": FABRIC_MUTATION_STATUS_SCHEMA,
                "workspace": "workspace",
                "mutation_id": mutation_id,
                "request_digest": request_digest,
            }
            # The receipt's durable idempotency scope is (session, mutation),
            # not the host generation or binding that happened to commit it.
            # Current authority was proven above; a later binding/host rotation
            # must not turn a known ambiguous commit into an unsafe false miss.
            if stored is None:
                return 200, {**common, "found": False}
            if stored[0] != request_digest:
                raise Rejected(409, "FABRIC_MUTATION_IDEMPOTENCY_CONFLICT")
            receipt = stored[3]
            return 200, {
                **common,
                "found": True,
                "operation": receipt["operation"],
                "touched_paths": _json_copy(receipt["touched_paths"]),
                "manifest_id": receipt["manifest_id"],
                "manifest_digest": receipt["manifest_digest"],
                "manifest_generation": receipt["manifest_generation"],
            }

    def fabric_publish(self, host: Host, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        self._exact_keys(
            payload, {"attachment_id", "workspace", "path", "content_base64", "sha256"}
        )
        with self._state_lock:
            self._require_fabric_attachment(host, payload)
            encoded = str(payload.get("content_base64", ""))
            try:
                data = base64.b64decode(encoded, validate=True)
            except ValueError as error:
                raise Rejected(400, "FABRIC_CONTENT_INVALID") from error
            digest = hashlib.sha256(data).hexdigest()
            if payload.get("sha256") != digest:
                raise Rejected(409, "FABRIC_DIGEST_MISMATCH")
            path = self._fabric_path(payload.get("path"))
            prior = self.fabric_files.get(path)
            previous_digest = self._manifest_digest_unlocked()
            self.fabric_files[path] = data
            self.fabric_file_blocks[path] = self._seed_file_blocks_locked(data)
            self.fabric_tombstones.pop(path, None)
            self.fabric_manifest_available = True
            generation, manifest_digest = self._advance_fabric_locked(
                previous_digest,
                [
                    {
                        "kind": "file",
                        **self._descriptor_locked(path),
                        "previous_sha256": (
                            hashlib.sha256(prior).hexdigest() if prior is not None else None
                        ),
                    }
                ],
            )
            document = {
                "schema": "meshia.connected_host.fabric_publish.v1",
                "workspace": "workspace",
                "path": path,
                "size_bytes": len(data),
                "sha256": digest,
                "manifest_id": self._fabric_manifest_ids[generation],
                "manifest_digest": manifest_digest,
                "manifest_generation": generation,
                "replayed": False,
            }
        if self.publish_hook:
            document = self.publish_hook(document)
        return 200, document

    def disconnect(self, host: Host) -> tuple[int, dict[str, Any]]:
        host.status = "disconnected"
        return 200, {"disconnected": True, "generation": host.generation}

    def forget(self, host: Host) -> tuple[int, dict[str, Any]]:
        host.status = "revoked"
        self.hosts.pop(host.id, None)
        return 200, {"forgotten": True}


_SIGNED_ROUTES = [
    (
        re.compile(r"^/api/connected-hosts/([^/]+)/workspaces/catalog$"),
        "workspace_catalog",
        True,
    ),
    (
        re.compile(r"^/api/connected-hosts/([^/]+)/workspaces/attach$"),
        "attach_workspaces",
        True,
    ),
    (
        re.compile(r"^/api/connected-hosts/([^/]+)/workspaces/([^/]+)/rename$"),
        "workspace_rename",
        False,
    ),
    (re.compile(r"^/api/connected-hosts/([^/]+)/attach$"), "attach", True),
    (re.compile(r"^/api/connected-hosts/([^/]+)/workspace$"), "workspace", False),
    (re.compile(r"^/api/connected-hosts/([^/]+)/heartbeat$"), "heartbeat", False),
    (re.compile(r"^/api/connected-hosts/([^/]+)/account-connection$"), "account_connection", True),
    (re.compile(r"^/api/connected-hosts/([^/]+)/metrics$"), "metrics", False),
    (re.compile(r"^/api/connected-hosts/([^/]+)/task-environment$"), "task_environment", False),
    (re.compile(r"^/api/connected-hosts/([^/]+)/commands/claim$"), "claim", False),
    (re.compile(r"^/api/connected-hosts/([^/]+)/commands/complete-app-batch$"), "complete_app_batch", False),
    (
        re.compile(r"^/api/connected-hosts/([^/]+)/commands/([^/]+)/complete$"),
        "complete",
        False,
    ),
    (re.compile(r"^/api/connected-hosts/([^/]+)/fabric/v2-snapshot$"), "fabric_v2_snapshot", False),
    (re.compile(r"^/api/connected-hosts/([^/]+)/fabric/v2-changes$"), "fabric_v2_changes", False),
    (re.compile(r"^/api/connected-hosts/([^/]+)/fabric/v2-lookup$"), "fabric_v2_lookup", False),
    (re.compile(r"^/api/connected-hosts/([^/]+)/fabric/v2-commit$"), "fabric_v2_commit", False),
    (re.compile(r"^/api/connected-hosts/([^/]+)/fabric/manifest$"), "fabric_manifest", False),
    (re.compile(r"^/api/connected-hosts/([^/]+)/fabric/read$"), "fabric_read", False),
    (re.compile(r"^/api/connected-hosts/([^/]+)/fabric/changes$"), "fabric_changes", False),
    (re.compile(r"^/api/connected-hosts/([^/]+)/fabric/blocks$"), "fabric_blocks", False),
    (re.compile(r"^/api/connected-hosts/([^/]+)/fabric/mutate$"), "fabric_mutate", False),
    (
        re.compile(r"^/api/connected-hosts/([^/]+)/fabric/mutation-status$"),
        "fabric_mutation_status",
        False,
    ),
    (re.compile(r"^/api/connected-hosts/([^/]+)/fabric/publish$"), "fabric_publish", False),
    (re.compile(r"^/api/connected-hosts/([^/]+)/disconnect$"), "disconnect", False),
]


def _make_handler(plane: FakeControlPlane) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_: Any) -> None:  # silence the test output
            return

        def _send(
            self,
            status: int,
            document: Any,
            headers: Mapping[str, str] | None = None,
        ) -> None:
            body = (
                b""
                if document is None
                else json.dumps(
                    document, ensure_ascii=False, separators=(",", ":")
                ).encode("utf-8")
            )
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            if body:
                self.wfile.write(body)

        def _send_rejected(self, error: Rejected) -> None:
            plane.safe_errors.append({'status': error.status, 'code': error.code})
            del plane.safe_errors[:-20]
            self._send(
                error.status,
                {"code": error.code, "error": str(error), **error.details},
                error.headers,
            )

        def _send_bytes(
            self, status: int, body: bytes, headers: dict[str, str] | None = None
        ) -> None:
            self.send_response(status)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "private, no-store")
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            if body:
                self.wfile.write(body)

        def _body(self) -> bytes:
            length = int(self.headers.get("Content-Length") or 0)
            return self.rfile.read(length) if length else b""

        def do_GET(self) -> None:  # noqa: N802 - stdlib naming
            match = re.fullmatch(r"/__fabric-blocks/([A-Za-z0-9_-]{32,128})", self.path)
            if match:
                try:
                    if self.headers.get('Range') is not None and hasattr(plane, 'fabric_direct_range'):
                        status, body, headers = plane.fabric_direct_range(match.group(1), self.headers['Range'])
                    else:
                        status, body = plane.fabric_direct_get(match.group(1))
                        headers = {}
                except Rejected as error:
                    self._send_rejected(error)
                    return
                self._send_bytes(status, body, headers)
                return
            self._send(200, {"ok": True})

        def do_PUT(self) -> None:  # noqa: N802
            match = re.fullmatch(r"/__fabric-blocks/([A-Za-z0-9_-]{32,128})", self.path)
            if not match:
                self._send(404, {"code": "NOT_FOUND"})
                return
            try:
                expected_size = plane.fabric_direct_upload_size(match.group(1))
                raw_length = self.headers.get("Content-Length")
                if raw_length != str(expected_size):
                    self.close_connection = True
                    raise Rejected(400, "FABRIC_BLOCK_UPLOAD_MISMATCH")
                body = self.rfile.read(expected_size) if expected_size else b""
                status, response, response_headers = plane.fabric_direct_put(
                    match.group(1), self.headers, body
                )
            except FabricResponseLost:
                # Close the actual transport without headers after the immutable
                # object is durable. This exercises the client's commit-unknown
                # receipt path rather than returning a synthetic HTTP error.
                self.close_connection = True
                try:
                    self.connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                self.connection.close()
                return
            except Rejected as error:
                self._send_rejected(error)
                return
            self._send_bytes(status, response, response_headers)

        def do_DELETE(self) -> None:  # noqa: N802
            body = self._body()
            match = re.match(r"^/api/connected-hosts/([^/]+)$", self.path)
            if not match:
                self._send(404, {"code": "NOT_FOUND"})
                return
            try:
                host = plane.authenticate("DELETE", self.path, self.headers, body, True)
                if body:
                    raise Rejected(400, "BAD_REQUEST", "Forget body must be empty.")
                status, document = plane.forget(host)
            except Rejected as error:
                self._send_rejected(error)
                return
            self._send(status, document)

        def do_POST(self) -> None:  # noqa: N802
            body = self._body()
            try:
                if self.path == "/api/connected-hosts/enroll":
                    status, document = plane.enroll(json.loads(body or b"{}"))
                    self._send(status, document)
                    return
                if self.path == "/api/connected-hosts/enroll/prove":
                    status, document = plane.prove(json.loads(body or b"{}"))
                    self._send(status, document)
                    return
                for pattern, operation, allow_disconnected in _SIGNED_ROUTES:
                    match = pattern.match(self.path.partition("?")[0])
                    if not match:
                        continue
                    host = plane.authenticate(
                        "POST", self.path, self.headers, body, allow_disconnected
                    )
                    if host.id != match.group(1):
                        raise Rejected(401, "HOST_ID_INVALID")
                    if operation in ("claim", "disconnect"):
                        payload = json.loads(body or b"{}")
                        app_claim = (operation == "claim" and isinstance(payload, dict)
                            and set(payload) == {"workspace_commands", "native_execution", "app_commands", "app_protocol", "active_apps"}
                            and payload["workspace_commands"] is True and payload["native_execution"] is True
                            and payload["app_commands"] is True and payload["app_protocol"] == "http-stream-v1"
                            and isinstance(payload["active_apps"], list) and len(payload["active_apps"]) <= 4)
                        if app_claim:
                            status, document = plane.claim_apps(host, payload)
                            self._send(status, document)
                            return
                        workspace_claim = (operation == "claim" and isinstance(payload, dict)
                            and set(payload) in ({"workspace_commands"}, {"workspace_commands", "active_command"},
                                {"workspace_commands", "native_execution"},
                                {"workspace_commands", "native_execution", "active_command"})
                            and payload["workspace_commands"] is True
                            and ("native_execution" not in payload or type(payload["native_execution"]) is bool))
                        if payload != {} and not workspace_claim:
                            raise Rejected(400, "BAD_REQUEST")
                        status, document = (
                            (plane.supervise(host, payload["active_command"]) if "active_command" in payload
                             else plane.claim(host)) if operation == "claim" else plane.disconnect(host)
                        )
                    elif operation == "complete":
                        status, document = plane.complete(
                            host, match.group(2), json.loads(body or b"{}")
                        )
                    elif operation == "workspace_rename":
                        status, document = plane.workspace_rename(
                            host, match.group(2), json.loads(body or b"{}")
                        )
                    else:
                        payload = json.loads(body or b"{}")
                        if operation == "fabric_blocks":
                            query = urllib.parse.parse_qsl(
                                urllib.parse.urlsplit(self.path).query,
                                keep_blank_values=True,
                            )
                            identity = query == [
                                ("ticket_feature", "content_encoding_identity_v1")
                            ]
                            if query and (not identity or payload.get("operation") != "write_batch"):
                                raise Rejected(400, "FABRIC_BLOCK_TICKET_FEATURE_INVALID")
                            status, document = plane.fabric_blocks(
                                host,
                                payload,
                                content_encoding_identity=identity,
                            )
                        else:
                            status, document = getattr(plane, operation)(host, payload)
                    self._send(status, document)
                    return
                self._send(404, {"code": "NOT_FOUND"})
            except Rejected as error:
                self._send_rejected(error)
            except Exception as error:  # pragma: no cover - surfaces test bugs
                plane.safe_errors.append({'status': 500, 'code': 'FAKE_PLANE_ERROR', 'error_type': type(error).__name__})
                del plane.safe_errors[:-20]
                self._send(500, {"code": "FAKE_PLANE_ERROR", "error": repr(error)})

    return Handler

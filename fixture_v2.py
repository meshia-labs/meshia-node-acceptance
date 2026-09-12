"""Bounded current Fabric fixture for this kit's empty workspace and file puts.

The existing signed dispatcher owns authentication. Legacy missing manifests
remain unavailable; sequence zero belongs only to the v2 snapshot/journal.
No native mount, readiness flag or process result is fabricated here.
"""
import base64
import copy
from datetime import datetime, timezone
import hashlib
import json
import re
import struct
import uuid

from fixture_control_plane import Rejected, UUID_RE, FABRIC_BLOCK_READ_SCHEMA


# A deliberately bounded, independent decoder for the released tree wire.
# It validates bytes and typed edges; it never imports the installed writer.
_TREE_ALGORITHM = 'sha256_tree_v1'
_TREE_DOMAIN = b'meshia.fabric.file-tree.v1\x00'
_STORAGE = 'connected_host_object_cas_v1'
_STORAGES = {_STORAGE, 'object_cas_v1'}
_MAX_FILE = 4 * 1024 * 1024
_MAX_SOURCE = 9 * 1024 * 1024
_MAX_TREE_SOURCE = 2 * 1024**3 + 4096
_PAGE = 4096


def _tree_height(size):
    height = 0
    while _PAGE * 64**height < size:
        height += 1
    return height


def _tree_reference(raw, height):
    if raw == b'\0':
        return None
    if raw[:1] == b'\1' and len(raw) == 45:
        size, offset, length = struct.unpack('!III', raw[33:])
        if not (0 < size <= _MAX_FILE and 0 < length <= _PAGE * 64**height
                and offset + length <= size):
            raise ValueError('Invalid data range')
        return ('data', raw[1:33].hex(), size, offset, length)
    if raw[:1] == b'\2' and len(raw) == 37 and height > 0:
        size, = struct.unpack('!I', raw[33:])
        if not 69 <= size <= _PAGE:
            raise ValueError('Invalid metadata size')
        return ('node', raw[1:33].hex(), size)
    raise ValueError('Invalid tree reference')


def _tree_node(raw, height):
    if not 1 <= height <= _tree_height(_MAX_TREE_SOURCE) or not 69 <= len(raw) <= _PAGE or raw[:5] != b'MFT\x01' + bytes([height]):
        raise ValueError('Invalid tree node')
    cursor, children = 5, []
    for _ in range(64):
        length = {0: 1, 1: 45, 2: 37}.get(raw[cursor] if cursor < len(raw) else -1)
        if length is None or cursor + length > len(raw):
            raise ValueError('Truncated tree node')
        children.append(_tree_reference(raw[cursor:cursor+length], height-1))
        cursor += length
    if cursor != len(raw):
        raise ValueError('Trailing tree node bytes')
    return children


def _tree_descriptor(value, size, digest):
    if (not isinstance(value, dict) or set(value) != {'version', 'algorithm', 'file_digest_algorithm', 'total_bytes', 'tree', 'storage'}
            or type(value['version']) is not int or value['version'] != 1 or value['algorithm'] != 'sha256'
            or value['file_digest_algorithm'] != _TREE_ALGORITHM or not isinstance(value['storage'], dict)
            or set(value['storage']) != {'kind'} or value['storage']['kind'] not in _STORAGES
            or type(size) is not int or not 0 <= size <= _MAX_TREE_SOURCE or type(value['total_bytes']) is not int
            or value['total_bytes'] != size):
        raise ValueError('Invalid tree descriptor')
    tree, height = value['tree'], _tree_height(size)
    if (not isinstance(tree, dict) or set(tree) != {'height', 'root'} or type(tree['height']) is not int
            or tree['height'] != height or not isinstance(tree['root'], str) or not 2 <= len(tree['root']) <= 90):
        raise ValueError('Invalid tree root')
    raw = bytes.fromhex(tree['root'])
    root = _tree_reference(raw, height)
    if raw.hex() != tree['root'] or (size == 0 and root is not None) or (root and root[0] == 'data' and root[4] > size):
        raise ValueError('Invalid tree root bounds')
    actual = hashlib.sha256(_TREE_DOMAIN + struct.pack('!QB', size, height) + raw).hexdigest()
    if digest != actual:
        raise ValueError('Tree identity mismatch')
    return height, root


class FabricV2Fixture:
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.v2_entries = {}
        self.v2_journal = []
        self.v2_receipts = {}
        self.v2_calls = {'snapshot': 0, 'changes': 0, 'commit': 0, 'lookup': 0}
        self.v2_tree_nodes = set()
        self.v2_data_proofs = set()
        self.v2_file_holds = {}
        self.v2_mutation_storage = {}
        self.cow_source_read_bytes = {}
        self.cow_counters = {'holds_acquired': 0, 'holds_released': 0,
                             'held_reads': 0, 'tree_commits': 0, 'tree_node_proofs': 0}

    def seed_cold_file(self, path, data, *, logical_size=None):
        """Inject fixture-only durable bytes after head zero, without touching the mount.

        The returned sequence is announced through the ordinary v2 journal.
        This is setup for a loopback acceptance account, not a production put.
        """
        with self._state_lock:
            path = self._fabric_path(path)
            if path in self.v2_entries or not isinstance(data, bytes) or not 0 < len(data) <= _MAX_FILE:
                raise ValueError('The cold fixture requires a new bounded nonempty file')
            size = len(data) if logical_size is None else logical_size
            if type(size) is not int or not len(data) <= size <= _MAX_TREE_SOURCE:
                raise ValueError('Invalid sparse fixture size')
            sha = hashlib.sha256(data).hexdigest()
            root = b'\1' + bytes.fromhex(sha) + struct.pack('!III', len(data), 0, len(data))
            height = _tree_height(size)
            digest = hashlib.sha256(_TREE_DOMAIN + struct.pack('!QB', size, height) + root).hexdigest()
            blocks = {'version': 1, 'algorithm': 'sha256', 'file_digest_algorithm': _TREE_ALGORITHM,
                      'total_bytes': size, 'tree': {'height': height, 'root': root.hex()}, 'storage': {'kind': _STORAGE}}
            self.fabric_cas[sha] = data
            self.fabric_cas_metadata[sha] = self._canonical_block_metadata(sha, len(data))
            self.v2_data_proofs.add((sha, len(data)))
            self.cow_source_read_bytes[sha] = 0
            seq, now = len(self.v2_journal)+1, datetime.now(timezone.utc).isoformat()
            self.v2_entries[path] = {'path': path, 'kind': 'file', 'size_bytes': size,
                'sha256': digest, 'entry_seq': seq, 'updated_at': now, 'blocks': copy.deepcopy(blocks)}
            # A sparse source exists only in the authoritative v2 namespace;
            # never expose its physical prefix as a truncated legacy file.
            if size == len(data):
                self.fabric_files[path], self.fabric_file_blocks[path] = data, copy.deepcopy(blocks)
            self.v2_journal.append({'seq': seq, 'path': path, 'op': 'put', 'kind': 'file',
                'digest': digest, 'prev_digest': None, 'size_bytes': size, 'blocks': copy.deepcopy(blocks),
                'destination_path': None, 'mutation_id': str(uuid.uuid4()), 'committed_at': now})
            return {'path': path, 'size_bytes': size, 'digest': digest, 'entry_seq': seq, 'content_sha256': sha}

    def seed_canonical_raw_file(self, op, data):
        """Install the checked-in actual web generator output, not a new descriptor."""
        with self._state_lock:
            if set(op) != {'op', 'path', 'kind', 'digest', 'size_bytes', 'blocks'} or op['op'] != 'put' or op['kind'] != 'file':
                raise ValueError('Invalid canonical source operation')
            path = self._fabric_path(op['path'])
            if path in self.v2_entries or not isinstance(data, bytes):
                raise ValueError('Canonical source requires a new fixture path')
            size, digest, blocks = self._v2_put_descriptor({'kind': 'file', 'size_bytes': op['size_bytes'],
                'sha256': op['digest'], 'blocks': op['blocks'], 'modified_at': None})
            if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
                raise ValueError('Canonical source bytes changed')
            for block in blocks['blocks']:
                raw = data[block['offset_bytes']:block['offset_bytes']+block['size_bytes']]
                if hashlib.sha256(raw).hexdigest() != block['sha256']:
                    raise ValueError('Canonical source block changed')
                sha = block['sha256']
                self.fabric_cas[sha] = raw
                self.fabric_cas_metadata[sha] = self._canonical_block_metadata(sha, len(raw))
                self.v2_data_proofs.add((sha, len(raw)))
                self.cow_source_read_bytes.setdefault(sha, 0)
            seq, now = len(self.v2_journal)+1, datetime.now(timezone.utc).isoformat()
            self.v2_entries[path] = {'path': path, 'kind': 'file', 'size_bytes': size, 'sha256': digest,
                                    'entry_seq': seq, 'updated_at': now, 'blocks': copy.deepcopy(blocks)}
            self.fabric_files[path], self.fabric_file_blocks[path] = data, copy.deepcopy(blocks)
            self.v2_journal.append({'seq': seq, 'path': path, 'op': 'put', 'kind': 'file', 'digest': digest,
                'prev_digest': None, 'size_bytes': size, 'blocks': copy.deepcopy(blocks),
                'destination_path': None, 'mutation_id': str(uuid.uuid4()), 'committed_at': now})
            return copy.deepcopy(self.v2_entries[path])

    def _tree_bytes(self, descriptor, size, digest, *, nodes=None, data_proofs=None, validate_only=False):
        """Resolve only admitted typed objects, with bounded logical traversal."""
        try:
            height, root = _tree_descriptor(descriptor, size, digest)
            if not validate_only and size > _MAX_FILE:
                raise Rejected(413, 'FIXTURE_MATERIALIZATION_TOO_LARGE')
            nodes = self.v2_tree_nodes if nodes is None else nodes
            data_proofs = self.v2_data_proofs if data_proofs is None else data_proofs
            visits = 0
            def read(ref, level, count):
                nonlocal visits
                visits += 1
                if visits > 2048:
                    raise ValueError('Tree traversal exceeds fixture bound')
                if ref is None:
                    return b'' if validate_only else bytes(count)
                kind, sha, length = ref[:3]
                raw = self._verify_canonical_block_locked({'sha256': sha, 'size_bytes': length})
                if kind == 'data':
                    if (sha, length) not in data_proofs:
                        raise Rejected(409, 'FABRIC_TREE_CLOSURE_UNAVAILABLE')
                    if validate_only:
                        return b''
                    offset, visible = ref[3:]
                    return raw[offset:offset+min(count, visible)] + bytes(max(0, count-visible))
                if (sha, length, level) not in nodes:
                    raise Rejected(409, 'FABRIC_TREE_CLOSURE_UNAVAILABLE')
                children = _tree_node(raw, level)
                span, result = _PAGE * 64**(level-1), []
                for child in children:
                    take = min(count, span)
                    # Validate closure even for references beyond logical EOF.
                    part = read(child, level-1, take)
                    result.append(part)
                    count -= take
                return b''.join(result)
            return read(root, height, size)
        except (ValueError, TypeError, KeyError, OverflowError) as error:
            raise Rejected(400, 'FABRIC_TREE_INVALID') from error

    def _v2_put_descriptor(self, descriptor):
        blocks = descriptor.get('blocks')
        if isinstance(blocks, dict) and blocks.get('storage') == {'kind': 'object_cas_v1'} and blocks.get('file_digest_algorithm') != _TREE_ALGORITHM:
            expected = {'version', 'algorithm', 'block_size_bytes', 'block_count', 'total_bytes', 'storage', 'blocks'}
            if (set(blocks) not in (expected, expected | {'file_digest_algorithm'})
                    or blocks.get('file_digest_algorithm', 'sha256') != 'sha256'):
                raise Rejected(400, 'FABRIC_MUTATION_DESCRIPTOR_INVALID')
            # Reuse geometry validation only; preserve the generator's storage
            # and raw-content identity verbatim in every served descriptor.
            check = {**blocks, 'storage': {'kind': _STORAGE}}
            check.pop('file_digest_algorithm', None)
            size, digest, _ = self._normalize_put_descriptor({**descriptor, 'blocks': check})
            if not 0 < size <= _MAX_SOURCE:
                raise Rejected(413, 'FIXTURE_FILE_TOO_LARGE')
            return size, digest, copy.deepcopy(blocks)
        if not isinstance(blocks, dict) or blocks.get('file_digest_algorithm') != _TREE_ALGORITHM:
            return self._normalize_put_descriptor(descriptor)
        size = descriptor.get('size_bytes')
        digest = self._raw_digest(descriptor.get('sha256'))
        try:
            _tree_descriptor(blocks, size, digest)
        except (ValueError, TypeError, KeyError, OverflowError) as error:
            raise Rejected(400, 'FABRIC_TREE_INVALID') from error
        return size, digest, copy.deepcopy(blocks)

    def _v2_file_bytes(self, descriptor):
        size, digest, blocks = self._v2_put_descriptor(descriptor)
        if blocks.get('file_digest_algorithm') == _TREE_ALGORITHM:
            return self._tree_bytes(blocks, size, digest), blocks
        data = b''.join(self._verify_canonical_block_locked(block) for block in blocks['blocks'])
        if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
            raise Rejected(400, 'FABRIC_MUTATION_DESCRIPTOR_INVALID')
        return data, blocks

    def _file_hold(self, host, payload):
        action = payload.get('action')
        if action not in {'acquire', 'renew', 'release', 'status'}:
            raise Rejected(400, 'FABRIC_FILE_HOLD_INVALID')
        attachment = self._v2_authority(host, payload, {'operation', 'action', 'hold_id', 'ttl_seconds'} |
            ({'path', 'file_digest', 'size_bytes', 'mode'} if action == 'acquire' else set()))
        hold_id = payload.get('hold_id')
        if not isinstance(hold_id, str) or not UUID_RE.fullmatch(hold_id):
            raise Rejected(400, 'FABRIC_FILE_HOLD_INVALID')
        ttl = self._integer(payload.get('ttl_seconds', 120), minimum=30, maximum=900, code='FABRIC_FILE_HOLD_INVALID')
        key = (host.session_id, host.id, hold_id)
        held = self.v2_file_holds.get(key)
        if held is not None and (held['attachment_id'] != attachment['id'] or held['generation'] != host.generation):
            raise Rejected(409, 'FABRIC_FILE_HOLD_BINDING_STALE')
        if action == 'release':
            if held is not None and not held['released']:
                held['released'] = True
                self.cow_counters['holds_released'] += 1
            return 200, {'schema': 'meshia.fabric_file_hold.v1', 'operation': 'file_hold',
                         'hold_id': hold_id, 'released': True}
        if held is not None:
            if held['attachment_id'] != attachment['id'] or held['generation'] != host.generation:
                raise Rejected(409, 'FABRIC_FILE_HOLD_BINDING_STALE')
            if action == 'acquire' and (payload.get('path'), payload.get('file_digest'), payload.get('size_bytes'), payload.get('mode')) != (
                    held['entry']['path'], held['entry']['sha256'], held['entry']['size_bytes'], held['mode']):
                raise Rejected(409, 'FABRIC_FILE_HOLD_IDENTITY_CONFLICT')
            if held['released'] or (held['deadline'] is not None and held['deadline'] <= self.now()):
                raise Rejected(410, 'FABRIC_FILE_HOLD_EXPIRED')
        elif action != 'acquire':
            raise Rejected(410, 'FABRIC_FILE_HOLD_EXPIRED')
        else:
            path = self._fabric_path(payload.get('path'))
            digest = self._raw_digest(payload.get('file_digest'))
            size = self._integer(payload.get('size_bytes'), minimum=0, maximum=_MAX_TREE_SOURCE, code='FABRIC_FILE_HOLD_INVALID')
            mode = payload.get('mode')
            if mode not in {'read', 'write'}:
                raise Rejected(400, 'FABRIC_FILE_HOLD_INVALID')
            if mode == 'write' and attachment['permissions'].get('workspace') != 'read_write':
                raise Rejected(403, 'FABRIC_WRITE_FORBIDDEN')
            entry = self.v2_entries.get(path)
            if entry is None or entry['kind'] != 'file' or (entry['sha256'], entry['size_bytes']) != (digest, size):
                raise Rejected(409, 'FABRIC_FILE_HOLD_VERSION_STALE')
            if entry['blocks'].get('file_digest_algorithm') == _TREE_ALGORITHM:
                self._tree_bytes(entry['blocks'], size, digest, validate_only=True)
            else:
                self._v2_file_bytes({'kind': 'file', 'size_bytes': size, 'sha256': digest, 'modified_at': None, 'blocks': entry['blocks']})
            if len(self.v2_file_holds) >= 128:
                raise Rejected(429, 'FIXTURE_FILE_HOLD_LIMIT')
            held = {'entry': copy.deepcopy(entry), 'mode': mode, 'released': False,
                    'attachment_id': attachment['id'], 'generation': host.generation,
                    'deadline': None if mode == 'write' else self.now()+ttl}
            self.v2_file_holds[key] = held
            self.cow_counters['holds_acquired'] += 1
        if action in {'acquire', 'renew'} and held['deadline'] is not None:
            held['deadline'] = max(held['deadline'], self.now()+ttl)
        entry = held['entry']
        return 200, {'schema': 'meshia.fabric_file_hold.v1', 'operation': 'file_hold', 'hold_id': hold_id,
            'path': entry['path'], 'digest': entry['sha256'], 'size_bytes': entry['size_bytes'],
            'mode': held['mode'], 'released': False, 'storage_kind': entry['blocks']['storage']['kind'],
            'expires_at': None if held['deadline'] is None else datetime.fromtimestamp(held['deadline'], timezone.utc).isoformat()}

    def _tree_verify(self, host, payload):
        self._exact_keys(payload, {'operation', 'mutation_id', 'blocks', 'storage_kind', 'tree_nodes'})
        storage = payload.get('storage_kind', _STORAGE)
        if storage not in _STORAGES:
            raise Rejected(400, 'FIXTURE_STORAGE_UNSUPPORTED')
        if self.v2_mutation_storage.get((host.session_id, payload.get('mutation_id')), _STORAGE) != storage:
            raise Rejected(409, 'FIXTURE_STORAGE_CHANGED')
        _requested, blocks = self._block_descriptors(payload.get('blocks'), maximum=4)
        for block in blocks:
            self._verify_canonical_block_locked(block)
        raw_nodes = payload.get('tree_nodes')
        if not isinstance(raw_nodes, list) or len(raw_nodes) > len(blocks):
            raise Rejected(400, 'FABRIC_TREE_INVALID')
        by_digest = {block['sha256']: block['size_bytes'] for block in blocks}
        admitted, candidates = [], []
        try:
            for node in raw_nodes:
                if not isinstance(node, dict) or set(node) != {'storage_kind', 'sha256', 'bytes_b64'} or node['storage_kind'] != storage:
                    raise ValueError('Invalid typed node')
                sha = self._raw_digest(node['sha256'])
                if not isinstance(node['bytes_b64'], str) or len(node['bytes_b64']) > 5500:
                    raise ValueError('Oversized node')
                raw = base64.b64decode(node['bytes_b64'], validate=True)
                if by_digest.get(sha) != len(raw) or hashlib.sha256(raw).hexdigest() != sha or any(row[0] == sha for row in candidates):
                    raise ValueError('Typed node identity mismatch')
                height = raw[4] if len(raw) > 4 else 0
                _tree_node(raw, height)
                candidates.append((sha, len(raw), height, raw))
            nodes = set(self.v2_tree_nodes)
            data_proofs = self.v2_data_proofs | {(block['sha256'], block['size_bytes']) for block in blocks}
            for sha, size, height, raw in sorted(candidates, key=lambda row: row[2]):
                for ref in _tree_node(raw, height):
                    if ref is None:
                        continue
                    if (ref[0] == 'node' and (ref[1], ref[2], height-1) not in nodes) or (
                            ref[0] == 'data' and (ref[1], ref[2]) not in data_proofs):
                        raise Rejected(409, 'FABRIC_TREE_CLOSURE_UNAVAILABLE')
                    self._verify_canonical_block_locked({'sha256': ref[1], 'size_bytes': ref[2]})
                nodes.add((sha, size, height))
                admitted.append({'storage_kind': storage, 'sha256': sha, 'size_bytes': size})
        except (ValueError, TypeError, KeyError, IndexError) as error:
            raise Rejected(400, 'FABRIC_TREE_INVALID') from error
        status, response = super().fabric_blocks(host, {key: value for key, value in payload.items()
            if key not in {'storage_kind', 'tree_nodes'}})
        self.v2_tree_nodes = nodes
        self.v2_data_proofs = data_proofs
        self.cow_counters['tree_node_proofs'] += len(admitted)
        return status, {**response, 'storage_kind': storage, 'admitted_nodes': admitted}

    def _v2_authority(self, host, payload, fields):
        self._exact_keys(payload, {'attachment_id', 'workspace'} | set(fields))
        attachment = self._require_fabric_attachment(host, payload)
        if attachment.get('session_id') != host.session_id or host.status != 'connected':
            raise Rejected(409, 'FABRIC_ATTACHMENT_INACTIVE')
        return attachment

    def fabric_v2_snapshot(self, host, payload):
        with self._state_lock:
            self._v2_authority(host, payload, {'after', 'limit'})
            after = payload.get('after')
            if after is not None:
                after = self._fabric_path(after)
            limit = self._integer(payload.get('limit', 256), minimum=1, maximum=2000, code='BAD_REQUEST')
            entries = [copy.deepcopy(self.v2_entries[path]) for path in sorted(self.v2_entries)
                       if after is None or path > after][:limit]
            self.v2_calls['snapshot'] += 1
            return 200, {'schema': 'meshia.fabric_v2.snapshot.v1', 'workspace': 'workspace',
                         'last_seq': len(self.v2_journal), 'entries': entries,
                         'next_after': entries[-1]['path'] if len(entries) == limit else None}

    def fabric_v2_changes(self, host, payload):
        with self._state_lock:
            self._v2_authority(host, payload, {'since_seq', 'limit'})
            since = self._integer(payload.get('since_seq'), minimum=0, maximum=2**53-1, code='BAD_REQUEST')
            limit = self._integer(payload.get('limit', 256), minimum=1, maximum=2000, code='BAD_REQUEST')
            changes = copy.deepcopy(self.v2_journal[since:since+limit])
            self.v2_calls['changes'] += 1
            return 200, {'schema': 'meshia.fabric_v2.changes.v1', 'workspace': 'workspace',
                         'since_seq': since, 'last_seq': len(self.v2_journal), 'changes': changes,
                         'next_since_seq': changes[-1]['seq'] if changes else since,
                         'has_more': since+len(changes) < len(self.v2_journal),
                         'requires_rebuild': False, 'checkpoint': None}

    def fabric_v2_lookup(self, host, payload):
        with self._state_lock:
            self._v2_authority(host, payload, {'path'})
            path = self._fabric_path(payload.get('path'))
            self.v2_calls['lookup'] += 1
            return 200, {'schema': 'meshia.fabric_v2.entry.v1', 'workspace': 'workspace',
                         'entry': copy.deepcopy(self.v2_entries.get(path))}

    def fabric_blocks(self, host, payload, *, content_encoding_identity=False):
        if payload.get('operation') == 'write_batch' and 'items' not in payload:
            with self._state_lock:
                storage = payload.get('storage_kind', _STORAGE)
                if storage not in _STORAGES:
                    raise Rejected(400, 'FIXTURE_STORAGE_UNSUPPORTED')
                key = (host.session_id, payload.get('mutation_id'))
                if self.v2_mutation_storage.get(key, storage) != storage:
                    raise Rejected(409, 'FIXTURE_STORAGE_CHANGED')
                status, result = super().fabric_blocks(host, {k: v for k, v in payload.items() if k != 'storage_kind'},
                    content_encoding_identity=content_encoding_identity)
                self.v2_mutation_storage[key] = storage
                if storage != _STORAGE:
                    result = {**result, 'tickets': [{**ticket, 'storage_kind': storage} for ticket in result['tickets']]}
                return status, result
        if payload.get('operation') == 'file_hold':
            with self._state_lock:
                return self._file_hold(host, payload)
        if payload.get('operation') == 'verify' and 'tree_nodes' in payload:
            with self._state_lock:
                return self._tree_verify(host, payload)
        if payload.get('operation') != 'read_batch_v2':
            return super().fabric_blocks(host, payload, content_encoding_identity=content_encoding_identity)
        with self._state_lock:
            attachment = self._v2_authority(host, payload, {'operation', 'path', 'blocks', 'ttl_seconds',
                                                         'hold_id', 'file_digest', 'tree_path'})
            path = self._fabric_path(payload.get('path'))
            entry = self.v2_entries.get(path)
            held = None
            if 'hold_id' in payload:
                if not isinstance(payload['hold_id'], str) or not UUID_RE.fullmatch(payload['hold_id']):
                    raise Rejected(400, 'FABRIC_FILE_HOLD_INVALID')
                held = self.v2_file_holds.get((host.session_id, host.id, payload['hold_id']))
                if (held is None or held['released'] or held['attachment_id'] != attachment['id']
                        or held['generation'] != host.generation or
                        (held['deadline'] is not None and held['deadline'] <= self.now())):
                    raise Rejected(410, 'FABRIC_FILE_HOLD_EXPIRED')
                entry = held['entry']
                if (entry['path'], entry['sha256']) != (path, payload.get('file_digest')):
                    raise Rejected(409, 'FABRIC_FILE_HOLD_IDENTITY_CONFLICT')
                self.cow_counters['held_reads'] += 1
            if entry is None or entry['kind'] != 'file':
                raise Rejected(404, 'FABRIC_FILE_NOT_FOUND')
            if 'file_digest' in payload and payload['file_digest'] != entry['sha256']:
                raise Rejected(409, 'FABRIC_FILE_HOLD_IDENTITY_CONFLICT')
            requested, blocks = self._block_descriptors(payload.get('blocks'), maximum=128)
            if entry['blocks'].get('file_digest_algorithm') == _TREE_ALGORITHM:
                self._tree_bytes(entry['blocks'], entry['size_bytes'], entry['sha256'], validate_only=True)
                height, root = _tree_descriptor(entry['blocks'], entry['size_bytes'], entry['sha256'])
                referenced = {}
                def visit(ref, level):
                    if ref is None:
                        return
                    kind, digest, size = ref[:3]
                    referenced[digest] = size
                    if kind == 'node':
                        for child in _tree_node(self.fabric_cas[digest], level):
                            visit(child, level-1)
                visit(root, height)
                proof = payload.get('tree_path', [])
                if not isinstance(proof, list) or len(proof) > _tree_height(_MAX_TREE_SOURCE):
                    raise Rejected(400, 'FABRIC_TREE_INVALID')
                try:
                    for encoded in proof:
                        if not isinstance(encoded, str) or len(encoded) > 5500:
                            raise ValueError('Invalid node proof')
                        raw = base64.b64decode(encoded, validate=True)
                        digest = hashlib.sha256(raw).hexdigest()
                        if referenced.get(digest) != len(raw) or self.fabric_cas.get(digest) != raw:
                            raise ValueError('Unreferenced node proof')
                except (ValueError, TypeError):
                    raise Rejected(400, 'FABRIC_TREE_INVALID') from None
            else:
                referenced = {block['sha256']: block['size_bytes'] for block in entry['blocks']['blocks']}
            if any(referenced.get(block['sha256']) != block['size_bytes'] for block in blocks):
                raise Rejected(409, 'FABRIC_BLOCK_NOT_REFERENCED')
            remaining = int(attachment['lease_expires_at'] - self.now()) - 5
            if remaining < 30:
                raise Rejected(409, 'FABRIC_ATTACHMENT_LEASE_TOO_SHORT')
            ttl = min(self._ticket_ttl(payload.get('ttl_seconds'), maximum=300), remaining)
            if held is not None and held['deadline'] is not None:
                held_remaining = int(held['deadline'] - self.now()) - 5
                if held_remaining < 30:
                    raise Rejected(409, 'FABRIC_FILE_HOLD_EXPIRED')
                ttl = min(ttl, held_remaining)
            tickets = [self._mint_direct_ticket_locked('GET', block, ttl) for block in blocks]
            return 200, {'schema': FABRIC_BLOCK_READ_SCHEMA, 'operation': 'read_batch_v2',
                         'requested_block_count': requested, 'unique_block_count': len(blocks), 'tickets': tickets}

    def fabric_v2_commit(self, host, payload):
        with self._state_lock:
            attachment = self._v2_authority(host, payload, {'mutation_id', 'request_digest', 'ops', 'inline_blocks', 'verification_mutation_ids'})
            if attachment['permissions'].get('workspace') != 'read_write':
                raise Rejected(403, 'FABRIC_WRITE_FORBIDDEN')
            mutation = payload.get('mutation_id')
            if not isinstance(mutation, str) or not UUID_RE.fullmatch(mutation):
                raise Rejected(400, 'FABRIC_MUTATION_ID_INVALID')
            ops = payload.get('ops')
            if not isinstance(ops, list) or not 1 <= len(ops) <= 128:
                raise Rejected(400, 'FABRIC_OPS_INVALID')
            # Preserve exact wire identity on replay, including optional fields.
            identity = json.dumps(payload, sort_keys=True, separators=(',', ':'))
            key = (host.id, host.generation, host.session_id, mutation)
            if key in self.v2_receipts:
                prior, result = self.v2_receipts[key]
                if prior != identity:
                    raise Rejected(409, 'FABRIC_MUTATION_IDEMPOTENCY_CONFLICT')
                return 200, copy.deepcopy(result)
            if payload.get('request_digest') is not None:
                # Production validates this caller-owned replay identity, not
                # one universal hash envelope. Released directory publishers
                # hash their op array; file cohorts include schema/session.
                # Exact-payload replay above and content checks below remain.
                self._raw_digest(payload['request_digest'])
            verification = payload.get('verification_mutation_ids')
            if verification is not None:
                if not isinstance(verification, list) or len(verification) != len(ops):
                    raise Rejected(400, 'FABRIC_VERIFICATION_IDENTITY_INVALID')
                used = set()
                for op, identity_id in zip(ops, verification):
                    if isinstance(op, dict) and op.get('op') == 'put' and op.get('kind') == 'file':
                        if not isinstance(identity_id, str) or not UUID_RE.fullmatch(identity_id) or identity_id in used:
                            raise Rejected(400, 'FABRIC_VERIFICATION_IDENTITY_INVALID')
                        used.add(identity_id)
                        prior = self.fabric_verification_operations.get((host.session_id, identity_id))
                        if prior is not None and (prior.host_id != host.id or prior.host_generation != host.generation or prior.expires_at <= self.now()):
                            raise Rejected(409, 'FABRIC_VERIFICATION_IDENTITY_INVALID')
                    elif identity_id is not None:
                        raise Rejected(400, 'FABRIC_VERIFICATION_IDENTITY_INVALID')
            normalized = []
            required = {}
            seen = set()
            for op in ops:
                if not isinstance(op, dict):
                    raise Rejected(400, 'FABRIC_OPS_INVALID')
                self._exact_keys(op, {'op', 'path', 'kind', 'digest', 'size_bytes', 'blocks', 'prev_digest', 'modified_at',
                                     'empty_directory_only', 'destination_path', 'source_path', 'source_prev_digest'})
                path = self._fabric_path(op.get('path'))
                if path in seen or op.get('op') not in {'put', 'delete', 'rename'}:
                    raise Rejected(400, 'FIXTURE_OPERATION_UNSUPPORTED')
                seen.add(path)
                related = None
                if op['op'] == 'rename':
                    related = self._fabric_path(op.get('destination_path'))
                elif 'destination_path' in op:
                    raise Rejected(400, 'FABRIC_OPS_INVALID')
                if 'source_path' in op or 'source_prev_digest' in op:
                    if op['op'] != 'put' or op.get('kind', 'file') != 'file':
                        raise Rejected(400, 'FABRIC_OPS_INVALID')
                    related = self._fabric_path(op.get('source_path'))
                    self._raw_digest(op.get('source_prev_digest'))
                if related is not None:
                    if related in seen or related.startswith(path+'/') or path.startswith(related+'/'):
                        raise Rejected(400, 'FABRIC_OPS_INVALID')
                    seen.add(related)
                previous = op.get('prev_digest')
                if previous is not None:
                    self._raw_digest(previous)
                descriptor = None
                if op['op'] == 'put' and op.get('kind') == 'file':
                    descriptor = {'kind': 'file', 'size_bytes': op.get('size_bytes'),
                                  'sha256': op.get('digest'), 'modified_at': None, 'blocks': op.get('blocks')}
                    size, digest, blocks = self._v2_put_descriptor(descriptor)
                    if size > 4*1024*1024:
                        raise Rejected(413, 'FIXTURE_FILE_TOO_LARGE')
                    for block in blocks.get('blocks', []):
                        required[block['sha256']] = block['size_bytes']
                elif op['op'] == 'put' and (op.get('kind') != 'dir' or any(op.get(k) is not None for k in ('digest', 'size_bytes', 'blocks'))):
                    raise Rejected(400, 'FABRIC_OPS_INVALID')
                modified = op.get('modified_at')
                if modified is not None:
                    if not isinstance(modified, str) or len(modified) > 40:
                        raise Rejected(400, 'FABRIC_OPS_INVALID')
                    try:
                        datetime.fromisoformat(modified.replace('Z', '+00:00'))
                    except ValueError:
                        raise Rejected(400, 'FABRIC_OPS_INVALID') from None
                normalized.append((op, path, descriptor))
            inline = payload.get('inline_blocks', [])
            if not isinstance(inline, list) or len(inline) > 256:
                raise Rejected(400, 'FABRIC_INLINE_BLOCKS_INVALID')
            staged = {}
            for block in inline:
                if not isinstance(block, dict) or set(block) != {'sha256', 'size_bytes', 'bytes_b64'}:
                    raise Rejected(400, 'FABRIC_INLINE_BLOCKS_INVALID')
                digest = self._raw_digest(block['sha256'])
                size = self._integer(block['size_bytes'], minimum=1, maximum=262144, code='FABRIC_INLINE_BLOCKS_INVALID')
                try:
                    data = base64.b64decode(block['bytes_b64'], validate=True)
                except (ValueError, TypeError):
                    raise Rejected(400, 'FABRIC_INLINE_BLOCKS_INVALID') from None
                if required.get(digest) != size or digest in staged or len(data) != size or hashlib.sha256(data).hexdigest() != digest:
                    raise Rejected(400, 'FABRIC_INLINE_BLOCK_DIGEST_MISMATCH')
                staged[digest] = data
            for digest, data in staged.items():
                self.fabric_cas[digest] = data
                self.fabric_cas_metadata[digest] = self._canonical_block_metadata(digest, len(data))
            validated = []
            for op, path, descriptor in normalized:
                if descriptor is not None:
                    for block in descriptor['blocks'].get('blocks', []):
                        if block['size_bytes'] == 0:
                            self.fabric_cas[block['sha256']] = b''
                            self.fabric_cas_metadata[block['sha256']] = self._canonical_block_metadata(block['sha256'], 0)
                    data, blocks = self._v2_file_bytes(descriptor)
                else:
                    data = blocks = None
                validated.append((op, path, data, blocks))
            verdicts = []
            for index, (op, path, data, blocks) in enumerate(validated):
                current = self.v2_entries.get(path)
                actual = current.get('sha256') if current else None
                if actual != op.get('prev_digest') or (op['op'] == 'put' and op.get('prev_digest') is None and current is not None):
                    verdicts.append({'index': index, 'path': path, 'status': 'rejected', 'code': 'FABRIC_PATH_DIVERGED', 'observed_digest': actual})
                    continue
                if op['op'] == 'rename':
                    destination = op['destination_path']
                    if current is None or current['kind'] != 'file' or destination in self.v2_entries:
                        verdicts.append({'index': index, 'path': path, 'status': 'rejected',
                                         'code': 'FABRIC_PATH_DIVERGED', 'observed_digest': actual})
                        continue
                source = op.get('source_path')
                if source is not None:
                    prior = self.v2_entries.get(source)
                    if prior is None or prior['kind'] != 'file' or prior['sha256'] != op['source_prev_digest']:
                        verdicts.append({'index': index, 'path': path, 'status': 'rejected',
                                         'code': 'FABRIC_PATH_DIVERGED', 'observed_digest': actual})
                        continue
                if op['op'] == 'delete' and any(p.startswith(path+'/') for p in self.v2_entries):
                    raise Rejected(409, 'FIXTURE_DIRECTORY_DELETE_UNSUPPORTED')
                seq = len(self.v2_journal)+1
                now = datetime.now(timezone.utc).isoformat()
                kind = op.get('kind') or (current or {}).get('kind', 'file')
                if op['op'] == 'rename':
                    destination = op['destination_path']
                    self.v2_entries[destination] = {**self.v2_entries.pop(path), 'path': destination,
                                                    'entry_seq': seq, 'updated_at': now}
                    self.fabric_files[destination] = self.fabric_files.pop(path)
                    self.fabric_file_blocks[destination] = self.fabric_file_blocks.pop(path)
                    blocks = self.fabric_file_blocks[destination]
                elif op['op'] == 'put':
                    entry = {'path': path, 'kind': kind, 'size_bytes': len(data) if data is not None else 0,
                             'sha256': op.get('digest'), 'entry_seq': seq, 'updated_at': now,
                             **({'blocks': blocks} if blocks is not None else {}),
                             **({'modified_at': op['modified_at']} if op.get('modified_at') is not None else {})}
                    self.v2_entries[path] = entry
                    if data is not None:
                        self.fabric_files[path] = data
                        self.fabric_file_blocks[path] = blocks
                        if blocks.get('file_digest_algorithm') == _TREE_ALGORITHM:
                            self.cow_counters['tree_commits'] += 1
                    if source is not None:
                        self.v2_entries.pop(source)
                        self.fabric_files.pop(source, None); self.fabric_file_blocks.pop(source, None)
                else:
                    self.v2_entries.pop(path, None); self.fabric_files.pop(path, None); self.fabric_file_blocks.pop(path, None)
                # M1848 projects PUT-with-source as one atomic RENAME event.
                # Merely echoing its PUT request leaves clients' source rows
                # alive after the authority consumed that name.
                self.v2_journal.append({'seq': seq, 'path': source or path, 'op': 'rename' if source is not None else op['op'], 'kind': kind,
                    'digest': actual if op['op'] == 'rename' else op.get('digest'),
                    'prev_digest': op['source_prev_digest'] if source is not None else op.get('prev_digest'),
                    'size_bytes': current['size_bytes'] if op['op'] == 'rename' else op.get('size_bytes', 0),
                    'blocks': blocks, 'destination_path': path if source is not None else op.get('destination_path'), 'mutation_id': mutation, 'committed_at': now,
                    **({'modified_at': op['modified_at']} if op.get('modified_at') is not None else {})})
                verdicts.append({'index': index, 'path': path, 'status': 'applied', 'seq': seq,
                    **({'modified_at': op['modified_at']} if op.get('modified_at') is not None else {})})
            self.v2_calls['commit'] += 1
            if verification is not None:
                for verdict in verdicts:
                    if verdict['status'] == 'applied' and verification[verdict['index']] is not None:
                        self.fabric_verification_operations.pop((host.session_id, verification[verdict['index']]), None)
            result = {'schema': 'meshia.fabric_commit.v2', 'session_id': host.session_id, 'mutation_id': mutation,
                      'seq': len(self.v2_journal), 'applied': sum(v['status'] == 'applied' for v in verdicts),
                      'rejected': sum(v['status'] == 'rejected' for v in verdicts), 'ops': verdicts}
            self.v2_receipts[key] = (identity, copy.deepcopy(result))
            return 200, result

    def fabric_direct_range(self, token, range_header):
        with self._state_lock:
            if not isinstance(range_header, str) or not re.fullmatch(r'bytes=\d+-\d+', range_header):
                raise Rejected(416, 'FABRIC_RANGE_INVALID')
            ticket = self._direct_block_tickets.get(token)
            if ticket is None or ticket.operation != 'GET' or ticket.expires_at <= self.now():
                raise Rejected(403, 'FABRIC_BLOCK_TICKET_INVALID')
            start, end = map(int, range_header[6:].split('-'))
            if not 0 <= start <= end < ticket.size_bytes:
                raise Rejected(416, 'FABRIC_RANGE_INVALID')
            data = self._verify_canonical_block_locked({'sha256': ticket.sha256, 'size_bytes': ticket.size_bytes})
            result = data[start:end+1]
            self.fabric_counters['direct_get_requests'] += 1
            self.fabric_counters['direct_get_bytes'] += len(result)
            if ticket.sha256 in self.cow_source_read_bytes:
                self.cow_source_read_bytes[ticket.sha256] += len(result)
            return 206, result, {'Content-Range': f'bytes {start}-{end}/{len(data)}',
                'x-amz-meta-meshia-sha256': ticket.sha256,
                'x-amz-meta-meshia-size-bytes': str(ticket.size_bytes),
                'ETag': '"' + ticket.sha256 + '"',
                'x-amz-checksum-sha256': base64.b64encode(bytes.fromhex(ticket.sha256)).decode(),
                'x-amz-checksum-type': 'FULL_OBJECT'}

    def fabric_direct_get(self, token):
        with self._state_lock:
            status, data = super().fabric_direct_get(token)
            digest = self._direct_block_tickets[token].sha256
            if digest in self.cow_source_read_bytes:
                self.cow_source_read_bytes[digest] += len(data)
            return status, data

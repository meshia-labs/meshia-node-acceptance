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

from fixture_control_plane import Rejected, UUID_RE, FABRIC_BLOCK_READ_SCHEMA


class FabricV2Fixture:
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.v2_entries = {}
        self.v2_journal = []
        self.v2_receipts = {}
        self.v2_calls = {'snapshot': 0, 'changes': 0, 'commit': 0, 'lookup': 0}

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
        if payload.get('operation') != 'read_batch_v2':
            return super().fabric_blocks(host, payload, content_encoding_identity=content_encoding_identity)
        with self._state_lock:
            attachment = self._v2_authority(host, payload, {'operation', 'path', 'blocks', 'ttl_seconds'})
            path = self._fabric_path(payload.get('path'))
            entry = self.v2_entries.get(path)
            if entry is None or entry['kind'] != 'file':
                raise Rejected(404, 'FABRIC_FILE_NOT_FOUND')
            requested, blocks = self._block_descriptors(payload.get('blocks'), maximum=128)
            referenced = {block['sha256']: block['size_bytes'] for block in entry['blocks']['blocks']}
            if any(referenced.get(block['sha256']) != block['size_bytes'] for block in blocks):
                raise Rejected(409, 'FABRIC_BLOCK_NOT_REFERENCED')
            remaining = int(attachment['lease_expires_at'] - self.now()) - 5
            if remaining < 30:
                raise Rejected(409, 'FABRIC_ATTACHMENT_LEASE_TOO_SHORT')
            ttl = min(self._ticket_ttl(payload.get('ttl_seconds'), maximum=300), remaining)
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
                self._raw_digest(payload['request_digest'])
                canonical = {'schema': 'meshiafabric.fabric_v2_commit_request.v1', 'session_id': host.session_id, 'ops': ops}
                expected = hashlib.sha256(json.dumps(canonical, ensure_ascii=False, sort_keys=True,
                                                     separators=(',', ':'), allow_nan=False).encode()).hexdigest()
                if payload['request_digest'] != expected:
                    raise Rejected(400, 'FABRIC_DIGEST_INVALID')
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
                self._exact_keys(op, {'op', 'path', 'kind', 'digest', 'size_bytes', 'blocks', 'prev_digest', 'modified_at', 'empty_directory_only'})
                path = self._fabric_path(op.get('path'))
                if path in seen or op.get('op') not in {'put', 'delete'}:
                    raise Rejected(400, 'FIXTURE_OPERATION_UNSUPPORTED')
                seen.add(path)
                previous = op.get('prev_digest')
                if previous is not None:
                    self._raw_digest(previous)
                descriptor = None
                if op['op'] == 'put' and op.get('kind') == 'file':
                    descriptor = {'kind': 'file', 'size_bytes': op.get('size_bytes'),
                                  'sha256': op.get('digest'), 'modified_at': None, 'blocks': op.get('blocks')}
                    size, digest, blocks = self._normalize_put_descriptor(descriptor)
                    if size > 4*1024*1024:
                        raise Rejected(413, 'FIXTURE_FILE_TOO_LARGE')
                    for block in blocks['blocks']:
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
                    for block in descriptor['blocks']['blocks']:
                        if block['size_bytes'] == 0:
                            self.fabric_cas[block['sha256']] = b''
                            self.fabric_cas_metadata[block['sha256']] = self._canonical_block_metadata(block['sha256'], 0)
                    data, blocks = self._put_descriptor_locked(descriptor)
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
                if op['op'] == 'delete' and any(p.startswith(path+'/') for p in self.v2_entries):
                    raise Rejected(409, 'FIXTURE_DIRECTORY_DELETE_UNSUPPORTED')
                seq = len(self.v2_journal)+1
                now = datetime.now(timezone.utc).isoformat()
                kind = op.get('kind') or (current or {}).get('kind', 'file')
                if op['op'] == 'put':
                    entry = {'path': path, 'kind': kind, 'size_bytes': len(data) if data is not None else 0,
                             'sha256': op.get('digest'), 'entry_seq': seq, 'updated_at': now,
                             **({'blocks': blocks} if blocks is not None else {}),
                             **({'modified_at': op['modified_at']} if op.get('modified_at') is not None else {})}
                    self.v2_entries[path] = entry
                    if data is not None:
                        self.fabric_files[path] = data
                        self.fabric_file_blocks[path] = blocks
                else:
                    self.v2_entries.pop(path, None); self.fabric_files.pop(path, None); self.fabric_file_blocks.pop(path, None)
                self.v2_journal.append({'seq': seq, 'path': path, 'op': op['op'], 'kind': kind,
                    'digest': op.get('digest'), 'prev_digest': op.get('prev_digest'), 'size_bytes': op.get('size_bytes', 0),
                    'blocks': blocks, 'destination_path': None, 'mutation_id': mutation, 'committed_at': now,
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

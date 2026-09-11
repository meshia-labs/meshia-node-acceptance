"""Portable kit adaptation checks: no product import, install, service or mount."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import acceptance
import cow_acceptance
import report


class Preparation(unittest.TestCase):
    def test_unbound_release_fails_before_artifact_access(self):
        lock = json.loads((acceptance.ROOT / 'release-lock.json').read_text())
        self.assertEqual(lock['version'], '1.3.29')
        if lock['source_commit'] is None:
            self.assertIsNone(lock['package_commit'])
            self.assertTrue(all(value is None for value in lock['artifacts'].values()))
            self.assertIsNone(acceptance.LOCK_SHA256)
            with self.assertRaisesRegex(AssertionError, 'not bound'):
                acceptance.verify_release(Path('/does-not-exist'))
        else:
            acceptance.verify_release()

    def test_recreation_workload_on_plain_files(self):
        with tempfile.TemporaryDirectory() as directory:
            source, destination = (Path(directory) / name for name in ('source', 'destination'))
            source.write_bytes(b'original')
            result = json.loads(subprocess.check_output([sys.executable, '-I', '-c',
                cow_acceptance.CLASSIC_RECREATE_PROBE, str(source), str(destination)], timeout=10))
            self.assertEqual(result, {'local_rename': True, 'source_recreated': True,
                                     'mounted_readback': True, 'fsync': True})
            self.assertEqual(source.read_bytes(), cow_acceptance.CLASSIC_RECREATE_BODY)
            self.assertEqual(destination.read_bytes(), cow_acceptance.CLASSIC_RENAME_BODY)
            self.assertEqual(report.public(result), result)

    def test_signed_recreation_projection_requires_both_exact_identities(self):
        bodies = {'source': cow_acceptance.CLASSIC_RECREATE_BODY, 'destination': cow_acceptance.CLASSIC_RENAME_BODY}
        entries = {name: {'path': name, 'kind': 'file', 'size_bytes': len(body),
                         'sha256': hashlib.sha256(body).hexdigest()} for name, body in bodies.items()}
        snapshot = {'schema': 'meshia.fabric_v2.snapshot.v1', 'workspace': 'workspace',
                    'next_after': None, 'entries': list(entries.values())}
        lookup = lambda name: {'schema': 'meshia.fabric_v2.entry.v1', 'workspace': 'workspace', 'entry': entries[name]}
        check = lambda s, a, b: cow_acceptance.verify_recreated_source_projection(
            s, a, b, source='source', destination='destination')
        self.assertEqual(check(snapshot, lookup('source'), lookup('destination')),
                         {'signed_recreated_source_present': True, 'signed_destination_present': True})
        for damage in ('source_absent', 'stale_digest', 'duplicate_path', 'wrong_workspace', 'partial_list'):
            with self.subTest(damage=damage):
                s, a, b = copy.deepcopy((snapshot, lookup('source'), lookup('destination')))
                if damage == 'source_absent': a['entry'] = None
                if damage == 'stale_digest': a['entry']['sha256'] = '0' * 64
                if damage == 'duplicate_path': s['entries'].append(s['entries'][0])
                if damage == 'wrong_workspace': b['workspace'] = 'other'
                if damage == 'partial_list': s['next_after'] = 'source'
                with self.assertRaises(AssertionError): check(s, a, b)


if __name__ == '__main__':
    unittest.main()

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
    def test_sparse_workload_is_bounded_on_a_disposable_sparse_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'fixture'
            with path.open('wb') as output:
                output.write(cow_acceptance.SPARSE_PREFIX)
                output.truncate(cow_acceptance.SPARSE_SIZE)
            self.assertLess(path.stat().st_blocks*512,8*1024**2)
            result=json.loads(subprocess.check_output([sys.executable,'-I','-c',
                cow_acceptance.SPARSE_PROBE,str(path)],timeout=10))
            self.assertEqual(path.read_bytes(),cow_acceptance.sparse_expected_bytes())
            self.assertTrue(result['far_zero_tail'])
            self.assertTrue(result['sampled_untouched_prefix'])
            self.assertEqual(result['logical_source_bytes'],cow_acceptance.SPARSE_SIZE)
            self.assertEqual(report.public(result),result)
        observation={'source_size_bytes':cow_acceptance.SPARSE_SIZE,'physical_source_bytes':len(cow_acceptance.SPARSE_PREFIX),
                     'source_read_bytes_before':0,'source_read_bytes':8192,'raw_stderr':'private-sentinel','token':'private-sentinel'}
        projected=report.public({'phase':'mounted_sparse_cow_cold_precondition','cow_observation':observation,
                                 'message':'private-sentinel'})
        self.assertEqual(projected['cow_observation']['source_read_bytes'],8192)
        self.assertNotIn('private-sentinel',json.dumps(projected))
        for marker in cow_acceptance.PROBE_FAILURE_MARKERS:
            result=acceptance.subprocess_diagnostics(['python3'],1,b'',
                ('AssertionError: '+marker+' private-sentinel').encode())
            self.assertEqual(result['known_errors'],[marker])
            self.assertEqual(result['exception_types'],['AssertionError'])
            self.assertNotIn('private-sentinel',json.dumps(report.public({'diagnostics':result})))

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

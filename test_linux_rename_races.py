"""Deterministic signed metadata-rename/read ordering regression."""
import os
import unittest

from test_fixture_cow import joined


class RenameReadRace(unittest.TestCase):
    def test_cold_open_acquires_exact_version_after_source_is_consumed(self):
        from meshia_node.fabric_mount import FabricMountBackend
        with joined() as (plane, host, common, transport, coordinator, database, workspace, drive):
            source = b'meshia replacement cache with a deliberately different length\n'
            plane.seed_cold_file('temp', source)
            target = plane.seed_cold_file('dest', b'meshia original cache\n')
            drive(lambda: database.get_remote_manifest_head().generation >= target['entry_seq'])
            self.assertTrue(coordinator.materialize('dest'))
            backend = FabricMountBackend(database, coordinator, workspace, 'Research', settle_seconds=60)
            backend._remote_quota.update_catalog(catalog_generation=1, quota_bytes=64*1024**2, used_bytes=0)
            opened = None
            block_reads = coordinator._file_versions.request
            try:
                backend.rename('/Research/temp', '/Research/dest')
                def consume_before_hold(payload):
                    if payload.get('operation') == 'file_hold' and payload.get('action') == 'acquire' and payload.get('path') == 'temp':
                        drive(lambda: not database.list_operations())
                        self.assertNotIn('temp', plane.v2_entries)
                        self.assertEqual(plane.fabric_files['dest'], source)
                    return block_reads(payload)
                coordinator._file_versions.request = consume_before_hold
                opened = backend.open('/Research/dest', os.O_RDONLY)
                self.assertEqual(backend.read(opened, 0, 100), source)
            finally:
                coordinator._file_versions.request = block_reads
                if opened is not None:
                    backend.release(opened)
                backend.close()

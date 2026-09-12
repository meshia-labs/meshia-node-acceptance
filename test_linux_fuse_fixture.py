"""Signed loopback namespace contract below the real Linux mount boundary."""
import os
import unittest

from test_fixture_cow import joined


class PublishedReplacement(unittest.TestCase):
    def test_signed_reusable_source_after_publication(self):
        from meshia_node.fabric_mount import FabricMountBackend
        with joined() as (plane, host, common, transport, coordinator, database, workspace, drive):
            backend = FabricMountBackend(database, coordinator, workspace, 'Research', settle_seconds=60)
            backend._remote_quota.update_catalog(catalog_generation=1, quota_bytes=64*1024**2, used_bytes=0)
            def create(name, value):
                handle = backend.open('/Research/' + name, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
                backend.write(handle, 0, value)
                backend.fsync(handle)
                backend.release(handle)
                backend.flush_writes()
                drive(lambda: plane.fabric_files.get(name) == value and not database.list_operations())
            reader = None
            try:
                create('dest', b'meshia original cache\n')
                for iteration, value in enumerate((b'meshia replacement cache with a deliberately different length\n',
                              b'meshia original cache\n', b'meshia third cache\n')):
                    create('temp', value)
                    backend.rename('/Research/temp', '/Research/dest')
                    drive(lambda: plane.fabric_files.get('dest') == value
                          and 'temp' not in plane.v2_entries and not database.list_operations())
                    event = plane.v2_journal[-1]
                    self.assertEqual((event['op'], event['path'], event['destination_path']), ('rename', 'temp', 'dest'))
                    if iteration == 0:
                        reader = backend.open('/Research/dest', os.O_RDONLY)
                    self.assertEqual(backend.read(reader, 0, 100), b'meshia replacement cache with a deliberately different length\n')
                    try:
                        visible = backend.getattr('/Research/temp')
                    except OSError:
                        continue
                    self.fail(repr({'iteration': iteration, 'size': visible.size_bytes,
                        'local_source': workspace.stat_fingerprint('temp'),
                        'materialized_source': database.get_materialized('temp'),
                        'remote_source': database.get_remote_entry('temp'),
                        'receipted_source': database.get_receipted_entry('temp'),
                        'view': backend._file_view('temp'),
                        'operations': [(op.kind, op.path, op.destination_path, op.state) for op in database.list_operations()],
                        'sessions': list(backend._sessions)}))
            finally:
                if reader is not None:
                    backend.release(reader)
                backend.close()

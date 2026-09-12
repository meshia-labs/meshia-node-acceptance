"""Unbound acceptance must stop before a fetch or filesystem mutation."""
from pathlib import Path
import unittest
from unittest.mock import patch

import linux_fuse_acceptance as acceptance


class ReleaseBinding(unittest.TestCase):
    def test_missing_source_stops_before_fetch_or_directory_creation(self):
        with patch.object(acceptance, 'SOURCE', ''), patch.object(acceptance, 'fetch_exact') as fetch, \
                patch.object(Path, 'mkdir') as mkdir, \
                patch('sys.argv', ['probe', 'fetch', '--directory', '/unused']):
            with self.assertRaisesRegex(ValueError, 'source is not bound'):
                acceptance.main()
        fetch.assert_not_called()
        mkdir.assert_not_called()

    def test_missing_wheel_stops_before_fetch_or_directory_creation(self):
        with patch.object(acceptance, 'SOURCE', 'a' * 40), \
                patch.object(acceptance, 'HASHES', {'release.json': 'b' * 64}), \
                patch.object(acceptance, 'fetch_exact') as fetch, patch.object(Path, 'mkdir') as mkdir, \
                patch('sys.argv', ['probe', 'fetch', '--directory', '/unused']):
            with self.assertRaisesRegex(ValueError, 'artifacts are not bound'):
                acceptance.main()
        fetch.assert_not_called()
        mkdir.assert_not_called()

    def test_exact_source_and_artifacts_are_required(self):
        with patch.object(acceptance, 'SOURCE', 'a' * 40), patch.object(acceptance, 'HASHES', {
                'release.json': 'b' * 64, 'meshia_node-1.3.41-py3-none-any.whl': 'c' * 64}):
            acceptance.require_binding()

    def test_eight_kernel_cases_remain_explicit(self):
        names = unittest.defaultTestLoader.getTestCaseNames(acceptance.LinuxFuse)
        self.assertEqual(len(names), 8)
        self.assertIn('test_replaced_read_description_survives_nullpath', names)
        self.assertIn('test_unlinked_read_description_survives_nullpath', names)
        self.assertIn('test_stdlib_default_temporary_file_lifecycle', names)

    def test_public_runner_has_all_nine_kernel_cases(self):
        from linux_public import PublicLinux
        names = unittest.defaultTestLoader.getTestCaseNames(PublicLinux)
        self.assertEqual(len(names), 9)
        self.assertIn('test_failed_replacement_retains_original_public_name', names)

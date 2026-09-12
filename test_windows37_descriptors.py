"""Temporary-file qualification of the installed public wheel, without a mount."""
import errno
import hashlib
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest
from meshia_node import fabric_mount as mount
from meshia_node.fabric_db import FabricDatabase, RemoteEntry
from meshia_node.fabric_sync import _fingerprint_text
from meshia_node.workspace import WorkspaceBoundary


@pytest.fixture
def local(tmp_path):
    root = tmp_path / "workspace"
    root.mkdir()
    database = FabricDatabase(tmp_path / "fabric.sqlite3")
    database.bind_authority(host_id="fixture", session_id="fixture", host_generation=1,
        attachment_id="fixture", workspace_root=root)
    original = bytes(range(251)) * 4096
    digest = hashlib.sha256(original).hexdigest()
    database.replace_remote_manifest(1, hashlib.sha256(b"fixture").hexdigest(),
        (RemoteEntry("dest", len(original), digest),))
    workspace = WorkspaceBoundary(root)
    workspace.write_file("dest", original)
    database.mark_materialized("dest", state="clean", clean_digest=digest,
        stat_fingerprint=_fingerprint_text(workspace.stat_fingerprint("dest")), bytes_on_disk=len(original))
    coordinator = SimpleNamespace(note_materialized_access=lambda _path: None,
        set_mount_cleanup_fence=lambda _provider: None)
    backend = mount.FabricMountBackend(database, coordinator, workspace, "Research")
    try:
        yield backend, workspace, original
    finally:
        backend.close()
        workspace.close()
        database.close()


def replace(local):
    backend, workspace, original = local
    reader = backend.open("/Research/dest", os.O_RDONLY)
    workspace.write_file("temp", b"new shorter bytes")
    # Use the exact Windows publication primitive, including its source/target
    # identity fences and FileRenameInfoEx POSIX replacement semantics.
    from meshia_node.workspace_win import _publish_windows_mount_stage
    source_identity = workspace.stat_fingerprint("temp")
    target_identity = workspace.stat_fingerprint("dest")
    backend._replace_pristine_rename_destination("dest", lambda: _publish_windows_mount_stage(
        str(workspace.root / "temp"), str(workspace.root / "dest"), source_identity, target_identity))
    pin = backend._handles[reader].retired_local
    assert pin is not None
    assert (workspace.root / "dest").read_bytes() == b"new shorter bytes"
    assert backend.read(reader, 0, len(original)) == original
    return reader, pin


@pytest.mark.parametrize("close_backend", [False, True])
def test_real_replacement_and_descriptor_cleanup(local, close_backend):
    backend, _workspace, _original = local
    reader, pin = replace(local)
    if close_backend:
        backend.close()
    else:
        backend.release(reader)
    with pytest.raises(OSError) as closed:
        os.fstat(pin.descriptor)
    assert closed.value.errno == errno.EBADF


def test_concurrent_portable_reads_preserve_offsets(local):
    backend, _workspace, original = local
    reader, _pin = replace(local)
    offsets = [i * 7919 % (len(original) - 4096) for i in range(128)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        actual = list(pool.map(lambda offset: backend.read(reader, offset, 4096), offsets))
    assert actual == [original[offset:offset + 4096] for offset in offsets]
    backend.release(reader)


@pytest.mark.parametrize("fail_read", [False, True])
def test_read_owns_duplicate_across_release(local, monkeypatch, fail_read):
    backend, _workspace, original = local
    reader, _pin = replace(local)
    entered, resume = threading.Event(), threading.Event()
    descriptors, results, errors = [], [], []
    pread = mount._portable_pread

    def paused(descriptor, size, offset):
        descriptors.append(descriptor)
        entered.set()
        assert resume.wait(3)
        if fail_read:
            raise OSError(errno.EIO, "fixture read error")
        return pread(descriptor, size, offset)

    def read():
        try:
            results.append(backend.read(reader, 9, 4096))
        except OSError as error:
            errors.append(error)

    monkeypatch.setattr(mount, "_portable_pread", paused)
    thread = threading.Thread(target=read)
    try:
        thread.start()
        assert entered.wait(3)
        backend.release(reader)
        resume.set()
        thread.join(3)
        assert not thread.is_alive()
        assert results == ([] if fail_read else [original[9:4105]])
        assert len(errors) == int(fail_read)
        for descriptor in descriptors:
            with pytest.raises(OSError):
                os.fstat(descriptor)
    finally:
        resume.set()
        thread.join(3)


@pytest.mark.parametrize("failure", ["replacement", "capacity"])
def test_failure_preserves_namespace_and_closes_pins(local, monkeypatch, failure):
    backend, workspace, original = local
    reader = backend.open("/Research/dest", os.O_RDONLY)
    descriptors = []
    duplicate = os.dup

    def dup(descriptor):
        if failure == "capacity":
            raise OSError(errno.EMFILE, "fixture rejection")
        result = duplicate(descriptor)
        descriptors.append(result)
        return result

    def reject():
        raise OSError(errno.EACCES, "fixture rejection")

    with monkeypatch.context() as patched:
        patched.setattr(os, "dup", dup)
        with pytest.raises(OSError, match="fixture rejection"):
            backend._replace_pristine_rename_destination("dest", reject)
    assert backend._handles[reader].retired_local is None
    assert (workspace.root / "dest").read_bytes() == original
    for descriptor in descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)
    backend.release(reader)

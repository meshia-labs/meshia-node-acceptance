# Linux40 mounted acceptance

Prepared only. `SOURCE` and `HASHES` in `production_install.py` are deliberately
empty. The Linux entrypoint rejects them before creating its output directory
or making an artifact request. The owner must bind the verified public40
source, manifest SHA256 and wheel SHA256 before authorizing one dispatch.

The registered `macos-acceptance.yml` workflow filename is reused only on this
isolated Linux branch. Its job is explicitly Linux40 on ordinary-user Ubuntu
24.04 with distribution FUSE; there is no Docker, production enrollment or
paid VM. The job compares every installed package Python module with the exact
public wheel. Mounts use signed disposable loopback authority and each context
asserts unmount, registry removal and polling-worker closure, including failures.

Eight distinct actual kernel cases are required, with zero skips:

1. Existing read/write descriptions without kernel pre-read.
2. Existing read/write descriptions with kernel pre-read.
3. Reusable temporary pathname after source publication.
4. Reusable temporary pathname immediately after close.
5. Reusable cold source over a materialized destination.
6. Replaced read description: retained bytes, fstat, fsync and close.
7. Unlinked read description: retained bytes, fstat, fsync and close.
8. Default-directory stdlib TemporaryFile: the unchanged Mac40 probe from
   9548418 runs with TMPDIR inside the mounted workspace, with no API mocks or
   explicit dir argument. It verifies write/read/seek, shrink/extend with zero
   fill, fstat/fsync, descriptor closure, and no local or authoritative leftovers.

The existing three replacement cases preserve their immediate syscall and
namespace checks; no retry or sleep was added around a failing file operation.
Normal bounded signed-publication polling remains separate from file calls.
The fixture journal contract and deterministic cold-hold race are also checked
below the mount boundary before the kernel tests.

Prior Linux39 failures remain archived under the harness's
`outbox/reliability/2026-09-08-mcp-installable-audit/linux39-mounted-acceptance`.
Local preparation checks are not public-wheel or actual-Linux acceptance.

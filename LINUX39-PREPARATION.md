# Linux39 mounted acceptance — prepared, not dispatched

This isolated branch derives from Mac39 kit `7a4dae5`. It deliberately uses the
already registered `macos-acceptance.yml` workflow filename, but its workflow
label, runner and job are explicitly Linux39. Neither kit `main` nor the Mac39
branch is changed.

The workflow downloads the public 1.3.39 manifest and wheel, verifies the hashes
already pinned in `production_install.py`, installs that wheel, and compares
every installed Python module byte-for-byte with the archive. Exact source:
`f901a10761911bbea518b50ee06b0b8c490364c4`; wheel SHA-256:
`2af5c22489632ea78cc72c888c3fbae17b9188d3f1ef67a7356a4a6b302ca553`.

Five cases use actual ordinary-user Linux FUSE with the kit's existing signed
loopback authority. Two reproduce the cached/uncached kernel-read cases from
the product's `test_fabric_mount_handle_coherence.py`. Three run the retained
reader and reusable temporary-name replacement sequence: immediate close,
published local source, and cold tree source over a materialized destination.
Each mount is owned by its temporary fixture and unmounted in `finally`.

This is a mounted file behavior qualification of the exact public wheel. It
does not enroll production compute, test production transport, install a system
service, or repeat the earlier Linux Full/Limited execution-policy acceptance.
It requires no Docker, paid VM, account token, or production workspace. The
public repository guard, ten-minute job timeout and five-minute probe timeout
bound the free hosted run; only distribution FUSE installation uses sudo.

After root verifies public delivery, dispatch exactly once:

```sh
gh workflow run macos-acceptance.yml --repo meshia-labs/meshia-node-acceptance --ref codex/native39-linux-fuse-20260912
```

Read the resulting run before any retry. The artifact is
`native39-linux-fuse-<run_id>/linux-fuse-receipt.json`, with exact source/wheel,
matched module count, ordinary UID, kernel, five test outcomes and zero skips
required for pass. Successful tests also require owned mount disappearance.

Preparation validation: Python syntax and whitespace checks; the existing
signed classic-rename fixture passed locally against current product code.
Actual Linux FUSE cases have not run during preparation on the Mac host.

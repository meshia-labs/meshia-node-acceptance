# Mac40 acceptance preparation — unbound and not dispatched

Derived from kit `985362d`, including exact native logger string-boolean
decoding. The observer now distinguishes `source_pending` from `source_changed`.
The original mounted replacement probe remains byte-identical to Mac38.

`production_install.py` specifies version 1.3.40 with `SOURCE=None` and empty
`HASHES`; it refuses artifact access/enrollment until exact bindings are supplied.
Root must bind public40 source, pointer, installer, wheel and signed app hashes
and verify production delivery before any dispatch. The workflow uses the new
`MESHIA_MAC40_PAIR_GRANT` name and a separate concurrency group.

No fresh workspace, owner deadline, grant, guest identity or cleanup state is
bound. Follow the scoped owner procedure in NATIVE39-PREPARATION.md with version
1.3.40 and fresh identities only; that prior document's candidate39 hashes are
historical and do not bind this run. The owner watcher accepts version1.3.40.
Maintain the 900-second owner deadline and guest's independent cleanup timeout.
Do not add a cloud scheduler or credential authority. No primary-host commands,
grant changes, revocation or mount writes are permitted by this preparation.

Current verification: 29 focused kit checks passed, including source_pending
and strict boolean-string decoding. This is preparation, not acceptance.

After the original replacement probe passes, run `tempfile_probe.py` as a
separate normal Limited native command with the same declared workspace cwd.
Use managed Python with `-I -c` and the unchanged probe source. Isolated mode
still permits the ordinary tempfile module to read TMPDIR.
The probe does not pass a directory to `TemporaryFile` or replace its behavior.
It asserts the actual default temp directory is under cwd, exercises buffered
stdio, seek, shrinking/extension, zero fill, fstat/fsync, then verifies descriptor
closure and no namespace leftovers. Do not run it concurrently with unrelated
writers in the same temporary directory. A failure must be preserved without
retry and must not be combined with replacement-probe acceptance.

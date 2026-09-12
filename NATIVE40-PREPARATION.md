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

# Mac41 kit — candidate bound, no dispatch

Version1.3.41 pins source4de0b28d5a8e8d410a9d9f79da4fb57aec921d17 and exact
packaged artifact hashes. Local verified wheel has86 Python modules. Root must
verify exact public41 release bytes before dispatch. Both the original mounted
replacement probe and separate real TemporaryFile probe are unchanged from40.
The manual workflow uses MESHIA_MAC41_PAIR_GRANT; owner state/deadline/workspace
remain unbound. Keep the existing 900-second maximum owner deadline and guest
cleanup timeout. No additional scheduler, authority or primary-host operation.

Installed Python module count is derived from the exact hash-verified wheel's
manifest, not hard-coded85 or assumed86. The check requires unique names and
the package initializer, compares the entire installed .py inventory against
that manifest, and compares every module's bytes. Missing, extra or changed
modules fail. A disposable86-module fixture exercises that exact child source.
Historical NATIVE39/40 preparation files do not bind this run.

## Final source binding procedure

Run `python3 prepare_bindings.py <final-candidate.json> --wheel <exact-wheel>`
after the final split-process fix is packaged. This read-only helper verifies
the wheel hash, derives its module inventory and requires linux_fuse.py. It
prints exact source/hash bindings and leaves public-delivery and dispatch
authorization false. Apply those exact values to production_install.py and the
Windows kit's windows37_package.py, then run focused tests, commit and push the
manual-only branches. Root verifies public delivery before any dispatch.

Do not bind main/HEAD, adae or any pre-fix snapshot by assumption. Final source
identity comes from the immutable candidate receipt and hash-verified wheel.
The Mac kit installs through the canonical installer with `--access limited`;
it does not instantiate an in-process coordinator or override coordinator mode.
Normal MCP commands traverse the installed production mount and its actual
coordinator transport. The source-level split-process candidate tests must pass
before packaging; this kit does not bypass or replace that gate.

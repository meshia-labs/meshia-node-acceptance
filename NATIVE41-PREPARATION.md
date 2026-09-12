# Mac41 kit — unbound, no dispatch

Version1.3.41 has no source or artifact hash bindings yet. Root must supply and
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

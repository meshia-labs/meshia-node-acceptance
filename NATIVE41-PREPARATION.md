# Windows41 kit — unbound, no dispatch

Manual-only Windows2022 descriptor workflow, derived from passing40 kitac65b7d.
Source and wheel hash are deliberately empty, blocking before network or local
artifact creation. Root must bind and verify public41 before dispatch. Seven
ordinary-user descriptor cases and the cleanup controller remain unchanged.

Expected module count is derived from the exact pinned wheel's manifest.
Unique names/package initializer are required; the full installed .py inventory
must equal the wheel inventory and each file must match its wheel bytes. The
new linux_fuse.py is therefore included automatically only if the verified
wheel contains it. There is no assumed85/86 shortcut or relaxed byte check.
No Azure allocation, enrollment or fresh workspace is required by this kit.

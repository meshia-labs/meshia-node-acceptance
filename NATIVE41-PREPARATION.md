# Windows41 kit — candidate bound, no dispatch

Manual-only Windows2022 descriptor workflow, derived from passing40 kitac65b7d.
Source4de0b28d5a8e8d410a9d9f79da4fb57aec921d17 and wheelfa63cc38e1fa9f4d06426e5ac691425f9e54fa504382a5062349d29366e9da06
are pinned. Root must verify public41 before dispatch. Seven
ordinary-user descriptor cases and the cleanup controller remain unchanged.

Expected module count is derived from the exact pinned wheel's manifest.
Unique names/package initializer are required; the full installed .py inventory
must equal the wheel inventory and each file must match its wheel bytes. The
new linux_fuse.py is therefore included automatically only if the verified
wheel contains it. There is no assumed85/86 shortcut or relaxed byte check.
No Azure allocation, enrollment or fresh workspace is required by this kit.

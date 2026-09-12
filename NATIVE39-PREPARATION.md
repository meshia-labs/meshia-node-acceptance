# Native39 preparation — not dispatched

This branch derives from Mac38 kit `608e7b25898d8a0a539cb18ffc7e6990667a7549`.
`mounted_replacement_probe.py` is byte-identical. The source/hash bindings now
pin the locally packaged 1.3.39 candidate at
`f901a10761911bbea518b50ee06b0b8c490364c4`. Public delivery is not yet verified:
root must verify production before dispatch. Owner/workspace/deadline bindings
remain unbound. Legacy fixture files for 1.3.30 are
unchanged and are not the production installation path.

The observer accepts only the native `fabric_mount_rename_busy` reason allowlist
and actual boolean cache/session/handle flags. It never exports raw paths,
exceptions or arbitrary log data. The unchanged probe runs through normal
Limited workspace execution; diagnostic observation must not warm its mount.

## Required root bindings before launch

1. Verify the pinned `production_install.py` source and four artifact hashes
   against exact production delivery before dispatching the published kit branch.
2. Create a new disposable workspace and record an absolute deadline at most
   900 seconds after creation; do not reuse prior stopped workspaces.
3. Create a mode-0700 owner state directory in durable local storage. Bind the
   watchdog JSON with `workspace_id`, `version: "1.3.39"`,
   `protected_primary_host: "72bc84ae-63b5-4e2a-a0e7-c2a62726a6c3"`,
   `root_authorized: true`, `delete_storage: true`, and numeric `created_at`
   and `deadline` UTC epoch seconds. Start `owner_watchdog.py --binding ...
   --state-dir ... --cli /Users/harsha/.local/bin/meshia` before pairing.
4. Bind the one-use `MESHIA_MAC39_PAIR_GRANT` secret, dispatch with diagnostics
   and the exact workspace UUID, then remove/verify absence of that secret once
   consumed. Do not import OAuth into the guest.
5. Read the installed artifact checkpoint and verify exact source/artifacts,
   fresh hosted Mac identity and Limited attachment before normal command run.
6. Submit the unchanged probe once; preserve failed results without retries.
   Read final file bytes through normal MCP separately from command completion.
7. Use account UI revocation on only the fresh hosted guest. Verify revoked
   generation, guest mount/service closure and uninstall. The guest's independent
   timeout performs owned cleanup even if the local owner disappears.

The watchdog only calls normal `meshia_workspace_status` and
`meshia_workspace_stop`. It never executes on or revokes a device, grants access,
creates a workspace, or reads a primary mount. Its CLI adapter follows the
existing durable `live-owner-execution.py` normal-MCP invocation; no historical
primary-host mutation scripts should be executed. For early cleanup, write
`cleanup-now.json` in the owner state directory containing only
`{"workspace_id":"<exact disposable workspace UUID>"}`. The existing watcher
reads that signal; do not start a concurrent controller. `--cleanup-now` is also
available when resuming an already stopped controller. An exclusive lifetime
lock prevents concurrent controllers. Never
delete state to retry an ambiguous stop. The persisted dispatch intent causes
all future iterations to read the original operation, including after restart.
Missing original operation after an ambiguous call requires operator readback,
not automatic retry. Archive the final state when billing and all nine cleanup
counters reach terminal values.

Host-process survival is not an independent deadline guarantee after a Mac
shutdown: root must retain a separately scheduled cleanup owner/backstop before
allocating, or explicitly use an already-running durable controller. This kit
preparation alone does not establish that external backstop.

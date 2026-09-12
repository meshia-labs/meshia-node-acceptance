# Private next-release Mac qualification

Privately bound to native1.3.37 sourcec126ddd811a09b361b4f0b1c9396ca1f1bf9160c,
candidate8f31a9cf8a320bdcbf889b16e69a467167c0ad7b. The four exact artifact pins
in production_install.py match the staged bytes and accepted/stapled notary
receipt in /tmp/meshia-native37-release-20260913/candidate.json. No branch push,
credentials, workspace creation, pairing or dispatch is authorized by this kit.
The preceding native36 failure archive remains unchanged.

The workflow now finishes the canonical install step immediately after its
verified checkpoint. This publishes the step log and summary before commands.
It then uploads only the sanitized installed-checkpoint.json using pinned
actions/upload-artifact v4.6.2, with one-day retention. The owner downloads that
artifact through ordinary authenticated GitHub REST while the job waits;
neither browser login nor unfinished job-log availability is a readiness gate.
The checkpoint explicitly includes host/run/UID,85module verification, codesign,
stapled ticket, Gatekeeper and exact native executable comparison. The next step
waits for owner commands and normal account revocation, using only the owned
sanitized receipt; no pairing grant crosses into that step.

Before the one command, root reads the exact completed install-step checkpoint
and confirms the wait step is running. The actual mounted probe uses distinct
old/new lengths, an open ordinary reader, newly opened pathname readback and a
third replacement reusing the same temporary pathname. Each replacement is a
new operation; no failing operation is retried.
Every replacement asserts immediate temporary-name absence. After the command
passes, root must independently use normal MCP file read to verify xcrun_db is
exactly `meshia third cache\n` (19bytes), and normal MCP listing must confirm
xcrun_db-Meshia36 is absent. This owner-side readback is a separate final join
requirement; a successful guest command alone does not satisfy it.

Install or wait failure leaves the unconditional owned cleanup step enabled.
Only that final cleanup step performs service stop/uninstall, exactly once;
install and wait merely record their state, avoiding duplicate guest teardown.
The receipt never calls local success complete owner acceptance. The original
660-second in-process budget spans install and wait, the job remains15minutes,
and the independently armed owner watchdog remains the external15-minute
cleanup bound. Root/host/workspace protections and generation-fenced revocation
are unchanged; the next owner kit must bind its new exact workspace and source.

After root verifies public delivery of these exact bytes, root separately
approves kit publication and one fresh run. The owner collector must
to read installed_waiting_owner from the completed install step and
service_and_mount_stopped from the separate owner-wait step. Require their
ordering around the command and actual revocation when joining final evidence.

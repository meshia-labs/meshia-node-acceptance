# Meshia Node macOS acceptance kit

**1.3.30 corrected fixture: bound, not yet republished or rerun.** The four files
come directly from canonical artifact commit `b474350a4382b772eb14c91db3e84d56c047c7a9`,
with native source `b909a4614582f49b4f8957dbeb2afe8cbd502a58`. Their hashes are
bound in `release-lock.json`; public delivery verification and the release
owner's GO are still required before a new tag, publication or workflow dispatch.
The exact bound kit passed 18 focused local checks in 11.999 seconds: retained
descriptor workload, signed access-snapshot ordering, app-driver ordering and
failure cleanup, artifact/primary-account fences, signed enrollment/revocation,
and the loopback app server. No native service or mount was installed by that
local gate, and the Mac29 cold COW matrix was not rerun.

This is a test-only distribution and a disposable macOS acceptance workflow.
It does not change Meshia's public installer channel. Once bound, the verifier
pins all four artifact hashes and the release lock's independent SHA-256.
No private repository checkout, Git history, production account, signing key,
Apple developer login, cloud provider, or Meshia backend is needed.

## Focused default for 1.3.30

The default `changed-paths` profile retains exact signed installation, actual
mounting, Full/Workspace-only filesystem and network boundaries, app transport,
detached-child cancellation and always-run cleanup. It adds:

- A retained, pre-read file descriptor and a separate writable descriptor must
  see identical in-place cross-page writes, fsync, truncate and zero regrowth.
  Reopened bytes and the exact durable 33-byte result must match too.
- Three normal signed empty app-list polls must leave the observed manifest
  head and local/remote registry bytes unchanged. The same check runs with an
  owned app already registered. It compares actual before/after state rather
  than assuming every internal file starts at generation zero.
- A deterministic fixture access snapshot lets a genuine signed new-mode app
  reservation complete before the ordinary heartbeat reports the new mode.
  Every heartbeat completes normally; no socket or signer lock is blocked.
  The installed config must then adopt the mode before register/HTTP proceeds.
  It uses the existing prior config directly and the original 40-second
  permission-adoption allowance, covering the unchanged 30-second heartbeat
  cadence. Fixed assertion names and safe phase facts are retained on failure.
  Both Full to Workspace-only and Workspace-only to Full are checked through
  the installed service. This is controlled fixture ordering, not production
  concurrency evidence; product tests separately cover old-grant cancellation.

The default skips the already-passed Mac29 cold COW matrix and restart sequence.
The optional `full` profile retains those checks, described below. Both profiles
keep the original ten-minute fixture and owned-resource cleanup limits. This
draft has not run either hosted profile. Local check results are recorded
separately and do not establish native Mac30 acceptance.

## Retained full baseline

- A fresh, non-root GitHub-hosted `runner` account with a GUI launchd domain.
- By default both standard runners (`macos-15` ARM64 and `macos-15-intel` x64) execute
  independently, with the actual architecture recorded from `uname -m`.
- The exact signed app passes codesign, stapled-ticket and Gatekeeper checks.
  Assessments must remain enabled before and after assessment; disabled policy
  fails the proof and is never changed by this kit.
- The unmodified versioned installer selects that app and runs its real user
  service; every installed Python module matches the exact wheel.
- An actual native filesystem mount starts with empty generation zero and
  persists a mounted read/write round trip to a loopback Fabric fixture.
  It then receives a 2 MiB tree-backed source through the signed namespace,
  partially overwrites it, verifies untouched bytes, shrinks and regrows it,
  fsyncs and checks both mounted readback and exact durable publication.
  A separate logical 2 GiB + 4096-byte typed tree exceeds the default eager
  materialization budget, using only a distinct 2 MiB physical prefix and an
  implicit zero tail. The fixture requires zero source bytes downloaded before
  this cold workload, samples prefix and far-tail reads/writes, then shrinks to
  roughly 1 MiB before fsync and durable publication. It never reads or hashes
  the complete logical file. Source reads remain bounded at 4 MiB.
  A separate canonical web-generated 9 MiB source retains its ordinary whole-
  content SHA and `object_cas_v1` 4+4+1 MiB block layout. The installed mount
  edits across the last block boundary, shrinks/regrows and renames it. Both
  the classic dirty-file rename and this COW rename must publish exact bytes
  and remove the old source from signed authoritative listing and lookup.
  The ordinary 2 MiB and 9 MiB cases allow normal eager materialization and
  record observed read counters without claiming they stayed cold.
  A separate real mounted dirty rename immediately recreates its old source
  with exclusive creation. Both the recreated source and renamed destination
  must retain their distinct bytes in signed listing/lookup and durable storage.
  This hosted workload does not force recreation before a remote ACK; the
  product's controlled joined regression covers that ordering separately.
  One canonical owned-service restart then verifies remounted bytes and old
  source absence; it is not a forced crash or pending-write crash-recovery test.
- Full compute uses the ordinary account and can read/write a personal canary.
- An owner change to Workspace-only preserves workspace writes and loopback
  networking while denying outside read, write, stat and create.
- In each Full and Workspace-only mode, the installed service receives signed
  app commands, reserves a port and launches a real app through its unchanged
  `NativeApps` and `AppProcessOwner`. The same owned port serves HTTP, a finite
  SSE body spanning multiple response chunks, and exact binary WebSocket echo.
  HEAD 200, ranged HEAD 206 and GET 304 must preserve their representation
  lengths while returning an empty body; ranged HEAD also preserves Content-Range.
  A separate 1,179,648-byte finite response negotiates 512 KiB reads while its
  initial response remains capped at 256 KiB. SSE retains 256 KiB reads. The
  receipt records the actual largest finite chunk and exact response digest.
  Each app writes its mounted workspace; Full permits the disposable personal
  canary and Workspace-only denies its read, write and stat. Unregister must
  close the app port and its remembered kernel process identity. No native
  launcher, coalition, socket ownership or policy check is replaced by a fixture.
- The actual managed interpreter loads a nonempty default public CA store
  through the signed Workspace-only command lane. Already installed Homebrew
  Python 3.14 interpreters receive the same check; absent interpreters are
  recorded as absent, and none is installed for this optional check. Only CA
  counts are reported. This local trust-store read is not a WAN TLS test.
- Signed queued execution owns a separate native coalition and cancels a
  detached child before its natural timeout, without relying on PID alone.
- Owned service, mounts and process identities are removed at completion.

Only the remote account/control plane is a fixture. Its enrollment proofs,
request signatures, generation/sequence fences and Fabric transport validation
are the existing independent protocol fixture, not a permissive HTTP stub.
Fixture keys and grants are generated in memory or disposable private state.
No real account credentials are accepted or requested.

## Explicit limits

This smaller kit still excludes large streamed assets, 4 MiB staged uploads, app
permission-change cleanup and command/app independence tests. Its finite SSE
body checks exact chunk transport and content type, not progressive first-event
timing or a long-lived event connection. Final Azure/WAN acceptance must cover
those separately. Mac app checks do not prove Linux or Windows app ownership.
It does not prove production sign-in, account revocation, browser app origins,
WAN transport, managed CPU/GPU readiness, or customer privacy-prompt UX.
It verifies immutable bundled artifact delivery over a local HTTP fixture,
not Meshia's public HTTPS installer endpoint. The installer is passed
`--insecure-dev` solely for the loopback fixture; native signature, notarization,
ownership, permissions and filesystem checks are retained.
There is no development native-host override and no fallback from limited to
Full. A missing runner GUI domain, runtime prerequisite, permission or mount
fails the job rather than skipping the check.

The canonical protocol fixture retains its string-dispatched current routes
and their validators. Twelve unreachable setup/test helpers were removed;
the Linux OS acceptance runner is absent. The small app fixture grants only
the enrolled attachment's current Full/Workspace-only revision, binds the first
reported instance, and expires supervision after 90 seconds. The app also has
an independent 90-second exit timer. Ordinary commands cannot consume app
claims. Both lanes retain signed request validation and completion receipts.
The standalone v2 fixture adds authenticated empty snapshots, journal changes,
file lookup, verified block reads, immutable file-version holds, bounded typed
tree proofs and the put/delete operations used here. Its independent tree
decoder limits materialized output and physical objects to 4 MiB. Read-only
closure validation admits the bounded logical sparse source through four
index levels without allocating its zero tail. It validates
attachment/generation, object bytes, per-path predecessors
and exact replay identity using the same in-memory fixture storage. Unsupported
namespace operations fail explicitly. Legacy missing manifests still fail;
an empty v2 workspace is represented by sequence zero and no entries.
The local regression runs the released wheel's real signed transport and sync
coordinator through this empty state and the first file publication/readback,
then joins its actual mount backend and native journal to the cold tree edit.
That local backend test creates no OS mount and makes no isolation claim; the
hosted installed-service workload provides those separate facts. Tree identity
and canonical implicit/explicit raw SHA are separate cases. The generated raw
fixture files and their exact producer provenance are included; the kit does
not author an alternate storage descriptor. A local journal-reload test also
reads held immutable bytes after a signed source deletion, without calling
that library-level reload a real process crash.
The only product implementation included is the already reviewed public
distribution wheel, app and installer. No server, pod, source archive or
internal contract tree is included.

## Local verification without installation

The portable adaptation checks run without product imports:

```sh
PYTHONDONTWRITEBYTECODE=1 python -m unittest -v test_preparation
```

These exercise the filesystem workload on ordinary temporary files, reject
bad authoritative projections and prove that an unbound kit cannot install.
They are not native mount or final wheel acceptance. For the bound wheel:

Use Python 3.12+ with the wheel's pinned dependencies available:

```sh
PYTHONDONTWRITEBYTECODE=1 python acceptance.py verify --directory /tmp/unused
PYTHONDONTWRITEBYTECODE=1 python -m unittest -v test_kit test_fixture_cow
```

These commands check hashes, fixture authority, output filtering, cleanup
fences and the disposable app server's HTTP/WebSocket bytes. Local driver tests
use simulated completions and do not prove native ownership or Limited policy.
Native installation is gated to the fresh hosted `runner` account.
Do not spoof the GitHub runner environment on a personal Mac.

## Publication and run plan

1. Publish only this directory's inventoried files to a purpose-specific public
   acceptance repository, as the test-only 1.3.30 prerelease. Do not copy any
   enclosing evidence folder, private repository history, `.env`, credentials,
   private source or temporary test state. The production installer pointer
   remains unchanged. Use the existing public repository
   `meshia-labs/meshia-node-acceptance`. Bind the final source/package commits
   and all four artifact hashes before publishing; the preparation guard rejects
   unbound artifacts before staging or installation.
2. Record the public kit commit and compare every file against the supplied
   inventory. The default branch must contain this workflow before dispatch.
3. Only after the release owner's explicit GO, tag the reviewed bound kit commit
   `v1.3.30-acceptance.2`, then dispatch
   `gh workflow run macos-acceptance.yml --repo meshia-labs/meshia-node-acceptance --ref v1.3.30-acceptance.2 -f profile=changed-paths`
   For an authorized focused diagnosis on a fresh reviewed tag, add
   `-f runner=macos-15-intel` (or `macos-15` for ARM). Omission exercises both.
   once. Read the resulting run's `head_sha` and require the exact reviewed kit
   commit before interpreting results. The workflow
   refuses private repositories, uses standard `macos-15` and `macos-15-intel`
   in parallel with `fail-fast: false`, `contents: read`,
   pinned checkout/setup actions, no repository secrets, no input-supplied URLs
   or executable commands, and a 15-minute limit for each job.
4. Read job admission before considering another attempt. Both public standard
   runners were admitted for the three earlier 1.3.17 runs. A billing
   refusal with zero steps is not an acceptance result; do not retry blindly or
   change billing as part of this workflow.
5. Require the native test and the always-run cleanup step to pass. Preserve the
   bounded public JSON printed in the final job summary, the exact kit commit,
   runner image and run URL. No Actions artifact/cache upload is configured.
   Do not publish raw runtime logs, config or fixture keys.

Installer failures expose only fixed literal messages found in the pinned
installer, exit status and byte counts, known exception classes, file-existence
flags and bounded fixture error codes. Captured output and runtime config are
never published. Earlier 1.3.17 runs
[34547438869](https://github.com/meshia-labs/meshia-node-acceptance/actions/runs/34547438869),
[34548844065](https://github.com/meshia-labs/meshia-node-acceptance/actions/runs/34548844065), and
[34549927120](https://github.com/meshia-labs/meshia-node-acceptance/actions/runs/34549927120)
failed and cleaned up on both runners. Their tagged source, artifacts and
results remain historical evidence, not native acceptance passes.

The exact 1.3.18 [run 34552641120](https://github.com/meshia-labs/meshia-node-acceptance/actions/runs/34552641120)
passed native acceptance and cleanup on both architectures. Its tagged source,
artifacts and receipts remain unchanged. That pass did not test the additional
TLS-directory restriction or default-public-CA coverage added for 1.3.19.

The first 1.3.19 [run 34555012949](https://github.com/meshia-labs/meshia-node-acceptance/actions/runs/34555012949)
passed Intel and failed ARM with native startup exit 70 at the CA-store step;
both runners cleaned up. The diagnostic-only [run 34555944736](https://github.com/meshia-labs/meshia-node-acceptance/actions/runs/34555944736)
then passed both architectures with unchanged artifacts, commands, permissions
and timeouts. The original startup failure remains unexplained. A later
candidate pass must not be described as a fix for that historical failure.

Dependency downloads use the wheel's pinned Python requirements and the
canonical installer's verified runtime prerequisites. They do not provision
compute or call production accounts. Network availability and GitHub's hosted
macOS restrictions remain real acceptance conditions.

The historical 1.3.28 kit commit `c173b09` passed 39 local checks against its
bound wheel, but the fresh hosted ARM run failed at `classic_dirty_rename`
after native installation, NFS mount and initial mounted publication passed.
Its local old-source absence assertion is retained here; a local backend pass
did not establish hosted acceptance. The original bounded public receipt is
preserved separately by the audit owner. The primary Mac28 upgrade also failed
automatic recovery of its older queued rename; no manual pending-row repair
was performed. Fresh29 acceptance must not be described as recovery of that
historical fixture.

The first 1.3.29 run, [34635392657](https://github.com/meshia-labs/meshia-node-acceptance/actions/runs/34635392657),
failed its original cold COW phase on both architectures after installation,
rename and source recreation passed. Cleanup passed. Its exact assertion was
not retained; local reproduction proved that the ordinary 2 MiB source could
be prefetched under the healthy default policy, so it did not establish a cold
precondition. The original run and immutable tag remain unchanged.

The corrected fixture-only 1.3.29 [run 34637700581](https://github.com/meshia-labs/meshia-node-acceptance/actions/runs/34637700581),
tag `v1.3.29-acceptance.2`, kit `260987777fab973a8f5314b33ebb0b194416a6e9`,
passed on ARM and Intel with unchanged product artifacts, including the bounded
sparse cold source and cleanup. This is historical Mac29 proof, not Mac30
acceptance. Both hosted images had SIP disabled while Gatekeeper remained
enabled; loopback authentication, bundled transport, finite SSE and controlled
recreation/restart limits still apply. No complete Mac30 pass is claimed here.

The first Mac30 [run 34644477967](https://github.com/meshia-labs/meshia-node-acceptance/actions/runs/34644477967),
kit `f856b4c3ef5ae2ca83afa76a26880e5692d5dcd5`, failed on both architectures;
both cleaned up. Signed installation, real NFS retained-FD coherence, exact
durable bytes and empty-list stability passed. Intel completed a genuine
new-mode reservation before failing the fixture's `delayed_access_heartbeat`
phase; ARM failed earlier in the transition setup. Exact assertion literals
were not preserved, and the original result remains unchanged.

The fixture incorrectly required a new heartbeat within exactly 30 seconds
and allowed only 15 seconds for the following adoption, while the released
runner's cadence is 30 seconds. This correction removes the preliminary wait
and restores the existing 40-second permission-adoption bound; no product
bytes, cadence, ownership or permission checks change. A virtual-clock test
using the exact released client's real signed heartbeat fails under the old
15-second bound and passes under the correction. Four focused tests passed in
9.233 seconds, including both access directions and timeout/cleanup handling.
These local checks do not establish a successful hosted app transition.

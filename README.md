# Meshia Node macOS acceptance kit

Local binding checkpoint: the kit now pins the packaged 1.3.28 artifacts.
All 39 local checks, including seven signed COW cases with canonical raw SHA
and both dirty rename paths, pass against the exact bundled wheel from source
`354f8bebd55b1bd2f93d9b546d8913ec674c564c`.
Public delivery must be verified before publishing or dispatching this kit.
No fresh Mac27 or Mac28 hosted result is claimed by this binding commit.

This is a test-only distribution and a disposable macOS acceptance workflow.
It tests the exact packaged 1.3.28 artifacts without changing Meshia's public installer channel.

Package commit: `dbd26afb4f091ccef9590f0994c2c50923f14ed1`; clean source:
`354f8bebd55b1bd2f93d9b546d8913ec674c564c`. The `release-lock.json` binds
every included file; the verifier separately pins the lock's SHA-256.
No private repository checkout, Git history, production account, signing key,
Apple developer login, cloud provider, or Meshia backend is needed.

## What the hosted job proves

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
  It then receives a cold 2 MiB tree-backed source through the signed namespace,
  partially overwrites it, verifies untouched bytes, shrinks and regrows it,
  fsyncs and checks both mounted readback and exact durable publication. The
  fixture confirms no source bytes were downloaded before this workload.
  A separate canonical web-generated 9 MiB source retains its ordinary whole-
  content SHA and `object_cas_v1` 4+4+1 MiB block layout. The installed mount
  edits across the last block boundary, shrinks/regrows and renames it. Both
  the classic dirty-file rename and this COW rename must publish exact bytes
  and remove the old source from signed authoritative listing and lookup.
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
decoder is limited to 4 MiB files and two index levels. It validates
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
   acceptance repository, as the test-only 1.3.28 prerelease. Do not copy any
   enclosing evidence folder, private repository history, `.env`, credentials,
   private source or temporary test state. The production installer pointer
   remains unchanged. Use the existing public repository
   `meshia-labs/meshia-node-acceptance`. Bind the final source/package commits
   and all four artifact hashes before publishing; the preparation guard rejects
   unbound artifacts before staging or installation.
2. Record the public kit commit and compare every file against the supplied
   inventory. The default branch must contain this workflow before dispatch.
3. Tag the reviewed kit commit `v1.3.28-acceptance.1`, then dispatch
   `gh workflow run macos-acceptance.yml --repo meshia-labs/meshia-node-acceptance --ref v1.3.28-acceptance.1`
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

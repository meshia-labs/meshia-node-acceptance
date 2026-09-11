# Meshia Node 1.3.21 macOS acceptance prerelease

This is a test-only distribution and a disposable macOS acceptance workflow.
It does not change Meshia's current public installer channel (1.3.20).

Package commit: `71aa8ce549754eccc950e30ab1f33d7305cc7880`; clean source:
`ea02034c8eb53628a81fa11be0007774ceb2ee92`. The `release-lock.json` binds
every included file; the verifier separately pins the lock's SHA-256.
No private repository checkout, Git history, production account, signing key,
Apple developer login, cloud provider, or Meshia backend is needed.

## What the hosted job proves

- A fresh, non-root GitHub-hosted `runner` account with a GUI launchd domain.
- Both standard runners (`macos-15` ARM64 and `macos-15-intel` x64) execute
  independently, with the actual architecture recorded from `uname -m`.
- The exact signed app passes codesign, stapled-ticket and Gatekeeper checks.
  Assessments must remain enabled before and after assessment; disabled policy
  fails the proof and is never changed by this kit.
- The unmodified versioned installer selects that app and runs its real user
  service; every installed Python module matches the exact wheel.
- An actual native filesystem mount starts with empty generation zero and
  persists a mounted read/write round trip to a loopback Fabric fixture.
- Full compute uses the ordinary account and can read/write a personal canary.
- An owner change to Workspace-only preserves workspace writes and loopback
  networking while denying outside read, write, stat and create.
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

This smaller kit excludes the canonical helper's app HTTP/SSE/WebSocket,
large asset, 4 MiB staged upload, app permission-change cleanup and command/app
independence tests. Final Azure/WAN acceptance must cover those separately.
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
the Linux OS acceptance runner and app-stream test implementations are absent.
The standalone v2 fixture adds authenticated empty snapshots, journal changes,
file lookup, verified block reads and the bounded put/delete operations used
here. It validates attachment/generation, object bytes, per-path predecessors
and exact replay identity using the same in-memory fixture storage. Unsupported
namespace operations fail explicitly. Legacy missing manifests still fail;
an empty v2 workspace is represented by sequence zero and no entries.
The local regression runs the released wheel's real signed transport and sync
coordinator through this empty state and the first file publication/readback.
The only product implementation included is the already reviewed public
distribution wheel, app and installer. No server, pod, source archive or
internal contract tree is included.

## Local verification without installation

Use Python 3.12+ with the wheel's pinned dependencies available:

```sh
PYTHONDONTWRITEBYTECODE=1 python acceptance.py verify --directory /tmp/unused
PYTHONDONTWRITEBYTECODE=1 python -m unittest -v test_kit
```

These commands check hashes, fixture authority, output filtering and cleanup
fences only. Native installation is gated to the fresh hosted `runner` account.
Do not spoof the GitHub runner environment on a personal Mac.

## Publication and run plan

1. Publish only this directory's inventoried files to a purpose-specific public
   acceptance repository, as the test-only 1.3.21 prerelease. Do not copy any
   enclosing evidence folder, private repository history, `.env`, credentials,
   private source or temporary test state. The production installer pointer
   remains unchanged. Use the existing public repository
   `meshia-labs/meshia-node-acceptance`. Bind the final source/package commits
   and all four artifact hashes before publishing; the preparation guard rejects
   unbound artifacts before staging or installation.
2. Record the public kit commit and compare every file against the supplied
   inventory. The default branch must contain this workflow before dispatch.
3. Tag the reviewed kit commit `v1.3.21-acceptance.1`, then dispatch
   `gh workflow run macos-acceptance.yml --repo meshia-labs/meshia-node-acceptance --ref v1.3.21-acceptance.1`
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

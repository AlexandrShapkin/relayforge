# Issue #89: reproducible process-role verification

Scope: move the R2 operational role checker into `deploy/process_roles.py`,
fix unrelated executable reads, and run deterministic regressions in existing
Ubuntu and Arch GitHub CI. No installed resources, runtime calls, receipts,
activation, staging, recovery-policy changes or new host authorization.
Base: b5730eb469846eadc7d3eb0a58440bfc89cec511.

Plan: inspect R2 and CI; separate bounded metadata discovery from streamed
identity hashes; test negative and valid chains; verify native checks and
exact-head CI; prepare a separately sealed private R3 copy for independent review.
Acceptance requires no executable-body open for unrelated members, strict role
hash/argv/UID/ancestry and identity checks, cgroup rechecks, and failure without
independently observed workers. R2 and original evidence remain immutable.

Metadata is bounded to 64 KiB per proc file. All members retain UID, starttime,
PPID, argv, executable link and inode/size/timestamp checks. Candidates are
processes advertising either restricted mode, named relayforge-mcp, or sharing
an executable identity with those candidates. Only these and the tunnel main
are hashed, streamed in 1 MiB chunks with the existing 128 MiB identity limit.
A named or alias MCP with an unexpected mode or hash fails closed. This is
role attestation, not a census of every unrelated executable's content.

The caller supplies trusted expected MCP/tunnel digests, UID, and a membership
callback returning `(main_pid, cgroup_identity, pid_set)`. Metadata discovery,
hashing, identity resampling and two membership rechecks must agree. This is
bounded observation, not an atomic kernel-wide snapshot; an unobserved transient
between samples cannot be ruled out. Missing/disappearing ephemeral workers
block acceptance, including at idle. The verifier never starts a request.

Run `python3 -B -m unittest discover -s scripts -p test_process_roles.py`.
The suite uses deterministic metadata and disposable procfs-shaped files,
including a sparse 276 MiB executable guarded against content opens. A live
container fixture would not establish private service/tunnel/rollback health
and is unnecessary for this regression.

Physical gates remain: independent exact-head/source and exact-seal R3 review;
owner-local integrity and installed-pin checks without ownership bypass;
explicitly bounded active authenticated request observation with genuine worker
evidence; protected recovery/baseline provenance and rollback acceptance; then
separate owner authorization before any staging or activation. CI provides no
live readiness claim. The private R3 package must pin the tracked verifier and
source SHA; original/R2 review does not transfer to R3. No release is made.

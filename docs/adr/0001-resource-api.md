# ADR-0001: Resource-oriented RelayForge API

- **Status:** Accepted as the target architecture by the project owner on 2026-10-22; **not implemented**.
- **Scope:** Public MCP contract, host routing, extension model, authorization, compatibility.
- **Tracking:** [#92](https://github.com/AlexandrShapkin/relayforge/issues/92) (API consolidation), [#91](https://github.com/AlexandrShapkin/relayforge/issues/91) (multi-host files), [#89](https://github.com/AlexandrShapkin/relayforge/issues/89) and [PR #90](https://github.com/AlexandrShapkin/relayforge/pull/90) (interim artifact reads), [#77](https://github.com/AlexandrShapkin/relayforge/issues/77) (live runtime isolation).
- **Authority:** This ADR authorizes architecture/design only. It does not authorize merges, local grants, deployment, changes to running services, broad host access, or new execution powers.

## Decision

RelayForge will use a **resource-oriented architecture with typed CRUD, explicit domain commands, capability discovery, and host-local authorization**.

The **logical public API** has six operations:

| Operation | Meaning | Typical use |
| --- | --- | --- |
| `discover` | Enumerate accessible hosts, resource kinds, versions and supported actions/views | Show available hosts and per-host file-read support |
| `read` | Read one resource or a bounded view of it | File content/ranges, directory listing, metadata, search, Git status, job result |
| `create` | Create an authorized resource | Create a document in a specifically approved workspace |
| `update` | Change an existing authorized resource | Replace file content with a version precondition |
| `delete` | Remove an authorized resource | Delete an approved disposable file |
| `execute` | Invoke a declared, bounded **domain command** that is not CRUD | Restart an approved service, start a build, sync Git, roll back a runtime |

These six names are **logical capabilities**, not a requirement to collapse every operation into an undifferentiated MCP tool. Preserve separate read-only versus mutating/destructive tool boundaries, conservative MCP annotations, typed input schemas and separate owner approval. If safety or tool discoverability requires distinct MCP tools or narrow wrappers, use them without multiplying underlying domain implementations.

**Resources are named for what they are, not why they were created.** A source file, Codex handoff and operational log are all `file` resources. Their origins and authorizations can differ without requiring `repo.read`, `artifact.read` or `workspace.read` in the final canonical API.

CRUD is **not** a permission grant. The local agent controls which actions are supported and approved for each resource/host/path. Not all resource kinds implement all CRUD verbs. `execute` is strictly a catalog of typed commands; it never accepts arbitrary shell, executable names, unreviewed scripts or opaque privileged operation payloads.

## Conceptual contracts (not current wire API)

```json
{"host":"thinkpad-a285","kind":"file","id":"/home/user/Projects/relayforge/README.md","view":"content","options":{"offset":0,"length":8192}}
```

This request uses `read`. The same `read` can fetch an authorized `/home/user/Projects/relayforge/.build/.../AUTHORIZATION.md` or an allowed path on `ru0`. All requested paths are evaluated against the target host's permissions.

```json
{"host":"thinkpad-a285","kind":"service","id":"relayforge-tunnel.service","command":"restart","options":{"dry_run":true}}
```

This request uses `execute`, not `update`. A real restart requires separate scope-specific operator authority and independent physical recovery. `dry_run` cannot stand in for approval and must not mutate state.

Common envelope: `host` (authenticated registered identity, not caller-supplied address), `kind`, `id`, operation, schema version and strictly typed options. For each kind, a versioned registry declares supported operations, views, input/output shapes, limits and risk class. Disallow extra/unknown fields. Avoid an unvalidated arbitrary `params` bag.

`read` views are declared by the resource provider (examples: `content`, `metadata`, `entries`, `search`, `status`, `output`). A directory listing is a read of a directory, not a file with special flags. Large file content requires bounded ranges or pagination; reads expose completeness/truncation. Search has independent query, traversal, duration and result-count limits.

Every result carries authoritative origin (`host`, `kind`, `id`), operation/schema version, observation time, typed status/error and available size/version/hash/mtime plus paging or truncation metadata. Hashes and timestamps must reflect observed files, not guessed consistency. Stable read handles or snapshot tokens can be added if chunk consistency requires them. Offline/unreachable/stale must never be represented as fresh successful output.

`discover` may reveal only resources/capabilities the caller is authorized to know; do not leak sensitive host inventories, grant bodies, credentials or filesystem trees.

## Layers and extension points

```text
ChatGPT / MCP client
    -> small typed MCP façade
    -> schema validation + identity/routing + audit
    -> authenticated per-host transport/agent
    -> host-local policy enforcement
    -> registered resource provider (file, directory, Git, job, service, ...)
    -> real host OS/resource
```

Transport/router, policy engine and resource providers are distinct responsibilities. **Authority is enforced on the target agent**, not inferred from an MCP request or a central router. The gateway may also restrict calls, but gateway approval alone cannot expand host privileges.

New functionality normally means **registering a new resource kind, read view or typed command/provider**, not adding a new public MCP verb. First use simple static in-process Rust adapters and the existing transport. Do not introduce a service mesh, global database, dynamic plugin VM or separate executor unless a concrete use case demands it.

Providers must declare unsupported operations explicitly, instead of simulating them. Existing special behavior remains as views or domain commands:
- Git status, diff, commits, branches and sync are Git semantics, not merely file I/O.
- Job status, output and immutable receipts are read views; run/stop/cancel are typed lifecycle commands subject to grants.
- `development.prepare/run/inspect` retain fixed-source, expiring-task-authorization and one-time execution invariants; they are **not** generic `file.update`.
- Service restart and runtime rollback require their own approval, bounded deadlines and independent recovery mechanisms.
- Filesystem read access does not imply filesystem write, execution or secret access.

## Authorization and safety invariants

1. **Default deny**, explicit owner-managed per-host profiles and a revocable local grant/policy. Profiles may authorize narrow roots or broad read scopes; broad/sensitive access requires explicit host-local consent. No model-driven self-grant, privilege escalation or bypass of actual OS permissions/ACLs.
2. Enforce **host identity + principal + kind + object/path + action/view + constraints** at the actual host. Separate read, create/update, delete and command approval; destructive operations demand stricter confirmation. Expiring grants and idempotency/precondition controls for mutations where possible.
3. Treat filesystem data, logs, prompts and repository content as **untrusted**; reading a file never authorizes obeying its instructions. Never publish retrieved secrets or copy file bodies into audit records by default. Sensitive-data filters are defense-in-depth, not a guarantee that secrets cannot leak.
4. Descriptor-based path resolution with strong symlink/TOCTOU resistance, confinement to authorized mounts/paths and OS identity; account for hard links, special files, proc magic links and bind mounts. Limit reads, traversal, bytes, time, concurrency, and output; fail closed on uncertainty.
5. Every host uses an independently authenticated transport. Host absence, disconnect, insufficient privilege and revoked grants produce distinct bounded errors, not fallback to SSH/RDC or stale cached data.
6. High-risk commands are declarative, reviewable, bounded, independently recoverable and audit only necessary metadata; no arbitrary shell hidden behind `execute`.
7. Server and client schemas must be versioned; compatibility aliases cannot change effective authority. The restricted Secure MCP Tunnel must **not** regain forbidden agent file-write, arbitrary process or restart powers via new routing.

## Migration and acceptance

1. **Keep #77 and #90 moving.** Interim `artifact.read/list` may be deployed and accepted without waiting for this architecture; its existing default-deny root policy remains in force.
2. Inventory actual MCP tools and nested operations across ThinkPad and managed-host agents; classify read vs mutate, schema, caller usage, authorization and exact behavioral differences. Record baseline public-operation count and duplicate filesystem/scheduler implementations. Publish a versioned contract/migration matrix before changing deployed APIs.
3. Implement the new `discover` and canonical **read-only** `read(file|directory)` first on ThinkPad, **reusing the reviewed safe reader**, with host-local allowlist, bounded ranges, metadata/list/search and capability discovery. Add no generic writes at this stage.
4. Implement the same contract on one separately authenticated second host without local privileges being inherited across hosts. Verify source file, approved Codex report and remote-host file reads through the canonical operation, plus failures for denied secrets/paths, offline hosts, symlink/path escapes, stale/changed files, truncation and revocation.
5. Move legacy `repo.read/list`, `artifact.read/list`, `workspace.read/list`, and remote file-inspection reads to the shared backend behind compatibility shims. Only deprecate their public names after behavior/permissions match, affected consumers migrate and authenticated live acceptance passes. Preserve unrelated `workspace.put/remove` authority until separately redesigned.
6. Consolidate job/task status/output on shared read views where identity, semantics and receipts are actually compatible. Preserve separate specialized commands, then evaluate any authorized write CRUD rollout. Do not mechanically combine unlike `job.start`, `repo.sync`, `build.start` or `development.run`.
7. Remove obsolete aliases and duplicate internals only in a reviewed versioned release, after measuring fewer publicly advertised operations/implementations and no widened authority. Rollback and original working client remain available.

**Acceptance:** one canonical read operation can retrieve an owner-approved source file, Codex report and second-host file with correct provenance and bounds; forbidden paths/actions fail; disconnection/revocation fails closed; unchanged old clients still work during the compatibility period. No production activation follows automatically from ADR or CI approval.

## Consequences

**Benefits:** small stable interface; adapter-based extensibility; fewer duplicate path readers; consistent multi-host identity, responses and permissions; less tool-discovery overhead for clients; clear migration/rollback.

**Costs/risks:** generic resource requests can hide overly broad schemas or authority if implemented carelessly; capability discovery, typed validation, per-host policy and compatibility testing are mandatory. Six logical verbs are a design target, not a reason to weaken MCP safety boundaries or obscure domain-specific semantics.

## Rejected alternatives

- Continue adding special-case verbs (`artifact.read`, `report.read`, `config.read`, etc.): duplicates transport, file handling and permission logic.
- A single untyped `dispatch/execute` for everything: poor safety/tool introspection; unacceptable authorization ambiguity.
- Model-controlled arbitrary shell or filesystem privileges as a shortcut: violates the local owner authorization boundary.
- Immediate big-bang API replacement: endangers existing tunnel and runtime recovery; incompatible with current safe staged deployment.

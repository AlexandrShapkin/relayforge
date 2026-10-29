# Internal typed resource boundary (#129)

This source-only ADR-0001 slice retains MCP API revision 9 and every existing
public operation. No discovery aliases, CRUD writes or network routes are added.
The ADR remains the broader target; canonical multi-host file CRUD is deferred.

`resources::ReadRequest<Q>` version 1 carries fixed host/kind/action enums,
object identity and a concrete query. Unknown fields, hosts, kinds, actions and
views fail closed. `ReadProvider` has associated query/output types; registering
another resource requires a typed registry slot, not an arbitrary JSON handler.
Only implemented actions exist: create/update/delete are unsupported, with no
placeholder executors. Observations bind local origin, version and observation
start time; typed errors distinguish unsupported versions, denied resources,
clock failure and existing provider failures. LocalWorkstation is process-local
scope, not authenticated remote identity. Observation time is not a snapshot.

The first route is the existing `relayforge_workstation_status` tool:

1. stdio/HTTP MCP transport and restricted tool allowlist remain unchanged.
2. The legacy adapter validates exactly empty arguments and builds a typed
   workstation/local/read/status request. No caller-controlled routing is added.
3. The registry routes to its workstation slot after fixed local read policy.
4. WorkstationProvider reuses the existing bounded, privacy-filtered probes.
5. The adapter serializes only the typed payload, preserving legacy keys, nulls,
   error messages and tool discovery. The versioned envelope stays internal.

This policy does not grant filesystem access or authenticate a new principal.
Host-local reader constraints and OS permissions remain independent. The other
providers/readers (including internal project inventory, artifact descriptor-safe
reads, SSH agents, RouterOS and Android) remain unchanged. Domain commands and
change approval remain separate from resource reads. No generic command handler,
plugin runtime, new dependencies, live installation or host verification occurs.

CI keeps required `Rust verification` and `RDC verification` identities from active
main ruleset 26089611. Rust checks owns fmt/clippy/workspace and Python tests;
RDC verification retains release builds, offline/security and package lifecycle
checks. Neither standalone success replaces the other. The trusted independent
review handoff continues on PR head changes and validates exact head/base owner
attestation. No installed autonomous reviewer service is configured; this task
uses a separate independent AI reviewer. Do not fabricate GitHub approval or
expand workflow token permissions to execute PR source with review authority.

Publication requires explicit main workflow dispatch selecting one full reviewed
main SHA. Exact-source native/security CI, review, tested artifact hashes,
immutable tag/asset checks, provenance and release narrative remain mandatory.
There is no automatic backlog release and no release is authorized by this PR.

# Agent transport and authentication — accepted target, not deployed

**Decision (owner, 2026-10-28):** QUIC over TLS 1.3 is the preferred
agent-to-coordinator transport; WSS over TLS/TCP is the required fallback.
Agent enrollment must be a short, browser-approved flow with no manually
distributed SSH keys or certificates. This is an **architecture decision, not
an implementation or live deployment acceptance**.

This refines the existing transport requirements and
[ADR-0001](adr/0001-resource-api.md). The public ChatGPT-to-MCP boundary
continues to use its separately managed OpenAI Secure MCP Tunnel and Keycloak
OAuth. Neither MCP nor an OpenAI API key authenticates an agent device.


## Trust boundaries

The MCP client authenticates to the coordinator. The coordinator separately
authenticates each agent over an outbound, TLS-protected channel. Neither a
client-provided device ID nor an agent-provided actor ID is an authorization
credential. Agent-side enforcement is mandatory for sensitive operations.

## Selected transport and routing contract

- Every agent initiates an **outbound** connection to a registered coordinator.
  The coordinator routes versioned typed requests over that connection.
  No agent-side inbound listener, SSH-key redistribution, public agent port,
  or host address supplied by an MCP caller is necessary.
- Use **QUIC (Quinn with a maintained Rust TLS stack)** as the primary channel:
  TLS 1.3, a bounded control stream, and separate reliable bidirectional
  streams for independent RPCs or bounded data transfer. Do not use unreliable
  datagrams for operations or results. Disable application **0-RTT** to avoid
  replaying a command during resumption.
- If UDP/QUIC is unavailable, automatically try **WSS/TLS over TCP**, using
  the *same* application request schema, authz checks, identity, error model
  and replay semantics. Never downgrade to plaintext WS, insecure TLS, an
  ad-hoc HTTP bearer listener or implicit SSH. Do not create separate policy
  engines or executors for each transport. QUIC connection migration is a
  possible optimization, not a delivery or continuity guarantee.
- Endpoint/ports and any HTTPS reverse-proxy integration are deployment
  inputs; do not hard-code UDP/443 or assume it is free on ru0. Validate
  coexistence with Nginx, VPN and other services before any firewall or
  listener change. Begin with a loopback-only/disposable pilot.
- The device proves its **own** cryptographic identity on both transports.
  Prefer mTLS with short-lived, device-scoped credentials; where a WSS
  reverse proxy terminates TLS, an independently verified device-key proof
  may be needed, never a trusted caller-supplied identity header. Both
  transports must provide equivalent protection, including server trust,
  credential revocation, session binding and audited failures.

## One-command enrollment and operator experience

**Goal after verified package installation:** run
`relayforge-agent enroll` once on the target device (proposed CLI, not
currently implemented). The expected user experience is:

1. The installed agent determines its approved coordinator enrollment
   endpoint from a validated distribution profile or a short-lived owner
   invitation. It does not require editing JSON/YAML, DNS, firewall rules,
   SSH config, or copying a certificate, password or API key. A freshly
   generated invitation can supply the endpoint when it is not configured.
2. The agent generates its own **non-exported private device key** locally,
   opens a short-lived, rate-limited pending enrollment and displays an
   HTTPS verification URL plus one-time code (optional QR).
3. The owner opens that URL on any browser, signs in to **Keycloak with MFA**,
   and explicitly approves the shown device name, device-key fingerprint
   and requested initial **read-only** capabilities. A code alone is not
   owner authorization. The agent never requests or stores the user's
   Keycloak password, OTP or long-lived user refresh token.
4. The coordinator checks the one-time transaction, binds approval to the
   pending public key and registered device ID, and issues an appropriately
   scoped, renewable device credential. The private key never leaves the
   device. Denied, timed-out, replayed or mismatched enrollments fail closed.
5. The agent verifies the server/credential, stores protected local state,
   tests a read-only connection and offers to enable its **unprivileged**
   systemd user service with explicit local consent. Package installation
   alone does not start a network daemon or grant host access.

Ordinary reconnect, credential renewal and QUIC→WSS fallback must be
automatic. `relayforge-agent status` (proposed) and an owner-visible
registered-device view should show online/offline, last contact, transport,
granted read capabilities and credential expiry without leaking secrets.
Device rename, re-enrollment, revocation and removal need simple attended
commands/UI; revocation immediately prevents new sessions and requests.
Re-enrollment does not silently restore revoked permissions.

**Usability acceptance:** after a trusted package is installed, onboarding
requires one local CLI command and one Keycloak MFA/browser confirmation,
with no manual configuration edits or secret copying. Initial distro
repository trust and package installation remain explicit OS operations.
Remote host updates, privileged services, broad file access and mutations
require **separate** local owner authorization; enrollment does not imply
them.

## Request delivery and host authority

- Bind the registered device identity to each authenticated session and
  agent-side policy. Never trust caller-controlled `device_id`, `actor_id`,
  `host` or operation fields as credentials. Convey verified, audience-
  appropriate actor/delegation context or require equivalent local owner
  authorization; a gateway's claims alone cannot expand agent grants.
- Do not execute arbitrary shell commands. Use ADR-0001's typed resource
  reads and explicitly enumerated bounded domain commands with versioned
  schemas. Keep the existing SSH/stdio pilot and its restricted rights until
  equivalence and an independently accepted migration are proven.
- The transport supplies request IDs, deadlines, bounded sizes and
  concurrency, and explicit `offline`, `denied`, `timeout` and
  `unknown_outcome` results. Losing a connection must not silently queue
  later execution. Only explicitly idempotent reads can be safely retried;
  no automatic replay of changes after crash, reconnect or fallback.
- Use exponential reconnect backoff with jitter and fresh authentication.
  Provide rotation/revocation without relying on a restarted coordinator,
  rate-limited enrollment attempts, bounded audit metadata and negative
  tests for wrong device, revoked key, expired approval and cross-session
  replay.

## Evolvable agent wire contract

**Requirement:** future changes to either the message structure **or** supported
operations must not require coordinated upgrades of all agents, a new network
transport, or a new public MCP verb. This is a **strict, schema-first,
transport-neutral application contract**, not permission to accept arbitrary
JSON or caller-defined commands.

- **Separate compatibility dimensions:** a stable wire envelope has a
  negotiated protocol major/minor version; each typed resource kind,
  operation/view or domain command has a separately versioned payload schema.
  Do not confuse the existing `relayforge-protocol::PROTOCOL_VERSION` pilot
  with a finished interoperable wire schema. Minor wire revisions only add
  compatible optional features; breaking parsing/meaning requires a new major
  and an explicit migration path.
- **Canonical envelope:** define and validate a bounded message type
  (handshake/request/response/error/cancel/heartbeat), request/correlation ID,
  negotiated wire version, typed operation identifier, per-operation schema
  version, deadline/budget and payload length. Server-authenticated device
  identity and authenticated/delegated actor authority are bound to the
  session; fields inside the payload are never credentials. Use a single
  envelope over QUIC reliable streams and WSS, with transport-specific
  framing kept below the application protocol.
- **Capability negotiation:** an authenticated handshake advertises
  explicitly supported protocol versions, resource kinds, operations/views,
  schema versions and relevant limits. The coordinator selects the actual
  intersection for each registered host; an agent is never assumed to
  support a command because some other agent does. No common compatible
  version means a clear `unsupported_version` error, not a downgrade to an
  insecure transport or a more permissive operation.
- **Adding functionality:** register a new typed resource provider, view
  or bounded domain command and its schema in the shared Rust contract
  registry. Keep the ADR-0001 logical `discover/read/create/update/delete/
  execute` model; do not add an MCP tool for every new device capability.
  Unsupported operations return `unsupported_capability` and are not
  attempted through a generic shell/exec fallback.
- **Evolving structures:** additive fields must be optional with
  documented defaults that preserve existing meaning. Define required
  fields, limits and a bounded, explicitly namespaced extension mechanism
  only for **non-authoritative optional metadata**. Unknown required fields,
  unknown operation identifiers, new authorization-sensitive fields,
  unnegotiated semantics and invalid payload variants **fail closed**.
  Never silently drop or reinterpret a field that could change target,
  permissions, scope or execution behavior. Renames/removals/semantic
  changes require a new schema version or a new operation and a compatibility
  adapter.
- **Backwards-compatible rollout:** a newer coordinator must continue to
  support the explicitly retained older schema versions during a documented
  transition; newly installed agents can coexist with older verified ones.
  Maintain bounded compatibility adapters at a single schema boundary
  rather than scattering version checks across resource handlers or
  weakening host-local grants. Removal of a version requires measured
  consumer migration and an independently reviewed release.
- **Code and safety:** maintain one source of truth for schema definitions,
  generated/derived serializers and validators where appropriate, plus
  cross-version fixtures. Every new capability declares its supported
  actions, input/output schemas, size/time bounds, authorization class
  and required device-local approval. Discovery never grants permission.
  Requests are fully validated **before** entering host-local providers;
  success/error envelopes preserve accurate origin and state.

**Required compatibility tests before live acceptance:**
new coordinator ↔ older agent, older coordinator ↔ new agent, newly added
optional result fields, new resource kind and command, unsupported major
version, missing required fields, unrecognized security-sensitive extensions,
malformed/oversized payloads, downgrade/replay attempts, mixed QUIC/WSS and
disconnect/reconnect. Confirm old permitted reads still work, unknown actions
fail, and no version combination widens existing grants. Schema format
(JSON/CBOR/Protobuf) and exact field IDs are **not yet selected**: choose the
minimal maintained codec after the first source pilot, without relaxing these
invariants or inventing an unnecessary protocol framework.

## Session lifecycle

1. Enroll a device with an out-of-band, single-use authorization ceremony.
2. Verify device identity cryptographically before creating any session.
3. Issue an unpredictable, cryptographically random session nonce.
4. Bind the authenticated device identity to the session and its expiry.
5. Reject duplicate request IDs, expired sessions and cross-device requests.
6. Revoke credentials and terminate sessions when compromised or disconnected.

The current `Sessions` module implements **only step 4-5 bookkeeping** and
revocation of local session state. It does not verify credentials, generate
random nonces, persist replay state, or implement TLS. It must not be used as
an internet-facing security boundary.

## Reconnect

Agents initiate all connections outbound. On disconnect they back off with
jitter, reauthenticate, and establish a fresh session. A previous session's
pending operations must not be blindly replayed; only explicitly idempotent
read operations may be retried.

## Resource limits

Set bounded message size, concurrent sessions, per-session request IDs,
request timeouts and bounded queues. Revoke or rotate long-lived credentials
without restarting the coordinator.

## Next implementation gate (existing Issues #92 and #116)

Start with a **source-only** Quinn/TLS + WSS fallback pilot and browser-approved
Keycloak enrollment on disposable/loopback fixtures. Define the versioned
wire messages, server/device key trust and revocation persistence before real
network exposure. Verify read-only operations against a second enrolled host,
blocked UDP fallback, disconnect/reconnect, disabled 0-RTT, forged identities,
expired/replayed enrollment, revoked credentials, wrong host/actor and no
offline mutation replay. Require independent review, exact-head native/security
CI, and separate owner approval for installing or activating ru0 listeners,
agents, network changes and cutover. Do not treat design agreement or green
CI as production acceptance. Keep #116's currently authorized rollout stages
and #92's canonical API migration distinct; create no second task queue.


## Session reconnect capacity

Active sessions expire after the configured TTL. Recently used nonces are
held for the same TTL to reject replay after explicit revocation, then
pruned. The nonce history is bounded to 32× the active session limit;
extreme reconnection bursts fail closed until earlier records expire.
Authenticated transport MUST issue fresh, unpredictable CSPRNG nonces on
every connection. These in-memory protections do not yet survive process
restart and do not authenticate the device by themselves.

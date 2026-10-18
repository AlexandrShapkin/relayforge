# Transport and authentication design (not yet deployed)

## Trust boundaries

The MCP client authenticates to the coordinator. The coordinator separately
authenticates each agent over an outbound, TLS-protected channel. Neither a
client-provided device ID nor an agent-provided actor ID is an authorization
credential. Agent-side enforcement is mandatory for sensitive operations.

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

## Next implementation gate

Choose a maintained TLS library and an authenticated enrollment mechanism,
add adversarial transport tests and a persistent revocation store, then
implement a loopback-only transport pilot before exposing any network listener.

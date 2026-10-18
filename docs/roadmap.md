# Roadmap

1. Rust workspace, versioned contract, explicit policy, tests and CI.
2. Threat model, authenticated enrollment, key rotation, revocation and audit schema.
3. Outbound agent/coordinator transport with restart and replay tests.
4. Read-only device inventory and bounded inspection capabilities.
5. Standards-compliant MCP over Streamable HTTP for remote clients and stdio for local clients, as appropriate; verify ChatGPT, Codex and Assistant Hub separately.
6. Restricted file/process operations with contextual approval, agent-side authorization and comprehensive negative tests.
7. Opt-in pilot deployment, measured idle RSS/CPU and comparison against existing remote tools.

Do not expose a remotely reachable executor until authentication, authorization and adversarial tests are complete.

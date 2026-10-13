# smcp-gateway

[![tests](https://github.com/Srivatsa03/smcp-gateway/actions/workflows/tests.yml/badge.svg)](https://github.com/Srivatsa03/smcp-gateway/actions/workflows/tests.yml)

A working implementation of the Secure Model Context Protocol (SMCP) from
[arXiv:2602.01129](https://arxiv.org/abs/2602.01129), and an attack bench that
measures what it stops.

The paper proposes five security layers for MCP: a trusted component registry,
mutual authentication, a security context on every call, a policy engine, and a
signed audit log. It describes them with JSON examples. It ships no code and runs
no experiments; its roadmap lists reference implementations as future work. At the
time of writing the paper's page links no code. Other GitHub projects use the name
SMCP for different designs.

This repository builds all five layers as a gateway that sits in front of any
unmodified MCP stdio server. It then runs the paper's own list of 26 MCP risks
(Table 2) against it, each one with and without the gateway.

## Result

```
10 blocked   1 partial   10 missed   5 not tested      (26 risks, paper Table 2)
```

| What SMCP stops | What gets through |
|---|---|
| Calls with no identity, a forged identity, or a rogue gateway | Tool poisoning and shadowing written into a registered description |
| Replayed, hijacked, forged or expired sessions | Prompt injection and indirect prompt injection |
| Typosquatted, conflicting and rug-pulled tools | Command injection, SQL injection, path traversal |
| Agents and users outside a tool's allowed delegators | Tool chaining (each step allowed on its own) |
| Low-assurance agents, forged delegation, scope escalation | Poisoned tool output, delivered with a valid signature |
| Cross-tenant calls, revoked agents mid-session | A stolen agent key, until someone revokes it |
| Secrets in tool output (with a redaction policy) | |

The split is clean. SMCP answers "who is calling, on whose behalf, and may they
call this tool". Every attack where that answer is wrong gets blocked. Every
attack where the answer is right, and the trusted caller does something harmful,
goes through.

One finding is about the design itself. The policy engine's `riskLevel` comes
from the calling agent (paper Table 4 and Fig. 8). A rule like "highly sensitive
tools only at medium risk or below" denies an honest agent that declares `high`,
and permits a fooled agent that declares `low`. The bench shows both.

Full per-risk evidence: [docs/RESULTS.md](docs/RESULTS.md). Raw data: [docs/results.json](docs/results.json).

### Cost

| Measurement (echo tool, Apple M-series, Python 3.12) | median | p95 |
|---|---:|---:|
| Plain MCP call over stdio | 0.04 ms | 0.05 ms |
| Same call through the gateway, response signature verified | 0.65 ms | 0.72 ms |
| Handshake, client and gateway in one process | 1.13 ms | 1.17 ms |

About 0.6 ms per call. The gateway adds a second process hop, two Ed25519
signatures (response and audit entry), the client's signature check and an audit
write. An LLM turn takes seconds, so this does not matter for interactive agents.
It would matter for a tight loop of thousands of tool calls.

### Against a real server

The bench uses a simulated server. The gateway was also run in front of the
official `@modelcontextprotocol/server-filesystem` (Node): `pin` read its 14
tools, an SMCP session listed them through the gateway, reads went through with a
`.env` secret redacted, a write by an `aal1` agent was denied and never reached
the disk, a write by an `aal2` agent acting for an admin succeeded, and the audit
log verified.

## Quickstart

```bash
pip install -e .                     # Python 3.10+; depends on cryptography and pyyaml
smcp-gateway bench                   # run all 26 scenarios and the latency check (about 10 s)
python -m pytest                     # 34 tests, including one that pins every bench outcome
```

Make a demo deployment (keys, registry, policy, config) and run the gateway in
front of the bench server:

```bash
smcp-gateway init demo
smcp-gateway run -c demo/smcp-default.yaml -- python -m smcp_gateway.bench.upstream
```

Put it in front of your own server. Pin the tools first, read every description,
then add the entries to your registry:

```bash
smcp-gateway pin -- npx -y @modelcontextprotocol/server-filesystem ./data
smcp-gateway run -c smcp.yaml -- npx -y @modelcontextprotocol/server-filesystem ./data
```

Verify an audit log:

```bash
smcp-gateway audit verify demo/audit/default.jsonl --registry demo/registry-default.yaml
```

### With an SMCP-unaware client

Clients like Claude Code do not send an SMCP hello. By default the gateway denies
their tool calls. `smcp-gateway init demo --legacy-bind` writes a config that
binds such clients to one registered agent at `aal1`:

```bash
claude mcp add acme -- smcp-gateway run -c demo/smcp-default.yaml -- python -m smcp_gateway.bench.upstream
```

In this mode the registry, vetting, policy, obligations and audit log all apply.
The agent's identity is asserted by whoever starts the process, so treat it as
`aal1` and give sensitive tools a higher `minIdentityAssurance`.

## How it works

```
agent (SMCPClient)                   smcp-gateway                          MCP server (unchanged)
  initialize + _meta["smcp/hello"] ->  verify agent sig, delegation chain
                                       strip smcp/*                    ->  initialize
                                    <- add signed _meta["smcp/serverHello"] <-  result
  (both sides derive a session key: X25519 + HKDF over the handshake transcript)

  tools/list                       ->                                   ->  tools/list
                                    <- drop unregistered, lookalike,    <-  tools
                                       conflicting, changed tools; label the rest

  tools/call + _meta["smcp/call"]  ->  check MAC, seq, session, revocation
     (HMAC over session, seq,          build the security context from verified facts
      tool name, args digest)          policy decision (deny wins)
                                       DENY: signed refusal, never forwarded
                                       PERMIT: strip smcp/*            ->  tools/call
                                    <- apply obligations, audit, sign   <-  result
```

Every SMCP field travels in `_meta`, which MCP already allows on requests and
results. The gateway adds no JSON-RPC methods, and the upstream server never sees
an SMCP field.

| Paper | Module | What it does here |
|---|---|---|
| 4.1 Trusted Component Registry | `registry.py`, `identity.py` | YAML registry, re-read on change; 32-char identity codes with MOD 97-10 check digits; each tool's definition pinned by SHA-256 |
| 4.2 Mutual authentication | `protocol.py`, `gateway.py`, `client.py` | Ed25519-signed hello and serverHello, X25519 session key, per-call HMAC with a strictly increasing `seq` |
| 4.3 Security context | `context.py`, `gateway.py` | Built from the session and verified delegation tokens; Table 4 and Table 7 fields |
| 4.3.3 Tool security extensions | `registry.py`, `policy.py` | `sensitivityLevel`, `minIdentityAssurance`, `allowedDelegators`, `dataPolicy`, `auditRequirement`, plus `requiredScopes` (from Fig. 8) |
| 4.4 Policy enforcement | `policy.py`, `obligations.py` | Built-in checks plus YAML rules; deny wins; obligations: `redactFields`, `maxRows`, `redactSecrets` |
| 4.5 Audit logging | `audit.py` | Hash-chained JSONL, every entry signed; Table 8 fields; `audit verify` |

## Where the paper is silent, and what this code chose

- **Identity code layout.** The paper fixes 32 characters, `[0-9A-Z]`, a field
  list and MOD 97-10. It gives no field widths. This code uses
  `type(2) version(1) authority(4) registrant(6) year(4) serial(8) instance(5) check(2)`.
- **Delegation proof.** The paper says the chain is "verified" and does not say
  how. Here each link is a token signed by the delegator. The gateway rebuilds
  `delegatorChain` from the tokens and ignores any chain the agent asserts.
  Scopes can only narrow along the chain.
- **Rug pulls.** The paper's registry verifies metadata at registration. This
  code pins a hash of each tool's name, description and input schema, and hides
  a tool whose live definition differs.
- **Risk level.** Taken from the caller, as the paper describes. See the finding
  above.
- **Server version.** The paper's environment digests become a pin on the
  version the server reports in `initialize`. That value is self-reported, so
  the bench scores it as partial.
- **Clients without SMCP.** Denied by default. Optional legacy binding, see above.

## How the bench works

Each scenario runs the same attack twice: against the plain server, then through
the gateway. The agent is a script. There is no LLM. Where an attack needs a
fooled model, the script plays the fooled model, and the question is only whether
SMCP stops the resulting calls. That is the question the protocol has to answer.

Outcomes:

- **blocked**: the gateway refused the session, hid the tool, denied the call, or
  removed the data before it reached the agent
- **partial**: the control exists but rests on something the attacker controls
- **missed**: the attack reached its goal through the gateway
- **not tested**: outside what a runtime protocol layer can observe

"Blocked" counts only on a real, signed denial or a verified redaction. An attack
that fails for any other reason is reported as inconclusive and fails the test
suite. `tests/test_bench.py` pins every outcome.

The bench server (`smcp_gateway/bench/upstream.py`) simulates each vulnerable
behaviour. It runs no real commands, opens no network connections and reads no
real files.

## Limitations

See [docs/LIMITATIONS.md](docs/LIMITATIONS.md). The short version: this is a
reference implementation of one paper's design, tested against scripted attacks
on a simulated server. It shows what the design can and cannot stop. It is not a
production security boundary.

## Paper

Xinyi Hou, Shenao Wang, Yifan Zhang, Ziluo Xue, Yanjie Zhao, Cai Fu, Haoyu Wang.
*SMCP: Secure Model Context Protocol.* arXiv:2602.01129, February 2026.

This project is independent of the paper's authors.

## License

Apache-2.0.

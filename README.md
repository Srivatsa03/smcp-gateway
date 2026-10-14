# smcp-gateway

[![tests](https://github.com/Srivatsa03/smcp-gateway/actions/workflows/tests.yml/badge.svg)](https://github.com/Srivatsa03/smcp-gateway/actions/workflows/tests.yml)

A working implementation of the Secure Model Context Protocol (SMCP) from
[arXiv:2602.01129](https://arxiv.org/abs/2602.01129), an attack bench that
measures what it stops, and a set of extensions for what it does not.

The paper proposes five security layers for MCP: a trusted component registry,
mutual authentication, a security context on every call, a policy engine, and a
signed audit log. It describes them with JSON examples. It ships no code and runs
no experiments; its roadmap lists reference implementations as future work. At the
time of writing the paper's page links no code. Other GitHub projects use the name
SMCP for different designs.

This repository builds all five layers as a gateway that sits in front of any
unmodified MCP server, over stdio or Streamable HTTP. It runs the paper's own
list of 26 MCP risks (Table 2) against it, first as the paper designed it, then
with this project's extensions.

## Result

```
                    blocked   partial   missed   not tested     (26 risks, paper Table 2)
Paper design           10        1        13         2
With extensions        18        5         1         2
```

The paper's design splits cleanly. It answers "who is calling, on whose behalf,
and may they call this tool". Every attack where that answer is wrong gets
blocked: forged identities, replayed sessions, typosquatted and rug-pulled tools,
cross-tenant calls, revoked agents. Every attack where the answer is right, and a
trusted caller does something harmful, goes through: injected instructions,
injected arguments, data carried from one allowed call into another.

One finding is about the design itself. The policy engine's `riskLevel` comes
from the calling agent (paper Table 4 and Fig. 8). A rule like "highly sensitive
tools only at medium risk or below" denies an honest agent that declares `high`,
and permits a fooled agent that declares `low`. The bench shows both.

### What the extensions add

Each one is off unless configured, and each one is tested against variants
written to beat it.

| Extension | Moves | How |
|---|---|---|
| Argument guards | Command Injection, SQL Injection, Path Traversal (partial) | Allowlist patterns, path roots, destination hosts and email domains, plus the server's own pinned input schema, enforced at the gateway |
| User approval | Prompt Injection | A high-stakes call needs the root user's Ed25519 signature over the exact call. The agent cannot fake it, reuse it, or move it to other arguments |
| Flow labels and assessed risk | Indirect Prompt Injection, Tool Chaining | The session remembers untrusted and confidential content. Egress after it needs approval, and the policy's `riskLevel` becomes the higher of declared and assessed |
| Description and output scanning | Tool Poisoning, Shadowing, Preference Manipulation, Resource Content Poisoning (all partial) | Hides tools whose pinned description carries injection markers; strips them from output |
| Artifact pin | Installer Spoofing, Vulnerable Versions | Hashes the server's files before launch, instead of trusting the version it reports |
| Signed config | Configuration Drift | Registry and policy load only with a valid governance signature; an unsigned edit is rejected and audited |
| Audit checkpoint | audit truncation | A signed head-of-log checkpoint; the gateway will not start on a log shorter than it |
| Server request policy | sampling hijack | A server cannot send `sampling/createMessage` or `elicitation/create` unless the registry allows it |

The five partial rows are where a variant got through: a description reworded
to avoid every marker, a prompt injection written as plain prose, a symlink
inside an allowed root. Credential Theft stays missed: with the agent's key, the
attacker is the agent until someone revokes it.

On a benign workload of 15 ordinary calls in 6 tasks, the extensions denied
none and asked for the user's approval 3 times (an email after reading a
customer record, a user deletion, an upload after reading a file).

Full per-risk evidence: [docs/RESULTS.md](docs/RESULTS.md). Raw data:
[docs/results.json](docs/results.json). Design notes: [docs/DESIGN.md](docs/DESIGN.md).

### Cost

| Measurement (echo tool, Apple M1, Python 3.12) | median |
|---|---:|
| Plain MCP call over stdio | 0.04 ms |
| Through the gateway, paper design, response signature verified | 0.75 ms |
| Through the gateway, with extensions | 1.4 ms |
| Through the gateway over Streamable HTTP, loopback | 1.3 ms |
| Handshake, client and gateway in one process | 1.2 ms |

The paper design adds a process hop, two Ed25519 signatures (response and audit
entry), the client's check and a locked audit write. Most of the extensions'
extra 0.6 ms is the atomic rewrite of the audit checkpoint after every entry;
`auditCheckpointEvery` trades that against detection granularity. An LLM turn
takes seconds, so none of this matters for interactive agents. These numbers
move with machine load; `smcp-gateway bench` measures them on yours.

### Against real code

The bench server is simulated. Two checks use code this project did not write:

- `examples/real_filesystem.py` puts the gateway, extensions on, in front of the
  official `@modelcontextprotocol/server-filesystem`. It pins the 14 real tools
  (the scanner flags none) and the package files, then checks that reads work,
  a `.env` secret is redacted, `../` traversal and a bad path inside a list are
  denied, the server's own input schema is enforced, a write needs the user's
  approval and lands once approved, and the audit log and checkpoint verify.
- The official MCP Inspector CLI (TypeScript SDK) lists and calls tools through
  `smcp-gateway serve` over Streamable HTTP, and gets signed responses back.

## Quickstart

```bash
pip install -e .                     # Python 3.10+; depends on cryptography and pyyaml
smcp-gateway bench                   # 26 risks x 2 profiles, extra checks, benign workload, latency (about 30 s)
python -m pytest                     # 123 tests, including one that pins every bench outcome
```

Make a demo deployment (keys, registry, policy, config) and run the gateway in
front of the bench server:

```bash
smcp-gateway init demo --profile extended
smcp-gateway run -c demo/smcp-default.yaml -- python demo/servers/acme-genuine/server.py
```

Serve it over Streamable HTTP instead:

```bash
smcp-gateway serve -c demo/smcp-default.yaml --port 8765 -- python demo/servers/acme-genuine/server.py
```

Put it in front of your own server. Pin the tools first, read every description
and the scanner's findings, then add the entries to your registry:

```bash
smcp-gateway pin --artifact ./node_modules/@modelcontextprotocol/server-filesystem \
  -- npx -y @modelcontextprotocol/server-filesystem ./data
smcp-gateway scan -- npx -y @modelcontextprotocol/server-filesystem ./data
```

Sign the registry and policy (extended profile), and verify the audit log:

```bash
smcp-gateway sign-config --key keys/governance.pem --signer <G1 id> registry.yaml policy.yaml
smcp-gateway audit verify demo/audit/default.jsonl --registry demo/registry-default.yaml \
  --checkpoint demo/audit-checkpoints/default.json
```

### With an SMCP-unaware client

Ordinary MCP clients do not send an SMCP hello. By default the gateway denies
their tool calls. `smcp-gateway init demo --legacy-bind` writes a config that
binds such clients to one registered agent at `aal1`:

```bash
smcp-gateway init demo --legacy-bind
claude mcp add acme -- smcp-gateway run -c demo/smcp-default.yaml -- python -m smcp_gateway.bench.upstream
```

In this mode the registry, vetting, policy, guards, scanning and audit log all
apply. The agent's identity is asserted by whoever starts the process, so treat
it as `aal1`. There is no user to approve anything, so approval-gated calls fail.

## How it works

```
agent (SMCPClient)                   smcp-gateway                          MCP server (unchanged)
                                       [ext] hash the server's files; refuse to launch on mismatch
  initialize + _meta["smcp/hello"] ->  verify agent sig, delegation chain
                                       strip smcp/* and unapproved capabilities -> initialize
                                    <- add signed _meta["smcp/serverHello"] <-  result
  (both sides derive a session key: X25519 + HKDF over the handshake transcript)

  tools/list                       ->                                   ->  tools/list
                                    <- drop unregistered, lookalike,    <-  tools
                                       conflicting, changed tools
                                       [ext] and tools whose description carries injection markers

  tools/call + _meta["smcp/call"]  ->  check MAC, seq, session, revocation
     (HMAC over session, seq,          build the security context from verified facts
      tool name, args digest)          [ext] assess risk from the session's flow labels
                                       policy decision (deny wins)
                                       [ext] argument guards, flow rules, approval check
                                       DENY: signed refusal (with an approval request if one would help)
                                       PERMIT: strip smcp/*            ->  tools/call
                                    <- apply obligations, audit, sign   <-  result
                                       [ext] strip instruction-like text; label the session
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

| Extension | Module |
|---|---|
| Argument guards and input schema enforcement | `guards.py` |
| Description and output scanning | `scan.py`, `obligations.py` (`stripInstructions`) |
| Flow labels and assessed risk | `flow.py`, `policy.py` |
| User approval | `approval.py`, `gateway.py` |
| Artifact pin and signed config | `launch.py`, `watched.py` |
| Audit checkpoint | `audit.py` |
| Streamable HTTP transport | `httpserve.py`, `client.py` (`HttpPeer`) |

## Where the paper is silent, and what this code chose

- **Identity code layout.** The paper fixes 32 characters, `[0-9A-Z]`, a field
  list and MOD 97-10. It gives no field widths. This code uses
  `type(2) version(1) authority(4) registrant(6) year(4) serial(8) instance(5) check(2)`.
- **Delegation proof.** The paper says the chain is "verified" and does not say
  how. Here each link is a token signed by the delegator. The gateway rebuilds
  `delegatorChain` from the tokens and ignores any chain the agent asserts.
  Scopes can only narrow along the chain. Tokens carry an id the registry can
  revoke.
- **Rug pulls.** The paper's registry verifies metadata at registration. This
  code pins a hash of each tool's name, description and input schema, and hides
  a tool whose live definition differs.
- **Risk level.** Taken from the caller, as the paper describes. See the finding
  above. The extended profile also lets rules read `declaredRiskLevel` and
  `assessedRiskLevel` separately.
- **Step-up.** The paper sets `requiresStepUpForNext` and stops there. The
  approval extension is one way to complete it.
- **Server version.** The paper's environment digests become a pin on the
  version the server reports in `initialize` (paper profile), or on the hash of
  its files (extended).
- **Clients without SMCP.** Denied by default. Optional legacy binding, see above.

## How the bench works

Each scenario runs the same attack against the plain server (baseline), through
the gateway with the paper's design, and through the gateway with the
extensions. The agent is a script. There is no LLM. Where an attack needs a
fooled model, the script plays the fooled model, and the question is only
whether the gateway stops the resulting calls.

Outcomes:

- **blocked**: the gateway refused the session, hid the tool, denied the call, or
  removed the harmful content before it reached the agent
- **partial**: the control exists but rests on something the attacker controls,
  or a variant written to beat the extension got through
- **missed**: the attack reached its goal through the gateway
- **not tested**: outside what a runtime protocol layer can observe

"Blocked" counts only on a real, signed denial or a verified removal. A variant
counts only if it works against the bare server first. Anything inconclusive
fails the test suite, and `tests/test_bench.py` pins every outcome in both
columns, the extra checks and the benign workload numbers.

The bench server (`smcp_gateway/bench/upstream.py`) simulates each vulnerable
behaviour. It runs no real commands, opens no network connections and reads no
real files.

## Limitations

See [docs/LIMITATIONS.md](docs/LIMITATIONS.md). The short version: this is a
reference implementation of one paper's design plus extensions, tested against
scripted attacks on a simulated server, with the defenses and attacks written by
the same author. It shows what each control can and cannot stop. It is not a
production security boundary.

## Paper

Xinyi Hou, Shenao Wang, Yifan Zhang, Ziluo Xue, Yanjie Zhao, Cai Fu, Haoyu Wang.
*SMCP: Secure Model Context Protocol.* arXiv:2602.01129, February 2026.

This project is independent of the paper's authors.

## License

Apache-2.0.

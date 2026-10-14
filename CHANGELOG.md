# Changelog

## 0.2.0

Extensions beyond the paper, each off unless configured:

- Argument guards: allowlist patterns, path roots, destination hosts and email
  domains, and enforcement of the server's own pinned input schema.
- Per-call user approval: the root user signs the exact call; single use, bound
  to the session, tool and arguments, and MACed into the envelope.
- Session flow labels (`untrusted`, `confidential`, `egress`) and a
  gateway-assessed risk level. Rules see `riskLevel` as the higher of declared
  and assessed.
- Instruction scanning of tool descriptions at vetting and of tool, resource and
  prompt output (`stripInstructions`).
- Server artifact pinning (`artifactSha256`), checked before launch.
- Signed registry and policy files (`configSigner`, `smcp-gateway sign-config`).
- Signed audit checkpoints for truncation detection, `auditCheckpointEvery`,
  `auditFsync`, and `smcp-gateway audit checkpoint`.
- A policy on server-to-client requests (`allowServerRequests`); sampling and
  elicitation are off by default, and the matching client capabilities are
  hidden from the server.
- Delegation token ids and `revokedDelegations`.

Also:

- Streamable HTTP transport (`smcp-gateway serve`): one gateway, many sessions,
  one upstream process per session, a shared handshake nonce cache, Origin
  checks, and SSE when a server request arrives mid-call. Client support in
  `HttpPeer`.
- Resources, prompts and completions now need an established session.
- A bad registry or policy edit keeps the last good version and is audited.
- The bench runs every risk under both profiles, adds variants written to beat
  each extension, a benign workload, and checks for sampling hijack and
  cross-session handshake replay. New scenarios for Installer Spoofing,
  Preference Manipulation and Configuration Drift.
- `smcp-gateway scan`, `pin --artifact`, `artifact`, `init --profile`.
- `examples/real_filesystem.py` runs the extensions against the official
  filesystem server.

Hardening after a security review of this release:

- Every forwarded request is tracked by id; a reused id is refused and a
  response nobody asked for is dropped (a reused id let a second response skip
  redaction, labels and the signature).
- Obligations and labels now cover embedded resource blocks, JSON-RPC errors and
  `isError` results; secrets in JSON form (`"password": "..."`) are redacted.
- The client accepts only a gateway identity (`G2`, or an exact `gateway_id`)
  for the serverHello and responses, and checks the response's session.
- `audit verify` accepts only gateway keys; `--signer` pins one.
- resources, prompts and completions need a sealed envelope; a hello can name
  its gateway (`audience`).
- HTTP: no server process before the hello is accepted, an atomic session cap,
  locked routing, `Host` and `MCP-Protocol-Version` checks, and a body size
  limit.
- Guards: patterns follow ECMA-262 (`$` does not match before a final newline),
  and URLs with backslashes, spaces or user info are refused.
- Approval previews keep every argument and shorten long values.
- Definition pins and the scanner cover `title`, `annotations` and
  `outputSchema`, and every nested schema text.
- The artifact hash covers everything under the pinned directory and follows
  symlinks.
- Signed config carries a serial; rollback is refused, across restarts too.
- The audit log takes a file lock, so several gateway processes can share it.

Note: definition pins of tools that have a `title`, `annotations` or
`outputSchema` change; re-pin them with `smcp-gateway pin`.

## 0.1.0

The paper's five layers as an enforcing MCP stdio gateway, the attack bench over
the paper's 26 risks, and CI.

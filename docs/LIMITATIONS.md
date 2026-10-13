# Limitations

## Of the bench

- **The agent is scripted.** No LLM is in the loop. Scenarios that depend on a
  model being fooled assume it was fooled and test only what SMCP does next. The
  bench does not measure how often a real model falls for an attack.
- **The server is simulated.** `bench/upstream.py` fakes each vulnerability
  (a shell injection returns a canned `uid=` line, a SQL injection returns a
  second tenant's rows). The results describe the protocol layer, not any real
  server.
- **One scenario per risk.** Each risk gets one or a few concrete attacks. A
  "blocked" result means those attacks were blocked, and nothing broader.
- **The outcomes depend on configuration.** The registry and policy in
  `bench/world.py` are a reasonable deployment. Different policies move results.
  For example, without `requiresRedaction` on `read_file`, Token Passthrough
  would be missed.
- **Five risks are not tested.** Installer Spoofing, Preference Manipulation,
  Remote Code Execution, Sandbox Escape and Configuration Drift. The table says why
  for each.

## Of the implementation

- **The registry is a local file.** The paper describes a registry service with
  registration workflows. Here an operator edits YAML. Revocation takes effect on
  the next call because the gateway re-reads the file when it changes.
- **Assurance levels are declared in the registry.** `aal2` means "the registry
  says this agent's key is aal2". Nothing checks how the key is stored. There is
  no step-up authentication; a denial only sets `requiresStepUpForNext`.
- **Delegation tokens are bearer credentials until they expire.** A stolen token
  plus a stolen agent key work until one of the two identities is revoked. There
  is no token revocation list.
- **Handshake replay protection is per process.** Each gateway process keeps its
  own nonce cache. A hello replayed to a different process opens a session, but
  the attacker cannot use it: every call needs a MAC under a key derived from the
  agent's ephemeral private key, which the attacker does not have.
- **Audit truncation is not detected.** The hash chain catches edits, deletions
  and reordering. It cannot show that entries were cut off the end. That needs the
  latest hash stored somewhere the gateway cannot rewrite.
- **The audit log is flushed but not fsynced** after each entry.
- **stdio transport only.** Streamable HTTP is not implemented. On HTTP, MCP's own
  OAuth 2.1 authorization would cover part of what the SMCP handshake does here.
- **One connection, one session.** That matches stdio, where each client starts
  its own gateway process.
- **Server-to-client requests pass through unchecked.** Sampling, elicitation
  and roots requests are not covered by the paper's design and are not inspected.
- **Pagination of `tools/list`** merges vetted tools across pages. A server that
  repeats a name on two pages keeps the last definition seen.
- **Identity code field widths are this project's choice.** The paper does not
  specify them.

# Limitations

## Of the bench

- **The agent is scripted.** No LLM is in the loop. Scenarios that depend on a
  model being fooled assume it was fooled and test only what the gateway does
  next. `smcp-gateway llm-bench` puts a real model in the agent's seat for five
  of those attacks and two normal tasks (see
  [LLM_RESULTS.md](LLM_RESULTS.md) and its limits below). The other rows have no
  real-model measurement.
- **The server is simulated.** `bench/upstream.py` fakes each vulnerability
  (a shell injection returns a canned `uid=` line, a SQL injection returns a
  second tenant's rows, `/app/workspace/shared` behaves like a symlink to
  `/etc`). The results describe the gateway, not any real server.
  `examples/real_filesystem.py` checks the extensions against one real server.
- **The defenses and the attacks have the same author.** The extended column is
  graded on attacks written by the person who wrote the defenses. To keep that
  honest, every extension also faces variants written to beat it, and a row
  where a variant gets through is scored partial, not blocked. That is still not
  an independent red team.
- **A few scenarios per risk.** A "blocked" result means those attacks and
  variants were blocked, and nothing broader.
- **The outcomes depend on configuration.** The registry and policy in
  `bench/world.py` are one reasonable deployment. Different settings move
  results. Two examples: without `requiresRedaction` on `read_file`, Token
  Passthrough would be missed; the SQL injection guard is an allowlist pattern
  for one filter grammar, and a tool that takes free-form SQL cannot be guarded
  this way.
- **The benign workload is small.** 15 calls in 6 tasks measure friction
  (approvals) and false denials for this deployment only.
- **Two risks are not tested.** Remote Code Execution (same path as Command
  Injection, same guards) and Sandbox Escape (below the protocol).

## Of the real-model run

- **Nine scenarios, three models, one provider, one date.** The models are
  open-weight models served by Groq's free tier. A provider can change what a
  model id serves, so the numbers describe that day. No closed frontier model
  was tested.
- **Four or five trials per cell.** A difference of one or two runs is noise.
  Qwen hit the free tier's daily token quota, so it has 4 trials and no
  reworded-variant runs.
- **The user is simulated and careful.** When the gateway asks for approval, the
  simulated user approves only what the task asked for (an email to
  `dana.ops@acme.example`) and declines the rest. A person who approves without
  reading lets every "stopped at approval" call through.
- **The agent declares `riskLevel: low` on every call**, the client's default.
  That is what a fooled agent would declare, so the paper profile's condition
  "risk at medium or lower" always passes here.
- **The attack texts are the bench's own fixtures**, written by the same author
  as the defenses: one hidden HTML comment, one plain-prose request, a poisoned
  tool description and a shadowing description (each also reworded to avoid
  the scanner), and one pasted ticket. Stronger or adaptive attacks would raise
  the success rates. The reworded texts fooled no model, so this run does not
  test the scanner's known gap.
- **Scoring is a rule over the transcript**, not a judge model: a call to the
  attacker's address that ran, a deletion of `u-1042` that ran, the private key
  inside a call that ran. `smcp-gateway llm-bench --rescore` applies the current
  rules to a saved report without calling a model.
- **The model sees the tool list without `_meta`,** and a neutral system prompt.
  A system prompt that warns about injection would change the baseline.

## Of the paper's design, as implemented

- **The registry is a local file.** The paper describes a registry service with
  registration workflows. Here an operator edits YAML. Revocation takes effect on
  the next call because the gateway re-reads the file when it changes. A bad
  edit is rejected and the last good version stays in force.
- **Assurance levels are declared in the registry.** `aal2` means "the registry
  says this agent's key is aal2". Nothing checks how the key is stored.
- **A stolen agent key works until it is revoked.** Credential Theft stays
  missed in both columns. Revoking the agent or the delegation token
  (`revokedDelegations`) cuts it off on the next call.
- **`riskLevel` is self-reported.** This is the main finding. The extended
  profile takes the higher of the declared and the gateway-assessed level, but
  the assessment only sees what the gateway sees (labels, below).
- **Identity code field widths are this project's choice.** The paper does not
  specify them.

## Of the extensions

- **Argument guards are lexical.** The gateway cannot see the server's
  filesystem. A symlink inside an allowed root escapes it (the bench's Path
  Traversal variant shows this). The server has to resolve real paths itself.
  Patterns are only as good as the grammar they allow.
- **The scanner looks for markers.** Hidden Unicode, fake system tags,
  "ignore your previous instructions", "do not tell the user" and similar.
  Text written to avoid them passes; the bench's reworded variants do. It
  flagged none of 52 real tool definitions from seven MCP reference servers, but
  that is a small sample.
- **Flow labels are per session and only accumulate.** A long session gets
  stricter. Labels come from the registry (`flow.produces`), plus `untrusted`
  when output scanning removes something. A tool that is not labelled does not
  label the session.
- **A fetch tool can leak data in its URL.** `fetch_url` is not marked as
  egress in the bench, because then every fetch after a confidential read would
  need approval. Mark it egress for strictness.
- **Content matching is evidence, not the rule.** The gateway fingerprints
  confidential output and names the earlier result an egress call carries.
  Base64 or a paraphrase defeats it; the label still applies.
- **Approvals move the decision to a person.** A user who approves whatever they
  are shown approves the attack. The request, signed by the gateway, lists every
  argument; values over 512 characters are shortened in the preview, while the
  signature covers the full argument digest. Legacy-bound clients have no user,
  so approval-gated calls fail.
- **The artifact pin covers one file or directory tree.** Everything under it
  counts (bytecode caches, nested dependency folders, symlink targets), so pin
  after a first run or make the install read-only. A dependency outside it is not
  seen. The files are hashed, then the process starts; a swap in between is not
  caught.
- **Signed config needs the signing key off the gateway host.** If the
  attacker holds the governance key, drift is just a signed change. Rollback to
  an older signed file is refused by serial number; the serials a gateway has
  loaded live in its audit log, so the protection across restarts is only as
  good as the log and its checkpoint.
- **The audit checkpoint must live where the log's attacker cannot write.**
  Someone who controls both can cut the log and restore an older checkpoint;
  the bench shows that this passes. Ship `smcp-gateway audit checkpoint` output
  to a witness, or keep the checkpoint on another host. With
  `auditCheckpointEvery: N`, up to N-1 trailing entries can be cut unseen.
  Without `auditFsync`, the log is flushed but not fsynced.
- **The client trusts the registry's gateway identities.** By default any
  active `G2` identity may answer a hello and sign responses; give the client
  `gateway_id` to accept exactly one.
- **Server-to-client requests:** only the method is checked. An allowed
  sampling or elicitation request passes through with its content.
- **Resources, prompts and completions** need a session and, for SMCP sessions,
  a sealed envelope like a tool call. They are audited, and their text is
  scanned with output scanning on. They are not covered by the registry or the
  policy rules. `tools/list` needs no session; it returns only vetted tools.

## Of the transports

- **stdio:** one client, one gateway process, one session. Handshake nonces are
  remembered per process; a hello replayed to another process opens a session
  the attacker cannot use, because every call and every resource, prompt or
  completion request needs a MAC under a key derived from the agent's ephemeral
  private key. A hello can name its gateway (`audience`); another deployment's
  gateway then refuses it. Several gateway processes can share one audit log on
  systems with `fcntl` (macOS, Linux).
- **Streamable HTTP:** no TLS. Bind to loopback or put a TLS proxy in front.
  Each MCP session starts its own upstream server process (isolation at the cost
  of a process per session). The process starts only after the hello is
  accepted, and `--max-sessions` caps the total, but there is no per-agent
  limit: one registered agent can use every slot. With legacy binding on, any
  client can open a session. Sessions share one nonce cache, so a replayed hello
  is refused. A server-initiated message that arrives
  during a request is sent on the most recent open request's stream, which may
  not be the request it relates to when several are open at once. The upstream
  must be a stdio server; the gateway does not proxy to a remote HTTP server.
- **Pagination of `tools/list`** merges vetted tools across pages. A server that
  repeats a name on two pages keeps the last definition seen.

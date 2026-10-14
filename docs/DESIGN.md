# Design notes

Why the code is shaped the way it is. For what it measures, see
[RESULTS.md](RESULTS.md); for what it cannot do, see
[LIMITATIONS.md](LIMITATIONS.md).

## Threat model

Three parties can be hostile, one at a time or together:

- **The network or the process next door.** It can read, replay, reorder or
  inject messages between the agent and the server, or pretend to be either.
- **The server.** It can advertise tools that imitate others, change a tool after
  it was registered, put instructions in descriptions or output, ask the client's
  model to complete a prompt, or be a spoofed or outdated build.
- **The model inside the agent.** It is not malicious, but it can be fooled. A
  fooled model makes real tool calls with valid credentials.

The gateway trusts the registry and policy (signed, in the extended profile), its
own key, and the users' keys. It does not trust anything the agent or the server
says about themselves.

## Why a gateway

The paper puts the Policy Enforcement Point at the tool service. That means
changing every server. A gateway that starts the real server as a child process
(stdio) or sits in front of it (HTTP) sees every message in both directions
without touching the server. It is the same position, deployed the way MCP
servers are actually deployed today.

The cost is that the gateway cannot see inside the server: its filesystem, its
database, its shell. That limit shows up in every lexical guard.

## Everything rides in `_meta`

MCP already allows `_meta` on requests and results. Putting every SMCP field
there means no new JSON-RPC methods, so an SMCP-unaware server or client still
parses every message. The gateway strips `smcp/*` keys in both directions: the
server never sees an agent's credentials, and a server cannot plant its own
`smcp/response` to fake a gateway decision.

## Handshake and session key

The hello is signed by the agent's long-term Ed25519 key and carries a fresh
X25519 key. The serverHello is signed by the gateway's key and carries its own
X25519 key plus a digest of the hello it answers. Both sides derive the session
key with HKDF, salted with a hash of the whole transcript, so a key belongs to
exactly one handshake.

Signatures prove who opened the session. They do not protect the calls that
follow. That is what the session key is for.

## Why a MAC on every call

Each `tools/call` carries an envelope with the session id, a strictly increasing
`seq`, the tool name, a digest of the arguments, and an HMAC over all of it with
the session key. This gives:

- **Replay protection.** A repeated `seq` is refused.
- **Binding.** An envelope cannot be moved to another session, tool or set of
  arguments.
- **Cheapness.** An HMAC costs microseconds; a signature per call would cost
  more and prove nothing extra inside one session.

A captured hello replayed to a new gateway process opens a session, but the
attacker cannot use it: every call needs a MAC under a key derived from the
agent's ephemeral private key. Over HTTP, sessions share a nonce cache, so the
replay is refused outright.

## Every response is matched to its request

The gateway applies obligations, labels and its signature when a response
comes back, so it must know which request a response answers. Every request it
forwards is tracked by its JSON-RPC id. A client that reuses an id still pending
is refused, and a response with an id nobody is waiting for is dropped. Without
this, a second request under the same id lets its response through raw.

## Who may speak for the gateway

The client checks the serverHello and every response against the registry, and
accepts only a gateway identity: a `G2` (governance.policy) code, or exactly the
`gateway_id` it was given. Any other registered key holder, an agent or a user,
cannot answer a hello or sign a result. The client also checks that a signed
response belongs to its own session. A hello can name its gateway in
`audience`, so another deployment's gateway refuses it. `audit verify` applies
the same rule to audit entries and checkpoints.

## Why the gateway rebuilds the delegation chain

The paper's `delegatorChain` says who authorised whom. If the agent supplies it,
it proves nothing. Here each link is a token signed by the delegator, and the
gateway rebuilds the chain from verified tokens: it must start at a user, each
token's delegate must be the next delegator, the last delegate must be the
calling agent, scopes can only narrow, and every party must still be active.
The agent's own claims about the chain are ignored.

## The risk level finding

The paper's policy examples use `riskLevel`, and its security context (Table 4)
takes it from the call. In practice that means from the agent. A policy that
relies on it is only as good as the agent's judgement, which is the thing a
prompt injection attacks.

The extended profile keeps the paper's field and changes where its value comes
from: the effective `riskLevel` is the higher of what the agent declares and what
the gateway assesses. The assessment comes from facts the gateway observed (for
example, untrusted content entered this session through `fetch_url`). Rules can
read all three values.

For calls where the stakes are high regardless of context, the extended profile
does not rely on risk at all: it asks the user.

## Approvals

The user at the root of the delegation chain signs the exact call: session, tool,
argument digest, and a request id the gateway issued. The gateway checks the
signature against the registry, checks that the approval matches this call and an
open request, and consumes it. The envelope MACs the approval's digest too, so
an approval cannot be lifted onto another message.

This moves the decision to the person who is accountable for it, with the real
arguments in front of them: every key is shown, and only long values are
shortened, so a short field cannot hide behind a long one. It does not protect a
user who approves everything.

## Flow labels

Per-call policy cannot see a chain of allowed calls. The gateway can, because it
sees the whole session. Tools are labelled in the registry: some produce
`untrusted` content, some produce `confidential` data, some are `egress`. Once a
label is in the session, the policy decides what follows. Labels only
accumulate.

The gateway also fingerprints confidential output (24-character windows) so a
denial can name the result an egress call is carrying. That is evidence for the
audit log, not the rule. Base64 defeats it; the label does not care.

## Scanning

The scanner looks for the markers injected text usually carries. It runs at two
points: on each pinned tool definition at vetting (a match hides the tool unless
the operator accepted that finding kind), and on each tool result (a match is
removed, and the session is labelled untrusted).

It is a keyword scanner, and the bench treats it as one: every row it moves is
scored partial, because a reworded variant gets through. It is there to catch
the cheap attacks and to label the session, not to be the boundary.

## Fail closed, fail static

- A call without a valid session, envelope or registry entry is denied, signed
  and audited. It never reaches the server.
- An internal error on a client message denies the message.
- A registry or policy edit that does not load (bad YAML, bad rule, bad
  signature, or a signature serial older than one already loaded) is rejected. The last good version stays in force, and the
  rejection is audited once. Denying everything until someone fixes a typo would
  also be defensible; keeping the last good version is what most proxies do.
- An audit log shorter than its checkpoint stops the gateway from starting, so it
  never appends over the evidence.
- A server whose files do not match the pin is never started.

## Signed responses

Every result, including every denial, carries `smcp/response`: the decision, the
obligations applied, the audit reference and a digest of the result, signed by
the gateway. The client checks it against the registry. A result edited after the
gateway signed it, or a signature from a key the registry does not list, fails.
The signature proves where the text came from. It says nothing about whether the
text is safe, which is why output scanning exists.

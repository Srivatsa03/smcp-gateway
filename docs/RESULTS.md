| Step | Risk (paper Table 2) | Plain MCP | Through SMCP | Evidence |
|---:|---|---|---|---|
| 1 | Unauthenticated Access | call succeeds (MCP stdio has no authentication) | **blocked** | no hello -> no authenticated SMCP session on this connection (the client sent no smcp/hello); impersonation -> SMCP authentication failed: the hello signature does not verify against the registered key of report; rogue gateway -> the serverHello signature does not verify against the registry |
| 1 | Session Management Flaws | replayed call executes twice | **blocked** | replay -> replayed or out-of-order call (seq 1, last accepted 1); other connection -> the envelope is bound to a different session; forged MAC -> the envelope MAC does not verify with this session's key; expired -> the SMCP session has expired; open a new session |
| 3 | Namespace Typosquatting | 'query_sa1es' is listed and callable | **blocked** | hidden from tools/list (typosquat: 'query_sa1es' imitates registered tool 'query_sales'); direct call denied |
| 3 | Tool Name Conflict | 'transfer_funds' is listed and callable | **blocked** | hidden from tools/list (name_conflict: 'transfer_funds' is registered to payments, not to this server); direct call denied |
| 3 | Tool Poisoning | hidden instruction reaches the agent | **missed** | the description was pinned at registration, so it passes vetting and reaches the agent with an SMCP security label attached |
| 3 | Command Injection | injected command runs | **missed** | SMCP checks who calls and what they may call; it does not look at argument content |
| 3 | Rug Pulls | 'get_weather' is listed and callable | **blocked** | hidden from tools/list (definition_changed: 'get_weather' no longer matches the definition pinned at registration (possible rug pull)); direct call denied |
| 3 | Cross-Server Shadowing | hidden instruction reaches the agent | **missed** | the description was pinned at registration, so it passes vetting and reaches the agent with an SMCP security label attached |
| 5 | Prompt Injection | delete runs | **missed** | riskLevel is declared by the calling agent. The same call declared 'high' is denied, so the rule works only while the agent is not fooled |
| 5 | Indirect Prompt Injection | both calls succeed | **missed** | each call is authorised on its own (public fetch, internal email), so both pass |
| 6 | Installer Spoofing | - | **not tested** | happens before any MCP session exists; needs package signing at registration |
| 6 | Preference Manipulation | - | **not tested** | same path as Tool Poisoning: a registered description is trusted as pinned |
| 7 | Remote Code Execution | - | **not tested** | same path as Command Injection: argument content is not inspected |
| 7 | SQL Injection | other tenant's rows returned | **missed** | the caller is authorised for run_report; the leak happens inside the tool |
| 7 | Credential Theft | no credentials needed in the first place | **missed** | with the key, the attacker is the agent; revocation (see Privilege Persistence) is the only cut-off |
| 7 | Sandbox Escape | - | **not tested** | a property of how the server is isolated, below the protocol |
| 8 | Tool Chaining Abuse | data leaves | **missed** | each call is permitted alone; secret redaction does not cover ordinary personal data |
| 8 | Unauthorized Access | call succeeds | **blocked** | agent rogue is not an allowed delegate for this tool |
| 8 | Privilege Abuse | all calls succeed | **blocked** | aal1 agent -> session assurance aal1 is below the tool's minimum aal2; forged delegation -> signature on the delegation from bob does not verify; analyst's agent on delete_user -> user alice (org ORG-ACME, roles ['data_analyst']) is not an allowed delegator for this tool; delegated scopes ['crm_read', 'sales_reporting'] do not cover the required scopes ['user_admin'] |
| 8 | Path Traversal | file contents returned | **missed** | argument content is not inspected; /etc/passwd lines are not secrets to the redactor |
| 9 | Resource Content Poisoning | poisoned output delivered | **missed** | delivered intact and signed by the gateway (signature valid: True). The signature proves where the text came from. It says nothing about whether it is safe |
| 9 | Token Passthrough | keys reach the agent | **blocked** | keys redacted (yes); smcp/* metadata and agent identity never reached the server (yes) |
| 10 | Cross-Tenant Data Exposure | ACME rows returned | **blocked** | user mallory (org ORG-GLOBEX, roles ['data_analyst']) is not an allowed delegator for this tool |
| 11 | Vulnerable Versions | connects without question | **partial** | the upstream server reports version '1.3.0' and the registry pins '1.4.2'. The check trusts serverInfo.version, which the server reports about itself |
| 11 | Privilege Persistence | nothing to revoke: access continues | **blocked** | next call on the same session -> agent report is revoked or suspended in the registry |
| 11 | Configuration Drift | - | **not tested** | not prevented; every audit entry records registry and policy hashes, so drift is visible afterwards |

**10 blocked, 1 partial, 10 missed, 5 not tested** out of 26 risks.

| Integrity check | Result | Evidence |
|---|---|---|
| Response tampering in transit | **detected** | edited result -> the result was modified after the gateway signed it; edited signed metadata -> the response signature does not verify |
| Audit log tampering | **detected** | edited DENIED->SUCCESS: caught at line 6; deleted a middle entry: caught at line 3; cut the last entry: NOT caught (needs an external anchor) |

| Latency (echo tool) | median | p95 |
|---|---:|---:|
| Plain MCP over stdio | 0.04 ms | 0.052 ms |
| Through the SMCP gateway, response verified | 0.648 ms | 0.719 ms |
| Handshake, in-process | 1.125 ms | 1.168 ms |
| One call, in-process (seal, decide, audit, sign, verify) | 0.499 ms | 0.553 ms |

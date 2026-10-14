"""Policy Decision Point (paper section 4.4).

Two layers decide each call:

1. Built-in checks from the tool's registered security extension (Table 6):
   ``minIdentityAssurance``, ``allowedDelegators``, ``requiredScopes`` and
   ``dataPolicy.requiresRedaction``.
2. Rules from a policy file. A rule matches tools, then either requires
   conditions on the security context (any failure denies) or attaches
   obligations such as redaction or a row limit.

Any deny wins. With no deny, the call is permitted, with obligations if any
matched.

Extensions (this project, not the paper), each active only when configured:

3. ``argumentGuards`` on the tool, and the server's own input schema when the
   gateway enforces it (see guards.py).
4. ``requiresApproval`` on the tool: the call needs the root user's signed
   approval (see approval.py).
5. A ``flow`` section in the policy file: what follows once untrusted or
   confidential content is in the session (see flow.py). ``riskFloor`` raises
   the gateway's own risk assessment; ``egress`` says whether an egress tool is
   allowed, needs approval, or is denied.

The paper's ``riskLevel`` is declared by the agent. Here the ``riskLevel`` that
rules see is the higher of the declared level and the gateway's assessment, and
both inputs are available to rules as ``declaredRiskLevel`` and
``assessedRiskLevel``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from . import guards
from .context import ASSURANCE, ORDERED, RISK, rank
from .crypto import digest
from .flow import LABELS, FlowState
from .registry import ToolRecord
from .watched import Verifier, WatchedFile

OPS = ("eq", "ne", "in", "not_in", "lt", "lte", "gt", "gte", "contains")
MATCH_KEYS = ("tool", "toolId", "sensitivityLevel")
OBLIGATIONS = ("redactFields", "maxRows", "redactSecrets", "stripInstructions")
EGRESS_ACTIONS = ("allow", "approve", "deny")


@dataclass
class Decision:
    effect: str
    reasons: list[str] = field(default_factory=list)
    obligations: list[dict] = field(default_factory=list)
    policy_refs: list[str] = field(default_factory=list)
    requires_step_up: bool = False
    approval: list[str] = field(default_factory=list)  # why the user must approve; empty if not needed

    @property
    def permitted(self) -> bool:
        return self.effect != "DENY"

    def to_dict(self) -> dict:
        d = {
            "effect": self.effect,
            "reasons": self.reasons,
            "obligations": self.obligations,
            "policyRefs": self.policy_refs,
            "requiresStepUp": self.requires_step_up,
        }
        if self.approval:
            d["approvalRequired"] = self.approval
        return d


class PolicyError(ValueError):
    pass


def attributes(ctx: dict, record: ToolRecord | None) -> dict:
    chain = ctx.get("delegatorChain") or []
    root = chain[0] if chain else {}
    users = [link for link in chain if link.get("subjectType") == "user"]
    user = users[0] if users else {}
    return {
        "tool": record.name if record else None,
        "toolId": record.tool_id if record else None,
        "sensitivityLevel": record.sensitivity if record else None,
        "riskLevel": ctx.get("riskLevel"),
        "declaredRiskLevel": ctx.get("declaredRiskLevel", ctx.get("riskLevel")),
        "assessedRiskLevel": ctx.get("assessedRiskLevel", "low"),
        "sessionLabels": ctx.get("sessionLabels") or [],
        "dataSensitivity": ctx.get("dataSensitivity"),
        "assurance": ctx.get("assurance"),
        "callerAgentId": ctx.get("callerAgentId"),
        "chainRootType": root.get("subjectType"),
        "chainLength": len(chain),
        "userId": user.get("subjectId"),
        "userOrg": user.get("org"),
        "userRoles": user.get("roles") or [],
        "scopes": ctx.get("scopes") or [],
    }


def _condition(cond: dict, attrs: dict) -> bool:
    attr, op, value = cond["attr"], cond["op"], cond.get("value")
    actual = attrs.get(attr)
    if op in ("lt", "lte", "gt", "gte"):
        scale = ORDERED.get(attr)
        try:
            a, b = (rank(scale, actual), rank(scale, value)) if scale else (float(actual), float(value))
        except (TypeError, ValueError):
            return False  # unknown or missing level: fail closed
        return {"lt": a < b, "lte": a <= b, "gt": a > b, "gte": a >= b}[op]
    if op == "eq":
        return actual == value
    if op == "ne":
        return actual != value
    if op == "in":
        return actual in (value or [])
    if op == "not_in":
        return actual not in (value or [])
    if op == "contains":
        return isinstance(actual, list) and value in actual
    return False


def _matches(match: dict, attrs: dict) -> bool:
    for key, wanted in match.items():
        wanted = wanted if isinstance(wanted, list) else [wanted]
        if attrs.get(key) not in wanted:
            return False
    return True


def _user_matches(rule: dict, link: dict) -> bool:
    orgs, roles, ids = rule.get("allowedOrgIds"), rule.get("allowedRoles"), rule.get("allowedUserIds")
    if orgs and link.get("org") not in orgs:
        return False
    if roles and not set(roles) & set(link.get("roles") or []):
        return False
    if ids and link.get("subjectId") not in ids:
        return False
    return True


def check_delegators(allowed: list[dict], chain: list[dict]) -> str | None:
    user_rules = [r for r in allowed if r.get("subjectType") == "user"]
    agent_rules = [r for r in allowed if r.get("subjectType") == "agent"]
    if user_rules:
        root = chain[0] if chain else None
        if root is None or root.get("subjectType") != "user":
            return "this tool needs a call delegated by a user, and the chain has no user at its root"
        if not any(_user_matches(r, root) for r in user_rules):
            return (f"user {root.get('alias') or root.get('subjectId')} (org {root.get('org')}, "
                    f"roles {root.get('roles')}) is not an allowed delegator for this tool")
    if agent_rules:
        for link in chain:
            if link.get("subjectType") != "agent":
                continue
            if not any(link.get("subjectId") in (r.get("allowedAgentIds") or []) for r in agent_rules):
                return f"agent {link.get('alias') or link.get('subjectId')} is not an allowed delegate for this tool"
    return None


class PolicyEngine(WatchedFile):
    def __init__(self, data: dict | None = None, path: Path | None = None,
                 verifier: Verifier | None = None) -> None:
        self._watch(path, verifier)
        self._load(data or {})

    @classmethod
    def load(cls, path: Path, verifier: Verifier | None = None) -> "PolicyEngine":
        return cls(cls.read(path, verifier), path, verifier)

    def _load(self, data: dict) -> None:
        rules = data.get("rules") or []
        for i, rule in enumerate(rules):
            rid = rule.get("id") or f"rule[{i}]"
            for key in (rule.get("match") or {}):
                if key not in MATCH_KEYS:
                    raise PolicyError(f"{rid}: unknown match key {key!r}; use {MATCH_KEYS}")
            for cond in rule.get("require") or []:
                if cond.get("op") not in OPS or "attr" not in cond:
                    raise PolicyError(f"{rid}: each condition needs attr and an op from {OPS}")
            for ob in rule.get("obligations") or []:
                if not isinstance(ob, dict) or len(ob) != 1 or next(iter(ob)) not in OBLIGATIONS:
                    raise PolicyError(f"{rid}: each obligation is one of {OBLIGATIONS}")
        flow = data.get("flow") or {}
        for label, spec in flow.items():
            if label not in LABELS or not isinstance(spec, dict):
                raise PolicyError(f"flow: unknown label {label!r}; use {LABELS}")
            if spec.get("riskFloor", "low") not in RISK:
                raise PolicyError(f"flow.{label}.riskFloor must be one of {RISK}")
            if spec.get("egress", "allow") not in EGRESS_ACTIONS:
                raise PolicyError(f"flow.{label}.egress must be one of {EGRESS_ACTIONS}")
        self.rules = rules
        self.flow = flow
        self.fingerprint = digest(data)

    def assess_risk(self, state: FlowState | None) -> tuple[str, list[str]]:
        """The gateway's own risk level for the next call, from what the session holds."""
        level, signals = "low", []
        for src in (state.sources if state else []):
            floor = (self.flow.get(src.label) or {}).get("riskFloor", "low")
            if rank(RISK, floor) > rank(RISK, level):
                level = floor
            if floor != "low":
                signals.append(f"{src.label} content from {src.tool} ({src.tool_call_id}) sets the floor at {floor}")
        return level, signals

    def evaluate(self, ctx: dict, record: ToolRecord | None, *, args: dict | None = None,
                 input_schema: dict | None = None, flow: FlowState | None = None) -> Decision:
        """Decide one call. ``args``, ``input_schema`` and ``flow`` feed the extensions;
        without them the decision is the paper's."""
        if record is None:
            return Decision("DENY", ["the tool is not registered for this server, or was not vetted "
                                     "in this session's tool listing"], policy_refs=["SMCP.REGISTRY"])
        reasons: list[str] = []
        refs: list[str] = []
        obligations: list[dict] = []
        step_up = False
        sec = record.security

        min_aal = sec.get("minIdentityAssurance")
        if min_aal:
            try:
                too_low = rank(ASSURANCE, ctx.get("assurance")) < rank(ASSURANCE, min_aal)
            except ValueError:
                too_low = True
            if too_low:
                reasons.append(f"session assurance {ctx.get('assurance')} is below the tool's "
                               f"minimum {min_aal}")
                refs.append("SMCP.TOOL.minIdentityAssurance")
                step_up = True

        allowed = sec.get("allowedDelegators")
        if allowed:
            problem = check_delegators(allowed, ctx.get("delegatorChain") or [])
            if problem:
                reasons.append(problem)
                refs.append("SMCP.TOOL.allowedDelegators")

        required = set(sec.get("requiredScopes") or [])
        granted = set(ctx.get("scopes") or [])
        if required and not required <= granted:
            reasons.append(f"delegated scopes {sorted(granted)} do not cover the required "
                           f"scopes {sorted(required)}")
            refs.append("SMCP.TOOL.requiredScopes")

        if (sec.get("dataPolicy") or {}).get("requiresRedaction"):
            obligations.append({"redactSecrets": True})
            refs.append("SMCP.TOOL.dataPolicy")

        approval: list[str] = []
        if args is not None and (sec.get("argumentGuards") or input_schema):
            problems = guards.check(sec.get("argumentGuards"), args, input_schema)
            if problems:
                reasons.extend(problems)
                refs.append("SMCP.EXT.argumentGuards")

        if sec.get("requiresApproval"):
            approval.append(f"{record.name} is registered as requiring the user's approval for every call")
            refs.append("SMCP.EXT.requiresApproval")

        if (sec.get("flow") or {}).get("egress") and flow is not None:
            carried = flow.carried(args) if args else None
            for label in flow.labels:
                action = (self.flow.get(label) or {}).get("egress", "allow")
                if action == "allow":
                    continue
                src = flow.first(label)
                why = (f"egress through {record.name} after {label} content entered the session "
                       f"({src.tool} {src.tool_call_id})")
                if carried is not None and label == carried.label:
                    why += f"; the arguments carry text from the {carried.tool} result ({carried.tool_call_id})"
                if action == "deny":
                    reasons.append(why)
                else:
                    approval.append(why)
                refs.append(f"SMCP.EXT.flow.{label}")

        attrs = attributes(ctx, record)
        for i, rule in enumerate(self.rules):
            rid = rule.get("id") or f"rule[{i}]"
            if not _matches(rule.get("match") or {}, attrs):
                continue
            failed = [c for c in rule.get("require") or [] if not _condition(c, attrs)]
            if failed:
                for c in failed:
                    reasons.append(f"{rid}: requires {c['attr']} {c['op']} {c.get('value')!r} "
                                   f"(was {attrs.get(c['attr'])!r})")
                refs.append(rid)
                continue
            if rule.get("obligations"):
                obligations.extend(rule["obligations"])
                refs.append(rid)

        if reasons:
            return Decision("DENY", reasons, [], refs, step_up)
        effect = "PERMIT_WITH_OBLIGATIONS" if obligations else "PERMIT"
        return Decision(effect, [], obligations, refs, approval=approval)

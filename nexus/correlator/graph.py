"""Correlation graph — link findings into attack chains via the expert system."""

from __future__ import annotations

import logging
import re
from typing import Any, Protocol

from nexus.db.models import AttackChain, ChainStep, Finding, Severity

log = logging.getLogger("nexus.correlator.graph")

_SQLI_TITLE_RE = re.compile(r"\bsql\s+injection\b|\bsqli\b")

_ACTION_TO_STATES: dict[str, tuple[str, ...]] = {
    "run_sqlmap_dump": ("db_dumped",),
    "extract_credentials": ("credentials_obtained",),
    "chain_to_auth_bypass": ("admin_access", "admin_panel_access"),
    "test_admin_panels": ("admin_access", "admin_panel_access"),
    "try_file_upload": ("webshell_uploaded", "file_uploaded"),
    "try_code_execution": ("rce_achieved",),
    "try_ssh_with_creds": ("ssh_access",),
    "try_rdp_with_creds": ("rdp_access",),
    "check_ghostcat": ("ghostcat_vuln",),
    "check_ms17_010": ("ms17_010_vuln",),
    "check_sqli": ("sqli_found",),
    "check_xss": ("xss_found",),
    "run_wpscan": ("service_wordpress",),
    "check_manager_exposed": ("tomcat_manager_found",),
    "try_war_deploy": ("war_uploaded",),
}


class ChainBuilderLike(Protocol):
    def find_attack_paths(
        self, start: str, goal: str, max_paths: int = 5
    ) -> list[list[dict[str, Any]]]: ...


class ExpertEngineLike(Protocol):
    def clear_facts(self) -> None: ...
    def add_fact(self, key: str, value: Any, source: str = "", confidence: float = 1.0) -> None: ...
    def evaluate(self) -> list[tuple[str, list[Any]]]: ...


def build_attack_chains(
    findings: list[Finding],
    *,
    chain_builder: ChainBuilderLike | None = None,
    expert: ExpertEngineLike | None = None,
) -> list[AttackChain]:
    """Analyze findings and build potential attack chains.

    Uses the expert system to identify relationships between findings
    and the chain builder to find viable attack paths.
    """
    if not findings or not chain_builder:
        return []

    # Derive current states from findings (match both ChainBuilder + YAML template keys)
    states: set[str] = set()
    for f in findings:
        title_l = f.title.lower()
        cwe_l = f.cwe_id.lower()
        if f.port:
            states.add(f"port_{f.port}")
        if f.cwe_id:
            states.add(f"vuln_{cwe_l}")
        if "ssh" in title_l or f.port == 22:
            states.add("service_ssh")
        if "http" in f.protocol.lower() or f.port in (80, 443, 8000, 8080, 8443, 8888):
            states.add("service_http")
        if "https" in f.protocol.lower() or f.port in (443, 8443):
            states.add("service_https")
        if "smb" in title_l or f.port in (139, 445):
            states.add("service_smb")
        if "tomcat" in title_l or "tomcat" in f.description.lower():
            states.add("service_tomcat")
        if "wordpress" in title_l or "wordpress" in f.description.lower():
            states.add("service_wordpress")
        if _SQLI_TITLE_RE.search(title_l) or "cwe-89" in cwe_l or "sqli" in cwe_l:
            states.add("vuln_sqli")
            states.add("sqli_found")
        if "xss" in title_l or "cwe-79" in cwe_l:
            states.add("vuln_xss")
            states.add("xss_found")
        if (
            re.search(r"\brce\b", title_l)
            or "remote code" in title_l
            or "remote command" in title_l
        ):
            states.add("vuln_rce")
        if (
            "lfi" in title_l
            or "file inclusion" in title_l
            or "path traversal" in title_l
            or "cwe-22" in cwe_l
        ):
            states.add("vuln_lfi")
            states.add("lfi_found")
        if "ssti" in title_l or "template injection" in title_l:
            states.add("ssti_found")
        if "upload" in title_l or "cwe-434" in cwe_l:
            states.add("vuln_upload")
        if "credential" in title_l or "default password" in title_l or f.tool_source == "hydra":
            states.add("credentials_obtained")

    # Feed states into expert system
    if expert:
        expert.clear_facts()
        for state in states:
            expert.add_fact(state, True, source="correlator")
        fired = expert.evaluate()
        log.info("Expert system fired %d rules during correlation", len(fired))

        # Add new states derived from fired rules (supports both str and tuple actions)
        for _rule_name, actions in fired:
            for action in actions:
                if isinstance(action, tuple) and len(action) >= 1:
                    states.add(str(action[0]))
                elif isinstance(action, str) and action.strip():
                    act = action.strip()
                    states.add(act)
                    for mapped in _ACTION_TO_STATES.get(act, ()):
                        states.add(mapped)

    # Find attack paths to high-value goal states present in ChainBuilder / YAML templates
    chains: list[AttackChain] = []
    goals = [
        "rce_achieved",
        "admin_panel_access",
        "admin_access",
        "data_exfiltrated",
        "lateral_movement",
        "privesc_achieved",
    ]
    for goal in goals:
        for start_state in sorted(states):
            if start_state == goal:
                continue
            paths = chain_builder.find_attack_paths(start_state, goal, max_paths=2)
            for path in paths:
                if not path:
                    continue

                cost = sum(float(s.get("weight", 0.5)) for s in path)
                steps: list[ChainStep] = []
                for i, step_dict in enumerate(path):
                    action = step_dict.get("action", "") or step_dict.get("to", "")
                    from_node = step_dict.get("from", "")
                    to_node = step_dict.get("to", "")
                    related = _find_related_finding(findings, from_node) or _find_related_finding(
                        findings, to_node
                    )
                    steps.append(
                        ChainStep(
                            order=i,
                            action=f"{action} ({from_node} -> {to_node})"
                            if from_node and to_node
                            else action,
                            tool=step_dict.get("tool")
                            or (related.tool_source if related else "manual"),
                            target=related.host if related else "",
                            finding_id=related.id if related else "",
                            result=to_node,
                        )
                    )

                chain = AttackChain(
                    name=f"{start_state} → {goal}",
                    description=f"Attack path from {start_state} to {goal} via {len(steps)} steps",
                    steps=steps,
                    confidence=round(max(0.1, min(1.0, 1.0 / (1.0 + cost * 0.1))), 2),
                    impact=Severity.CRITICAL
                    if goal in ("rce_achieved", "privesc_achieved")
                    else Severity.HIGH,
                )
                chains.append(chain)

    # Deduplicate chains by name
    seen: set[str] = set()
    unique_chains: list[AttackChain] = []
    for c in chains:
        if c.name not in seen:
            seen.add(c.name)
            unique_chains.append(c)

    log.info("Built %d attack chains from %d findings", len(unique_chains), len(findings))
    return unique_chains


def _find_related_finding(findings: list[Finding], state: str) -> Finding | None:
    """Find a finding that relates to a chain state."""
    state_lower = state.lower()
    for f in findings:
        if state_lower.startswith("port_"):
            try:
                port = int(state_lower.split("_")[1])
                if f.port == port:
                    return f
            except (ValueError, IndexError):
                pass
        if state_lower.startswith("vuln_") and f.cwe_id:
            if state_lower[5:] in f.cwe_id.lower():
                return f
        if state_lower.startswith("service_"):
            svc = state_lower[8:]
            if svc in f.title.lower() or svc in f.protocol.lower():
                return f
    return None

"""Expert System rule engine — production rules for attack decisions."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class Fact:
    """A single piece of knowledge about the engagement state."""
    key: str
    value: Any
    source: str = ""
    confidence: float = 1.0


@dataclass
class Rule:
    """IF conditions THEN actions production rule."""
    name: str
    priority: int = 50  # Lower = higher priority (0-100)
    conditions: list[Callable[[dict[str, Fact]], bool]] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)
    description: str = ""

    def evaluate(self, facts: dict[str, Fact]) -> bool:
        """Check if all conditions are met."""
        return all(cond(facts) for cond in self.conditions)


class RuleEngine:
    """Forward-chaining production rule engine.

    Evaluates rules against the current fact base, fires matching rules,
    and collects recommended actions.
    """

    def __init__(self) -> None:
        self._rules: list[Rule] = []
        self._facts: dict[str, Fact] = {}

    @property
    def fact_count(self) -> int:
        return len(self._facts)

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def add_fact(self, key: str, value: Any, source: str = "", confidence: float = 1.0) -> None:
        self._facts[key] = Fact(key=key, value=value, source=source, confidence=confidence)

    def get_fact(self, key: str) -> Any:
        f = self._facts.get(key)
        return f.value if f else None

    def has_fact(self, key: str) -> bool:
        return key in self._facts

    def add_rule(self, rule: Rule) -> None:
        self._rules.append(rule)
        self._rules.sort(key=lambda r: r.priority)

    def evaluate(self) -> list[tuple[str, list[str]]]:
        """Evaluate all rules and return (rule_name, actions) for fired rules."""
        fired: list[tuple[str, list[str]]] = []
        for rule in self._rules:
            if rule.evaluate(self._facts):
                fired.append((rule.name, rule.actions))
        return fired

    def clear_facts(self) -> None:
        self._facts.clear()

    def reset(self) -> None:
        self._facts.clear()
        self._rules.clear()


def build_service_rules() -> list[Rule]:
    """Pre-built rules for service-to-attack routing."""

    def _has(key: str) -> Callable[[dict[str, Fact]], bool]:
        return lambda facts: key in facts

    def _val_contains(key: str, substring: str) -> Callable[[dict[str, Fact]], bool]:
        def check(facts: dict[str, Fact]) -> bool:
            f = facts.get(key)
            return f is not None and substring.lower() in str(f.value).lower()
        return check

    def _port_open(port: int) -> Callable[[dict[str, Fact]], bool]:
        return lambda facts: f"port_{port}" in facts

    rules = [
        Rule(
            name="http_detected",
            priority=10,
            conditions=[_has("service_http")],
            actions=["run_nuclei", "run_ffuf", "run_nikto", "run_whatweb", "check_sqli", "check_xss"],
            description="HTTP service found — run web vulnerability scanners",
        ),
        Rule(
            name="https_detected",
            priority=10,
            conditions=[_has("service_https")],
            actions=["run_nuclei", "run_ffuf", "run_nikto", "check_ssl", "check_sqli", "check_xss"],
            description="HTTPS service found — run web scanners + SSL audit",
        ),
        Rule(
            name="ssh_detected",
            priority=20,
            conditions=[_has("service_ssh")],
            actions=["run_ssh_audit", "try_default_creds_ssh", "check_ssh_cves"],
            description="SSH service found — audit config + test credentials",
        ),
        Rule(
            name="smb_detected",
            priority=15,
            conditions=[_has("service_smb")],
            actions=["run_enum4linux", "run_crackmapexec", "check_null_session", "check_ms17_010"],
            description="SMB service found — enumerate shares, check EternalBlue",
        ),
        Rule(
            name="ftp_detected",
            priority=20,
            conditions=[_has("service_ftp")],
            actions=["check_anonymous_ftp", "try_default_creds_ftp", "check_ftp_cves"],
            description="FTP service found — test anonymous login + credentials",
        ),
        Rule(
            name="mysql_detected",
            priority=20,
            conditions=[_has("service_mysql")],
            actions=["try_default_creds_mysql", "check_mysql_cves", "check_remote_access"],
            description="MySQL service found — test credentials + CVEs",
        ),
        Rule(
            name="mssql_detected",
            priority=20,
            conditions=[_has("service_mssql")],
            actions=["try_default_creds_mssql", "check_mssql_cves", "check_xp_cmdshell"],
            description="MSSQL service found — test sa credentials + xp_cmdshell",
        ),
        Rule(
            name="rdp_detected",
            priority=25,
            conditions=[_has("service_rdp")],
            actions=["try_default_creds_rdp", "check_bluekeep", "check_rdp_nla"],
            description="RDP service found — test credentials + BlueKeep",
        ),
        Rule(
            name="smtp_detected",
            priority=30,
            conditions=[_has("service_smtp")],
            actions=["check_open_relay", "run_smtp_user_enum", "check_spoofing"],
            description="SMTP service found — check relay + user enumeration",
        ),
        Rule(
            name="dns_detected",
            priority=25,
            conditions=[_has("service_dns")],
            actions=["check_zone_transfer", "run_dns_enum", "check_subdomain_takeover"],
            description="DNS service found — zone transfer + enumeration",
        ),
        Rule(
            name="tomcat_detected",
            priority=5,
            conditions=[_val_contains("tech_stack", "tomcat")],
            actions=["try_default_creds_tomcat", "check_ghostcat", "check_manager_exposed", "try_war_deploy"],
            description="Apache Tomcat detected — high-value target",
        ),
        Rule(
            name="wordpress_detected",
            priority=5,
            conditions=[_val_contains("tech_stack", "wordpress")],
            actions=["run_wpscan", "check_xmlrpc", "enumerate_wp_users", "check_wp_plugins"],
            description="WordPress detected — high-value target",
        ),
        Rule(
            name="jenkins_detected",
            priority=5,
            conditions=[_val_contains("tech_stack", "jenkins")],
            actions=["check_jenkins_anon", "try_default_creds_jenkins", "check_jenkins_script_console"],
            description="Jenkins detected — check unauthenticated access",
        ),
        Rule(
            name="no_waf",
            priority=40,
            conditions=[_val_contains("waf_status", "none")],
            actions=["enable_aggressive_scan", "skip_evasion"],
            description="No WAF detected — enable aggressive scanning",
        ),
        Rule(
            name="waf_cloudflare",
            priority=10,
            conditions=[_val_contains("waf_status", "cloudflare")],
            actions=["enable_stealth_mode", "use_cloudflare_bypass", "throttle_requests"],
            description="Cloudflare WAF detected — enable evasion",
        ),
        Rule(
            name="sqli_confirmed",
            priority=1,
            conditions=[_has("vuln_sqli")],
            actions=["run_sqlmap_dump", "extract_credentials", "chain_to_auth_bypass"],
            description="SQLi confirmed — dump data + chain to auth bypass",
        ),
        Rule(
            name="credentials_found",
            priority=1,
            conditions=[_has("credentials_obtained")],
            actions=["try_credential_reuse", "test_admin_panels", "try_ssh_with_creds", "try_rdp_with_creds"],
            description="Credentials obtained — test reuse across services",
        ),
        Rule(
            name="admin_access",
            priority=1,
            conditions=[_has("admin_panel_access")],
            actions=["try_file_upload", "try_plugin_install", "try_code_execution"],
            description="Admin panel access — attempt code execution",
        ),
    ]
    return rules

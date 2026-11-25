"""NEXUS Scanner — vulnerability scanning tool wrappers."""

from nexus.scanner.cms_scan import wpscan_audit
from nexus.scanner.crawler import crawl_web
from nexus.scanner.exposure import audit_exposed_artifacts
from nexus.scanner.headers import audit_http_security
from nexus.scanner.host_audit import audit_host_packages
from nexus.scanner.importer import import_file
from nexus.scanner.network_services import audit_network_service
from nexus.scanner.nikto import nikto_scan
from nexus.scanner.nuclei import nuclei_scan
from nexus.scanner.openapi import audit_openapi_spec, parse_openapi_spec
from nexus.scanner.passive_dast import (
    analyze_html_passive,
    audit_auth_enforcement,
    audit_graphql_introspection,
)
from nexus.scanner.proxy import NexusMitmAddon, NexusProxyRecorder
from nexus.scanner.ssh_audit import audit_ssh
from nexus.scanner.tls import audit_tls
from nexus.scanner.web import ffuf_scan
from nexus.scanner.yaml_rules import PassiveRule, YamlPassiveRuleEngine
from nexus.scanner.zap import build_zap_automation_plan, parse_zap_json_report, zap_scan

__all__ = [
    "NexusMitmAddon",
    "NexusProxyRecorder",
    "PassiveRule",
    "YamlPassiveRuleEngine",
    "analyze_html_passive",
    "audit_auth_enforcement",
    "audit_exposed_artifacts",
    "audit_graphql_introspection",
    "audit_host_packages",
    "audit_http_security",
    "audit_network_service",
    "audit_openapi_spec",
    "audit_ssh",
    "audit_tls",
    "build_zap_automation_plan",
    "crawl_web",
    "ffuf_scan",
    "import_file",
    "nikto_scan",
    "nuclei_scan",
    "parse_openapi_spec",
    "parse_zap_json_report",
    "wpscan_audit",
    "zap_scan",
]

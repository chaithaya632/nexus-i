"""NEXUS Scanner — vulnerability scanning tool wrappers."""

from nexus.scanner.nuclei import nuclei_scan
from nexus.scanner.web import ffuf_scan
from nexus.scanner.nikto import nikto_scan
from nexus.scanner.importer import import_file
from nexus.scanner.tls import audit_tls
from nexus.scanner.ssh_audit import audit_ssh
from nexus.scanner.crawler import crawl_web
from nexus.scanner.exposure import audit_exposed_artifacts
from nexus.scanner.headers import audit_http_security
from nexus.scanner.network_services import audit_network_service
from nexus.scanner.cms_scan import wpscan_audit
from nexus.scanner.openapi import audit_openapi_spec, parse_openapi_spec
from nexus.scanner.passive_dast import analyze_html_passive, audit_auth_enforcement, audit_graphql_introspection
from nexus.scanner.host_audit import audit_host_packages

__all__ = [
    "nuclei_scan",
    "ffuf_scan",
    "nikto_scan",
    "import_file",
    "audit_tls",
    "audit_ssh",
    "crawl_web",
    "audit_exposed_artifacts",
    "audit_http_security",
    "audit_network_service",
    "wpscan_audit",
    "audit_openapi_spec",
    "parse_openapi_spec",
    "analyze_html_passive",
    "audit_graphql_introspection",
    "audit_auth_enforcement",
    "audit_host_packages",
]

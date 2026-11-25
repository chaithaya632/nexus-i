"""NEXUS Scanner — vulnerability scanning tool wrappers."""

from nexus.scanner.nuclei import nuclei_scan
from nexus.scanner.web import ffuf_scan
from nexus.scanner.nikto import nikto_scan
from nexus.scanner.importer import import_file
from nexus.scanner.tls import audit_tls
from nexus.scanner.ssh_audit import audit_ssh
from nexus.scanner.crawler import crawl_web
from nexus.scanner.headers import audit_http_security
from nexus.scanner.openapi import audit_openapi_spec, parse_openapi_spec

__all__ = [
    "nuclei_scan",
    "ffuf_scan",
    "nikto_scan",
    "import_file",
    "audit_tls",
    "audit_ssh",
    "crawl_web",
    "audit_http_security",
    "audit_openapi_spec",
    "parse_openapi_spec",
]

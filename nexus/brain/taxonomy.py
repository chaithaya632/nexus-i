"""OWASP / CWE / CAPEC taxonomy mapper for automatic finding classification."""

from __future__ import annotations

import re
from typing import Any

OWASP_TOP_10_2021: dict[str, dict[str, str]] = {
    "A01": {
        "name": "Broken Access Control",
        "keywords": "idor,bola,privilege,authorization,access control,directory traversal,path traversal,insecure direct object",
    },
    "A02": {
        "name": "Cryptographic Failures",
        "keywords": "ssl,tls,cipher,encryption,certificate,cleartext,plaintext,weak crypto,hashing,md5,sha1",
    },
    "A03": {
        "name": "Injection",
        "keywords": "sqli,sql injection,xss,cross-site scripting,command injection,ldap injection,xpath,template injection,ssti,nosql injection",
    },
    "A04": {
        "name": "Insecure Design",
        "keywords": "business logic,design flaw,threat model,abuse case",
    },
    "A05": {
        "name": "Security Misconfiguration",
        "keywords": "default credentials,unnecessary features,error messages,directory listing,debug,stack trace,misconfiguration,open port",
    },
    "A06": {
        "name": "Vulnerable Components",
        "keywords": "cve,outdated,vulnerable version,component,library,dependency,supply chain",
    },
    "A07": {
        "name": "Identification and Authentication",
        "keywords": "authentication,brute force,credential stuffing,password,session,weak password,multi-factor,mfa",
    },
    "A08": {
        "name": "Software and Data Integrity",
        "keywords": "deserialization,ci/cd,integrity,unsigned,untrusted data",
    },
    "A09": {
        "name": "Security Logging and Monitoring",
        "keywords": "logging,monitoring,audit,detection,alerting,insufficient logging",
    },
    "A10": {
        "name": "Server-Side Request Forgery",
        "keywords": "ssrf,server-side request,internal service,metadata endpoint",
    },
}

# Common CWE mappings for penetration testing findings
CWE_MAP: dict[str, str] = {
    "sqli": "CWE-89",
    "sql_injection": "CWE-89",
    "xss": "CWE-79",
    "cross_site_scripting": "CWE-79",
    "reflected_xss": "CWE-79",
    "stored_xss": "CWE-79",
    "command_injection": "CWE-78",
    "os_command_injection": "CWE-78",
    "path_traversal": "CWE-22",
    "directory_traversal": "CWE-22",
    "lfi": "CWE-98",
    "rfi": "CWE-98",
    "file_inclusion": "CWE-98",
    "ssrf": "CWE-918",
    "idor": "CWE-639",
    "bola": "CWE-639",
    "open_redirect": "CWE-601",
    "csrf": "CWE-352",
    "xxe": "CWE-611",
    "xml_injection": "CWE-611",
    "deserialization": "CWE-502",
    "ssti": "CWE-1336",
    "template_injection": "CWE-1336",
    "default_credentials": "CWE-1393",
    "weak_password": "CWE-521",
    "brute_force": "CWE-307",
    "broken_auth": "CWE-287",
    "session_fixation": "CWE-384",
    "information_disclosure": "CWE-200",
    "sensitive_data_exposure": "CWE-200",
    "directory_listing": "CWE-548",
    "missing_encryption": "CWE-311",
    "weak_ssl": "CWE-326",
    "buffer_overflow": "CWE-120",
    "race_condition": "CWE-362",
    "rce": "CWE-94",
    "remote_code_execution": "CWE-94",
    "file_upload": "CWE-434",
    "unrestricted_upload": "CWE-434",
    "privilege_escalation": "CWE-269",
    "null_session": "CWE-284",
    "anonymous_access": "CWE-284",
}


# Common CWE -> OWASP Top 10 2021 mapping
CWE_TO_OWASP: dict[str, str] = {
    "CWE-22": "A01",
    "CWE-269": "A01",
    "CWE-284": "A01",
    "CWE-352": "A01",
    "CWE-601": "A01",
    "CWE-639": "A01",
    "CWE-732": "A01",
    "CWE-200": "A01",
    "CWE-311": "A02",
    "CWE-326": "A02",
    "CWE-327": "A02",
    "CWE-20": "A03",
    "CWE-78": "A03",
    "CWE-79": "A03",
    "CWE-89": "A03",
    "CWE-94": "A03",
    "CWE-98": "A03",
    "CWE-917": "A03",
    "CWE-1336": "A03",
    "CWE-434": "A04",
    "CWE-1021": "A04",
    "CWE-16": "A05",
    "CWE-548": "A05",
    "CWE-611": "A05",
    "CWE-1393": "A05",
    "CWE-120": "A06",
    "CWE-122": "A06",
    "CWE-126": "A06",
    "CWE-416": "A06",
    "CWE-287": "A07",
    "CWE-306": "A01",
    "CWE-307": "A07",
    "CWE-384": "A07",
    "CWE-521": "A07",
    "CWE-798": "A07",
    "CWE-426": "A08",
    "CWE-502": "A08",
    "CWE-400": "A05",
    "CWE-444": "A05",
    "CWE-362": "A04",
    "CWE-918": "A10",
}


class TaxonomyMapper:
    """Maps findings to OWASP Top 10, CWE, and CAPEC classifications."""

    def map_cwe(self, cwe_id: str) -> dict[str, str] | None:
        """Map a CWE ID (e.g. 'CWE-89' or '89') to its OWASP Top 10 category."""
        norm = cwe_id.strip().upper()
        if norm.isdigit():
            norm = f"CWE-{norm}"
        cat_id = CWE_TO_OWASP.get(norm)
        if not cat_id:
            return None
        return {
            "cwe": norm,
            "owasp": f"{cat_id} — {self.get_owasp_name(cat_id)}",
            "owasp_id": cat_id,
        }

    def classify_owasp(self, title: str, description: str = "") -> str:
        """Return the most likely OWASP Top 10 category ID (e.g., 'A03')."""
        raw = f"{title} {description}".lower()
        normalized = re.sub(r"[-_]+", " ", raw)
        best_match = ""
        best_score = 0
        for cat_id, cat_data in OWASP_TOP_10_2021.items():
            keywords = cat_data["keywords"].split(",")
            score = 0
            for kw in keywords:
                k = kw.strip().lower()
                if not k:
                    continue
                k_norm = re.sub(r"[-_]+", " ", k)
                pattern = r"\b" + re.escape(k_norm) + r"\b"
                if re.search(pattern, normalized) or re.search(r"\b" + re.escape(k) + r"\b", raw):
                    score += 1
            if score > best_score:
                best_score = score
                best_match = cat_id
        return best_match

    def get_owasp_name(self, cat_id: str) -> str:
        entry = OWASP_TOP_10_2021.get(cat_id, {})
        return entry.get("name", "Unknown")

    def classify_cwe(self, vuln_type: str) -> str:
        """Return the CWE ID for a vulnerability type."""
        key = vuln_type.lower().strip().replace(" ", "_").replace("-", "_")
        return CWE_MAP.get(key, "")

    def map_finding(self, finding: Any) -> str:
        """Return formatted OWASP Top 10 category string for a Finding or dict."""
        cwe_id = (
            finding.get("cwe_id", "")
            if isinstance(finding, dict)
            else getattr(finding, "cwe_id", "")
        )
        title = (
            finding.get("title", "") if isinstance(finding, dict) else getattr(finding, "title", "")
        )
        desc = (
            finding.get("description", "")
            if isinstance(finding, dict)
            else getattr(finding, "description", "")
        )
        if cwe_id:
            mapped = self.map_cwe(str(cwe_id))
            if mapped:
                return mapped.get("owasp", "")
        cat_id = self.classify_owasp(str(title), str(desc))
        if cat_id:
            return f"{cat_id} — {self.get_owasp_name(cat_id)}"
        return ""

    def classify_finding(
        self, title: str, description: str = "", vuln_type: str = ""
    ) -> dict[str, str]:
        """Full classification of a finding."""
        owasp = self.classify_owasp(title, description)
        cwe = self.classify_cwe(vuln_type) if vuln_type else ""
        if not cwe:
            title_norm = re.sub(r"[-_]+", " ", title.lower())
            # Prefer longest keyword match with word boundaries
            for key in sorted(CWE_MAP, key=len, reverse=True):
                phrase = key.replace("_", " ")
                if re.search(r"\b" + re.escape(phrase) + r"\b", title_norm):
                    cwe = CWE_MAP[key]
                    break
        return {
            "owasp_category": owasp,
            "owasp_name": self.get_owasp_name(owasp),
            "cwe_id": cwe,
        }

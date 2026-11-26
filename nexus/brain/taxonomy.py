"""OWASP / CWE / CAPEC taxonomy mapper for automatic finding classification."""

from __future__ import annotations

import re
from typing import Any

OWASP_TOP_10_2021: dict[str, dict[str, str]] = {
    "A01": {
        "name": "Broken Access Control",
        "keywords": (
            "idor,bola,privilege,authorization,access control,directory traversal,"
            "path traversal,insecure direct object,csrf,cross-site request forgery,"
            "open redirect,cors,wildcard origin,exposed git,exposed env,dotenv,"
            "unauthenticated access,missing authentication,tabnabbing,noopener,"
            "improper permission,forced browsing,privilege escalation,information disclosure"
        ),
    },
    "A02": {
        "name": "Cryptographic Failures",
        "keywords": (
            "ssl,tls,cipher,encryption,certificate,cleartext,plaintext,weak crypto,"
            "hashing,md5,sha1,hsts,strict-transport-security,weak cipher,rc4,3des,"
            "padding oracle,weak prng,predictable random,unencrypted,mixed content,"
            "self-signed,expired certificate,sslv2,sslv3,tls 1.0,tls 1.1,"
            "protocol downgrade,jwt signature,unsigned jwt,cleartext password,plaintext password"
        ),
    },
    "A03": {
        "name": "Injection",
        "keywords": (
            "sqli,sql injection,xss,cross-site scripting,command injection,os command,"
            "ldap injection,xpath,template injection,ssti,nosql injection,code injection,"
            "crlf injection,http response splitting,prototype pollution,expression language,"
            "el injection,ognl,spel,dom sink,html injection,lfi,rfi,file inclusion"
        ),
    },
    "A04": {
        "name": "Insecure Design",
        "keywords": (
            "business logic,design flaw,threat model,abuse case,race condition,toctou,"
            "unrestricted upload,file upload,clickjacking,x-frame-options,frame-ancestors,"
            "rate limit,rate limiting,insufficient anti-automation,workflow bypass,"
            "client-side enforcement,fail open,security through obscurity,parameter tampering"
        ),
    },
    "A05": {
        "name": "Security Misconfiguration",
        "keywords": (
            "default credentials,default password,unnecessary features,error messages,"
            "directory listing,debug,stack trace,misconfiguration,open port,xxe,"
            "xml external entity,http smuggling,request smuggling,security header,"
            "missing header,csp,content-security-policy,nosniff,x-content-type-options,"
            "httponly,samesite,cache-control,browser cache,source map,html comment,"
            "verbose error,x-powered-by,billion laughs,resource exhaustion"
        ),
    },
    "A06": {
        "name": "Vulnerable Components",
        "keywords": (
            "cve,outdated,vulnerable version,component,library,dependency,supply chain,"
            "end-of-life,unsupported version,unpatched,vulnerable plugin,"
            "outdated library,deprecated component,known vulnerability"
        ),
    },
    "A07": {
        "name": "Identification and Authentication",
        "keywords": (
            "authentication,brute force,credential stuffing,password,session,weak password,"
            "multi-factor,mfa,hardcoded credential,hard-coded credential,hardcoded secret,"
            "session fixation,session timeout,session expiration,password reset,"
            "unsalted hash,ip spoofing,authentication bypass,account lockout,smb signing"
        ),
    },
    "A08": {
        "name": "Software and Data Integrity",
        "keywords": (
            "deserialization,ci/cd,integrity,unsigned,untrusted data,subresource integrity,"
            "sri,dll hijacking,untrusted search path,mass assignment,insecure update,"
            "code signing,unverified download,third-party script"
        ),
    },
    "A09": {
        "name": "Security Logging and Monitoring",
        "keywords": (
            "logging,monitoring,audit,detection,alerting,insufficient logging,"
            "log injection,log forging,sensitive data in logs,missing logs,excessive logging"
        ),
    },
    "A10": {
        "name": "Server-Side Request Forgery",
        "keywords": (
            "ssrf,server-side request,server-side request forgery,internal service,"
            "metadata endpoint,cloud metadata,open proxy,confused deputy"
        ),
    },
}

# Common CWE mappings for penetration testing and passive security findings
CWE_MAP: dict[str, str] = {
    # A01 — Broken Access Control
    "path_traversal": "CWE-22",
    "directory_traversal": "CWE-22",
    "information_disclosure": "CWE-200",
    "sensitive_data_exposure": "CWE-200",
    "graphql_introspection": "CWE-200",
    "privilege_escalation": "CWE-269",
    "improper_privilege_management": "CWE-269",
    "incorrect_default_permissions": "CWE-276",
    "null_session": "CWE-284",
    "anonymous_access": "CWE-284",
    "improper_access_control": "CWE-284",
    "link_following": "CWE-59",
    "symlink_traversal": "CWE-59",
    "missing_authentication": "CWE-306",
    "unauthenticated_endpoint": "CWE-306",
    "csrf": "CWE-352",
    "cross_site_request_forgery": "CWE-352",
    "forced_browsing": "CWE-425",
    "direct_request": "CWE-425",
    "exposed_git": "CWE-538",
    "exposed_env": "CWE-538",
    "sensitive_file_exposure": "CWE-538",
    "open_redirect": "CWE-601",
    "idor": "CWE-639",
    "bola": "CWE-639",
    "exposed_resource_wrong_sphere": "CWE-668",
    "incorrect_permission_assignment": "CWE-732",
    "missing_authorization": "CWE-862",
    "incorrect_authorization": "CWE-863",
    "cors_misconfiguration": "CWE-942",
    "permissive_cors": "CWE-942",
    "reverse_tabnabbing": "CWE-1022",
    "missing_noopener": "CWE-1022",
    # A02 — Cryptographic Failures
    "improper_certificate_validation": "CWE-295",
    "invalid_certificate": "CWE-295",
    "expired_certificate": "CWE-295",
    "missing_encryption": "CWE-311",
    "cleartext_storage": "CWE-312",
    "cleartext_cookie": "CWE-315",
    "cleartext_transmission": "CWE-319",
    "mixed_content": "CWE-319",
    "hardcoded_cryptographic_key": "CWE-321",
    "weak_ssl": "CWE-326",
    "weak_encryption_strength": "CWE-326",
    "weak_tls_protocol": "CWE-326",
    "broken_crypto": "CWE-327",
    "weak_cipher": "CWE-327",
    "weak_hash": "CWE-328",
    "weak_randomness": "CWE-330",
    "weak_prng": "CWE-330",
    "improper_signature_verification": "CWE-347",
    "jwt_signature_bypass": "CWE-347",
    "unprotected_credential_transport": "CWE-523",
    "missing_hsts": "CWE-523",
    "cookie_without_secure_flag": "CWE-614",
    "missing_secure_cookie": "CWE-614",
    "algorithm_downgrade": "CWE-757",
    "protocol_downgrade": "CWE-757",
    # A03 — Injection
    "improper_input_validation": "CWE-20",
    "generic_injection": "CWE-74",
    "command_injection": "CWE-78",
    "os_command_injection": "CWE-78",
    "xss": "CWE-79",
    "cross_site_scripting": "CWE-79",
    "reflected_xss": "CWE-79",
    "stored_xss": "CWE-79",
    "dom_xss": "CWE-79",
    "dom_sink": "CWE-79",
    "sqli": "CWE-89",
    "sql_injection": "CWE-89",
    "ldap_injection": "CWE-90",
    "rce": "CWE-94",
    "remote_code_execution": "CWE-94",
    "code_injection": "CWE-94",
    "lfi": "CWE-98",
    "rfi": "CWE-98",
    "file_inclusion": "CWE-98",
    "crlf_injection": "CWE-113",
    "http_response_splitting": "CWE-113",
    "improper_output_encoding": "CWE-116",
    "xpath_injection": "CWE-643",
    "el_injection": "CWE-917",
    "expression_language_injection": "CWE-917",
    "nosql_injection": "CWE-943",
    "prototype_pollution": "CWE-1321",
    "ssti": "CWE-1336",
    "template_injection": "CWE-1336",
    # A04 — Insecure Design
    "integer_overflow": "CWE-190",
    "race_condition": "CWE-362",
    "toctou_race": "CWE-362",
    "toctou_filesystem_race": "CWE-367",
    "file_upload": "CWE-434",
    "unrestricted_upload": "CWE-434",
    "parameter_tampering": "CWE-472",
    "client_side_enforcement": "CWE-602",
    "reachable_assertion": "CWE-617",
    "fail_open": "CWE-636",
    "client_controlled_state": "CWE-642",
    "security_through_obscurity": "CWE-656",
    "unbounded_resource_allocation": "CWE-770",
    "missing_rate_limiting": "CWE-799",
    "business_logic_error": "CWE-840",
    "workflow_bypass": "CWE-841",
    "clickjacking": "CWE-1021",
    "missing_x_frame_options": "CWE-1021",
    # A05 — Security Misconfiguration
    "security_misconfiguration": "CWE-16",
    "verbose_error_message": "CWE-209",
    "stack_trace_disclosure": "CWE-209",
    "debug_info_disclosure": "CWE-215",
    "resource_exhaustion": "CWE-400",
    "http_request_smuggling": "CWE-444",
    "active_debug_code": "CWE-489",
    "debug_mode_enabled": "CWE-489",
    "sensitive_data_cached": "CWE-524",
    "browser_cache_sensitive_data": "CWE-525",
    "secret_in_env_var": "CWE-526",
    "source_map_exposed": "CWE-540",
    "directory_listing": "CWE-548",
    "xxe": "CWE-611",
    "xml_injection": "CWE-611",
    "sensitive_html_comment": "CWE-615",
    "missing_security_headers": "CWE-693",
    "missing_csp": "CWE-693",
    "weak_csp": "CWE-693",
    "missing_nosniff": "CWE-693",
    "xml_entity_expansion": "CWE-776",
    "missing_httponly_cookie": "CWE-1004",
    "cookie_without_httponly": "CWE-1004",
    "improper_samesite_cookie": "CWE-1275",
    "default_credentials": "CWE-1393",
    "default_password": "CWE-1393",
    # A06 — Vulnerable and Outdated Components
    "buffer_overflow": "CWE-120",
    "stack_buffer_overflow": "CWE-121",
    "heap_overflow": "CWE-122",
    "out_of_bounds_read": "CWE-125",
    "buffer_over_read": "CWE-126",
    "off_by_one_error": "CWE-193",
    "use_after_free": "CWE-416",
    "out_of_bounds_write": "CWE-787",
    "type_confusion": "CWE-843",
    "outdated_component": "CWE-1104",
    "unmaintained_component": "CWE-1104",
    "vulnerable_dependency": "CWE-1395",
    # A07 — Identification and Authentication Failures
    "plaintext_password_storage": "CWE-256",
    "broken_auth": "CWE-287",
    "improper_authentication": "CWE-287",
    "auth_bypass_spoofing": "CWE-290",
    "smb_signing_disabled": "CWE-300",
    "channel_accessible_by_non_endpoint": "CWE-300",
    "brute_force": "CWE-307",
    "credential_stuffing": "CWE-307",
    "session_fixation": "CWE-384",
    "weak_password": "CWE-521",
    "insufficiently_protected_credentials": "CWE-522",
    "sensitive_data_in_get_query": "CWE-598",
    "insufficient_session_expiration": "CWE-613",
    "unverified_password_change": "CWE-620",
    "weak_password_recovery": "CWE-640",
    "unsalted_hash": "CWE-759",
    "hardcoded_credentials": "CWE-798",
    # A08 — Software and Data Integrity Failures
    "insufficient_data_authenticity": "CWE-345",
    "missing_sri": "CWE-353",
    "missing_integrity_check": "CWE-353",
    "untrusted_search_path": "CWE-426",
    "dll_hijacking": "CWE-426",
    "unverified_code_download": "CWE-494",
    "deserialization": "CWE-502",
    "untrusted_external_inclusion": "CWE-829",
    "mass_assignment": "CWE-915",
    # A09 — Security Logging and Monitoring Failures
    "log_injection": "CWE-117",
    "omission_of_security_log_info": "CWE-223",
    "sensitive_info_in_logs": "CWE-532",
    "insufficient_logging": "CWE-778",
    "excessive_logging": "CWE-779",
    # A10 — Server-Side Request Forgery
    "confused_deputy": "CWE-441",
    "externally_controlled_resource_reference": "CWE-610",
    "ssrf": "CWE-918",
    "server_side_request_forgery": "CWE-918",
}


# CWE -> OWASP Top 10:2021 mapping
CWE_TO_OWASP: dict[str, str] = {
    # A01 — Broken Access Control
    "CWE-22": "A01",
    "CWE-59": "A01",
    "CWE-200": "A01",
    "CWE-269": "A01",
    "CWE-276": "A01",
    "CWE-284": "A01",
    "CWE-306": "A01",
    "CWE-352": "A01",
    "CWE-425": "A01",
    "CWE-538": "A01",
    "CWE-601": "A01",
    "CWE-639": "A01",
    "CWE-668": "A01",
    "CWE-732": "A01",
    "CWE-862": "A01",
    "CWE-863": "A01",
    "CWE-942": "A01",
    "CWE-1022": "A01",
    # A02 — Cryptographic Failures
    "CWE-295": "A02",
    "CWE-311": "A02",
    "CWE-312": "A02",
    "CWE-315": "A02",
    "CWE-319": "A02",
    "CWE-321": "A02",
    "CWE-326": "A02",
    "CWE-327": "A02",
    "CWE-328": "A02",
    "CWE-330": "A02",
    "CWE-347": "A02",
    "CWE-523": "A02",
    "CWE-614": "A02",
    "CWE-757": "A02",
    # A03 — Injection
    "CWE-20": "A03",
    "CWE-74": "A03",
    "CWE-78": "A03",
    "CWE-79": "A03",
    "CWE-89": "A03",
    "CWE-90": "A03",
    "CWE-94": "A03",
    "CWE-98": "A03",
    "CWE-113": "A03",
    "CWE-116": "A03",
    "CWE-643": "A03",
    "CWE-917": "A03",
    "CWE-943": "A03",
    "CWE-1321": "A03",
    "CWE-1336": "A03",
    # A04 — Insecure Design
    "CWE-190": "A04",
    "CWE-362": "A04",
    "CWE-367": "A04",
    "CWE-434": "A04",
    "CWE-472": "A04",
    "CWE-602": "A04",
    "CWE-617": "A04",
    "CWE-636": "A04",
    "CWE-642": "A04",
    "CWE-656": "A04",
    "CWE-770": "A04",
    "CWE-799": "A04",
    "CWE-840": "A04",
    "CWE-841": "A04",
    "CWE-1021": "A04",
    # A05 — Security Misconfiguration
    "CWE-16": "A05",
    "CWE-209": "A05",
    "CWE-215": "A05",
    "CWE-400": "A05",
    "CWE-444": "A05",
    "CWE-489": "A05",
    "CWE-524": "A05",
    "CWE-525": "A05",
    "CWE-526": "A05",
    "CWE-540": "A05",
    "CWE-548": "A05",
    "CWE-611": "A05",
    "CWE-615": "A05",
    "CWE-693": "A05",
    "CWE-776": "A05",
    "CWE-1004": "A05",
    "CWE-1275": "A05",
    "CWE-1393": "A05",
    # A06 — Vulnerable Components
    "CWE-120": "A06",
    "CWE-121": "A06",
    "CWE-122": "A06",
    "CWE-125": "A06",
    "CWE-126": "A06",
    "CWE-193": "A06",
    "CWE-416": "A06",
    "CWE-787": "A06",
    "CWE-843": "A06",
    "CWE-1104": "A06",
    "CWE-1395": "A06",
    # A07 — Identification and Authentication
    "CWE-256": "A07",
    "CWE-287": "A07",
    "CWE-290": "A07",
    "CWE-300": "A07",
    "CWE-307": "A07",
    "CWE-384": "A07",
    "CWE-521": "A07",
    "CWE-522": "A07",
    "CWE-598": "A07",
    "CWE-613": "A07",
    "CWE-620": "A07",
    "CWE-640": "A07",
    "CWE-759": "A07",
    "CWE-798": "A07",
    # A08 — Software and Data Integrity
    "CWE-345": "A08",
    "CWE-353": "A08",
    "CWE-426": "A08",
    "CWE-494": "A08",
    "CWE-502": "A08",
    "CWE-829": "A08",
    "CWE-915": "A08",
    # A09 — Security Logging and Monitoring
    "CWE-117": "A09",
    "CWE-223": "A09",
    "CWE-532": "A09",
    "CWE-778": "A09",
    "CWE-779": "A09",
    # A10 — Server-Side Request Forgery
    "CWE-441": "A10",
    "CWE-610": "A10",
    "CWE-918": "A10",
}


class TaxonomyMapper:
    """Maps findings to OWASP Top 10, CWE, and CAPEC classifications."""

    def map_cwe(self, cwe_id: str) -> dict[str, str] | None:
        """Map a CWE ID (e.g. 'CWE-89', 'cwe-89', or '89') to its OWASP Top 10 category."""
        if not cwe_id:
            return None
        match = re.match(r"^(?:CWE[-_\s]*)?(\d+)$", str(cwe_id).strip(), re.IGNORECASE)
        if not match:
            return None
        norm = f"CWE-{int(match.group(1))}"
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
        if not owasp and cwe:
            mapped = self.map_cwe(cwe)
            if mapped:
                owasp = mapped["owasp_id"]
        return {
            "owasp_category": owasp,
            "owasp_name": self.get_owasp_name(owasp),
            "cwe_id": cwe,
        }

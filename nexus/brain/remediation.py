"""Remediation knowledge base — per-CWE and per-CVE fix guidance."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

import yaml

log = logging.getLogger("nexus.brain.remediation")


@dataclass
class Remediation:
    """Fix guidance for a vulnerability class or specific CVE."""

    id: str  # CWE-89, CVE-2021-44228, etc.
    title: str
    severity: str = "high"
    short_fix: str = ""  # One-line fix summary
    detailed_fix: str = ""  # Multi-paragraph remediation
    references: list[str] = field(default_factory=list)
    code_examples: dict[str, str] = field(default_factory=dict)  # language → example
    tags: list[str] = field(default_factory=list)


# Tuple layout: (id, title, severity, short_fix, detailed_fix, tags)
_ADDITIONAL_CWE_DEFS: tuple[tuple[str, str, str, str, str, tuple[str, ...]], ...] = (
    # A01 — Broken Access Control
    (
        "CWE-276",
        "Incorrect Default Permissions",
        "medium",
        "Set restrictive default permissions (umask, ACLs) and enforce least privilege.",
        (
            "Overly permissive default permissions expose sensitive files, directories, "
            "or IPC resources to unauthorized local actors.\n\n"
            "**Primary Fix:** Configure restrictive umask and explicit ACLs during "
            "installation so configuration and runtime artifacts follow least privilege.\n\n"
            "**Secondary:** Automate permission and CIS baseline checks in deployment pipelines."
        ),
        ("permissions", "access-control", "owasp-a01"),
    ),
    (
        "CWE-284",
        "Improper Access Control",
        "high",
        "Enforce deny-by-default server-side authorization checks on every resource.",
        (
            "Insufficient access controls allow unauthorized actors to read or modify "
            "protected functionality or resources.\n\n"
            "**Primary Fix:** Centralize authorization enforcement using deny-by-default "
            "policies across all routes, RPC handlers, and network services.\n\n"
            "**Secondary:** Disable anonymous/null sessions and verify role and tenant scope."
        ),
        ("access-control", "authorization", "owasp-a01"),
    ),
    (
        "CWE-425",
        "Direct Request (Forced Browsing)",
        "medium",
        "Require server-side authorization on all routes; remove unlinked sensitive files.",
        (
            "Relying on hidden or unlinked URLs allows attackers to access administrative "
            "pages, backups, or internal files directly.\n\n"
            "**Primary Fix:** Apply authentication and authorization middleware globally "
            "across every route and static/dynamic asset.\n\n"
            "**Secondary:** Store internal or temporary files outside the webroot."
        ),
        ("access-control", "forced-browsing", "owasp-a01"),
    ),
    (
        "CWE-538",
        "Exposed Sensitive File or Repository (.git / .env / Backup)",
        "high",
        "Block access to VCS metadata (.git), .env files, and backups; rotate secrets.",
        (
            "Publicly accessible dotfiles, version-control directories, or backup files "
            "can expose source code, database credentials, and API keys.\n\n"
            "**Primary Fix:** Deny HTTP access to hidden files/directories (e.g., /.git, "
            "/.env) at the reverse proxy and exclude dev artifacts from deployments.\n\n"
            "**Secondary:** Rotate any credentials found in exposed files immediately."
        ),
        ("exposure", "secrets", "access-control", "owasp-a01"),
    ),
    (
        "CWE-601",
        "Open Redirect (URL Redirection to Untrusted Site)",
        "medium",
        "Validate redirect destinations against an allowlist of relative paths or domains.",
        (
            "Unvalidated user-controlled redirect URLs enable phishing and token leakage.\n\n"
            "**Primary Fix:** Restrict redirect targets to safe local relative paths or an "
            "explicit allowlist of trusted origins.\n\n"
            "**Secondary:** Use indirect route keys instead of raw URLs in parameters."
        ),
        ("redirect", "access-control", "owasp-a01"),
    ),
    (
        "CWE-639",
        "Insecure Direct Object Reference (IDOR / BOLA)",
        "high",
        "Verify object ownership and authorization server-side for every resource ID.",
        (
            "Exposing predictable or user-supplied identifiers without ownership checks "
            "allows access to other users' or tenants' records.\n\n"
            "**Primary Fix:** Scope every data lookup to the authenticated principal and "
            "check object-level permissions server-side on every read and write.\n\n"
            "**Secondary:** Use non-enumerable UUIDs alongside strict authorization tests."
        ),
        ("idor", "bola", "authorization", "owasp-a01"),
    ),
    (
        "CWE-862",
        "Missing Authorization",
        "high",
        "Require explicit server-side authorization checks on every sensitive endpoint.",
        (
            "Endpoints lacking authorization checks allow any authenticated or anonymous "
            "caller to invoke privileged operations.\n\n"
            "**Primary Fix:** Enforce centralized deny-by-default authorization middleware "
            "on all API endpoints and administrative controllers.\n\n"
            "**Secondary:** Add automated negative tests verifying unauthorized access fails."
        ),
        ("authorization", "access-control", "owasp-a01"),
    ),
    (
        "CWE-863",
        "Incorrect Authorization",
        "high",
        "Verify role, scope, tenant, and HTTP method checks accurately on every action.",
        (
            "Flawed authorization conditions can let lower-privileged users perform "
            "administrative actions or bypass method/path restrictions.\n\n"
            "**Primary Fix:** Standardize RBAC/ABAC policy evaluation so role, tenant, "
            "and HTTP method permissions are enforced consistently.\n\n"
            "**Secondary:** Cover edge cases and alternate methods in authorization tests."
        ),
        ("authorization", "access-control", "owasp-a01"),
    ),
    (
        "CWE-942",
        "Permissive Cross-Domain Policy (CORS)",
        "medium",
        "Allowlist trusted CORS origins explicitly; never combine * with credentials.",
        (
            "Wildcard or blindly reflected Access-Control-Allow-Origin headers allow "
            "untrusted origins to read sensitive authenticated API responses.\n\n"
            "**Primary Fix:** Validate the Origin header against an exact allowlist of "
            "trusted domains and set Vary: Origin.\n\n"
            "**Secondary:** Never return Access-Control-Allow-Credentials: true with "
            "wildcard or unvalidated origins."
        ),
        ("cors", "headers", "access-control", "owasp-a01"),
    ),
    (
        "CWE-1022",
        "Reverse Tabnabbing (target=_blank Without rel=noopener)",
        "low",
        "Add rel='noopener noreferrer' to external links opening with target='_blank'.",
        (
            "External links opened with target='_blank' without rel='noopener' can expose "
            "window.opener in older browsers, enabling navigation tampering.\n\n"
            "**Primary Fix:** Add rel='noopener noreferrer' on all target='_blank' anchors.\n\n"
            "**Secondary:** Enforce Cross-Origin-Opener-Policy headers for stronger isolation."
        ),
        ("tabnabbing", "client-side", "owasp-a01"),
    ),
    # A02 — Cryptographic Failures
    (
        "CWE-295",
        "Improper TLS Certificate Validation",
        "medium",
        "Enforce full certificate chain and hostname verification; replace expired certs.",
        (
            "Untrusted, self-signed, expired, or unverified TLS certificates expose "
            "connections to interception and impersonation.\n\n"
            "**Primary Fix:** Enable strict CA chain and hostname validation across all "
            "clients and deploy valid CA-signed certificates with automated renewal.\n\n"
            "**Secondary:** Remove any disabled-verification flags (e.g., verify=False)."
        ),
        ("tls", "certificate", "crypto", "owasp-a02"),
    ),
    (
        "CWE-312",
        "Cleartext Storage of Sensitive Information",
        "high",
        "Encrypt sensitive data at rest with AES-256-GCM and store keys in a KMS/vault.",
        (
            "Storing PII, tokens, or secrets in plaintext inside databases, files, or "
            "mobile/client storage risks exposure if storage is compromised.\n\n"
            "**Primary Fix:** Encrypt sensitive fields at rest using authenticated "
            "encryption (AES-256-GCM or ChaCha20-Poly1305) with managed KMS keys.\n\n"
            "**Secondary:** Minimize retained sensitive data and purge unused secrets."
        ),
        ("encryption", "storage", "crypto", "owasp-a02"),
    ),
    (
        "CWE-315",
        "Cleartext Sensitive Information in Cookie",
        "medium",
        "Store only opaque high-entropy session tokens in cookies, never raw PII/secrets.",
        (
            "Placing sensitive attributes or credentials directly in browser cookies "
            "exposes them to local inspection and tampering.\n\n"
            "**Primary Fix:** Keep sensitive user state on the server behind an opaque "
            "CSPRNG session ID, or encrypt/authenticate cookie contents server-side.\n\n"
            "**Secondary:** Pair session cookies with Secure, HttpOnly, and SameSite flags."
        ),
        ("cookie", "encryption", "crypto", "owasp-a02"),
    ),
    (
        "CWE-319",
        "Cleartext Transmission of Sensitive Information",
        "high",
        "Enforce HTTPS/TLS 1.2+ on all endpoints, forms, APIs, and embedded assets.",
        (
            "Sending credentials, tokens, or sensitive payloads over plaintext HTTP or "
            "unencrypted database/mail protocols permits passive eavesdropping.\n\n"
            "**Primary Fix:** Enforce TLS 1.2+ everywhere, eliminate mixed-content HTTP "
            "scripts/iframes, and enable TLS/STARTTLS on backend services.\n\n"
            "**Secondary:** Redirect HTTP traffic to HTTPS and enable HSTS."
        ),
        ("tls", "cleartext", "mixed-content", "owasp-a02"),
    ),
    (
        "CWE-326",
        "Inadequate Encryption Strength / Deprecated Protocols",
        "medium",
        "Disable SSLv2/v3, TLS 1.0/1.1, SMBv1, and weak ciphers; require TLS 1.2+/1.3.",
        (
            "Short keys or deprecated protocol versions (TLS 1.0/1.1, SSLv3, SMBv1, "
            "weak SSH KEX/MACs) weaken confidentiality and integrity guarantees.\n\n"
            "**Primary Fix:** Allow only TLS 1.2/1.3 with ECDHE AEAD cipher suites, "
            ">=2048-bit RSA or P-256+ ECDSA keys, and hardened SSH algorithms.\n\n"
            "**Secondary:** Re-audit TLS/SSH configurations automatically in CI."
        ),
        ("tls", "ssh", "crypto", "owasp-a02"),
    ),
    (
        "CWE-327",
        "Use of Broken or Risky Cryptographic Algorithm",
        "medium",
        "Replace RC4, DES, 3DES, ECB mode, and MD5/SHA-1 signatures with AES-GCM/SHA-256.",
        (
            "Broken ciphers and modes allow plaintext recovery, bit-flipping, or forgery.\n\n"
            "**Primary Fix:** Migrate to modern standardized AEAD primitives "
            "(AES-256-GCM or ChaCha20-Poly1305) and SHA-256+ or Ed25519.\n\n"
            "**Secondary:** Use high-level vetted libraries rather than custom primitives."
        ),
        ("crypto", "cipher", "owasp-a02"),
    ),
    (
        "CWE-328",
        "Use of Weak Hash Algorithm",
        "medium",
        "Replace MD5 and SHA-1 with SHA-256/SHA-3 for digests and Argon2id for passwords.",
        (
            "Collision-prone hash algorithms (MD4, MD5, SHA-1) are unsuitable for "
            "digital signatures, integrity verification, or credential protection.\n\n"
            "**Primary Fix:** Use SHA-256/SHA-512 for integrity checks and Argon2id or "
            "bcrypt for password hashing.\n\n"
            "**Secondary:** Deprecate legacy hash validation paths after migration."
        ),
        ("hashing", "crypto", "owasp-a02"),
    ),
    (
        "CWE-330",
        "Insufficiently Random Values / Weak PRNG",
        "medium",
        "Use a CSPRNG (secrets, crypto.randomBytes, SecureRandom) for tokens and nonces.",
        (
            "Predictable tokens generated via standard PRNGs or timestamps allow "
            "session hijacking or reset-token guessing.\n\n"
            "**Primary Fix:** Generate all session IDs, API keys, CSRF tokens, and "
            "nonces with a cryptographic PRNG providing >=128 bits of entropy.\n\n"
            "**Secondary:** Never seed randomness from predictable inputs like time or PID."
        ),
        ("randomness", "crypto", "tokens", "owasp-a02"),
    ),
    (
        "CWE-347",
        "Improper Verification of Cryptographic Signature",
        "high",
        "Strictly verify cryptographic signatures (JWT/SAML) using explicit allowed algs.",
        (
            "Failing to verify signatures or permitting algorithm confusion (such as "
            "JWT 'alg: none' or RS256-to-HS256) allows forged tokens.\n\n"
            "**Primary Fix:** Pin expected verification algorithms server-side and enforce "
            "signature verification before trusting any token claims.\n\n"
            "**Secondary:** Rotate signing keys regularly and validate issuer/audience."
        ),
        ("signature", "jwt", "crypto", "owasp-a02"),
    ),
    (
        "CWE-523",
        "Unprotected Transport of Credentials / Missing HSTS",
        "medium",
        "Require TLS with Strict-Transport-Security (HSTS) for all credential traffic.",
        (
            "Missing HSTS or plaintext credential transport exposes login pages and "
            "authentication headers to protocol-downgrade interception.\n\n"
            "**Primary Fix:** Transmit credentials solely over HTTPS and send "
            "Strict-Transport-Security: max-age=31536000; includeSubDomains.\n\n"
            "**Secondary:** Configure HSTS preload and enforce TLS on mail/DB auth."
        ),
        ("hsts", "tls", "credentials", "owasp-a02"),
    ),
    (
        "CWE-614",
        "Sensitive Cookie Without 'Secure' Attribute",
        "medium",
        "Set the 'Secure' attribute on all session and auth cookies served over HTTPS.",
        (
            "Without the Secure flag, browsers may send sensitive session cookies over "
            "plaintext HTTP requests to the same domain.\n\n"
            "**Primary Fix:** Add Secure to every Set-Cookie header for session tokens.\n\n"
            "**Secondary:** Combine with HttpOnly, SameSite, and HSTS."
        ),
        ("cookie", "tls", "headers", "owasp-a02"),
    ),
    (
        "CWE-757",
        "Algorithm or Protocol Downgrade During Negotiation",
        "medium",
        "Disable legacy protocol/cipher fallback and require TLS 1.2+ or TLS 1.3.",
        (
            "Supporting weak cipher suites or legacy protocol fallbacks lets active "
            "network attackers force connections down to breakable cryptography.\n\n"
            "**Primary Fix:** Remove SSLv2/v3, TLS 1.0/1.1, and export/weak ciphers from "
            "server negotiation lists and enable TLS_FALLBACK_SCSV.\n\n"
            "**Secondary:** Prefer TLS 1.3 where supported by clients."
        ),
        ("tls", "downgrade", "crypto", "owasp-a02"),
    ),
    # A03 — Injection
    (
        "CWE-20",
        "Improper Input Validation",
        "medium",
        "Validate untrusted inputs server-side against strict allowlists and schemas.",
        (
            "Accepting malformed, out-of-range, or uncanonicalized inputs at trust "
            "boundaries enables injection and business-logic flaws.\n\n"
            "**Primary Fix:** Canonicalize inputs and validate type, length, range, and "
            "allowed character sets using strict schemas (e.g., Pydantic).\n\n"
            "**Secondary:** Reject invalid payloads cleanly rather than silently coercing."
        ),
        ("validation", "injection", "owasp-a03"),
    ),
    (
        "CWE-74",
        "Improper Neutralization of Special Elements (Injection)",
        "high",
        "Separate untrusted data from interpreter syntax using parameterized APIs.",
        (
            "Embedding unescaped user input into downstream parsers allows syntax "
            "breakout and unintended command or query execution.\n\n"
            "**Primary Fix:** Use structured, parameterized APIs for downstream "
            "interpreters and apply context-specific encoding where parameterization "
            "is unavailable.\n\n"
            "**Secondary:** Validate inputs against strict allowlists."
        ),
        ("injection", "owasp-a03"),
    ),
    (
        "CWE-90",
        "LDAP Injection",
        "high",
        "Escape LDAP filter/DN special characters and validate directory lookup inputs.",
        (
            "Constructing LDAP search filters or DNs via string concatenation allows "
            "attackers to alter directory queries and bypass authentication.\n\n"
            "**Primary Fix:** Use parameterized LDAP APIs or RFC 4515/4514 escaping for "
            "all untrusted values inserted into filters or distinguished names.\n\n"
            "**Secondary:** Restrict directory bind accounts to least privilege."
        ),
        ("ldap", "injection", "owasp-a03"),
    ),
    (
        "CWE-98",
        "Local / Remote File Inclusion (LFI / RFI)",
        "critical",
        "Map file/module selection to a fixed allowlist; never include user paths.",
        (
            "Dynamic file include/require calls with user-controlled paths can read "
            "arbitrary files or execute untrusted remote code.\n\n"
            "**Primary Fix:** Replace dynamic paths with indirect allowlist identifiers "
            "and disable remote URL file inclusion (allow_url_include=Off).\n\n"
            "**Secondary:** Canonicalize paths and verify containment in base directory."
        ),
        ("file-inclusion", "lfi", "rfi", "owasp-a03"),
    ),
    (
        "CWE-113",
        "CRLF Injection / HTTP Response Splitting",
        "medium",
        "Reject or strip CR and LF control characters from HTTP header values.",
        (
            "Unvalidated CR (\\r) and LF (\\n) sequences in headers allow attackers to "
            "inject arbitrary response headers or split HTTP responses.\n\n"
            "**Primary Fix:** Reject inputs containing CR/LF or control characters before "
            "writing Location, Set-Cookie, or custom HTTP headers.\n\n"
            "**Secondary:** Rely on modern HTTP libraries that enforce header validation."
        ),
        ("crlf", "headers", "injection", "owasp-a03"),
    ),
    (
        "CWE-116",
        "Improper Output Encoding or Escaping",
        "medium",
        "Apply context-aware output encoding (HTML, JS, CSV, XML) via standard APIs.",
        (
            "Missing or mismatched encoding allows untrusted data to be interpreted as "
            "markup, formulas, or script by downstream consumers.\n\n"
            "**Primary Fix:** Use standard context-specific encoders and auto-escaping "
            "template engines rather than ad-hoc string replacement.\n\n"
            "**Secondary:** Neutralize formula prefixes in exported CSV/spreadsheet data."
        ),
        ("encoding", "injection", "owasp-a03"),
    ),
    (
        "CWE-643",
        "XPath Injection",
        "high",
        "Use parameterized XPath queries with variable bindings instead of concatenation.",
        (
            "Concatenating user input into XPath queries allows attackers to alter "
            "predicates and extract unauthorized XML nodes.\n\n"
            "**Primary Fix:** Use precompiled XPath expressions with bound variable "
            "resolvers or strict character allowlists.\n\n"
            "**Secondary:** Restrict XML data exposure by user role."
        ),
        ("xpath", "xml", "injection", "owasp-a03"),
    ),
    (
        "CWE-917",
        "Expression Language (EL / OGNL / SpEL) Injection",
        "critical",
        "Never evaluate user input as EL, OGNL, or SpEL; use restricted contexts.",
        (
            "Evaluating untrusted input in expression languages can trigger arbitrary "
            "server-side code execution.\n\n"
            "**Primary Fix:** Pass user data strictly as literal values rather than "
            "evaluating dynamic EL/SpEL/OGNL strings; use SimpleEvaluationContext.\n\n"
            "**Secondary:** Keep web frameworks patched against EL bypasses."
        ),
        ("el-injection", "rce", "injection", "owasp-a03"),
    ),
    (
        "CWE-943",
        "NoSQL / Data Query Logic Injection",
        "high",
        "Validate input types strictly (reject operator objects) and use safe ODM APIs.",
        (
            "Accepting unvalidated nested JSON/dict objects in NoSQL queries allows "
            "operator injection (e.g., $ne/$gt) and auth or filter bypass.\n\n"
            "**Primary Fix:** Enforce strict scalar input validation (schemas rejecting "
            "dict/operator keys) and avoid server-side JS query evaluation ($where).\n\n"
            "**Secondary:** Parameterize queries and apply least-privilege DB roles."
        ),
        ("nosql", "database", "injection", "owasp-a03"),
    ),
    (
        "CWE-1321",
        "Prototype Pollution",
        "high",
        "Block __proto__, constructor, and prototype keys during recursive merges.",
        (
            "Modifying JavaScript Object.prototype via recursive merge/path utilities "
            "can tamper with application logic, auth flags, or lead to XSS/RCE.\n\n"
            "**Primary Fix:** Reject __proto__, constructor, and prototype property keys "
            "in merge/clone helpers and use Map or Object.create(null) for lookups.\n\n"
            "**Secondary:** Upgrade vulnerable JS packages and freeze prototypes."
        ),
        ("prototype-pollution", "javascript", "injection", "owasp-a03"),
    ),
    (
        "CWE-1336",
        "Server-Side Template Injection (SSTI)",
        "critical",
        "Never compile user input as template source; pass values as context variables.",
        (
            "Concatenating untrusted input into server-side templates allows attackers "
            "to break out into template directives and execute arbitrary code.\n\n"
            "**Primary Fix:** Keep templates static and pass user input strictly as "
            "bound context variables with auto-escaping enabled.\n\n"
            "**Secondary:** Use sandboxed or logic-less templates where user layouts exist."
        ),
        ("ssti", "template", "rce", "owasp-a03"),
    ),
    # A04 — Insecure Design
    (
        "CWE-362",
        "Race Condition / Improper Synchronization",
        "high",
        "Use atomic DB transactions, row locks, and idempotency keys on state changes.",
        (
            "Concurrent requests exploiting check-then-act (TOCTOU) gaps can duplicate "
            "transfers, bypass quotas, or corrupt shared state.\n\n"
            "**Primary Fix:** Perform balance/quota checks and updates atomically inside "
            "serializable transactions or with row-level locks/compare-and-swap.\n\n"
            "**Secondary:** Require single-use idempotency keys on mutating endpoints."
        ),
        ("race-condition", "concurrency", "design", "owasp-a04"),
    ),
    (
        "CWE-472",
        "Tampering With Assumed-Immutable Web Parameter",
        "medium",
        "Re-derive authoritative prices, roles, and IDs server-side; ignore client copy.",
        (
            "Trusting hidden form fields, query parameters, or client fields for "
            "pricing or privilege decisions allows trivial tampering.\n\n"
            "**Primary Fix:** Store and recompute authoritative state server-side from "
            "database records rather than trusting round-tripped client parameters.\n\n"
            "**Secondary:** Sign any unavoidable client tokens with server-keyed HMAC."
        ),
        ("business-logic", "tampering", "design", "owasp-a04"),
    ),
    (
        "CWE-602",
        "Client-Side Enforcement of Server-Side Security",
        "high",
        "Enforce all validation, authorization, and business limits on the server.",
        (
            "Security checks implemented solely in browser JS or mobile apps can be "
            "bypassed easily via direct HTTP requests.\n\n"
            "**Primary Fix:** Re-validate every security constraint, role check, and "
            "workflow invariant inside server-side API handlers.\n\n"
            "**Secondary:** Treat client validation strictly as UX convenience."
        ),
        ("client-side", "design", "validation", "owasp-a04"),
    ),
    (
        "CWE-636",
        "Not Failing Securely (Fail-Open Behavior)",
        "high",
        "Default exception, timeout, and fallback handlers to deny access safely.",
        (
            "Failing open when a policy service times out or an exception occurs lets "
            "attackers force errors to bypass security controls.\n\n"
            "**Primary Fix:** Ensure auth, authorization, and validation logic deny by "
            "default on any error, timeout, or unexpected state.\n\n"
            "**Secondary:** Add unit tests covering dependency failure paths."
        ),
        ("fail-open", "design", "access-control", "owasp-a04"),
    ),
    (
        "CWE-642",
        "External Control of Critical State Data",
        "high",
        "Persist critical workflow and privilege state server-side or HMAC-protect it.",
        (
            "Storing unsigned workflow steps, roles, or feature flags in cookies or "
            "client storage lets attackers alter application state.\n\n"
            "**Primary Fix:** Store authoritative workflow/session state on the server "
            "and verify state transitions against persisted records.\n\n"
            "**Secondary:** Use authenticated encryption if state must live in tokens."
        ),
        ("state", "tampering", "design", "owasp-a04"),
    ),
    (
        "CWE-656",
        "Reliance on Security Through Obscurity",
        "low",
        "Rely on standard authentication and vetted cryptography instead of obfuscation.",
        (
            "Assuming hidden paths, proprietary encoding, or obfuscated client code "
            "provides security leaves assets exposed once discovered.\n\n"
            "**Primary Fix:** Protect sensitive routes and data with real server-side "
            "authentication, RBAC, and standard cryptography.\n\n"
            "**Secondary:** Never embed secrets in client bundles or obscure URLs."
        ),
        ("design", "obscurity", "owasp-a04"),
    ),
    (
        "CWE-770",
        "Allocation of Resources Without Limits or Throttling",
        "medium",
        "Enforce payload size caps, pagination bounds, timeouts, and per-client quotas.",
        (
            "Unbounded request sizes, page sizes, or expensive jobs allow single callers "
            "to exhaust server CPU, memory, or storage.\n\n"
            "**Primary Fix:** Cap upload sizes, array lengths, pagination limits, and "
            "per-user resource quotas before processing requests.\n\n"
            "**Secondary:** Set execution timeouts and circuit breakers."
        ),
        ("dos", "throttling", "design", "owasp-a04"),
    ),
    (
        "CWE-799",
        "Missing Rate Limiting / Interaction Frequency Control",
        "medium",
        "Apply per-IP, per-account, and per-token rate limits on auth and costly APIs.",
        (
            "Lacking rate limits permits automated credential stuffing, OTP brute-force, "
            "enumeration, and resource abuse.\n\n"
            "**Primary Fix:** Enforce sliding-window or token-bucket rate limiters at "
            "the API gateway and application layers.\n\n"
            "**Secondary:** Require step-up verification or lockout after abuse thresholds."
        ),
        ("rate-limiting", "anti-automation", "design", "owasp-a04"),
    ),
    (
        "CWE-840",
        "Business Logic Errors",
        "medium",
        "Validate domain invariants (positive amounts, valid states) server-side.",
        (
            "Missing domain checks (e.g., negative quantities, coupon stacking, or "
            "unbounded credits) enable financial or workflow abuse.\n\n"
            "**Primary Fix:** Enforce strict domain invariants and pre/post-conditions "
            "inside server-side business services.\n\n"
            "**Secondary:** Include abuse-case threat modeling and invariant unit tests."
        ),
        ("business-logic", "design", "owasp-a04"),
    ),
    (
        "CWE-841",
        "Improper Enforcement of Behavioral Workflow",
        "medium",
        "Validate sequential workflow state transitions with a server-side state machine.",
        (
            "Allowing out-of-order requests lets attackers skip verification, MFA, "
            "or payment steps in multi-step flows.\n\n"
            "**Primary Fix:** Track current workflow state server-side and reject any "
            "action whose required prior state has not completed.\n\n"
            "**Secondary:** Invalidate completed or stale workflow tokens immediately."
        ),
        ("workflow", "business-logic", "design", "owasp-a04"),
    ),
    # A05 — Security Misconfiguration
    (
        "CWE-16",
        "Security Misconfiguration",
        "medium",
        "Harden server/framework defaults, disable unused features, and verify baselines.",
        (
            "Insecure default settings, exposed admin consoles, or permissive server "
            "configurations unnecessarily expand the attack surface.\n\n"
            "**Primary Fix:** Apply CIS/vendor hardening baselines, disable unused ports "
            "and sample apps, and manage configuration declaratively.\n\n"
            "**Secondary:** Run automated configuration audits in CI/CD."
        ),
        ("misconfiguration", "hardening", "owasp-a05"),
    ),
    (
        "CWE-209",
        "Verbose Error Message / Stack Trace Disclosure",
        "medium",
        "Return generic error responses to clients; log stack traces securely on server.",
        (
            "Unhandled exception tracebacks, SQL errors, or Whitelabel pages reveal "
            "framework internals, file paths, and query structure.\n\n"
            "**Primary Fix:** Configure global exception handlers and custom error pages "
            "that return generic messages and correlation IDs to clients.\n\n"
            "**Secondary:** Restrict detailed trace logging to centralized internal logs."
        ),
        ("error-handling", "information-disclosure", "owasp-a05"),
    ),
    (
        "CWE-215",
        "Sensitive Information in Debugging Code",
        "medium",
        "Disable debug endpoints, profiling routes, and diagnostic dumps in production.",
        (
            "Diagnostic or profiling code left active in production leaks runtime "
            "internals, environment details, and request traces.\n\n"
            "**Primary Fix:** Remove debug handlers and profiling middleware from "
            "production builds or gate them behind internal network authentication.\n\n"
            "**Secondary:** Verify production environment configs in CI/CD."
        ),
        ("debug", "misconfiguration", "owasp-a05"),
    ),
    (
        "CWE-400",
        "Uncontrolled Resource Consumption (DoS)",
        "high",
        "Enforce request size limits, parser bounds, safe regexes, and timeouts.",
        (
            "Unrestricted memory, CPU, or socket consumption (e.g., ReDoS, slowloris, "
            "or zip bombs) allows denial of service.\n\n"
            "**Primary Fix:** Configure reverse-proxy body/header limits, connection "
            "timeouts, bounded decompression, and linear-time regex patterns.\n\n"
            "**Secondary:** Isolate heavy parsing tasks with resource quotas."
        ),
        ("dos", "resource-limits", "owasp-a05"),
    ),
    (
        "CWE-444",
        "HTTP Request Smuggling",
        "high",
        "Reject ambiguous Content-Length/Transfer-Encoding headers across proxies.",
        (
            "Discrepancies between front-end proxy and back-end server HTTP framing "
            "enable request smuggling, cache poisoning, and auth bypass.\n\n"
            "**Primary Fix:** Reject requests with duplicate Content-Length or mixed "
            "Content-Length/Transfer-Encoding headers and normalize HTTP parsing.\n\n"
            "**Secondary:** Upgrade proxies/servers and prefer end-to-end HTTP/2."
        ),
        ("http-smuggling", "proxy", "owasp-a05"),
    ),
    (
        "CWE-489",
        "Active Debug Code / Debug Mode Enabled in Production",
        "high",
        "Disable DEBUG mode (e.g., DEBUG=False) and interactive debug consoles in prod.",
        (
            "Leaving framework debug mode enabled exposes configuration, environment "
            "variables, stack traces, or interactive code consoles.\n\n"
            "**Primary Fix:** Enforce DEBUG=False and strip interactive debuggers in "
            "production configuration profiles.\n\n"
            "**Secondary:** Fail CI/CD release gates if debug settings are enabled."
        ),
        ("debug", "misconfiguration", "owasp-a05"),
    ),
    (
        "CWE-524",
        "Sensitive Information Stored in Shared Cache",
        "medium",
        "Set 'Cache-Control: no-store, private' on responses holding sensitive data.",
        (
            "Caching authenticated or PII-bearing responses in shared CDNs or proxies "
            "can expose one user's data to subsequent callers.\n\n"
            "**Primary Fix:** Emit Cache-Control: no-store, private and Vary headers on "
            "authenticated endpoints and sensitive API responses.\n\n"
            "**Secondary:** Audit CDN/reverse-proxy cache rules regularly."
        ),
        ("caching", "headers", "owasp-a05"),
    ),
    (
        "CWE-525",
        "Browser Cache Retaining Sensitive Information",
        "low",
        "Add 'Cache-Control: no-store' on sensitive forms and authenticated pages.",
        (
            "Allowing browsers to cache sensitive responses enables local recovery from "
            "shared devices or browser history.\n\n"
            "**Primary Fix:** Include Cache-Control: no-store and Pragma: no-cache on "
            "sensitive pages and credential forms.\n\n"
            "**Secondary:** Clear local client storage cleanly on logout."
        ),
        ("caching", "browser", "headers", "owasp-a05"),
    ),
    (
        "CWE-526",
        "Sensitive Information Exposed via Environment Variables",
        "medium",
        "Restrict diagnostic env endpoints and inject secrets via mounted secret stores.",
        (
            "Exposing process environment dumps (e.g., debug pages, actuator /env) "
            "leaks credentials and service tokens.\n\n"
            "**Primary Fix:** Disable unauthenticated env/diagnostic endpoints and pull "
            "secrets from a secret manager (Vault, cloud KMS) with minimal scope.\n\n"
            "**Secondary:** Mask sensitive keys in diagnostic telemetry."
        ),
        ("secrets", "environment", "misconfiguration", "owasp-a05"),
    ),
    (
        "CWE-540",
        "Sensitive Information or Source Maps in Client Assets",
        "low",
        "Exclude .map source maps and internal code/secrets from production bundles.",
        (
            "Publishing JavaScript source maps or internal artifacts reveals original "
            "unminified frontend source, API routes, and comments.\n\n"
            "**Primary Fix:** Disable public sourceMappingURL files in production builds "
            "or restrict .map uploads to private error-tracking systems.\n\n"
            "**Secondary:** Scan build artifacts for unintended internal strings."
        ),
        ("source-map", "exposure", "owasp-a05"),
    ),
    (
        "CWE-548",
        "Web Server Directory Listing Enabled",
        "medium",
        "Disable auto-generated directory indexes (Apache Options -Indexes, Nginx off).",
        (
            "Directory browsing exposes internal filenames, backups, and unlinked assets "
            "to automated discovery.\n\n"
            "**Primary Fix:** Disable directory indexing globally in web servers and "
            "static file handlers (Options -Indexes / autoindex off).\n\n"
            "**Secondary:** Return 403/404 when no index file is present."
        ),
        ("directory-listing", "misconfiguration", "owasp-a05"),
    ),
    (
        "CWE-615",
        "Sensitive Information in Source Code / HTML Comments",
        "low",
        "Strip developer comments with internal hosts, TODOs, or secrets in prod builds.",
        (
            "Comments left in HTML templates or client scripts can disclose internal "
            "endpoints, test accounts, or architecture details.\n\n"
            "**Primary Fix:** Configure HTML/JS build pipelines to strip comments and "
            "remove sensitive annotations from source templates.\n\n"
            "**Secondary:** Run secret scanning across source repositories."
        ),
        ("comments", "information-disclosure", "owasp-a05"),
    ),
    (
        "CWE-693",
        "Protection Mechanism Failure (Missing Security Headers / CSP)",
        "low",
        "Set strict CSP (no unsafe-inline/eval), X-Content-Type-Options: nosniff, etc.",
        (
            "Missing or overly permissive HTTP security headers weaken browser-side "
            "defense-in-depth against XSS, MIME sniffing, and data injection.\n\n"
            "**Primary Fix:** Enforce Content-Security-Policy without unsafe-inline or "
            "unsafe-eval, X-Content-Type-Options: nosniff, and Referrer-Policy.\n\n"
            "**Secondary:** Apply headers globally at the edge proxy or middleware."
        ),
        ("headers", "csp", "hardening", "owasp-a05"),
    ),
    (
        "CWE-776",
        "XML Entity Expansion (Billion Laughs DoS)",
        "high",
        "Disable DTD declarations and recursive entity expansion in XML parsers.",
        (
            "Nested recursive entity definitions in XML DTDs can amplify small payloads "
            "into massive memory consumption and server crashes.\n\n"
            "**Primary Fix:** Disallow DOCTYPE declarations (use defusedxml in Python) "
            "or disable external/internal entity expansion in XML parsers.\n\n"
            "**Secondary:** Prefer JSON over XML and bound request payload sizes."
        ),
        ("xxe", "xml", "dos", "owasp-a05"),
    ),
    (
        "CWE-1004",
        "Sensitive Cookie Without 'HttpOnly' Flag",
        "medium",
        "Set 'HttpOnly' on all session and authentication cookies to block JS access.",
        (
            "Session cookies without HttpOnly can be read via document.cookie if an "
            "XSS flaw occurs on the origin.\n\n"
            "**Primary Fix:** Configure session management and Set-Cookie headers with "
            "HttpOnly=True across all authentication cookies.\n\n"
            "**Secondary:** Pair HttpOnly with Secure and SameSite attributes."
        ),
        ("cookie", "httponly", "headers", "owasp-a05"),
    ),
    (
        "CWE-1275",
        "Sensitive Cookie With Improper SameSite Attribute",
        "low",
        "Set 'SameSite=Lax' or 'SameSite=Strict' on session cookies.",
        (
            "Missing or unsafe SameSite cookie settings weaken cross-site request "
            "forgery protections.\n\n"
            "**Primary Fix:** Set SameSite=Lax or Strict on session cookies; only use "
            "SameSite=None together with Secure when cross-site embedding is required.\n\n"
            "**Secondary:** Retain server-side anti-CSRF tokens on state changes."
        ),
        ("cookie", "samesite", "csrf", "owasp-a05"),
    ),
    (
        "CWE-1393",
        "Use of Default Passwords / Default Credentials",
        "critical",
        "Change or disable all vendor-default accounts and enforce unique secrets.",
        (
            "Default vendor usernames and passwords allow trivial administrative "
            "compromise of databases, panels, and appliances.\n\n"
            "**Primary Fix:** Rotate default credentials during initial provisioning, "
            "disable built-in demo accounts, and require unique strong passwords.\n\n"
            "**Secondary:** Restrict management interfaces to private networks + MFA."
        ),
        ("credentials", "default-password", "misconfiguration", "owasp-a05"),
    ),
    # A06 — Vulnerable and Outdated Components
    (
        "CWE-120",
        "Classic Buffer Overflow",
        "critical",
        "Upgrade vulnerable native libraries and enforce bounded buffer copy APIs.",
        (
            "Unchecked buffer writes in native components can corrupt adjacent memory "
            "and lead to crashes or remote code execution.\n\n"
            "**Primary Fix:** Apply vendor patches for affected components, replace "
            "unbounded copy calls with bounds-checked APIs, and validate lengths.\n\n"
            "**Secondary:** Compile with ASLR, NX/DEP, and stack canaries."
        ),
        ("memory-safety", "overflow", "components", "owasp-a06"),
    ),
    (
        "CWE-122",
        "Heap-Based Buffer Overflow",
        "critical",
        "Patch vulnerable native dependencies and validate heap allocation bounds.",
        (
            "Writing past heap-allocated buffers corrupts heap metadata and adjacent "
            "objects, often enabling arbitrary code execution.\n\n"
            "**Primary Fix:** Update affected libraries to patched releases and enforce "
            "overflow-safe size calculations and bounds checks.\n\n"
            "**Secondary:** Run AddressSanitizer/fuzzing on native parsers in CI."
        ),
        ("memory-safety", "heap-overflow", "components", "owasp-a06"),
    ),
    (
        "CWE-126",
        "Buffer Over-Read (Memory Disclosure)",
        "high",
        "Upgrade affected libraries (e.g., OpenSSL) and enforce strict read bounds.",
        (
            "Reading beyond the end of an allocated buffer leaks sensitive process "
            "memory such as keys, credentials, and session tokens.\n\n"
            "**Primary Fix:** Patch vulnerable native packages immediately and verify "
            "length fields against actual buffer sizes before reading.\n\n"
            "**Secondary:** Rotate private keys/certificates if memory exposure occurred."
        ),
        ("memory-safety", "over-read", "tls", "owasp-a06"),
    ),
    (
        "CWE-416",
        "Use After Free",
        "critical",
        "Update vulnerable components and nullify pointers after releasing memory.",
        (
            "Dereferencing freed heap memory can cause crashes or arbitrary execution.\n\n"
            "**Primary Fix:** Upgrade affected runtime/native dependencies to patched "
            "versions and enforce strict pointer ownership and lifetime rules.\n\n"
            "**Secondary:** Enable compiler sanitizers and memory-safe abstractions."
        ),
        ("memory-safety", "use-after-free", "components", "owasp-a06"),
    ),
    (
        "CWE-1104",
        "Use of Unmaintained or Outdated Third-Party Component",
        "medium",
        "Upgrade outdated libraries, CMS plugins, and EOL runtimes to supported versions.",
        (
            "Unmaintained or end-of-life dependencies no longer receive security fixes "
            "and accumulate unpatched vulnerabilities.\n\n"
            "**Primary Fix:** Maintain an SBOM, upgrade outdated packages/plugins to "
            "actively maintained releases, and remove unused third-party code.\n\n"
            "**Secondary:** Monitor EOL advisories continuously."
        ),
        ("components", "outdated", "sbom", "owasp-a06"),
    ),
    (
        "CWE-1395",
        "Dependency on Vulnerable Third-Party Component",
        "high",
        "Upgrade vulnerable dependencies to patched versions and run SCA in CI/CD.",
        (
            "Including libraries with known CVEs exposes the application even if first-"
            "party code contains no bugs.\n\n"
            "**Primary Fix:** Pin and update direct and transitive dependencies to fixed "
            "versions using lockfiles and automated SCA scanning.\n\n"
            "**Secondary:** Apply vendor mitigations or virtual patches until upgraded."
        ),
        ("dependencies", "cve", "sca", "owasp-a06"),
    ),
    # A07 — Identification and Authentication Failures
    (
        "CWE-256",
        "Plaintext Storage of a Password",
        "critical",
        "Hash all stored passwords with Argon2id or bcrypt using unique per-user salts.",
        (
            "Storing user or service passwords in cleartext lets any database or config "
            "disclosure immediately compromise accounts.\n\n"
            "**Primary Fix:** Replace plaintext passwords with salted Argon2id or bcrypt "
            "hashes; store retrievable service secrets in a vault/KMS.\n\n"
            "**Secondary:** Enforce password rotation after migrating storage."
        ),
        ("passwords", "hashing", "authentication", "owasp-a07"),
    ),
    (
        "CWE-290",
        "Authentication Bypass by Spoofing",
        "high",
        "Never rely on spoofable IP headers, User-Agent, or reverse DNS for auth.",
        (
            "Trusting client-supplied headers (X-Forwarded-For, X-Real-IP, Host) or "
            "unverified hostnames allows callers to impersonate trusted peers.\n\n"
            "**Primary Fix:** Authenticate clients cryptographically (tokens, mTLS) and "
            "strip/overwrite proxy headers at trusted ingress boundaries.\n\n"
            "**Secondary:** Validate proxy chains explicitly before reading forwarded IPs."
        ),
        ("authentication", "spoofing", "owasp-a07"),
    ),
    (
        "CWE-300",
        "Channel Accessible by Non-Endpoint (Missing Message Signing / MitM)",
        "medium",
        "Require cryptographic message signing and channel integrity (e.g., SMB signing).",
        (
            "Protocols with disabled or optional message signing (such as SMB without "
            "signing required) allow on-path tampering and relay attacks.\n\n"
            "**Primary Fix:** Require cryptographic signing and mutual authentication "
            "(e.g., enable RequireSecuritySignature on SMB, enforce TLS).\n\n"
            "**Secondary:** Segment internal protocols and disable legacy dialects."
        ),
        ("smb", "mitm", "signing", "owasp-a07"),
    ),
    (
        "CWE-307",
        "Brute Force / Excessive Authentication Attempts",
        "high",
        "Enforce rate limiting, progressive backoff, account lockout, and MFA on login.",
        (
            "Unthrottled authentication or OTP endpoints allow automated password "
            "guessing and credential stuffing.\n\n"
            "**Primary Fix:** Apply per-IP and per-account rate limiting, progressive "
            "delays/lockout, and multi-factor authentication.\n\n"
            "**Secondary:** Screen against breached-password lists and alert on spikes."
        ),
        ("brute-force", "authentication", "rate-limiting", "owasp-a07"),
    ),
    (
        "CWE-384",
        "Session Fixation",
        "high",
        "Regenerate session identifiers upon login and privilege changes.",
        (
            "Reusing a pre-authentication session ID after login lets attackers who "
            "planted that token hijack the authenticated session.\n\n"
            "**Primary Fix:** Invalidate any pre-login session and issue a fresh CSPRNG "
            "session token on authentication and privilege elevation.\n\n"
            "**Secondary:** Reject session IDs supplied in URL query strings."
        ),
        ("session", "authentication", "owasp-a07"),
    ),
    (
        "CWE-521",
        "Weak Password Requirements",
        "medium",
        "Enforce strong password length (>=12 chars), block breached passwords, add MFA.",
        (
            "Short or predictable passwords fall rapidly to brute-force and credential "
            "stuffing attacks.\n\n"
            "**Primary Fix:** Require >=12-character passwords (per NIST SP 800-63B), "
            "block common/breached passwords, and enable MFA.\n\n"
            "**Secondary:** Prefer SSH keys or SSO/OIDC over password logins."
        ),
        ("passwords", "authentication", "owasp-a07"),
    ),
    (
        "CWE-522",
        "Insufficiently Protected Credentials",
        "high",
        "Protect credentials with TLS in transit and Argon2id/vault storage at rest.",
        (
            "Exposing credentials via weak encoding, insecure channels, or readable "
            "configs compromises authentication boundaries.\n\n"
            "**Primary Fix:** Transmit credentials only over TLS, hash passwords with "
            "Argon2id/bcrypt, and protect tokens in secure secret stores.\n\n"
            "**Secondary:** Use short-lived scoped tokens where possible."
        ),
        ("credentials", "authentication", "owasp-a07"),
    ),
    (
        "CWE-598",
        "Sensitive Parameters or Credentials in GET Query String",
        "medium",
        "Transmit passwords, tokens, and secrets in POST bodies or Authorization headers.",
        (
            "Sensitive values placed in URL query strings are leaked in browser history, "
            "Referer headers, proxy caches, and server access logs.\n\n"
            "**Primary Fix:** Move credentials, API keys, and tokens to POST request "
            "bodies or Authorization headers over HTTPS.\n\n"
            "**Secondary:** Scrub legacy query-string secrets from logs and rotate them."
        ),
        ("url", "credentials", "logging", "owasp-a07"),
    ),
    (
        "CWE-613",
        "Insufficient Session Expiration",
        "medium",
        "Enforce idle and absolute session timeouts; revoke sessions server-side.",
        (
            "Sessions or tokens that never expire or remain valid after logout widen "
            "the window for stolen-token abuse.\n\n"
            "**Primary Fix:** Configure bounded idle/absolute session lifetimes and "
            "invalidate session state/refresh tokens server-side on logout.\n\n"
            "**Secondary:** Revoke active sessions upon password or role changes."
        ),
        ("session", "timeout", "authentication", "owasp-a07"),
    ),
    (
        "CWE-620",
        "Unverified Password Change",
        "high",
        "Require current password verification (and MFA) before changing credentials.",
        (
            "Allowing password or recovery-email updates without verifying the current "
            "password lets brief session access become permanent takeover.\n\n"
            "**Primary Fix:** Prompt for current password and MFA verification prior to "
            "credential or recovery-channel changes.\n\n"
            "**Secondary:** Send out-of-band notifications and revoke old sessions."
        ),
        ("passwords", "authentication", "owasp-a07"),
    ),
    (
        "CWE-640",
        "Weak Password Recovery Mechanism",
        "high",
        "Use short-lived, single-use CSPRNG reset tokens over verified channels.",
        (
            "Predictable reset tokens, security questions, or Host-header poisoning in "
            "reset links allow unauthorized account recovery.\n\n"
            "**Primary Fix:** Generate >=128-bit single-use expiring tokens, construct "
            "reset URLs from a configured canonical origin, and return generic messages.\n\n"
            "**Secondary:** Rate-limit recovery endpoints and invalidate tokens on use."
        ),
        ("password-reset", "authentication", "owasp-a07"),
    ),
    (
        "CWE-759",
        "One-Way Password Hash Without Salt",
        "high",
        "Use salted memory-hard password hashes (Argon2id or bcrypt) with unique salts.",
        (
            "Unsalted digests allow identical passwords to share hashes and fall quickly "
            "to precomputed lookup or rainbow tables.\n\n"
            "**Primary Fix:** Migrate to Argon2id or bcrypt, which automatically generate "
            "cryptographically random per-password salts.\n\n"
            "**Secondary:** Upgrade legacy hashes transparently at next user login."
        ),
        ("hashing", "passwords", "owasp-a07"),
    ),
    # A08 — Software and Data Integrity Failures
    (
        "CWE-345",
        "Insufficient Verification of Data Authenticity",
        "high",
        "Verify cryptographic signatures or HMACs before trusting external payloads.",
        (
            "Processing unsigned packages, webhooks, or configuration updates allows "
            "tampering in transit or in CI/CD pipelines.\n\n"
            "**Primary Fix:** Validate detached cryptographic signatures or HMAC-SHA256 "
            "tags using trusted keys before acting on external data.\n\n"
            "**Secondary:** Enforce signed commits, images, and SBOM attestations."
        ),
        ("integrity", "signature", "owasp-a08"),
    ),
    (
        "CWE-353",
        "Missing Integrity Check / Subresource Integrity (SRI)",
        "low",
        "Add SRI 'integrity' hashes to third-party scripts and stylesheets.",
        (
            "Loading external CDN scripts without integrity attributes trusts third-party "
            "hosts implicitly if the CDN is compromised.\n\n"
            "**Primary Fix:** Add Subresource Integrity (integrity='sha384-...') and "
            "crossorigin attributes to external script/link tags, or self-host assets.\n\n"
            "**Secondary:** Enforce strict CSP script-src allowlists."
        ),
        ("sri", "integrity", "client-side", "owasp-a08"),
    ),
    (
        "CWE-426",
        "Untrusted Search Path (DLL / Binary Hijacking)",
        "high",
        "Load libraries/binaries via canonical absolute paths; sanitize PATH entries.",
        (
            "Searching writable working directories or relative paths when loading DLLs "
            "or executables allows local privilege escalation or code execution.\n\n"
            "**Primary Fix:** Specify full canonical system paths when loading libraries "
            "and remove relative/writable entries from PATH/LD_LIBRARY_PATH.\n\n"
            "**Secondary:** Verify file ownership and digital signatures before loading."
        ),
        ("integrity", "search-path", "owasp-a08"),
    ),
    (
        "CWE-494",
        "Download of Code Without Integrity Check",
        "high",
        "Verify cryptographic signatures and SHA-256 checksums over HTTPS before running.",
        (
            "Downloading and executing updates, plugins, or installers without signature "
            "verification risks supply-chain compromise.\n\n"
            "**Primary Fix:** Fetch artifacts over verified TLS and validate publisher "
            "cryptographic signatures and SHA-256 digests prior to execution.\n\n"
            "**Secondary:** Pin package checksums in lockfiles and CI manifests."
        ),
        ("integrity", "supply-chain", "updates", "owasp-a08"),
    ),
    (
        "CWE-829",
        "Inclusion of Functionality From Untrusted Control Sphere",
        "high",
        "Only load external scripts, packages, or plugins from pinned, verified sources.",
        (
            "Executing third-party code from unpinned or untrusted origins grants those "
            "external parties full runtime control.\n\n"
            "**Primary Fix:** Self-host or pin external scripts/dependencies with SRI and "
            "cryptographic lockfiles, and restrict third-party script execution via CSP.\n\n"
            "**Secondary:** Audit third-party widgets and CI/CD actions regularly."
        ),
        ("supply-chain", "integrity", "third-party", "owasp-a08"),
    ),
    (
        "CWE-915",
        "Mass Assignment / Improper Dynamic Attribute Modification",
        "high",
        "Bind inputs via explicit DTO/schema allowlists; block privileged attributes.",
        (
            "Binding raw request dictionaries directly to ORM/model fields lets callers "
            "overwrite protected attributes such as role, is_admin, or balance.\n\n"
            "**Primary Fix:** Define explicit input schemas/DTOs listing only user-"
            "editable fields and never pass raw request JSON into model updates.\n\n"
            "**Secondary:** Protect sensitive fields at the model/ORM layer."
        ),
        ("mass-assignment", "api", "integrity", "owasp-a08"),
    ),
    # A09 — Security Logging and Monitoring Failures
    (
        "CWE-117",
        "Log Injection / Improper Log Output Neutralization",
        "medium",
        "Sanitize CR/LF and control characters in log fields; use structured JSON logs.",
        (
            "Writing unsanitized user input into plain-text logs lets attackers forge "
            "log entries or inject terminal escape sequences.\n\n"
            "**Primary Fix:** Use structured JSON logging with proper serialization and "
            "strip/escape CR, LF, and ANSI control characters from logged values.\n\n"
            "**Secondary:** Protect log viewer pipelines from injection."
        ),
        ("logging", "log-injection", "owasp-a09"),
    ),
    (
        "CWE-223",
        "Omission of Security-Relevant Log Information",
        "low",
        "Record timestamp, actor, source IP, target resource, and outcome on audit logs.",
        (
            "Audit logs missing context (such as user identity, IP, or action outcome) "
            "impede incident detection and forensic investigation.\n\n"
            "**Primary Fix:** Standardize audit log schemas to include UTC timestamp, "
            "actor ID, source IP, action, target, and pass/fail status.\n\n"
            "**Secondary:** Synchronize system clocks via NTP."
        ),
        ("logging", "audit", "owasp-a09"),
    ),
    (
        "CWE-532",
        "Sensitive Information Logged in Clear Text",
        "medium",
        "Redact passwords, bearer tokens, API keys, and PII before writing logs.",
        (
            "Writing credentials, session tokens, or sensitive PII into log files "
            "exposes secrets to anyone with log read access.\n\n"
            "**Primary Fix:** Apply centralized log-redaction filters and avoid logging "
            "Authorization headers, Set-Cookie headers, or raw auth payloads.\n\n"
            "**Secondary:** Restrict access to centralized log stores and encrypt at rest."
        ),
        ("logging", "secrets", "pii", "owasp-a09"),
    ),
    (
        "CWE-778",
        "Insufficient Security Logging and Monitoring",
        "low",
        "Log all auth events, access denials, and admin changes to centralized SIEM.",
        (
            "Failing to log security-critical events prevents timely detection and "
            "response to active intrusion attempts.\n\n"
            "**Primary Fix:** Emit tamper-evident audit logs for logins, failed auth, "
            "authorization denials, and privilege changes to centralized SIEM.\n\n"
            "**Secondary:** Configure automated alerting on anomalous bursts."
        ),
        ("logging", "monitoring", "owasp-a09"),
    ),
    (
        "CWE-779",
        "Logging of Excessive Data",
        "low",
        "Rate-limit repetitive log messages, enforce log rotation, and curb debug logs.",
        (
            "Unbounded or verbose logging of unauthenticated traffic can exhaust disk "
            "space and obscure high-signal security alerts.\n\n"
            "**Primary Fix:** Enforce log rotation, retention quotas, rate-limiting on "
            "repetitive warnings, and disable verbose debug logging in production.\n\n"
            "**Secondary:** Separate high-volume trace logs from security audit streams."
        ),
        ("logging", "dos", "owasp-a09"),
    ),
    # A10 — Server-Side Request Forgery (SSRF)
    (
        "CWE-441",
        "Unintended Proxy / Confused Deputy",
        "high",
        "Restrict outbound forwarding targets to an allowlist; disable open proxying.",
        (
            "Forwarding or fetching arbitrary external destinations on behalf of callers "
            "enables internal network pivoting and IP spoofing.\n\n"
            "**Primary Fix:** Disable unintended proxy behavior, allowlist permitted "
            "upstream destinations, and validate caller authorization strictly.\n\n"
            "**Secondary:** Enforce egress firewall rules blocking internal subnets."
        ),
        ("ssrf", "proxy", "owasp-a10"),
    ),
    (
        "CWE-610",
        "Externally Controlled Reference to Resource in Another Sphere",
        "high",
        "Allowlist external hosts/URIs and block private/metadata IP resolutions.",
        (
            "Resolving arbitrary user-controlled hostnames, URLs, or remote resources "
            "can expose internal services and cloud metadata endpoints.\n\n"
            "**Primary Fix:** Validate scheme, host, and resolved IP addresses against "
            "explicit allowlists while denying RFC1918, loopback, and link-local ranges.\n\n"
            "**Secondary:** Isolate outbound network access from sensitive internal nets."
        ),
        ("ssrf", "access-control", "owasp-a10"),
    ),
    (
        "CWE-59",
        "Improper Link Resolution Before File Access (Link Following)",
        "high",
        "Canonicalize paths cleanly and reject symbolic links crossing trust boundaries.",
        (
            "Following symlinks without boundary validation enables unauthorized file reads "
            "or overwrites outside intended directories.\n\n"
            "**Primary Fix:** Resolve canonical paths, disable symlink traversal across untrusted "
            "roots, and enforce O_NOFOLLOW where supported."
        ),
        ("filesystem", "symlink", "owasp-a01"),
    ),
    (
        "CWE-121",
        "Stack-based Buffer Overflow",
        "critical",
        "Use bounds-checked string/memory operations and compile with stack protectors.",
        (
            "Unbounded stack writes corrupt return addresses and adjacent stack frames.\n\n"
            "**Primary Fix:** Enforce strict buffer bounds checks, migrate to memory-safe APIs "
            "or languages, and enable stack canaries (-fstack-protector-strong) and ASLR/NX."
        ),
        ("memory-safety", "overflow", "owasp-a06"),
    ),
    (
        "CWE-125",
        "Out-of-bounds Read",
        "high",
        "Validate array indices, offsets, and packet/buffer lengths before reading.",
        (
            "Reading past allocated buffer bounds discloses sensitive memory or crashes services.\n\n"
            "**Primary Fix:** Check all lengths and indices against buffer capacities prior to "
            "indexing or memory copies, and patch affected native dependencies."
        ),
        ("memory-safety", "disclosure", "owasp-a06"),
    ),
    (
        "CWE-190",
        "Integer Overflow or Wraparound",
        "high",
        "Validate arithmetic bounds and use overflow-safe integer math before allocations.",
        (
            "Arithmetic wraparound produces unexpectedly small buffer sizes or bypassed checks.\n\n"
            "**Primary Fix:** Perform explicit pre-operation range checks or use checked integer "
            "arithmetic helpers before memory allocation or loop bounds calculations."
        ),
        ("integer-overflow", "memory-safety", "owasp-a04"),
    ),
    (
        "CWE-193",
        "Off-by-one Error",
        "medium",
        "Audit loop limits and null-terminator room for exact <= vs < bounds.",
        (
            "Miscomputing slice/buffer sizes by one byte can trigger out-of-bounds memory access.\n\n"
            "**Primary Fix:** Use standard size-aware containers and verify boundary conditions "
            "including NUL terminators in unit tests."
        ),
        ("memory-safety", "bounds", "owasp-a06"),
    ),
    (
        "CWE-321",
        "Use of Hard-coded Cryptographic Key",
        "critical",
        "Rotate hard-coded keys and provision unique per-environment secrets via KMS/Vault.",
        (
            "Static cryptographic keys embedded in configs, code, or client bundles allow "
            "attackers to decrypt or forge protected tokens.\n\n"
            "**Primary Fix:** Remove embedded keys, generate strong CSPRNG keys outside code, "
            "and store keys in a managed KMS or hardware security module."
        ),
        ("cryptography", "keys", "owasp-a02"),
    ),
    (
        "CWE-367",
        "Time-of-check Time-of-use (TOCTOU) Race Condition",
        "high",
        "Operate directly on opened file descriptors rather than re-resolving paths.",
        (
            "Checking file attributes before opening by path creates a race window between "
            "validation and use.\n\n"
            "**Primary Fix:** Open resources atomically and perform validation using file "
            "descriptors (fstat) or database transactions."
        ),
        ("race-condition", "filesystem", "owasp-a04"),
    ),
    (
        "CWE-617",
        "Reachable Assertion",
        "medium",
        "Replace assert statements on untrusted input with explicit error handling.",
        (
            "Assertions triggered by remote inputs crash worker processes, causing denial "
            "of service.\n\n"
            "**Primary Fix:** Validate external inputs with proper exception handling and return "
            "controlled error responses instead of runtime assertions."
        ),
        ("availability", "dos", "owasp-a04"),
    ),
    (
        "CWE-668",
        "Exposure of Resource to Wrong Sphere",
        "high",
        "Isolate internal sockets, IPC endpoints, and admin files from untrusted access.",
        (
            "Resources intended only for internal components are accessible across trust "
            "boundaries.\n\n"
            "**Primary Fix:** Restrict bind addresses, apply namespace/network isolation, and "
            "enforce authentication on every exposed endpoint."
        ),
        ("isolation", "access-control", "owasp-a01"),
    ),
    (
        "CWE-787",
        "Out-of-bounds Write",
        "critical",
        "Apply strict length checks on all writes and upgrade patched native components.",
        (
            "Writing past buffer boundaries corrupts adjacent memory and frequently leads to "
            "remote code execution.\n\n"
            "**Primary Fix:** Enforce explicit capacity bounds before writes, patch vulnerable "
            "native packages, and enable compiler hardening flags."
        ),
        ("memory-safety", "rce", "owasp-a06"),
    ),
    (
        "CWE-843",
        "Access of Resource Using Incompatible Type (Type Confusion)",
        "high",
        "Validate runtime object types before casting or dispatching operations.",
        (
            "Operating on values using an incompatible type can corrupt memory or bypass "
            "logic invariants.\n\n"
            "**Primary Fix:** Enforce explicit schema/type checks before casting objects and "
            "apply vendor security updates."
        ),
        ("type-safety", "memory-safety", "owasp-a06"),
    ),
)


class RemediationDB:
    """In-memory remediation knowledge base.

    Provides per-CWE fix guidance (covers broad vulnerability classes)
    and per-CVE specific patch instructions.
    """

    def __init__(self) -> None:
        self._by_id: dict[str, Remediation] = {}
        self._load_builtins()

    @property
    def count(self) -> int:
        return len(self._by_id)

    def _load_builtins(self) -> None:
        for r in self._cwe_remediations():
            self._by_id[r.id.strip().upper()] = r

    def load_from_yaml(self, yaml_dir: Path) -> None:
        """Load additional remediations from YAML files."""
        if not yaml_dir.is_dir():
            return
        for f in sorted(yaml_dir.glob("*.yaml")):
            try:
                raw = yaml.safe_load(f.read_text(encoding="utf-8"))
            except (yaml.YAMLError, OSError) as exc:
                log.warning("Failed to load remediation file %s: %s", f, exc)
                continue
            if not isinstance(raw, dict):
                continue
            for entry in raw.get("remediations", []):
                if isinstance(entry, dict) and "id" in entry and "title" in entry:
                    r_id = str(entry["id"]).strip().upper()
                    r = Remediation(
                        id=r_id,
                        title=entry["title"],
                        severity=entry.get("severity", "high"),
                        short_fix=entry.get("short_fix", ""),
                        detailed_fix=entry.get("detailed_fix", ""),
                        references=entry.get("references", []),
                        code_examples=entry.get("code_examples", {}),
                        tags=entry.get("tags", []),
                    )
                    self._by_id[r_id] = r

    def get(self, vuln_id: str) -> Remediation | None:
        """Get remediation by CWE/CVE ID (case-insensitive)."""
        if not vuln_id:
            return None
        return self._by_id.get(vuln_id.strip().upper())

    def lookup(self, vuln_id: str) -> Remediation | None:
        """Alias for get()."""
        return self.get(vuln_id)

    def search(self, keyword: str) -> list[Remediation]:
        """Search remediations by keyword in title, fix text, or tags."""
        kw = keyword.lower()
        return [
            r
            for r in self._by_id.values()
            if kw in r.title.lower()
            or kw in r.short_fix.lower()
            or kw in r.detailed_fix.lower()
            or any(kw in t.lower() for t in r.tags)
        ]

    def get_for_finding(
        self, cwe_id: str = "", cve_ids: list[str] | None = None
    ) -> Remediation | None:
        """Get the best remediation for a finding, preferring CVE-specific over CWE-generic."""
        # Try specific CVEs first
        if cve_ids:
            for cve in cve_ids:
                r = self.get(cve)
                if r:
                    return r
        # Fall back to CWE class
        if cwe_id:
            return self.get(cwe_id)
        return None

    def _cwe_remediations(self) -> list[Remediation]:
        return [
            Remediation(
                id="CWE-89",
                title="SQL Injection",
                severity="critical",
                short_fix="Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
                detailed_fix=(
                    "SQL injection occurs when untrusted data is sent to an interpreter as part of a command or query. "
                    "The attacker's hostile data can trick the interpreter into executing unintended commands or accessing data without authorization.\n\n"
                    "**Primary Fix:** Use parameterized queries (prepared statements) with bound variables for ALL database interactions.\n\n"
                    "**Secondary:** Apply input validation using allowlists for expected data types and formats. "
                    "Use stored procedures where possible. Apply least-privilege database accounts. "
                    "Deploy a Web Application Firewall as defense-in-depth (not primary fix)."
                ),
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
                ],
                code_examples={
                    "python": 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
                    "php": '$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?"); $stmt->execute([$id]);',
                    "java": 'PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?"); ps.setInt(1, id);',
                },
                tags=["injection", "database", "owasp-a03"],
            ),
            Remediation(
                id="CWE-79",
                title="Cross-Site Scripting (XSS)",
                severity="high",
                short_fix="Encode all user-controlled output for the correct context (HTML, JS, URL, CSS).",
                detailed_fix=(
                    "XSS attacks occur when an application includes untrusted data in a web page without proper validation or encoding.\n\n"
                    "**Primary Fix:** Context-sensitive output encoding — HTML-encode for HTML body, JS-encode for JavaScript, URL-encode for URLs.\n\n"
                    "**Secondary:** Implement Content Security Policy (CSP) headers. Use HttpOnly and Secure cookie flags. "
                    "Validate input using allowlists. Use auto-escaping template engines (Jinja2 with autoescape, React JSX)."
                ),
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
                ],
                code_examples={
                    "python": "from markupsafe import escape; return escape(user_input)",
                    "javascript": "element.textContent = userInput; // NOT innerHTML",
                },
                tags=["xss", "injection", "client-side", "owasp-a03"],
            ),
            Remediation(
                id="CWE-78",
                title="OS Command Injection",
                severity="critical",
                short_fix="Avoid calling OS commands with user input. Use language APIs instead of shell commands.",
                detailed_fix=(
                    "Command injection occurs when an application passes unsafe user-supplied data to a system shell.\n\n"
                    "**Primary Fix:** Avoid OS command calls entirely — use language-native APIs (e.g., file operations, network libraries).\n\n"
                    "**If unavoidable:** Use parameterized command execution (subprocess with list args, never shell=True). "
                    "Apply strict allowlist validation on inputs. Escape shell metacharacters. Run with minimal OS privileges."
                ),
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"
                ],
                code_examples={
                    "python": 'subprocess.run(["ping", "-c", "1", validated_host], shell=False)',
                },
                tags=["injection", "command", "rce", "owasp-a03"],
            ),
            Remediation(
                id="CWE-22",
                title="Path Traversal / LFI",
                severity="high",
                short_fix="Validate and canonicalize file paths. Use allowlists for accessible directories.",
                detailed_fix=(
                    "Path traversal allows attackers to access files outside the intended directory.\n\n"
                    "**Primary Fix:** Canonicalize the file path and verify it starts with the expected base directory. "
                    "Use an allowlist of permitted filenames/paths.\n\n"
                    "**Secondary:** Run the application with minimal filesystem permissions. Use chroot jails or containers. "
                    "Strip or reject path separators and '..' sequences from user input."
                ),
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html"
                ],
                code_examples={
                    "python": (
                        "base = Path(BASE_DIR).resolve()\n"
                        "target = (base / user_path).resolve()\n"
                        "if not target.is_relative_to(base):\n"
                        "    raise ValueError('Path traversal detected')"
                    ),
                },
                tags=["file", "traversal", "lfi", "owasp-a01"],
            ),
            Remediation(
                id="CWE-918",
                title="Server-Side Request Forgery (SSRF)",
                severity="high",
                short_fix="Validate and allowlist URLs. Block requests to internal/metadata endpoints.",
                detailed_fix=(
                    "SSRF occurs when an application fetches a remote resource using a user-supplied URL without validation.\n\n"
                    "**Primary Fix:** Allowlist permitted domains and protocols. Block RFC1918 ranges, link-local addresses, "
                    "and cloud metadata endpoints (169.254.169.254).\n\n"
                    "**Secondary:** Use a network-level firewall to restrict outbound access from the application. "
                    "Disable unnecessary URL schemes (file://, gopher://, dict://). Validate DNS resolution results."
                ),
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"
                ],
                tags=["ssrf", "network", "owasp-a10"],
            ),
            Remediation(
                id="CWE-611",
                title="XML External Entity (XXE)",
                severity="high",
                short_fix="Disable external entity processing in XML parsers.",
                detailed_fix=(
                    "XXE attacks exploit XML parsers that process external entity references.\n\n"
                    "**Primary Fix:** Disable DTDs (external entities) entirely in the XML parser configuration.\n\n"
                    "**Secondary:** Use less complex data formats (JSON) where possible. Validate, filter, and sanitize XML input. "
                    "Use updated XML libraries with XXE disabled by default."
                ),
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html"
                ],
                code_examples={
                    "python": "from defusedxml import ElementTree  # Drop-in safe replacement",
                    "java": 'factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);',
                },
                tags=["xxe", "xml", "injection", "owasp-a05"],
            ),
            Remediation(
                id="CWE-434",
                title="Unrestricted File Upload",
                severity="critical",
                short_fix="Validate file type, size, and content. Store uploads outside the webroot with random names.",
                detailed_fix=(
                    "Unrestricted file upload allows attackers to upload executable files (webshells).\n\n"
                    "**Primary Fix:** Validate file type by content (magic bytes), not just extension. Store uploads outside "
                    "the web-accessible directory. Use random filenames. Set non-executable permissions.\n\n"
                    "**Secondary:** Limit file size. Scan uploads with antivirus. Serve files via a separate domain. "
                    "Set Content-Disposition: attachment headers."
                ),
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"
                ],
                tags=["file-upload", "webshell", "rce", "owasp-a04"],
            ),
            Remediation(
                id="CWE-287",
                title="Improper Authentication",
                severity="critical",
                short_fix="Implement MFA. Use proven authentication frameworks. Never roll your own auth.",
                detailed_fix=(
                    "Authentication weaknesses allow attackers to compromise passwords, keys, or session tokens.\n\n"
                    "**Primary Fix:** Use established authentication frameworks (OAuth2, SAML). Implement MFA. "
                    "Enforce strong password policies. Use bcrypt/argon2 for password hashing.\n\n"
                    "**Secondary:** Implement account lockout after failed attempts. Log authentication failures. "
                    "Use session management best practices. Invalidate sessions on logout."
                ),
                tags=["authentication", "identity", "owasp-a07"],
            ),
            Remediation(
                id="CWE-306",
                title="Missing Authentication for Critical Function",
                severity="critical",
                short_fix="Require authentication for all sensitive endpoints. Apply principle of least privilege.",
                detailed_fix=(
                    "Sensitive functionality is exposed without authentication.\n\n"
                    "**Primary Fix:** Require authentication for all administrative and sensitive functions. "
                    "Implement role-based access control (RBAC). Verify authorization on every request server-side.\n\n"
                    "**Secondary:** Remove or restrict management interfaces. Use network segmentation. "
                    "Monitor and alert on unauthenticated access attempts."
                ),
                tags=["authentication", "access-control", "owasp-a01"],
            ),
            Remediation(
                id="CWE-200",
                title="Information Exposure / Sensitive Data Disclosure",
                severity="medium",
                short_fix="Remove verbose error messages, debug info, and stack traces from production.",
                detailed_fix=(
                    "The application exposes sensitive information through error messages, headers, or debug output.\n\n"
                    "**Primary Fix:** Configure custom error pages. Disable debug mode in production. Remove server version headers.\n\n"
                    "**Secondary:** Review responses for sensitive data leakage. Implement proper exception handling. "
                    "Remove comments containing sensitive info from client-side code."
                ),
                tags=["information-disclosure", "owasp-a01"],
            ),
            Remediation(
                id="CWE-502",
                title="Deserialization of Untrusted Data",
                severity="critical",
                short_fix="Never deserialize untrusted data. Use data-only formats (JSON) instead of serialization.",
                detailed_fix=(
                    "Insecure deserialization can lead to remote code execution.\n\n"
                    "**Primary Fix:** Avoid deserializing data from untrusted sources. Use data-only interchange formats like JSON.\n\n"
                    "**If unavoidable:** Implement integrity checks (HMAC) on serialized objects. Enforce strict type constraints. "
                    "Run deserialization code with minimal privileges. Monitor deserialization exceptions."
                ),
                tags=["deserialization", "rce", "owasp-a08"],
            ),
            Remediation(
                id="CWE-352",
                title="Cross-Site Request Forgery (CSRF)",
                severity="medium",
                short_fix="Use anti-CSRF tokens on all state-changing operations. Use SameSite cookie attribute.",
                detailed_fix=(
                    "CSRF forces authenticated users to perform unintended actions.\n\n"
                    "**Primary Fix:** Include unique, unpredictable CSRF tokens in all state-changing requests. "
                    "Verify the token server-side.\n\n"
                    "**Secondary:** Set SameSite=Strict or Lax on cookies. Verify Origin/Referer headers. "
                    "Require re-authentication for sensitive operations."
                ),
                tags=["csrf", "session", "owasp-a01"],
            ),
            Remediation(
                id="CWE-269",
                title="Improper Privilege Management",
                severity="high",
                short_fix="Apply principle of least privilege. Run services as non-root. Use RBAC.",
                detailed_fix=(
                    "The application runs with excessive privileges or fails to drop privileges.\n\n"
                    "**Primary Fix:** Run applications as non-root users. Apply least-privilege to database accounts, "
                    "API keys, and filesystem permissions.\n\n"
                    "**Secondary:** Implement RBAC. Audit privilege assignments regularly. Use Linux capabilities instead of full root. "
                    "Implement privilege separation in application architecture."
                ),
                tags=["privilege", "access-control", "owasp-a01"],
            ),
            Remediation(
                id="CWE-798",
                title="Hard-coded Credentials",
                severity="critical",
                short_fix="Remove all hard-coded credentials. Use environment variables or secret managers.",
                detailed_fix=(
                    "Hard-coded passwords, API keys, or cryptographic keys in source code.\n\n"
                    "**Primary Fix:** Remove all hard-coded credentials. Use environment variables, vault services "
                    "(HashiCorp Vault, AWS Secrets Manager), or configuration files outside the codebase.\n\n"
                    "**Secondary:** Rotate all discovered credentials immediately. Scan repositories with git-secrets or truffleHog. "
                    "Add pre-commit hooks to prevent credential commits."
                ),
                tags=["credentials", "secrets", "owasp-a07"],
            ),
            Remediation(
                id="CWE-311",
                title="Missing Encryption of Sensitive Data",
                severity="high",
                short_fix="Encrypt sensitive data in transit (TLS 1.2+) and at rest (AES-256).",
                detailed_fix=(
                    "Sensitive data is transmitted or stored without encryption.\n\n"
                    "**Primary Fix:** Use TLS 1.2+ for all data in transit. Encrypt sensitive data at rest with AES-256-GCM.\n\n"
                    "**Secondary:** Disable deprecated protocols (SSLv3, TLS 1.0/1.1). Use HSTS headers. "
                    "Classify data by sensitivity and apply appropriate encryption. Use strong key management practices."
                ),
                tags=["encryption", "tls", "owasp-a02"],
            ),
            Remediation(
                id="CWE-732",
                title="Incorrect Permission Assignment",
                severity="medium",
                short_fix="Set restrictive file and directory permissions. Remove world-readable/writable on sensitive files.",
                detailed_fix=(
                    "Files or directories have overly permissive access controls.\n\n"
                    "**Primary Fix:** Set minimal required permissions (600 for config files, 700 for directories). "
                    "Never use 777/666 on production files.\n\n"
                    "**Secondary:** Audit filesystem permissions regularly. Use umask to set default permissions. "
                    "Implement mandatory access controls (SELinux, AppArmor)."
                ),
                tags=["permissions", "filesystem", "owasp-a01"],
            ),
            Remediation(
                id="CWE-1021",
                title="Clickjacking / UI Redress",
                severity="medium",
                short_fix="Set X-Frame-Options: DENY and Content-Security-Policy: frame-ancestors 'none'.",
                detailed_fix=(
                    "The application can be framed by malicious pages to trick users into unintended clicks.\n\n"
                    "**Primary Fix:** Set the X-Frame-Options header to DENY or SAMEORIGIN. "
                    "Use CSP frame-ancestors directive.\n\n"
                    "**Secondary:** Implement frame-busting JavaScript as a fallback. "
                    "Require user confirmation for sensitive actions."
                ),
                tags=["clickjacking", "ui", "owasp-a04"],
            ),
            Remediation(
                id="CWE-94",
                title="Code Injection / SSTI",
                severity="critical",
                short_fix="Never pass user input to eval/exec. Use sandboxed template engines with autoescape.",
                detailed_fix=(
                    "Server-side template injection or code injection allows arbitrary code execution.\n\n"
                    "**Primary Fix:** Never pass user input to template engines as template code. "
                    "Use sandboxed environments. Enable autoescape.\n\n"
                    "**Secondary:** Use a logic-less template engine (Mustache) where possible. "
                    "Validate and sanitize all template inputs. Apply principle of least privilege to the application runtime."
                ),
                tags=["ssti", "code-injection", "rce", "owasp-a03"],
            ),
            *[
                Remediation(
                    id=cwe_id,
                    title=title,
                    severity=severity,
                    short_fix=short_fix,
                    detailed_fix=detailed_fix,
                    tags=list(tags),
                )
                for cwe_id, title, severity, short_fix, detailed_fix, tags in _ADDITIONAL_CWE_DEFS
            ],
        ]

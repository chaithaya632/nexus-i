"""Remediation knowledge base — per-CWE and per-CVE fix guidance."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


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
            self._by_id[r.id] = r

    def load_from_yaml(self, yaml_dir: Path) -> None:
        """Load additional remediations from YAML files."""
        if not yaml_dir.is_dir():
            return
        for f in sorted(yaml_dir.glob("*.yaml")):
            try:
                raw = yaml.safe_load(f.read_text(encoding="utf-8"))
            except (yaml.YAMLError, OSError):
                continue
            if not isinstance(raw, dict):
                continue
            for entry in raw.get("remediations", []):
                if isinstance(entry, dict) and "id" in entry and "title" in entry:
                    r = Remediation(
                        id=entry["id"],
                        title=entry["title"],
                        severity=entry.get("severity", "high"),
                        short_fix=entry.get("short_fix", ""),
                        detailed_fix=entry.get("detailed_fix", ""),
                        references=entry.get("references", []),
                        code_examples=entry.get("code_examples", {}),
                        tags=entry.get("tags", []),
                    )
                    self._by_id[r.id] = r

    def get(self, vuln_id: str) -> Remediation | None:
        """Get remediation by exact CWE/CVE ID."""
        return self._by_id.get(vuln_id)

    def search(self, keyword: str) -> list[Remediation]:
        """Search remediations by keyword in title, fix text, or tags."""
        kw = keyword.lower()
        return [
            r for r in self._by_id.values()
            if kw in r.title.lower() or kw in r.short_fix.lower()
            or kw in r.detailed_fix.lower() or any(kw in t for t in r.tags)
        ]

    def get_for_finding(self, cwe_id: str = "", cve_ids: list[str] | None = None) -> Remediation | None:
        """Get the best remediation for a finding, preferring CVE-specific over CWE-generic."""
        # Try specific CVEs first
        if cve_ids:
            for cve in cve_ids:
                r = self._by_id.get(cve)
                if r:
                    return r
        # Fall back to CWE class
        if cwe_id:
            return self._by_id.get(cwe_id)
        return None

    def _cwe_remediations(self) -> list[Remediation]:
        return [
            Remediation(
                id="CWE-89", title="SQL Injection", severity="critical",
                short_fix="Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
                detailed_fix=(
                    "SQL injection occurs when untrusted data is sent to an interpreter as part of a command or query. "
                    "The attacker's hostile data can trick the interpreter into executing unintended commands or accessing data without authorization.\n\n"
                    "**Primary Fix:** Use parameterized queries (prepared statements) with bound variables for ALL database interactions.\n\n"
                    "**Secondary:** Apply input validation using allowlists for expected data types and formats. "
                    "Use stored procedures where possible. Apply least-privilege database accounts. "
                    "Deploy a Web Application Firewall as defense-in-depth (not primary fix)."
                ),
                references=["https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"],
                code_examples={
                    "python": 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
                    "php": '$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?"); $stmt->execute([$id]);',
                    "java": 'PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?"); ps.setInt(1, id);',
                },
                tags=["injection", "database", "owasp-a03"],
            ),
            Remediation(
                id="CWE-79", title="Cross-Site Scripting (XSS)", severity="high",
                short_fix="Encode all user-controlled output for the correct context (HTML, JS, URL, CSS).",
                detailed_fix=(
                    "XSS attacks occur when an application includes untrusted data in a web page without proper validation or encoding.\n\n"
                    "**Primary Fix:** Context-sensitive output encoding — HTML-encode for HTML body, JS-encode for JavaScript, URL-encode for URLs.\n\n"
                    "**Secondary:** Implement Content Security Policy (CSP) headers. Use HttpOnly and Secure cookie flags. "
                    "Validate input using allowlists. Use auto-escaping template engines (Jinja2 with autoescape, React JSX)."
                ),
                references=["https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"],
                code_examples={
                    "python": "from markupsafe import escape; return escape(user_input)",
                    "javascript": "element.textContent = userInput; // NOT innerHTML",
                },
                tags=["xss", "injection", "client-side", "owasp-a03"],
            ),
            Remediation(
                id="CWE-78", title="OS Command Injection", severity="critical",
                short_fix="Avoid calling OS commands with user input. Use language APIs instead of shell commands.",
                detailed_fix=(
                    "Command injection occurs when an application passes unsafe user-supplied data to a system shell.\n\n"
                    "**Primary Fix:** Avoid OS command calls entirely — use language-native APIs (e.g., file operations, network libraries).\n\n"
                    "**If unavoidable:** Use parameterized command execution (subprocess with list args, never shell=True). "
                    "Apply strict allowlist validation on inputs. Escape shell metacharacters. Run with minimal OS privileges."
                ),
                references=["https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"],
                code_examples={
                    "python": 'subprocess.run(["ping", "-c", "1", validated_host], shell=False)',
                },
                tags=["injection", "command", "rce", "owasp-a03"],
            ),
            Remediation(
                id="CWE-22", title="Path Traversal / LFI", severity="high",
                short_fix="Validate and canonicalize file paths. Use allowlists for accessible directories.",
                detailed_fix=(
                    "Path traversal allows attackers to access files outside the intended directory.\n\n"
                    "**Primary Fix:** Canonicalize the file path and verify it starts with the expected base directory. "
                    "Use an allowlist of permitted filenames/paths.\n\n"
                    "**Secondary:** Run the application with minimal filesystem permissions. Use chroot jails or containers. "
                    "Strip or reject path separators and '..' sequences from user input."
                ),
                references=["https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html"],
                code_examples={
                    "python": "real = os.path.realpath(os.path.join(BASE_DIR, user_path))\nassert real.startswith(os.path.realpath(BASE_DIR))",
                },
                tags=["file", "traversal", "lfi", "owasp-a01"],
            ),
            Remediation(
                id="CWE-918", title="Server-Side Request Forgery (SSRF)", severity="high",
                short_fix="Validate and allowlist URLs. Block requests to internal/metadata endpoints.",
                detailed_fix=(
                    "SSRF occurs when an application fetches a remote resource using a user-supplied URL without validation.\n\n"
                    "**Primary Fix:** Allowlist permitted domains and protocols. Block RFC1918 ranges, link-local addresses, "
                    "and cloud metadata endpoints (169.254.169.254).\n\n"
                    "**Secondary:** Use a network-level firewall to restrict outbound access from the application. "
                    "Disable unnecessary URL schemes (file://, gopher://, dict://). Validate DNS resolution results."
                ),
                references=["https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"],
                tags=["ssrf", "network", "owasp-a10"],
            ),
            Remediation(
                id="CWE-611", title="XML External Entity (XXE)", severity="high",
                short_fix="Disable external entity processing in XML parsers.",
                detailed_fix=(
                    "XXE attacks exploit XML parsers that process external entity references.\n\n"
                    "**Primary Fix:** Disable DTDs (external entities) entirely in the XML parser configuration.\n\n"
                    "**Secondary:** Use less complex data formats (JSON) where possible. Validate, filter, and sanitize XML input. "
                    "Use updated XML libraries with XXE disabled by default."
                ),
                references=["https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html"],
                code_examples={
                    "python": "from defusedxml import ElementTree  # Drop-in safe replacement",
                    "java": 'factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);',
                },
                tags=["xxe", "xml", "injection", "owasp-a05"],
            ),
            Remediation(
                id="CWE-434", title="Unrestricted File Upload", severity="critical",
                short_fix="Validate file type, size, and content. Store uploads outside the webroot with random names.",
                detailed_fix=(
                    "Unrestricted file upload allows attackers to upload executable files (webshells).\n\n"
                    "**Primary Fix:** Validate file type by content (magic bytes), not just extension. Store uploads outside "
                    "the web-accessible directory. Use random filenames. Set non-executable permissions.\n\n"
                    "**Secondary:** Limit file size. Scan uploads with antivirus. Serve files via a separate domain. "
                    "Set Content-Disposition: attachment headers."
                ),
                references=["https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"],
                tags=["file-upload", "webshell", "rce", "owasp-a04"],
            ),
            Remediation(
                id="CWE-287", title="Improper Authentication", severity="critical",
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
                id="CWE-306", title="Missing Authentication for Critical Function", severity="critical",
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
                id="CWE-200", title="Information Exposure / Sensitive Data Disclosure", severity="medium",
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
                id="CWE-502", title="Deserialization of Untrusted Data", severity="critical",
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
                id="CWE-352", title="Cross-Site Request Forgery (CSRF)", severity="medium",
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
                id="CWE-269", title="Improper Privilege Management", severity="high",
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
                id="CWE-798", title="Hard-coded Credentials", severity="critical",
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
                id="CWE-311", title="Missing Encryption of Sensitive Data", severity="high",
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
                id="CWE-732", title="Incorrect Permission Assignment", severity="medium",
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
                id="CWE-1021", title="Clickjacking / UI Redress", severity="medium",
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
                id="CWE-94", title="Code Injection / SSTI", severity="critical",
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
        ]

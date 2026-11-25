"""WAF detection wrapper — wafw00f."""

from __future__ import annotations

import logging
import re
from typing import Any

from nexus.db.models import Finding, Severity, Target
from nexus.recon.runner import ToolRunner

log = logging.getLogger("nexus.recon.waf")

# Pattern to extract WAF name from wafw00f output.
# Example line: "[*] The site https://example.com is behind Cloudflare (Cloudflare Inc.) WAF."
_WAF_PATTERN = re.compile(
    r"is behind\s+(.+?)(?:\s+WAF|\s+\()", re.IGNORECASE
)
_NO_WAF_PATTERN = re.compile(r"No WAF detected", re.IGNORECASE)


async def wafw00f_detect(
    target: str,
    *,
    timeout: int = 60,
) -> dict[str, Any]:
    """Run wafw00f against a target and return detection results.

    Returns:
        {"target": str, "waf": str | None, "raw": str}
    """
    args = [target]
    out = await ToolRunner.run("wafw00f", args, timeout=timeout)

    combined = out.stdout + "\n" + out.stderr
    waf_name: str | None = None

    match = _WAF_PATTERN.search(combined)
    if match:
        waf_name = match.group(1).strip()
    elif _NO_WAF_PATTERN.search(combined):
        waf_name = None

    return {
        "target": target,
        "waf": waf_name,
        "raw": combined,
    }


async def detect_waf(
    targets: list[Target],
    *,
    timeout: int = 120,
) -> tuple[list[Target], list[Finding]]:
    """Run WAF detection on all live targets.

    Modifies targets in-place (sets waf_detected) and returns findings.
    """
    findings: list[Finding] = []

    if not ToolRunner.is_available("wafw00f"):
        log.warning("wafw00f not found — skipping WAF detection")
        return targets, findings

    for t in targets:
        if not t.is_live:
            continue

        url = t.host
        if not url.startswith("http"):
            url = f"http://{t.host}"

        try:
            result = await wafw00f_detect(url, timeout=timeout)
            waf = result.get("waf")
            if waf:
                t.waf_detected = waf
                findings.append(Finding(
                    host=t.host,
                    title=f"WAF Detected: {waf}",
                    description=(
                        f"A Web Application Firewall ({waf}) was detected "
                        f"protecting {t.host}.  Scan/exploit techniques may "
                        f"need WAF bypass adjustments."
                    ),
                    severity=Severity.INFO,
                    tool_source="wafw00f",
                ))
                log.info("WAF detected on %s: %s", t.host, waf)
            else:
                log.info("No WAF detected on %s", t.host)
        except Exception as e:
            log.debug("wafw00f failed for %s: %s", t.host, e)

    return targets, findings

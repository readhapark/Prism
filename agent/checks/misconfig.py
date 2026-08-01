from __future__ import annotations

from typing import Any
from urllib.parse import urljoin

import httpx

from agent.config import get_settings
from agent.models import Finding, Severity


SECURITY_HEADERS = [
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "strict-transport-security",
    "referrer-policy",
    "permissions-policy",
]


async def run_misconfig_checks(
    base_url: str,
    headers: dict[str, str],
    path_hits: list[dict[str, Any]],
    technologies: list[str],
    set_cookies: list[str] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_header_findings(base_url, headers))
    findings.extend(_cookie_findings(base_url, set_cookies or []))
    findings.extend(_path_findings(base_url, path_hits))
    findings.extend(await _cors_check(base_url))
    findings.extend(_tech_driven_findings(base_url, technologies, path_hits))
    return findings


def _header_findings(asset: str, headers: dict[str, str]) -> list[Finding]:
    out: list[Finding] = []
    lower = {k.lower(): v for k, v in headers.items()}

    missing = [h for h in SECURITY_HEADERS if h not in lower]
    if missing:
        sev = Severity.MEDIUM if "content-security-policy" in missing else Severity.LOW
        out.append(
            Finding(
                title="Missing security headers",
                severity=sev,
                category="headers",
                asset=asset,
                evidence=f"Missing: {', '.join(missing)}",
                remediation=(
                    "Add Content-Security-Policy, X-Frame-Options (or frame-ancestors), "
                    "X-Content-Type-Options: nosniff, Referrer-Policy, Permissions-Policy, "
                    "and HSTS on HTTPS endpoints."
                ),
                cwe="CWE-693",
                confidence=0.95,
            )
        )

    server = lower.get("server") or lower.get("x-powered-by")
    if server:
        out.append(
            Finding(
                title="Server / framework version disclosure",
                severity=Severity.INFO,
                category="information_disclosure",
                asset=asset,
                evidence=f"Banner: {server}",
                remediation="Remove or genericize Server and X-Powered-By response headers.",
                cwe="CWE-200",
                confidence=0.9,
            )
        )

    if "access-control-allow-origin" in lower and lower["access-control-allow-origin"] == "*":
        if "access-control-allow-credentials" in lower:
            out.append(
                Finding(
                    title="Permissive CORS with credentials risk",
                    severity=Severity.HIGH,
                    category="cors",
                    asset=asset,
                    evidence="Access-Control-Allow-Origin: * present alongside credential headers",
                    remediation="Reflect explicit origins; never combine ACAO:* with credentials.",
                    cwe="CWE-942",
                    confidence=0.75,
                )
            )
        else:
            out.append(
                Finding(
                    title="Wildcard CORS policy",
                    severity=Severity.LOW,
                    category="cors",
                    asset=asset,
                    evidence="Access-Control-Allow-Origin: *",
                    remediation="Restrict CORS to trusted origins where possible.",
                    cwe="CWE-942",
                    confidence=0.85,
                )
            )
    return out


def _cookie_findings(asset: str, set_cookies: list[str]) -> list[Finding]:
    out: list[Finding] = []
    for raw in set_cookies:
        lower = raw.lower()
        name = raw.split("=", 1)[0].strip()
        issues = []
        if "httponly" not in lower:
            issues.append("missing HttpOnly")
        if "secure" not in lower and asset.startswith("https"):
            issues.append("missing Secure")
        if "samesite" not in lower:
            issues.append("missing SameSite")
        if issues:
            out.append(
                Finding(
                    title=f"Weak cookie flags on '{name}'",
                    severity=Severity.MEDIUM,
                    category="cookies",
                    asset=asset,
                    evidence=f"{raw[:180]} → {', '.join(issues)}",
                    remediation="Set HttpOnly, Secure (HTTPS), and SameSite=Lax/Strict on session cookies.",
                    cwe="CWE-614",
                    confidence=0.9,
                )
            )
    return out


def _path_findings(asset: str, hits: list[dict[str, Any]]) -> list[Finding]:
    out: list[Finding] = []
    for hit in hits:
        if hit.get("error") or hit.get("status") not in {200, 401, 403}:
            continue
        path = hit.get("path", "")
        status = hit["status"]
        preview = (hit.get("preview") or "").lower()

        if path in {"/.git/HEAD", "/.git/config"} and status == 200:
            out.append(
                Finding(
                    title="Exposed .git metadata",
                    severity=Severity.CRITICAL,
                    category="source_exposure",
                    asset=hit.get("url", asset),
                    evidence=f"{path} returned {status}: {hit.get('preview', '')[:100]}",
                    remediation=(
                        "Block /.git at the reverse proxy; remove .git from deploy artifacts. "
                        "Rotate any secrets that may have been in history."
                    ),
                    cwe="CWE-527",
                    references=["https://owasp.org/www-community/vulnerabilities/Source_code_disclosure"],
                    confidence=0.95,
                )
            )
        elif path == "/.env" and status == 200 and (
            "key" in preview or "secret" in preview or "password" in preview or "=" in preview
        ):
            out.append(
                Finding(
                    title="Exposed environment file (.env)",
                    severity=Severity.CRITICAL,
                    category="secret_exposure",
                    asset=hit.get("url", asset),
                    evidence=f"/.env returned 200 ({hit.get('length')} bytes)",
                    remediation="Remove .env from web root; load secrets from a vault / env at runtime; rotate exposed keys.",
                    cwe="CWE-538",
                    confidence=0.9,
                )
            )
        elif path in {"/backup.zip", "/dump.sql"} and status == 200:
            out.append(
                Finding(
                    title=f"Downloadable backup artifact ({path})",
                    severity=Severity.HIGH,
                    category="backup_exposure",
                    asset=hit.get("url", asset),
                    evidence=f"{path} accessible (status {status}, {hit.get('length')} bytes)",
                    remediation="Store backups off the web root with authenticated access only.",
                    cwe="CWE-530",
                    confidence=0.85,
                )
            )
        elif path in {"/swagger.json", "/openapi.json", "/swagger/v1/swagger.json"} and status == 200:
            out.append(
                Finding(
                    title="Public OpenAPI / Swagger schema",
                    severity=Severity.MEDIUM,
                    category="api_exposure",
                    asset=hit.get("url", asset),
                    evidence=f"{path} returned 200 — API surface mapped without auth",
                    remediation="Restrict schema docs to internal networks or authenticated operators in production.",
                    cwe="CWE-200",
                    confidence=0.8,
                )
            )
        elif path == "/graphql" and status in {200, 400}:
            out.append(
                Finding(
                    title="GraphQL endpoint discovered",
                    severity=Severity.INFO,
                    category="api_exposure",
                    asset=hit.get("url", asset),
                    evidence=f"/graphql responded {status}",
                    remediation="Disable introspection in production; enforce authz on every resolver.",
                    confidence=0.7,
                )
            )
        elif path.startswith("/api") and status == 200:
            # Juice Shop style unauthenticated API
            if "product" in preview or "email" in preview or "[" in preview:
                out.append(
                    Finding(
                        title=f"Unauthenticated API data at {path}",
                        severity=Severity.HIGH,
                        category="broken_access_control",
                        asset=hit.get("url", asset),
                        evidence=f"{path} returned 200 with data preview: {hit.get('preview', '')[:120]}",
                        remediation=(
                            "Require authentication and object-level authorization. "
                            "Avoid returning PII/catalog admin fields to anonymous callers."
                        ),
                        cwe="CWE-306",
                        confidence=0.75,
                    )
                )
        elif path in {"/admin", "/admin/", "/wp-admin/"} and status in {200, 401, 403}:
            out.append(
                Finding(
                    title=f"Admin surface exposed at {path}",
                    severity=Severity.LOW if status in {401, 403} else Severity.MEDIUM,
                    category="admin_exposure",
                    asset=hit.get("url", asset),
                    evidence=f"{path} → HTTP {status}",
                    remediation="Restrict admin panels by IP / VPN / SSO; ensure MFA and rate limiting.",
                    confidence=0.8,
                )
            )
        elif path == "/package.json" and status == 200:
            out.append(
                Finding(
                    title="Exposed package.json (dependency disclosure)",
                    severity=Severity.MEDIUM,
                    category="information_disclosure",
                    asset=hit.get("url", asset),
                    evidence="package.json is publicly readable — aids CVE targeting",
                    remediation="Do not serve package.json / lockfiles from the public web root.",
                    cwe="CWE-200",
                    confidence=0.9,
                )
            )
        elif path == "/phpinfo.php" and status == 200 and "php version" in preview:
            out.append(
                Finding(
                    title="phpinfo() exposed",
                    severity=Severity.HIGH,
                    category="information_disclosure",
                    asset=hit.get("url", asset),
                    evidence="phpinfo.php returned configuration details",
                    remediation="Remove phpinfo scripts from all deployed environments.",
                    cwe="CWE-215",
                    confidence=0.95,
                )
            )
        elif path in {"/actuator", "/actuator/health", "/metrics", "/debug", "/console"} and status == 200:
            out.append(
                Finding(
                    title=f"Operational endpoint exposed: {path}",
                    severity=Severity.MEDIUM,
                    category="ops_exposure",
                    asset=hit.get("url", asset),
                    evidence=f"{path} returned 200",
                    remediation="Bind actuator/debug endpoints to internal networks and require auth.",
                    cwe="CWE-200",
                    confidence=0.8,
                )
            )
    return out


async def _cors_check(base_url: str) -> list[Finding]:
    settings = get_settings()
    out: list[Finding] = []
    evil = "https://evil-prism-probe.example"
    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=settings.request_timeout_s,
            verify=False,
        ) as client:
            resp = await client.options(
                base_url,
                headers={
                    "Origin": evil,
                    "Access-Control-Request-Method": "GET",
                },
            )
            acao = resp.headers.get("access-control-allow-origin", "")
            if acao == evil or acao == "*":
                out.append(
                    Finding(
                        title="CORS reflects arbitrary Origin",
                        severity=Severity.HIGH if acao == evil else Severity.MEDIUM,
                        category="cors",
                        asset=base_url,
                        evidence=f"Preflight with Origin {evil} → ACAO: {acao}",
                        remediation="Allowlist exact trusted origins; do not reflect arbitrary Origin values.",
                        cwe="CWE-942",
                        confidence=0.85,
                    )
                )
    except Exception:
        pass
    return out


def _tech_driven_findings(
    asset: str,
    technologies: list[str],
    path_hits: list[dict[str, Any]],
) -> list[Finding]:
    out: list[Finding] = []
    tech = {t.lower() for t in technologies}

    if "juice shop" in tech or any("juice" in t.lower() for t in technologies):
        out.append(
            Finding(
                title="OWASP Juice Shop detected (intentionally vulnerable)",
                severity=Severity.INFO,
                category="tech_stack",
                asset=asset,
                evidence="Fingerprint matched OWASP Juice Shop signatures",
                remediation=(
                    "Sandbox only — do not expose Juice Shop to the public internet. "
                    "Useful as a lab target for this agent's misconfig chain."
                ),
                confidence=0.99,
            )
        )
        # Classic Juice Shop: score-board / challenges API often open
        for hit in path_hits:
            if hit.get("path") in {"/api/Challenges", "/api/Users", "/api/users"} and hit.get("status") == 200:
                out.append(
                    Finding(
                        title="Juice Shop challenge/user API anonymously readable",
                        severity=Severity.HIGH,
                        category="broken_access_control",
                        asset=hit.get("url", asset),
                        evidence=f"{hit.get('path')} → 200",
                        remediation="In real apps: enforce authn/authz; here expected for the lab app.",
                        cwe="CWE-306",
                        confidence=0.85,
                    )
                )

    if "wordpress" in tech:
        out.append(
            Finding(
                title="WordPress detected — plugin/theme CVE surface",
                severity=Severity.INFO,
                category="tech_stack",
                asset=asset,
                evidence="WordPress markers in responses",
                remediation="Keep core/plugins patched; restrict wp-admin; disable XML-RPC if unused.",
                references=["https://wpscan.com/"],
                confidence=0.85,
            )
        )
        for hit in path_hits:
            if hit.get("path") == "/wp-json/" and hit.get("status") == 200:
                out.append(
                    Finding(
                        title="WordPress REST API publicly accessible",
                        severity=Severity.LOW,
                        category="api_exposure",
                        asset=hit.get("url", asset),
                        evidence="/wp-json/ returned 200",
                        remediation="Limit REST API to authenticated users where business-appropriate.",
                        confidence=0.8,
                    )
                )

    if "amazon s3" in tech:
        out.append(
            Finding(
                title="S3-related response fingerprints",
                severity=Severity.MEDIUM,
                category="cloud_storage",
                asset=asset,
                evidence="Responses resemble S3 error/headers — verify bucket ACLs are private",
                remediation="Ensure Block Public Access is on; audit bucket policies and object ACLs.",
                cwe="CWE-284",
                confidence=0.6,
            )
        )

    return out


async def check_git_exposure(base_url: str) -> list[Finding]:
    """Focused follow-up when path probe hints at .git."""
    settings = get_settings()
    findings: list[Finding] = []
    url = urljoin(base_url.rstrip("/") + "/", ".git/HEAD")
    async with httpx.AsyncClient(timeout=settings.request_timeout_s, verify=False) as client:
        try:
            resp = await client.get(url)
            if resp.status_code == 200 and "ref:" in resp.text:
                findings.append(
                    Finding(
                        title="Confirmed bare .git/HEAD disclosure",
                        severity=Severity.CRITICAL,
                        category="source_exposure",
                        asset=url,
                        evidence=resp.text.strip()[:80],
                        remediation="Deny web access to .git; purge from image; rotate secrets.",
                        cwe="CWE-527",
                        confidence=0.99,
                    )
                )
        except Exception:
            pass
    return findings
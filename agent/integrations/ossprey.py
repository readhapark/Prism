"""Ossprey supply-chain malware scanning integration.

Triggered when Prism discovers package manifests (package.json, requirements.txt)
or exposed dependency metadata on the target. Uses the Ossprey CLI when present,
otherwise the public HTTP API.

Auth: OSSPREY_API_KEY (or browser login via `ossprey login` for local demos).
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

import httpx

from agent.config import get_settings
from agent.models import Finding, Severity


async def scan_dependencies(
    packages: list[dict[str, str]],
    ecosystem: str = "npm",
    workdir: Path | None = None,
) -> dict[str, Any]:
    """Scan a list of {name, version?} packages or a local project directory."""
    settings = get_settings()
    if workdir is not None:
        return await _scan_path(workdir)

    if not packages:
        return {"skipped": True, "reason": "no packages", "findings": []}

    # Prefer named package check
    return await check_packages(packages, ecosystem=ecosystem)


async def check_packages(
    packages: list[dict[str, str]],
    ecosystem: str = "npm",
) -> dict[str, Any]:
    settings = get_settings()
    cli = shutil.which("ossprey")
    if cli and (settings.ossprey_api_key or _has_ossprey_login()):
        return await _cli_check(packages, ecosystem)

    if settings.ossprey_api_key:
        return await _api_check(packages, ecosystem)

    # Offline / demo fallback: catalogue only + heuristic flags
    return _local_catalogue(packages, ecosystem)


async def scan_manifest_content(
    filename: str,
    content: str,
) -> dict[str, Any]:
    """Parse a discovered remote manifest and check packages via Ossprey."""
    name = filename.lower()
    if name.endswith("package.json") or name == "package.json" or content.strip().startswith("{"):
        packages = _parse_packages_from_json(content)
        if not packages:
            # package.json with only name/version and no deps section
            return {
                "ecosystem": "npm",
                "components": [],
                "malware": [],
                "skipped": True,
                "reason": "no dependencies declared in package.json",
            }
        return await check_packages(packages, ecosystem="npm")

    if "requirements" in name:
        packages = _parse_requirements(content)
        return await check_packages(packages, ecosystem="pypi")

    return {"skipped": True, "reason": f"unsupported manifest: {filename}", "malware": [], "components": []}


def results_to_findings(result: dict[str, Any], asset: str) -> list[Finding]:
    findings: list[Finding] = []
    for item in result.get("malware", []):
        pkg = item.get("package") or item.get("name") or "unknown"
        findings.append(
            Finding(
                title=f"Ossprey: malicious package {pkg}",
                severity=Severity.CRITICAL,
                category="supply_chain",
                asset=asset,
                evidence=item.get("message") or json.dumps(item)[:300],
                remediation=(
                    f"Remove/replace `{pkg}` immediately, rotate any credentials "
                    "the host may have exposed, and re-scan the dependency tree with Ossprey."
                ),
                references=["https://www.ossprey.com/", "https://docs.ossprey.com"],
                confidence=0.95,
                cwe="CWE-506",
            )
        )

    comps = result.get("components") or []
    if comps and not findings and not result.get("error"):
        findings.append(
            Finding(
                title=f"Ossprey: scanned {len(comps)} dependencies — no malware verdict",
                severity=Severity.INFO,
                category="supply_chain",
                asset=asset,
                evidence=f"Ecosystem={result.get('ecosystem', '?')}; components={len(comps)}",
                remediation="Keep Ossprey in CI so new dependencies are checked before install.",
                references=["https://www.ossprey.com/"],
                confidence=0.9,
            )
        )

    if result.get("error") and not result.get("skipped"):
        findings.append(
            Finding(
                title="Ossprey scan could not complete",
                severity=Severity.INFO,
                category="supply_chain",
                asset=asset,
                evidence=str(result.get("error")),
                remediation="Verify OSSPREY_API_KEY and network access to api.ossprey.com.",
                confidence=0.5,
            )
        )
    return findings


async def _scan_path(path: Path) -> dict[str, Any]:
    settings = get_settings()
    cli = shutil.which("ossprey")
    if not cli:
        # Parse manifests ourselves
        pkg = path / "package.json"
        req = path / "requirements.txt"
        if pkg.exists():
            packages = _parse_packages_from_json(pkg.read_text(encoding="utf-8"))
            return await check_packages(packages, ecosystem="npm")
        if req.exists():
            packages = _parse_requirements(req.read_text(encoding="utf-8"))
            return await check_packages(packages, ecosystem="pypi")
        return {"skipped": True, "reason": "no ossprey CLI / manifests", "findings": []}

    out_file = path / "ossbom.json"
    cmd = [cli, "scan", str(path), "-o", str(out_file)]
    env = os.environ.copy()
    if settings.ossprey_api_key:
        env["OSSPREY_API_KEY"] = settings.ossprey_api_key
    if settings.ossprey_api_url:
        env["OSSPREY_API_URL"] = settings.ossprey_api_url
        cmd += ["--url", settings.ossprey_api_url]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=90.0)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        return {
            "error": "ossprey scan timed out after 90s",
            "malware": [],
            "components": [],
            "ecosystem": "npm",
        }

    malware: list[dict[str, Any]] = []
    components: list[dict[str, Any]] = []
    if out_file.exists():
        try:
            bom = json.loads(out_file.read_text(encoding="utf-8"))
            components = bom.get("components") or bom.get("packages") or []
            for v in bom.get("vulnerabilities") or bom.get("malware") or []:
                malware.append(v if isinstance(v, dict) else {"message": str(v)})
        except json.JSONDecodeError:
            pass

    # Parse stderr WARNING lines
    for line in (stderr.decode("utf-8", errors="ignore") + stdout.decode("utf-8", errors="ignore")).splitlines():
        if "malware" in line.lower():
            malware.append({"message": line.strip()})

    return {
        "exit_code": proc.returncode,
        "malware": malware,
        "components": components,
        "stdout": stdout.decode("utf-8", errors="ignore")[-2000:],
        "stderr": stderr.decode("utf-8", errors="ignore")[-2000:],
    }


async def _cli_check(packages: list[dict[str, str]], ecosystem: str) -> dict[str, Any]:
    settings = get_settings()
    cli = shutil.which("ossprey")
    assert cli
    specs = []
    for p in packages[:40]:
        name = p["name"]
        ver = p.get("version")
        specs.append(f"{name}@{ver}" if ver else name)
    cmd = [cli, "check", "-e", ecosystem, *specs]
    env = os.environ.copy()
    if settings.ossprey_api_key:
        env["OSSPREY_API_KEY"] = settings.ossprey_api_key
    if settings.ossprey_api_url:
        cmd += ["--url", settings.ossprey_api_url]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=90.0)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        return {
            "ecosystem": ecosystem,
            "error": "ossprey check timed out after 90s",
            "malware": [],
            "components": [{"name": p["name"], "version": p.get("version")} for p in packages],
        }

    text = stdout.decode() + stderr.decode()
    malware = [{"package": line.split(":")[0].strip(), "message": line.strip()}
               for line in text.splitlines() if "malware" in line.lower()]
    return {
        "ecosystem": ecosystem,
        "exit_code": proc.returncode,
        "malware": malware,
        "components": [{"name": p["name"], "version": p.get("version")} for p in packages],
        "raw": text[-2000:],
    }


async def _api_check(packages: list[dict[str, str]], ecosystem: str) -> dict[str, Any]:
    """Best-effort public API call — schema may evolve; fail soft."""
    settings = get_settings()
    base = (settings.ossprey_api_url or "https://api.ossprey.com").rstrip("/")
    headers = {
        "Authorization": f"Bearer {settings.ossprey_api_key}",
        "X-API-Key": settings.ossprey_api_key,
        "Content-Type": "application/json",
    }
    payload = {
        "eco_system": ecosystem,
        "ecosystem": ecosystem,
        "packages": [
            {"name": p["name"], "version": p.get("version")}
            for p in packages[:40]
        ],
    }
    urls = [
        f"{base}/public/v1/check",
        f"{base}/public/v1/scan/packages",
        f"{base}/v1/check",
    ]
    async with httpx.AsyncClient(timeout=45.0) as client:
        last_err = None
        for url in urls:
            try:
                resp = await client.post(url, headers=headers, json=payload)
                if resp.status_code >= 400:
                    last_err = f"{url} → {resp.status_code} {resp.text[:200]}"
                    continue
                data = resp.json()
                malware = data.get("malware") or data.get("vulnerabilities") or []
                if isinstance(malware, dict):
                    malware = malware.get("items") or []
                return {
                    "ecosystem": ecosystem,
                    "malware": malware,
                    "components": payload["packages"],
                    "raw": data,
                }
            except Exception as exc:  # noqa: BLE001
                last_err = str(exc)
        return {
            "ecosystem": ecosystem,
            "error": last_err or "Ossprey API unreachable",
            "components": payload["packages"],
            "malware": [],
            # Fall through to CLI messaging
            "hint": "Install ossprey CLI or verify API path; catalogue still recorded.",
        }


def _local_catalogue(packages: list[dict[str, str]], ecosystem: str) -> dict[str, Any]:
    return {
        "skipped": True,
        "reason": "OSSPREY_API_KEY not set and CLI unavailable — local catalogue only",
        "ecosystem": ecosystem,
        "components": packages,
        "malware": [],
    }


def _parse_packages_from_json(content: str) -> list[dict[str, str]]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []
    out: list[dict[str, str]] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        deps = data.get(section) or {}
        if isinstance(deps, dict):
            for name, ver in deps.items():
                out.append({"name": name, "version": str(ver).lstrip("^~>=< ")})
    return out


def _parse_requirements(content: str) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        for sep in ("==", ">=", "~=", "<="):
            if sep in line:
                name, ver = line.split(sep, 1)
                out.append({"name": name.strip(), "version": ver.strip()})
                break
        else:
            out.append({"name": line.split("[")[0].strip()})
    return out


def _has_ossprey_login() -> bool:
    cfg = Path.home() / ".config" / "ossprey" / "credentials.json"
    return cfg.exists()
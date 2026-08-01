from __future__ import annotations

import asyncio
import re
import ssl
from typing import Any
from urllib.parse import urlparse

import httpx

from agent.config import get_settings


COMMON_PORTS = [80, 443, 3000, 3001, 8000, 8080, 8443, 5000, 8888, 9000]

TECH_SIGNATURES: list[tuple[str, re.Pattern[str], str]] = [
    ("Juice Shop", re.compile(r"OWASP Juice Shop|juice-shop", re.I), "header_or_body"),
    ("Express", re.compile(r"Express", re.I), "header"),
    ("nginx", re.compile(r"nginx", re.I), "header"),
    ("Apache", re.compile(r"Apache", re.I), "header"),
    ("WordPress", re.compile(r"wp-content|WordPress", re.I), "body"),
    ("Drupal", re.compile(r"Drupal|X-Generator:\s*Drupal", re.I), "body"),
    ("React", re.compile(r"react|__NEXT_DATA__|data-reactroot", re.I), "body"),
    ("Angular", re.compile(r"ng-version|angular", re.I), "body"),
    ("jQuery", re.compile(r"jquery", re.I), "body"),
    ("PHP", re.compile(r"X-Powered-By:\s*PHP|\\.php", re.I), "header_or_body"),
    ("Django", re.compile(r"csrftoken|django", re.I), "header_or_body"),
    ("Flask", re.compile(r"Werkzeug|Flask", re.I), "header"),
    ("Next.js", re.compile(r"__NEXT_DATA__|_next/static", re.I), "body"),
    ("Bootstrap", re.compile(r"bootstrap", re.I), "body"),
    ("Cloudflare", re.compile(r"cloudflare|cf-ray", re.I), "header"),
    ("Amazon S3", re.compile(r"Amz-Request-Id|NoSuchBucket|s3\\.amazonaws", re.I), "header_or_body"),
]


async def fingerprint_ports(host: str, ports: list[int] | None = None) -> dict[str, Any]:
    """TCP connect fingerprint — banner grab is intentionally shallow (read-only)."""
    ports = ports or COMMON_PORTS
    # For localhost / docker juice shop, prioritize app ports
    open_ports: list[dict[str, Any]] = []

    async def probe(port: int) -> dict[str, Any] | None:
        try:
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=1.2)
            service = _guess_service(port)
            banner = ""
            try:
                writer.write(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % host.encode())
                await writer.drain()
                data = await asyncio.wait_for(reader.read(256), timeout=0.8)
                banner = data.decode("latin-1", errors="ignore")[:200]
            except Exception:
                pass
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return {"port": port, "state": "open", "service": service, "banner": banner}
        except Exception:
            return None

    results = await asyncio.gather(*[probe(p) for p in ports])
    for r in results:
        if r:
            open_ports.append(r)

    return {"host": host, "open_ports": open_ports, "scanned": ports}


async def detect_tech(base_url: str) -> dict[str, Any]:
    settings = get_settings()
    technologies: list[str] = []
    evidence: dict[str, str] = {}

    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=settings.request_timeout_s,
        verify=False,
    ) as client:
        try:
            resp = await client.get(base_url)
        except Exception as exc:
            return {"technologies": [], "error": str(exc)}

        headers_blob = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        body = resp.text[:80_000]
        combined = headers_blob + "\n" + body

        for name, pattern, where in TECH_SIGNATURES:
            hay = (
                headers_blob
                if where == "header"
                else body
                if where == "body"
                else combined
            )
            if pattern.search(hay):
                technologies.append(name)
                m = pattern.search(hay)
                evidence[name] = (m.group(0) if m else name)[:120]

        # TLS quick check
        tls_info: dict[str, Any] = {}
        parsed = urlparse(base_url)
        if parsed.scheme == "https" and parsed.hostname:
            tls_info = await _tls_probe(parsed.hostname, parsed.port or 443)

    return {
        "technologies": sorted(set(technologies)),
        "evidence": evidence,
        "status_code": resp.status_code,
        "server": resp.headers.get("server", ""),
        "powered_by": resp.headers.get("x-powered-by", ""),
        "tls": tls_info,
    }


async def _tls_probe(host: str, port: int) -> dict[str, Any]:
    try:
        ctx = ssl.create_default_context()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=host),
            timeout=3.0,
        )
        sslobj = writer.get_extra_info("ssl_object")
        info = {
            "version": sslobj.version() if sslobj else None,
            "cipher": sslobj.cipher()[0] if sslobj and sslobj.cipher() else None,
        }
        writer.close()
        await writer.wait_closed()
        return info
    except Exception as exc:
        return {"error": str(exc)}


def _guess_service(port: int) -> str:
    return {
        80: "http",
        443: "https",
        3000: "http-alt",
        3001: "http-alt",
        8000: "http-alt",
        8080: "http-proxy",
        8443: "https-alt",
        5000: "http-alt",
        8888: "http-alt",
        9000: "http-alt",
    }.get(port, "unknown")
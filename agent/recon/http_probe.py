from __future__ import annotations

from typing import Any
from urllib.parse import urljoin

import httpx

from agent.config import get_settings

# Passive path probes — existence / exposure only, no auth bypass payloads
INTERESTING_PATHS = [
    "/.git/HEAD",
    "/.git/config",
    "/.env",
    "/.DS_Store",
    "/robots.txt",
    "/sitemap.xml",
    "/package.json",
    "/composer.json",
    "/wp-json/",
    "/wp-admin/",
    "/admin",
    "/admin/",
    "/api",
    "/api/",
    "/api/users",
    "/api/Products",
    "/api/Challenges",
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/openapi.json",
    "/graphql",
    "/actuator",
    "/actuator/health",
    "/server-status",
    "/phpinfo.php",
    "/backup.zip",
    "/dump.sql",
    "/.well-known/security.txt",
    "/crossdomain.xml",
    "/config.json",
    "/metrics",
    "/debug",
    "/console",
]


async def fetch_headers(base_url: str) -> dict[str, Any]:
    settings = get_settings()
    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=settings.request_timeout_s,
        verify=False,
    ) as client:
        resp = await client.get(base_url)
        return {
            "url": str(resp.url),
            "status_code": resp.status_code,
            "headers": {k.lower(): v for k, v in resp.headers.items()},
            "cookies": [
                {
                    "name": c.name,
                    "value_preview": (c.value[:8] + "…") if len(c.value) > 8 else c.value,
                    "secure": c.secure,
                    # httpx Cookie has limited attrs; parse set-cookie later in checks
                }
                for c in resp.cookies.jar
            ],
            "set_cookie_raw": resp.headers.get_list("set-cookie")
            if hasattr(resp.headers, "get_list")
            else ([resp.headers["set-cookie"]] if "set-cookie" in resp.headers else []),
        }


async def probe_paths(base_url: str, paths: list[str] | None = None) -> dict[str, Any]:
    settings = get_settings()
    paths = paths or INTERESTING_PATHS
    hits: list[dict[str, Any]] = []

    async with httpx.AsyncClient(
        follow_redirects=False,
        timeout=settings.request_timeout_s,
        verify=False,
    ) as client:
        for path in paths:
            url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
            try:
                resp = await client.get(url)
            except Exception as exc:
                hits.append({"path": path, "error": str(exc)})
                continue
            # Record interesting statuses only
            if resp.status_code in {200, 201, 204, 301, 302, 401, 403, 500}:
                body_preview = ""
                try:
                    body_preview = resp.text[:240]
                except Exception:
                    body_preview = ""
                hits.append(
                    {
                        "path": path,
                        "url": url,
                        "status": resp.status_code,
                        "content_type": resp.headers.get("content-type", ""),
                        "length": len(resp.content),
                        "preview": body_preview,
                    }
                )
    return {"base_url": base_url, "hits": hits, "probed": len(paths)}


async def fetch_robots(base_url: str) -> dict[str, Any]:
    settings = get_settings()
    url = urljoin(base_url.rstrip("/") + "/", "robots.txt")
    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=settings.request_timeout_s,
        verify=False,
    ) as client:
        try:
            resp = await client.get(url)
            if resp.status_code != 200:
                return {"present": False, "status": resp.status_code}
            text = resp.text[:5000]
            disallows = [
                line.split(":", 1)[1].strip()
                for line in text.splitlines()
                if line.lower().startswith("disallow:")
            ]
            return {"present": True, "disallows": disallows, "raw": text}
        except Exception as exc:
            return {"present": False, "error": str(exc)}
from __future__ import annotations

from typing import Any


# Common lab / juice-shop style prefixes — passive dictionary only (no zone transfer)
COMMON_PREFIXES = [
    "www",
    "api",
    "admin",
    "staging",
    "dev",
    "test",
    "mail",
    "cdn",
    "static",
    "app",
    "beta",
    "secure",
    "vpn",
    "git",
    "status",
]


async def enumerate_subdomains(host: str) -> dict[str, Any]:
    """Lightweight subdomain enum via DNS A lookups on a small wordlist.

    Skips public recursive blasting for localhost / IP targets.
    """
    import asyncio

    import dns.asyncresolver
    import dns.exception

    if host in {"localhost", "127.0.0.1", "0.0.0.0"} or _is_ip(host):
        return {
            "host": host,
            "subdomains": [host],
            "notes": ["IP/localhost target — subdomain enum skipped"],
        }

    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 2.0
    found: list[str] = []

    async def lookup(name: str) -> str | None:
        try:
            await resolver.resolve(name, "A")
            return name
        except (dns.exception.DNSException, Exception):
            return None

    # Always include apex if it resolves
    apex = await lookup(host)
    if apex:
        found.append(apex)

    tasks = [lookup(f"{p}.{host}") for p in COMMON_PREFIXES]
    results = await asyncio.gather(*tasks)
    for r in results:
        if r and r not in found:
            found.append(r)

    return {
        "host": host,
        "subdomains": found,
        "wordlist_size": len(COMMON_PREFIXES),
        "notes": [f"Resolved {len(found)} name(s) from {len(COMMON_PREFIXES)} candidates"],
    }


def _is_ip(host: str) -> bool:
    parts = host.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return True
    return ":" in host  # rough IPv6
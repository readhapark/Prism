"""
Prism lab target on a Modal Sandbox (not a web_server Function).

Creates a stateful, isolated container that:
  1. Runs the deliberately-vulnerable Juice Shop–style lab app
  2. Exposes it via an encrypted Modal tunnel (*.modal.host)
  3. Optionally hosts a stateful Python code interpreter for sandboxed recon

Usage:
  modal setup   # once
  python -m prism_modal.sandbox_target spawn
  # or via Prism API: POST /api/sandbox/start

The tunnel URL is allowlisted by default (*.modal.run / *.modal.host).
"""

from __future__ import annotations

import argparse
import inspect
import json
import time
from pathlib import Path
from typing import Any, Iterator

import modal

APP_NAME = "prism-attack-surface-lab"
SANDBOX_NAME = "prism-juice-lab"
LAB_PORT = 3000

# Lightweight image: Python + FastAPI lab mirror (fast for demos).
# For full OWASP Juice Shop, see modal/juice_shop.py (web_server) or
# pass --full-juice to spawn().
LAB_IMAGE = (
    modal.Image.debian_slim(python_version="3.11")
    .pip_install("fastapi", "uvicorn[standard]")
    .add_local_file(
        local_path=str(Path(__file__).resolve().parent.parent / "demo" / "sandbox_app.py"),
        remote_path="/opt/prism/sandbox_app.py",
        copy=True,
    )
)

# Optional heavier Juice Shop image (slow first build — cache afterwards)
JUICE_IMAGE = (
    modal.Image.debian_slim(python_version="3.11")
    .apt_install("curl", "ca-certificates", "gnupg")
    .run_commands(
        "curl -fsSL https://deb.nodesource.com/setup_20.x | bash -",
        "apt-get install -y nodejs",
        "mkdir -p /opt/juice-shop",
        "curl -fsSL https://github.com/juice-shop/juice-shop/releases/download/v17.1.1/"
        "juice-shop-17.1.1_node20_linux_x64.tgz "
        "| tar -xz -C /opt/juice-shop --strip-components=1",
        "cd /opt/juice-shop && npm ci --omit=dev || npm install --omit=dev",
    )
)


def _lab_entrypoint() -> list[str]:
    return [
        "uvicorn",
        "sandbox_app:app",
        "--host",
        "0.0.0.0",
        "--port",
        str(LAB_PORT),
        "--app-dir",
        "/opt/prism",
    ]


def _juice_entrypoint() -> list[str]:
    return ["bash", "-c", f"cd /opt/juice-shop && PORT={LAB_PORT} npm start"]


# ---------------------------------------------------------------------------
# Stateful code interpreter (Modal Sandbox pattern)
# ---------------------------------------------------------------------------

def driver_program() -> None:
    """Runs inside the Sandbox — listens for JSON code on stdin, execs it."""
    import json
    import sys
    from contextlib import redirect_stderr, redirect_stdout
    from io import StringIO
    from typing import Any

    globals_state: dict[str, Any] = {}
    while True:
        try:
            line = input()
        except EOFError:
            break
        command = json.loads(line)
        if (code := command.get("code")) is None:
            print(json.dumps({"error": "No code to execute"}), flush=True)
            continue
        stdout_io, stderr_io = StringIO(), StringIO()
        with redirect_stdout(stdout_io), redirect_stderr(stderr_io):
            try:
                exec(code, globals_state)
            except Exception as e:  # noqa: BLE001
                print(f"Execution Error: {e}", file=sys.stderr)
        print(
            json.dumps({"stdout": stdout_io.getvalue(), "stderr": stderr_io.getvalue()}),
            flush=True,
        )


def run_code(writer: Any, reader: Iterator[str], code: str) -> dict[str, str]:
    writer.write(json.dumps({"code": code}) + "\n")
    writer.drain()
    result = json.loads(next(reader))
    return result


class PrismSandbox:
    """Lifecycle helper around a Modal Sandbox lab target."""

    def __init__(self, sandbox: modal.Sandbox, tunnel_url: str, sandbox_id: str):
        self.sandbox = sandbox
        self.tunnel_url = tunnel_url
        self.sandbox_id = sandbox_id
        self._interp = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "sandbox_id": self.sandbox_id,
            "tunnel_url": self.tunnel_url,
            "dashboard_url": self.sandbox.get_dashboard_url(),
            "port": LAB_PORT,
        }

    def start_interpreter(self) -> None:
        """Start a stateful Python interpreter process via Sandbox.exec."""
        driver_program_text = inspect.getsource(driver_program)
        driver_program_command = f"{driver_program_text}\n\ndriver_program()"
        p = self.sandbox.exec("python", "-c", driver_program_command, bufsize=1)
        self._interp = p

    def exec_python(self, code: str) -> dict[str, str]:
        if self._interp is None:
            self.start_interpreter()
        assert self._interp is not None
        return run_code(self._interp.stdin, iter(self._interp.stdout), code)

    def terminate(self) -> None:
        try:
            self.sandbox.terminate()
        finally:
            try:
                self.sandbox.detach()
            except Exception:
                pass


def spawn(
    *,
    full_juice: bool = False,
    timeout: int = 60 * 60,
    name: str = SANDBOX_NAME,
) -> PrismSandbox:
    """Create a Modal Sandbox running the lab app; return tunnel URL."""
    app = modal.App.lookup(APP_NAME, create_if_missing=True)
    image = JUICE_IMAGE if full_juice else LAB_IMAGE
    entry = _juice_entrypoint() if full_juice else _lab_entrypoint()

    # Reuse named sandbox if still alive
    try:
        existing = modal.Sandbox.from_name(APP_NAME, name)
        tunnels = existing.tunnels()
        if LAB_PORT in tunnels:
            url = tunnels[LAB_PORT].url
            return PrismSandbox(existing, url, existing.object_id)
    except Exception:
        pass

    sb = modal.Sandbox.create(
        *entry,
        app=app,
        name=name,
        image=image,
        timeout=timeout,
        encrypted_ports=[LAB_PORT],
        readiness_probe=modal.Probe.with_tcp(LAB_PORT, interval_ms=500),
        cpu=1.0,
        memory=2048 if full_juice else 512,
    )
    sb.wait_until_ready(timeout=600)
    tunnels = sb.tunnels()
    tunnel = tunnels[LAB_PORT]
    url = tunnel.url
    # Give the ASGI/Node server a beat after TCP accept
    time.sleep(1.0)
    return PrismSandbox(sb, url, sb.object_id)


def terminate(name: str = SANDBOX_NAME) -> bool:
    try:
        sb = modal.Sandbox.from_name(APP_NAME, name)
        sb.terminate()
        return True
    except Exception:
        return False


def status(name: str = SANDBOX_NAME) -> dict[str, Any]:
    try:
        sb = modal.Sandbox.from_name(APP_NAME, name)
        tunnels = sb.tunnels(timeout=10)
        url = tunnels[LAB_PORT].url if LAB_PORT in tunnels else None
        return {
            "running": True,
            "sandbox_id": sb.object_id,
            "tunnel_url": url,
            "dashboard_url": sb.get_dashboard_url(),
        }
    except Exception as exc:
        return {"running": False, "error": str(exc)}


def main() -> None:
    parser = argparse.ArgumentParser(description="Prism Modal Sandbox lab target")
    parser.add_argument("command", choices=["spawn", "status", "terminate", "demo-interp"])
    parser.add_argument("--full-juice", action="store_true", help="Use real OWASP Juice Shop image")
    parser.add_argument("--name", default=SANDBOX_NAME)
    args = parser.parse_args()

    if args.command == "spawn":
        ps = spawn(full_juice=args.full_juice, name=args.name)
        print(json.dumps(ps.to_dict(), indent=2))
        print(f"\nPoint Prism at: {ps.tunnel_url}")
    elif args.command == "status":
        print(json.dumps(status(args.name), indent=2))
    elif args.command == "terminate":
        ok = terminate(args.name)
        print(json.dumps({"terminated": ok}))
    elif args.command == "demo-interp":
        # Stateful interpreter demo (Modal docs pattern)
        app = modal.App.lookup(APP_NAME, create_if_missing=True)
        sb = modal.Sandbox.create(app=app, timeout=10 * 60)
        driver_program_text = inspect.getsource(driver_program)
        driver_program_command = f"{driver_program_text}\n\ndriver_program()"
        p = sb.exec("python", "-c", driver_program_command, bufsize=1)
        reader, writer = iter(p.stdout), p.stdin
        for code in [
            "print('hello from Modal Sandbox!')",
            "x = 10",
            "y = 5",
            "print(f'The result is: {x + y}')",
        ]:
            result = run_code(writer, reader, code)
            print(result.get("stdout", ""), end="")
            if result.get("stderr"):
                print(result["stderr"], end="")
        sb.terminate()


if __name__ == "__main__":
    main()
"""
Alternate deploy: Juice Shop as a long-lived Modal *web endpoint*.

Prefer `prism_modal/sandbox_target.py` for the hackathon demo — that uses a true
Modal Sandbox with encrypted tunnels + optional stateful code interpreter.

This file remains useful if you want a durable *.modal.run URL without
managing Sandbox lifecycle:

  modal deploy prism_modal/juice_shop.py
"""

from __future__ import annotations

import subprocess
import time

import modal

app = modal.App("prism-juice-shop-web")

image = (
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


@app.function(image=image, allow_concurrent_inputs=50, timeout=60 * 60 * 6, memory=2048)
@modal.web_server(port=3000, startup_timeout=180)
def juice_shop():
    subprocess.Popen(
        ["npm", "start"],
        cwd="/opt/juice-shop",
        env={"PORT": "3000", "NODE_ENV": "production", "PATH": "/usr/local/bin:/usr/bin:/bin"},
    )
    time.sleep(2)


@app.local_entrypoint()
def main():
    print("For Sandbox (recommended): python -m prism_modal.sandbox_target spawn")
    print("For durable web endpoint:  modal deploy prism_modal/juice_shop.py")
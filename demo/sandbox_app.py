"""
Local deliberately-vulnerable sandbox for Prism demos.

Mimics Juice Shop-style misconfigs WITHOUT needing Docker/Modal:
- Missing security headers
- Weak cookies
- Open /api/Products, /api/Users, /api/Challenges
- Exposed /.git/HEAD, /package.json
- Permissive CORS reflection
- robots.txt with juicy disallows

Run:  python demo/sandbox_app.py
URL:   http://127.0.0.1:3001
"""

from __future__ import annotations

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse
import uvicorn

app = FastAPI(title="OWASP Juice Shop (Prism Lab Mirror)", version="0.0.lab")


@app.middleware("http")
async def insecure_defaults(request: Request, call_next):
    # Reflect arbitrary Origin (misconfig)
    origin = request.headers.get("origin")
    response: Response = await call_next(request)
    if origin:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
    else:
        response.headers["Access-Control-Allow-Origin"] = "*"
    # Fingerprintable banners — intentional disclosure
    response.headers["Server"] = "nginx/1.18.0"
    response.headers["X-Powered-By"] = "Express"
    # Deliberately omit CSP, XFO, nosniff, HSTS, Referrer-Policy
    if "set-cookie" not in {k.lower() for k in response.headers.keys()}:
        response.headers["Set-Cookie"] = "token=lab-session-demo; Path=/"
    return response


@app.get("/")
async def home():
    html = """<!doctype html>
<html><head><title>OWASP Juice Shop</title></head>
<body>
  <h1>OWASP Juice Shop</h1>
  <p>Prism lab mirror — intentionally vulnerable sandbox.</p>
  <script>window.__JUICE_SHOP__=true</script>
  <link rel="stylesheet" href="/bootstrap.min.css">
</body></html>"""
    return Response(html, media_type="text/html")


@app.get("/robots.txt")
async def robots():
    return PlainTextResponse(
        "User-agent: *\nDisallow: /encryptionkeys\nDisallow: /api/Users\nDisallow: /rest/admin\n"
    )


@app.get("/.git/HEAD")
async def git_head():
    return PlainTextResponse("ref: refs/heads/master\n")


@app.get("/.git/config")
async def git_config():
    return PlainTextResponse("[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://example.com/juice-shop.git\n")


@app.get("/.env")
async def env_file():
    return PlainTextResponse(
        "NODE_ENV=production\nJWT_SECRET=super-secret-lab-key\nSTRIPE_KEY=sk_test_prism_lab\n"
    )


@app.get("/package.json")
async def package_json():
    return JSONResponse(
        {
            "name": "juice-shop",
            "version": "17.1.1",
            "description": "OWASP Juice Shop",
            "dependencies": {"express": "4.21.0", "sequelize": "6.37.0"},
        }
    )


@app.get("/api/")
@app.get("/api")
async def api_root():
    return {"status": "ok", "app": "OWASP Juice Shop"}


@app.get("/api/Products")
async def products():
    return {
        "status": "success",
        "data": [
            {"id": 1, "name": "Apple Juice", "price": 1.99},
            {"id": 2, "name": "Orange Juice", "price": 2.99},
            {"id": 3, "name": "Christmas Super-Surprise-Box", "price": 99.99},
        ],
    }


@app.get("/api/Users")
@app.get("/api/users")
async def users():
    return {
        "status": "success",
        "data": [
            {"id": 1, "email": "admin@juice-sh.op", "password": "hash…"},
            {"id": 2, "email": "jim@juice-sh.op", "password": "hash…"},
        ],
    }


@app.get("/api/Challenges")
async def challenges():
    return {
        "status": "success",
        "data": [
            {"id": 1, "name": "Score Board", "difficulty": 1},
            {"id": 2, "name": "Error Handling", "difficulty": 1},
        ],
    }


@app.get("/rest/admin/application-configuration")
async def admin_config():
    return {"server": {"port": 3000}, "application": {"name": "OWASP Juice Shop"}}


@app.get("/admin")
@app.get("/admin/")
async def admin():
    return Response("<html><body>Admin panel</body></html>", media_type="text/html")


@app.get("/swagger.json")
async def swagger():
    return {
        "openapi": "3.0.0",
        "info": {"title": "Juice Shop API", "version": "17.1.1"},
        "paths": {"/api/Products": {"get": {"summary": "List products"}}},
    }


@app.options("/{path:path}")
async def options_all(path: str, request: Request):
    origin = request.headers.get("origin", "*")
    return Response(
        status_code=204,
        headers={
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
            "Access-Control-Allow-Headers": "*",
            "Access-Control-Allow-Credentials": "true",
        },
    )


if __name__ == "__main__":
    print("Prism lab sandbox on http://127.0.0.1:3001")
    uvicorn.run(app, host="0.0.0.0", port=3001, log_level="info")
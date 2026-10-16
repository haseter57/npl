import asyncio
import base64
import hmac
import html as _html
import ipaddress
import logging
import os
import socket
import uuid
from urllib.parse import quote

import uvicorn
from fastapi import FastAPI, WebSocket
from fastapi.responses import HTMLResponse, PlainTextResponse

try:
    import segno
except ImportError:
    segno = None

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("vless")

# ── Fixed user: everything is derived from env vars, no state on disk ─────────
SECRET = os.environ.get("SECRET_KEY", "").strip()
if len(SECRET) < 16:
    raise SystemExit("SECRET_KEY env var is required (min 16 chars)")

USER_UUID = os.environ.get("USER_UUID") or str(uuid.uuid5(uuid.NAMESPACE_URL, SECRET))
USER_BYTES = uuid.UUID(USER_UUID).bytes
REMARK = os.environ.get("REMARK", "Proxy")
PORT = int(os.environ.get("PORT", "8000"))
WS_PATH = "/ws"

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


def get_domain() -> str:
    raw = (
        os.environ.get("PUBLIC_DOMAIN")
        or os.environ.get("zeropsSubdomain")
        or os.environ.get("RENDER_EXTERNAL_URL")
        or os.environ.get("RAILWAY_PUBLIC_DOMAIN")
        or "localhost"
    )
    return raw.replace("https://", "").replace("http://", "").rstrip("/")


def vless_link() -> str:
    d = get_domain()
    q = {
        "encryption": "none", "security": "tls", "type": "ws",
        "host": d, "path": WS_PATH, "sni": d, "fp": "chrome", "alpn": "http/1.1",
    }
    query = "&".join(f"{k}={quote(v, safe='')}" for k, v in q.items())
    return f"vless://{USER_UUID}@{d}:443?{query}#{quote(REMARK)}"


def _auth(token: str) -> bool:
    # the page key can be either SECRET_KEY or the user UUID
    t = token.encode()
    return hmac.compare_digest(t, SECRET.encode()) or hmac.compare_digest(t, USER_UUID.encode())


@app.get("/")
async def root():
    return PlainTextResponse("OK")


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/panel/{token}")
async def panel(token: str):
    if not _auth(token):
        return PlainTextResponse("OK")
    link = vless_link()
    qr = ""
    if segno:
        try:
            qr = segno.make(link, error="m").svg_inline(scale=5, border=2, dark="#111", light="#fff")
        except Exception:
            qr = ""
    page = f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>VLESS</title>
<style>body{{font-family:sans-serif;max-width:640px;margin:20px auto;padding:0 12px}}
textarea{{width:100%;box-sizing:border-box;font-family:monospace;font-size:13px;padding:8px}}
button{{padding:10px 18px;font-size:16px;margin:8px 0}}svg{{max-width:100%;height:auto}}</style></head>
<body><h3>VLESS config</h3>
<textarea id="l" readonly rows="7">{_html.escape(link)}</textarea><br>
<button onclick="var t=document.getElementById('l');t.select();document.execCommand('copy');this.textContent='Copied'">Copy</button>
<div>{qr}</div></body></html>"""
    return HTMLResponse(page)


@app.get("/link/{token}")
async def link(token: str):
    if not _auth(token):
        return PlainTextResponse("OK")
    return PlainTextResponse(vless_link())


@app.get("/sub/{token}")
async def sub(token: str):
    if not _auth(token):
        return PlainTextResponse("OK")
    return PlainTextResponse(base64.b64encode(vless_link().encode()).decode())


# ── VLESS over WebSocket (TCP only) ───────────────────────────────────────────
def parse_header(d: bytes):
    try:
        if len(d) < 24 or d[0] != 0 or not hmac.compare_digest(d[1:17], USER_BYTES):
            return None
        i = 18 + d[17]
        if d[i] != 1:  # only TCP
            return None
        port = int.from_bytes(d[i + 1:i + 3], "big")
        atyp = d[i + 3]
        i += 4
        if atyp == 1:
            host = ".".join(str(b) for b in d[i:i + 4]); i += 4
        elif atyp == 2:
            n = d[i]; host = d[i + 1:i + 1 + n].decode(); i += 1 + n
        elif atyp == 3:
            host = socket.inet_ntop(socket.AF_INET6, d[i:i + 16]); i += 16
        else:
            return None
        return host, port, d[i:]
    except Exception:
        return None


async def resolve_public(host: str, port: int) -> str | None:
    """Resolve and refuse private/internal targets (protects Zerops private network)."""
    infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast):
            return str(ip)
    return None


@app.websocket(WS_PATH)
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    writer = None
    try:
        parsed = parse_header(await asyncio.wait_for(ws.receive_bytes(), 15))
        if not parsed:
            await ws.close()
            return
        host, port, payload = parsed
        ip = await resolve_public(host, port)
        if not ip:
            await ws.close()
            return
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), 10)
        if payload:
            writer.write(payload)
            await writer.drain()

        async def up():
            while True:
                msg = await ws.receive()
                if msg["type"] == "websocket.disconnect":
                    return
                b = msg.get("bytes")
                if b:
                    writer.write(b)
                    await writer.drain()

        async def down():
            first = True
            while True:
                chunk = await reader.read(65536)
                if not chunk:
                    return
                if first:
                    chunk, first = b"\x00\x00" + chunk, False
                await ws.send_bytes(chunk)

        tasks = [asyncio.create_task(up()), asyncio.create_task(down())]
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for t in tasks:
            t.cancel()
    except Exception as e:
        log.debug("ws closed: %s", e)
    finally:
        if writer:
            writer.close()
        try:
            await ws.close()
        except Exception:
            pass


@app.on_event("startup")
async def startup():
    log.info("Domain: %s", get_domain())
    log.info("UUID: %s", USER_UUID)
    log.info("Config page: https://%s/panel/%s", get_domain(), USER_UUID)
    log.info("VLESS link: %s", vless_link())


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=PORT, log_level="warning")

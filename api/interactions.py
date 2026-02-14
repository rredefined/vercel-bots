import os
import json
from fastapi import FastAPI, Request, HTTPException
from nacl.signing import VerifyKey
from nacl.encoding import HexEncoder
from nacl.exceptions import BadSignatureError

app = FastAPI()

PUBLIC_KEY = os.getenv("DISCORD_PUBLIC_KEY")
if not PUBLIC_KEY:
    # Crash early in logs with a clear message (instead of random 500 later)
    raise RuntimeError("DISCORD_PUBLIC_KEY is not set in Vercel Environment Variables")

def verify_discord_signature(signature: str, timestamp: str, body: bytes) -> None:
    try:
        key = VerifyKey(PUBLIC_KEY, encoder=HexEncoder)
        key.verify(timestamp.encode() + body, bytes.fromhex(signature))
    except BadSignatureError:
        raise HTTPException(status_code=401, detail="Bad signature")

# IMPORTANT:
# This function file is /api/interactions.py
# so Vercel maps it to /api/interactions
# Inside FastAPI, use "/" (not "/api/interactions")
@app.post("/")
async def interactions(req: Request):
    body = await req.body()

    sig = req.headers.get("X-Signature-Ed25519")
    ts = req.headers.get("X-Signature-Timestamp")
    if not sig or not ts:
        raise HTTPException(status_code=401, detail="Missing signature headers")

    verify_discord_signature(sig, ts, body)

    payload = json.loads(body.decode("utf-8"))

    # Discord PING
    if payload.get("type") == 1:
        return {"type": 1}

    # Example slash command: /hello
    name = (payload.get("data") or {}).get("name")
    if name == "hello":
        return {"type": 4, "data": {"content": "Hello 👋 (Vercel working)"}}

    return {"type": 4, "data": {"content": "Unknown command"}}

@app.get("/")
async def health():
    return {"ok": True}

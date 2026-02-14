import os, json
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError
from nacl.encoding import HexEncoder

PUBLIC_KEY = os.environ["5f3e56efdbd595a287e92be4ce9a34cd9959423ddf5bdbe33d1ebcebb33df1fb"]

def _verify(headers, raw_body: bytes):
    sig = headers.get("x-signature-ed25519")
    ts  = headers.get("x-signature-timestamp")
    if not sig or not ts:
        raise ValueError("Missing signature headers")

    try:
        key = VerifyKey(PUBLIC_KEY, encoder=HexEncoder)
        key.verify(ts.encode() + raw_body, bytes.fromhex(sig))
    except BadSignatureError:
        raise ValueError("Bad signature")

def handler(request):
    raw = request.get_data() if hasattr(request, "get_data") else request.body
    headers = {k.lower(): v for k, v in (request.headers or {}).items()}

    try:
        _verify(headers, raw)
    except Exception as e:
        return ("Unauthorized", 401)

    data = json.loads(raw.decode("utf-8"))

    # Discord "PING" verification
    if data.get("type") == 1:
        return (json.dumps({"type": 1}), 200, {"Content-Type": "application/json"})

    # Example: /hello
    name = (data.get("data") or {}).get("name")
    if name == "hello":
        return (
            json.dumps({"type": 4, "data": {"content": "Hello 👋 (Vercel interactions)"}}),
            200,
            {"Content-Type": "application/json"},
        )

    return (
        json.dumps({"type": 4, "data": {"content": "Unknown command"}}),
        200,
        {"Content-Type": "application/json"},
    )

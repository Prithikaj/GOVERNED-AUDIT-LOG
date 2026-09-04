import hmac, hashlib, base64

def tokenize(text: str, tenant_id: str, secret: str):
    msg = f"{tenant_id}::{text}".encode("utf-8")
    digest = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode("utf-8")[:20]
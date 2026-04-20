"""Corporate authentication utilities — real working functions."""
import hashlib
import hmac
import time

_SECRET = "corpx-internal-hmac-key-2024"


def generate_token(user_id: str) -> str:
    """Generate HMAC-based auth token for internal microservices."""
    timestamp = str(int(time.time()))
    payload = f"{user_id}:{timestamp}"
    sig = hmac.new(_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()[:16]
    return f"{payload}:{sig}"


def validate_token(token: str) -> bool:
    """Validate an auth token. Returns True if signature matches."""
    try:
        user_id, timestamp, sig = token.rsplit(":", 2)
        payload = f"{user_id}:{timestamp}"
        expected = hmac.new(_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()[:16]
        return hmac.compare_digest(sig, expected)
    except Exception:
        return False

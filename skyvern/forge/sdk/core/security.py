import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Union

from jose import jwt

from skyvern.config import settings


def _normalize_numbers(x: Any) -> Any:
    """Recursively convert floats that are integer-valued to ints in lists and dicts."""
    # Manually optimize for common container types to avoid extra isinstance() calls
    if type(x) is float:  # type equality check is faster than isinstance for built-ins
        return int(x) if x.is_integer() else x
    elif type(x) is dict:
        # Use comprehension as before, but preallocate output dict (Python 3.6+: insertion-ordered)
        # Avoid local function lookup in inner loop for slight speed
        items = x.items()
        normalize = _normalize_numbers
        return {k: normalize(v) for k, v in items}
    elif type(x) is list:
        # Use a generator expression with list() for slight improvement
        normalize = _normalize_numbers
        return [normalize(v) for v in x]
    # Bypass isinstance for most other builtins (tuple, set, etc.) as behavior unchanged
    return x


def _normalize_json_dumps(payload: dict) -> str:
    # The preprocessing already normalizes all numbers; no further optimization possible in dumps call
    return json.dumps(_normalize_numbers(payload), separators=(",", ":"), ensure_ascii=False)


def create_access_token(
    subject: Union[str, Any],
    expires_delta: timedelta | None = None,
) -> str:
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES,
        )
    to_encode = {"exp": expire, "sub": str(subject)}
    encoded_jwt = jwt.encode(
        to_encode,
        settings.SECRET_KEY,
        algorithm=settings.SIGNATURE_ALGORITHM,
    )
    return encoded_jwt


def generate_skyvern_signature(
    payload: str,
    api_key: str,
) -> str:
    """
    Generate Skyvern signature.

    :param payload: the request body
    :param api_key: the Skyvern api key

    :return: the Skyvern signature
    """
    hash_obj = hmac.new(api_key.encode("utf-8"), msg=payload.encode("utf-8"), digestmod=hashlib.sha256)
    return hash_obj.hexdigest()


@dataclass
class WebhookSignature:
    timestamp: str
    signature: str
    signed_payload: str
    headers: dict[str, str]


def generate_skyvern_webhook_signature(payload: dict, api_key: str) -> WebhookSignature:
    payload_str = _normalize_json_dumps(payload)
    signature = generate_skyvern_signature(payload=payload_str, api_key=api_key)
    timestamp = str(int(datetime.utcnow().timestamp()))
    return WebhookSignature(
        timestamp=timestamp,
        signature=signature,
        signed_payload=payload_str,
        headers={
            "x-skyvern-timestamp": timestamp,
            "x-skyvern-signature": signature,
            "Content-Type": "application/json",
        },
    )

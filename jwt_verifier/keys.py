"""HS256 JWT verifier with multi-key rotation support.

The whole exercise uses one compact token format and one key format:

* A token is exactly ``header.payload.signature`` (three dot-separated
  base64url segments).  Base64url is unpadded: it must not contain ``=``,
  whitespace or characters outside ``[A-Za-z0-9_-]``.
* ``header`` and ``payload`` are UTF-8 JSON objects.  The protected header
  must contain ``alg`` and may contain ``kid``.
* The only supported algorithm is ``HS256``; its signature is
  ``HMAC-SHA256(secret, header_segment + "." + payload_segment)`` and the
  signature is compared in constant time.
* A JWKS document has the shape::

      {"keys": [{"kid": "...", "kty": "oct", "alg": "HS256",
                 "secret": "<lower- or upper-case hex>"}]}

  ``secret`` is the raw HMAC key encoded as hex.  A key used for rotation
  may additionally carry ``"retired": true`` and a numeric
  ``"retired_at"`` (seconds since the Unix epoch).
* All times (``now``, ``exp``, ``nbf``, ``iat``, ``retired_at``, ``leeway``,
  ``max_age``) are integer/float seconds since the Unix epoch.  The default
  clock skew allowance is 60 seconds.
* Invalid input is always reported by raising ``InvalidToken``.
"""

import base64
import hashlib
import hmac
import json
import math
import re


class InvalidToken(Exception):
    """Raised whenever a token, header, key or claim fails validation."""


_B64URL_RE = re.compile(r"[A-Za-z0-9_-]*")
_KID_RE = re.compile(r"[A-Za-z0-9._-]{1,64}")
_HEX_RE = re.compile(r"[0-9a-fA-F]+")

_SUPPORTED_ALG = "HS256"


def b64url_decode(s: str) -> bytes:
    """Strictly decode an unpadded base64url string into bytes."""
    if not isinstance(s, str):
        raise InvalidToken("base64url input must be a string")
    if not _B64URL_RE.fullmatch(s):
        raise InvalidToken("illegal base64url character")
    if len(s) % 4 == 1:
        raise InvalidToken("impossible base64url length")
    padded = s + "=" * (-len(s) % 4)
    try:
        return base64.b64decode(padded.encode("ascii"), altchars=b"-_", validate=True)
    except Exception as exc:
        raise InvalidToken("invalid base64url encoding") from exc


def _is_number(value) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
    )


def _require_number(value, what: str) -> float:
    if not _is_number(value):
        raise InvalidToken(f"{what} must be a finite number")
    return value


def select_key(header: dict, jwks: dict) -> dict:
    """Select exactly one HS256 key for a decoded JWT header."""
    if not isinstance(header, dict):
        raise InvalidToken("header must be a JSON object")
    alg = header.get("alg")
    if not isinstance(alg, str) or not alg:
        raise InvalidToken("header must declare an alg")
    if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
        raise InvalidToken("jwks must contain a keys list")
    keys = jwks["keys"]

    if "kid" in header:
        kid = header["kid"]
        # Validate before any lookup: no path separators, no control chars.
        if not isinstance(kid, str) or not _KID_RE.fullmatch(kid):
            raise InvalidToken("kid fails the character/length policy")
        matches = [k for k in keys if isinstance(k, dict) and k.get("kid") == kid]
        if len(matches) != 1:
            raise InvalidToken("kid must match exactly one key")
        key = matches[0]
    else:
        # No kid: only an unambiguous single-key JWKS is acceptable.
        if len(keys) != 1 or not isinstance(keys[0], dict):
            raise InvalidToken("no kid and the JWKS does not hold exactly one key")
        key = keys[0]

    # Bind the declared algorithm to the key type and the key's own alg.
    if key.get("kty") != "oct":
        raise InvalidToken("key type does not match the algorithm")
    if key.get("alg") != alg:
        raise InvalidToken("key alg does not match the header alg")
    secret = key.get("secret")
    if (
        not isinstance(secret, str)
        or not secret
        or len(secret) % 2 != 0
        or not _HEX_RE.fullmatch(secret)
    ):
        raise InvalidToken("secret must be non-empty even-length hex")
    return key


def _reject_duplicate_keys(pairs: list) -> dict:
    obj = {}
    for name, value in pairs:
        if name in obj:
            raise InvalidToken(f"duplicate JSON key: {name!r}")
        obj[name] = value
    return obj


def _json_object(raw: bytes, what: str) -> dict:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InvalidToken(f"{what} is not valid UTF-8") from exc
    try:
        value = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except InvalidToken:
        raise
    except Exception as exc:
        raise InvalidToken(f"{what} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise InvalidToken(f"{what} must be a JSON object")
    return value


def _parse_token(token: str):
    """Split and decode a token into (header, payload, signing_input, signature)."""
    if not isinstance(token, str):
        raise InvalidToken("token must be a string")
    parts = token.split(".")
    if len(parts) != 3 or any(part == "" for part in parts):
        raise InvalidToken("token must have exactly three non-empty segments")
    header_segment, payload_segment, signature_segment = parts
    header = _json_object(b64url_decode(header_segment), "header")
    payload = _json_object(b64url_decode(payload_segment), "payload")
    signature = b64url_decode(signature_segment)
    signing_input = f"{header_segment}.{payload_segment}".encode("ascii")
    return header, payload, signing_input, signature


def _signature_matches(key: dict, signing_input: bytes, signature: bytes) -> bool:
    secret = bytes.fromhex(key["secret"])
    expected = hmac.new(secret, signing_input, hashlib.sha256).digest()
    return hmac.compare_digest(expected, signature)


def decode(token: str, jwks: dict, now: float, leeway: int = 60) -> dict:
    """Decode, authenticate and validate one HS256 JWT."""
    header, payload, signing_input, signature = _parse_token(token)

    # alg whitelist: only HS256, decided by us -- never trust "none" or
    # let an RS256 header be paired with an HMAC key.
    if header.get("alg") != _SUPPORTED_ALG:
        raise InvalidToken("unsupported or missing alg")

    key = select_key(header, jwks)
    if not _signature_matches(key, signing_input, signature):
        raise InvalidToken("signature verification failed")

    check_claims(payload, now, leeway)
    return payload


def check_claims(
    payload: dict, now: float, leeway: int = 60, max_age: int = 3600
) -> None:
    """Validate the time claims of an already-decoded JWT payload."""
    if not isinstance(payload, dict):
        raise InvalidToken("payload must be a JSON object")
    _require_number(now, "now")
    leeway = _require_number(leeway, "leeway")
    max_age = _require_number(max_age, "max_age")
    if leeway < 0 or max_age < 0:
        raise InvalidToken("leeway and max_age must be non-negative")

    if "exp" not in payload:
        raise InvalidToken("exp is required")
    if "iat" not in payload:
        raise InvalidToken("iat is required")
    exp = _require_number(payload["exp"], "exp")
    iat = _require_number(payload["iat"], "iat")
    nbf = None
    if "nbf" in payload:
        nbf = _require_number(payload["nbf"], "nbf")

    # Expiry: accepted exactly on the leeway boundary, rejected beyond it.
    if not now <= exp + leeway:
        raise InvalidToken("token has expired")
    # Not-before.
    if nbf is not None and not nbf - leeway <= now:
        raise InvalidToken("token is not yet valid")
    # Issued-at: tolerate small future skew, reject stale tokens.
    if not iat <= now + leeway:
        raise InvalidToken("iat is too far in the future")
    if not now - iat <= max_age:
        raise InvalidToken("token is older than max_age")
    # Internally inconsistent validity interval.
    if nbf is not None and exp < nbf:
        raise InvalidToken("exp precedes nbf")
    if exp < iat:
        raise InvalidToken("exp precedes iat")


def verify_with_rotation(token: str, jwks_versions: list[dict], now: float) -> dict:
    """Verify a token across rotated JWKS versions and enforce retirement."""
    if not isinstance(jwks_versions, list) or not jwks_versions:
        raise InvalidToken("jwks_versions must be a non-empty list")

    header, payload, signing_input, signature = _parse_token(token)
    if header.get("alg") != _SUPPORTED_ALG:
        raise InvalidToken("unsupported or missing alg")

    # Newest to oldest: a version is a hit when its key verifies the signature.
    hit_version = None
    for version in jwks_versions:
        try:
            key = select_key(header, version)
        except InvalidToken:
            continue
        if _signature_matches(key, signing_input, signature):
            hit_version = version
            break
    if hit_version is None:
        raise InvalidToken("no JWKS version verifies the token")

    # The retirement status of the CURRENT version always wins.
    current_key = select_key(header, jwks_versions[0])
    if current_key.get("retired", False):
        retired_at = current_key.get("retired_at")
        if not _is_number(retired_at):
            raise InvalidToken("retired key lacks a numeric retired_at")
        iat = payload.get("iat")
        if not _is_number(iat) or not iat <= retired_at:
            raise InvalidToken("retired key cannot authenticate a newer token")
    else:
        # The current key is active: the signature must verify against it,
        # not merely against an older key that shares the kid.
        if not _signature_matches(current_key, signing_input, signature):
            raise InvalidToken("signature does not match the current key")

    # Full validation (leeway, duplicate claims, max_age) on the hit version.
    return decode(token, hit_version, now)

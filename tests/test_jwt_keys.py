"""Acceptance tests for the pairwise JWT key-rotation exercise.

Every test constructs its token inline with a fixed clock.  No key files,
network access or randomness are used.  With the contract-only stubs in
``jwt_verifier/keys.py`` all 15 tests fail via ``NotImplementedError``.
"""

import base64
import hashlib
import hmac
import json

import pytest

from jwt_verifier.keys import (
    InvalidToken,
    b64url_decode,
    decode,
    select_key,
    verify_with_rotation,
)

NOW = 1700000000.0
LEEWAY = 60
OLD_KID = "key-2024-01"
NEW_KID = "key-2025-02"
OLD_SECRET_HEX = "00112233445566778899aabbccddeeff"
NEW_SECRET_HEX = "ffeeddccbbaa99887766554433221100"
OLD_SECRET = bytes.fromhex(OLD_SECRET_HEX)
NEW_SECRET = bytes.fromhex(NEW_SECRET_HEX)
RETIRED_AT = 1699999000


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _segment(obj) -> str:
    raw = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return _b64u(raw)


def _raw_segment(text: str) -> str:
    return _b64u(text.encode("utf-8"))


def _sign(secret: bytes, signing_input: bytes) -> bytes:
    return hmac.new(secret, signing_input, hashlib.sha256).digest()


def _make_token(
    secret: bytes,
    payload=None,
    *,
    header=None,
    raw_payload: str | None = None,
    sig_len: int | None = None,
) -> str:
    if header is None:
        header = _header()
    header_segment = _segment(header)
    payload_segment = (
        _raw_segment(raw_payload) if raw_payload is not None else _segment(payload)
    )
    signing_input = f"{header_segment}.{payload_segment}".encode("ascii")
    signature = _sign(secret, signing_input)
    if sig_len is not None:
        signature = signature[:sig_len]
    return f"{header_segment}.{payload_segment}.{_b64u(signature)}"


def _header(kid: str | None = OLD_KID, alg: str = "HS256") -> dict:
    header = {"alg": alg, "typ": "JWT"}
    if kid is not None:
        header["kid"] = kid
    return header


def _payload(**overrides) -> dict:
    payload = {
        "sub": "alice",
        "iat": int(NOW) - 10,
        "nbf": int(NOW) - 10,
        "exp": int(NOW) + 300,
    }
    payload.update(overrides)
    return payload


def _key(
    kid: str,
    secret_hex: str,
    *,
    retired: bool = False,
    retired_at: int | None = None,
) -> dict:
    key = {"kid": kid, "kty": "oct", "alg": "HS256", "secret": secret_hex}
    key["retired"] = retired
    if retired:
        key["retired_at"] = retired_at
    return key


def _jwks(*keys: dict) -> dict:
    return {"keys": list(keys)}


def _simple_jwks() -> dict:
    return _jwks(_key(OLD_KID, OLD_SECRET_HEX))


def _rotation_versions() -> list[dict]:
    current = _jwks(
        _key(OLD_KID, OLD_SECRET_HEX, retired=True, retired_at=RETIRED_AT),
        _key(NEW_KID, NEW_SECRET_HEX),
    )
    older = _jwks(_key(OLD_KID, OLD_SECRET_HEX))
    return [current, older]


class TestAlgorithmBinding:
    def test_alg_none_rejected(self):
        token = _make_token(
            OLD_SECRET,
            _payload(),
            header=_header(alg="none"),
        )
        with pytest.raises(InvalidToken):
            decode(token, _simple_jwks(), NOW)

    def test_alg_rs256_with_hs256_signature_rejected(self):
        token = _make_token(OLD_SECRET, _payload(), header=_header(alg="RS256"))
        with pytest.raises(InvalidToken):
            decode(token, _simple_jwks(), NOW)

    def test_hs256_token_accepted(self):
        token = _make_token(OLD_SECRET, _payload())
        header_segment, payload_segment, signature_segment = token.split(".")

        expected = _sign(
            OLD_SECRET, f"{header_segment}.{payload_segment}".encode("ascii")
        )
        assert b64url_decode(signature_segment) == expected
        for malformed in (
            signature_segment + "=",
            " " + signature_segment,
            signature_segment + "\n",
            signature_segment + "!",
        ):
            with pytest.raises(InvalidToken):
                b64url_decode(malformed)

        payload = decode(token, _simple_jwks(), NOW)
        assert payload["sub"] == "alice"
        assert payload["exp"] == int(NOW) + 300


class TestKidValidation:
    def test_kid_with_slash_rejected(self):
        bad_kid = "tenant/../../admin"
        header = _header(kid=bad_kid)
        with pytest.raises(InvalidToken):
            select_key(header, _jwks(_key(bad_kid, OLD_SECRET_HEX)))

    def test_kid_too_long_rejected(self):
        bad_kid = "a" * 65
        header = _header(kid=bad_kid)
        with pytest.raises(InvalidToken):
            select_key(header, _jwks(_key(bad_kid, OLD_SECRET_HEX)))

    def test_missing_kid_with_multiple_keys_rejected(self):
        header = _header(kid=None)
        jwks = _jwks(
            _key("key-a", OLD_SECRET_HEX),
            _key("key-b", NEW_SECRET_HEX),
        )
        with pytest.raises(InvalidToken):
            select_key(header, jwks)


class TestTimeClaims:
    def test_expired_token_rejected(self):
        expired_at = int(NOW) - LEEWAY - 1
        token = _make_token(
            OLD_SECRET,
            _payload(iat=expired_at - 10, nbf=expired_at - 10, exp=expired_at),
        )
        with pytest.raises(InvalidToken):
            decode(token, _simple_jwks(), NOW)

    def test_exp_within_leeway_accepted(self):
        # Exactly on the leeway boundary: now == exp + leeway.
        expired_at = int(NOW) - LEEWAY
        token = _make_token(
            OLD_SECRET,
            _payload(iat=expired_at - 10, nbf=expired_at - 10, exp=expired_at),
        )
        payload = decode(token, _simple_jwks(), NOW)
        assert payload["exp"] == expired_at

    def test_nbf_in_future_rejected(self):
        token = _make_token(
            OLD_SECRET, _payload(nbf=int(NOW) + LEEWAY + 1)
        )
        with pytest.raises(InvalidToken):
            decode(token, _simple_jwks(), NOW)


class TestMalformedToken:
    def test_duplicate_exp_claim_rejected(self):
        raw_payload = (
            '{"sub":"alice","iat":1699999990,"nbf":1699999990,'
            '"exp":1700000300,"exp":1700000400}'
        )
        token = _make_token(OLD_SECRET, raw_payload=raw_payload)
        with pytest.raises(InvalidToken):
            decode(token, _simple_jwks(), NOW)

    def test_payload_not_object_rejected(self):
        token = _make_token(OLD_SECRET, raw_payload='["alice",1700000300]')
        with pytest.raises(InvalidToken):
            decode(token, _simple_jwks(), NOW)

    def test_truncated_signature_rejected(self):
        token = _make_token(OLD_SECRET, _payload(), sig_len=16)
        with pytest.raises(InvalidToken):
            decode(token, _simple_jwks(), NOW)


class TestKeyRotation:
    def test_retired_key_rejects_new_token(self):
        token = _make_token(
            OLD_SECRET,
            _payload(iat=RETIRED_AT + 100, nbf=RETIRED_AT + 100),
        )
        with pytest.raises(InvalidToken):
            verify_with_rotation(token, _rotation_versions(), NOW)

    def test_retired_key_accepts_old_token(self):
        token = _make_token(
            OLD_SECRET,
            _payload(iat=RETIRED_AT - 100, nbf=RETIRED_AT - 100),
        )
        payload = verify_with_rotation(token, _rotation_versions(), NOW)
        assert payload["sub"] == "alice"
        assert payload["iat"] == RETIRED_AT - 100

    def test_rotated_new_kid_verifies(self):
        token = _make_token(
            NEW_SECRET,
            _payload(iat=int(NOW) - 100, nbf=int(NOW) - 100),
            header=_header(kid=NEW_KID),
        )
        payload = verify_with_rotation(token, _rotation_versions(), NOW)
        assert payload["sub"] == "alice"
        assert payload["iat"] == int(NOW) - 100

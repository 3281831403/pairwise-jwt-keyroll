"""Contract-only stubs for the HS256 JWT verifier.

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
* Invalid input is always reported by raising ``InvalidToken``; the stubs
  below raise ``NotImplementedError`` because the implementation is the
  task.
"""


class InvalidToken(Exception):
    """Raised whenever a token, header, key or claim fails validation."""


def b64url_decode(s: str) -> bytes:
    """Strictly decode an unpadded base64url string into bytes.

    Contract:
    - Only ``A-Z``, ``a-z``, ``0-9``, ``-`` and ``_`` are legal.
    - ``=`` padding, whitespace (spaces, tabs, newlines) and every other
      character are rejected.
    - The number of characters must form a valid base64url payload; an
      impossible length is rejected.
    - Empty input is legal and decodes to ``b""``.
    - Raise ``InvalidToken`` for any violation; return the decoded bytes.
    """

    raise NotImplementedError


def select_key(header: dict, jwks: dict) -> dict:
    """Select exactly one HS256 key for a decoded JWT header.

    Contract:
    - ``header`` must be a dict containing ``alg``; ``jwks`` must be a dict
      containing a list under ``"keys"``.
    - If ``header`` has a ``kid``, it must be a string that fully matches
      ``^[A-Za-z0-9._-]{1,64}$``.  An invalid ``kid`` is rejected *before*
      any lookup, so path separators and control characters can never be
      used for injection.  Exactly one key with that exact ``kid`` must
      exist; zero or duplicate matches are rejected.
    - If ``header`` has no ``kid``, selection is allowed only when
      ``jwks["keys"]`` contains exactly one key.  Never fall back to the
      first key when several keys are present.
    - The selected key must be an octet key (``kty == "oct"``), must declare
      the same ``alg`` as the header, and must contain a non-empty,
      even-length hexadecimal ``secret``.  This binds the declared algorithm
      to the key type and forbids HS/RS confusion: an ``RS256`` header can
      never be paired with an HS256 key, and a key declaring another
      algorithm is never accepted.
    - Raise ``InvalidToken`` on every violation; return the selected key
      dict unchanged.
    """

    raise NotImplementedError


def decode(token: str, jwks: dict, now: float, leeway: int = 60) -> dict:
    """Decode, authenticate and validate one HS256 JWT.

    Contract:
    - ``token`` must be a string with exactly three dot-separated, non-empty
      segments (``header.payload.signature``).  Extra or missing dots are
      rejected.
    - Decode all three segments with :func:`b64url_decode`; padding,
      whitespace and illegal base64url characters are rejected rather than
      ignored.
    - The header must be a JSON object.  ``alg`` is taken from that object
      but is accepted only when it is exactly ``"HS256"``.  ``"none"`` and
      every other algorithm are rejected before key selection or signature
      processing.
    - Select the key with :func:`select_key`, including its ``kid`` and
      algorithm/key-type binding rules.
    - Recompute ``HMAC-SHA256(secret, header_segment + "." + payload_segment)``
      over the ASCII segments and compare it to the decoded signature in
      constant time.  A missing, truncated, empty or wrong signature is
      rejected.
    - The payload must be a JSON object.  Duplicate top-level claim names in
      the payload JSON are rejected; last-one-wins parsing is forbidden.
      Arrays and scalar JSON values are rejected.
    - Validate time claims by calling
      ``check_claims(payload, now, leeway)``; the default ``max_age`` of
      3600 seconds applies.
    - Return the payload dict; raise ``InvalidToken`` on any failure.
    """

    raise NotImplementedError


def check_claims(payload: dict, now: float, leeway: int = 60, max_age: int = 3600) -> None:
    """Validate the time claims of an already-decoded JWT payload.

    All values are seconds.  ``leeway`` and ``max_age`` must be
    non-negative numbers.

    Contract:
    - ``payload`` must be a dict.  ``exp`` and ``iat`` must be present and
      numeric; booleans, strings, ``NaN`` and infinities are rejected.
      ``nbf`` is optional but must be numeric when present.
    - Expiry: ``now <= exp + leeway``.  A token exactly on the leeway
      boundary is accepted; one second beyond it is rejected.
    - Not-before: when ``nbf`` is present, ``nbf - leeway <= now``.
    - Issued-at: ``iat <= now + leeway`` (a small future clock skew is
      tolerated, a larger one is rejected) and ``now - iat <= max_age``
      (stale tokens are rejected).
    - Also reject an inconsistent interval where ``exp < nbf`` or
      ``exp < iat``.
    - Return ``None`` on success; raise ``InvalidToken`` on any violation.
    """

    raise NotImplementedError


def verify_with_rotation(token: str, jwks_versions: list[dict], now: float) -> dict:
    """Verify a token across rotated JWKS versions and enforce retirement.

    ``jwks_versions`` is a non-empty list with the newest JWKS first; the
    current version is ``jwks_versions[0]``.  Every item has the JWKS shape
    documented at module level.  A key may carry ``"retired": false`` (the
    default) or ``"retired": true`` together with a numeric ``"retired_at"``
    epoch timestamp.

    Contract:
    - Try versions from newest to oldest.  A version is a hit when
      :func:`select_key` finds the matching kid/alg key and the HS256
      signature verifies against that key.
    - After a hit, the same kid must still be present in the current
      (newest) version.  If its current ``retired`` flag is false, the token
      is accepted.  If it is true, the token is accepted only when the
      payload contains a numeric ``iat`` with ``iat <= retired_at``.  A
      retired key therefore can never authenticate a token issued after its
      retirement time.
    - An older version being active must never override the current
      version's retired status.  Likewise, when the current key is active,
      a signature produced by an older key with the same kid is rejected.
    - Apply full :func:`decode` validation (including leeway, duplicate
      claims and ``max_age``) to the accepted version and return its
      payload.
    - Raise ``InvalidToken`` when no version verifies, when the kid is no
      longer present in the current version, or when the retirement rule is
      violated.
    """

    raise NotImplementedError

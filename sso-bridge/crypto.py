"""
Reimplementation of Umami's own token minting (see umami-software/umami:
src/lib/crypto.ts, src/lib/jwt.ts, src/app/api/auth/login/route.ts).

Umami stores its session as a JWT signed with sha512(APP_SECRET), wrapped in
an extra layer of AES-256-GCM encryption (also keyed off APP_SECRET). The
payload binds the token to the user's *current* password hash:

    { userId, role, pwd: sha512(user.password) }

so that changing the Umami password (or deleting the user) immediately
invalidates any previously minted token. Because that binding uses the
password *hash* already stored in Postgres -- not the plaintext password --
this bridge never needs to know (or store) anyone's Umami password: it only
needs read access to the "user" table and the same APP_SECRET Umami uses.

The output of create_secure_token() is byte-for-byte what Umami's own
POST /api/auth/login would have produced for that user, verified against a
live Node/jsonwebtoken round trip during development.
"""

import base64
import hashlib
import os

import jwt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_TAG_LENGTH = 16
_IV_LENGTH = 16
_SALT_LENGTH = 64
_PBKDF2_ITERATIONS = 10000
_KEY_LENGTH = 32


def _sha512_hex(value: str) -> str:
    return hashlib.sha512(value.encode("utf-8")).hexdigest()


def app_secret_digest(app_secret: str) -> str:
    """Equivalent of umami's secret() = hash(APP_SECRET)."""
    return _sha512_hex(app_secret)


def password_fingerprint(password_hash: str) -> str:
    """Equivalent of umami's pwd = hash(user.password)."""
    return _sha512_hex(password_hash)


def _derive_key(secret: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha512", secret.encode("utf-8"), salt, _PBKDF2_ITERATIONS, dklen=_KEY_LENGTH
    )


def _encrypt(plaintext: str, secret: str) -> str:
    iv = os.urandom(_IV_LENGTH)
    salt = os.urandom(_SALT_LENGTH)
    key = _derive_key(secret, salt)

    ciphertext_and_tag = AESGCM(key).encrypt(iv, plaintext.encode("utf-8"), None)
    ciphertext, tag = ciphertext_and_tag[:-_TAG_LENGTH], ciphertext_and_tag[-_TAG_LENGTH:]

    # Layout must match umami's Buffer.concat([salt, iv, tag, encrypted]).
    blob = salt + iv + tag + ciphertext
    return base64.b64encode(blob).decode("ascii")


def create_secure_token(payload: dict, app_secret: str) -> str:
    secret = app_secret_digest(app_secret)
    jwt_token = jwt.encode(payload, secret, algorithm="HS256")
    return _encrypt(jwt_token, secret)

"""Secure File Guard — cryptographic core.

Key hierarchy (all private material lives ONLY on the licensing server):

  master.key    32 random bytes. Wraps per-build data keys and setting secrets.
  signing.key   Ed25519 private key. Signs manifests + authorization tokens.
  signing.pub   Ed25519 public key. Ships inside protected packages (public is safe).

Per build:
  build key     32 random bytes, AES-256-GCM data key. Stored wrapped:
                wrap = AESGCM(master).encrypt(nonce_12, build_key, aad=None)
  The build key never leaves the server. Protected components are sealed with it.

Authorization token (server -> protected runtime), self-contained & verifiable:
    base64url(header) . base64url(payload) . base64url(Ed25519(sig_input))
The runtime re-verifies the signature with the embedded public key before use.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import config

MASTER_KEY_PATH = config.KEYS_DIR / "master.key"
SIGNING_KEY_PATH = config.KEYS_DIR / "signing.key"
SIGNING_PUB_PATH = config.KEYS_DIR / "signing.pub"

_master_key: bytes | None = None
_signing_private: ed25519.Ed25519PrivateKey | None = None
_signing_public: ed25519.Ed25519PublicKey | None = None


def _perm_600(p) -> None:
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass


def ensure_keys() -> None:
    """Create key material on first start. Idempotent."""
    global _master_key, _signing_private, _signing_public
    config.ensure_dirs()

    if not MASTER_KEY_PATH.exists():
        _master_key = secrets.token_bytes(32)
        MASTER_KEY_PATH.write_bytes(_master_key)
    else:
        _master_key = MASTER_KEY_PATH.read_bytes()
        if len(_master_key) != 32:
            raise RuntimeError("master.key must be 32 bytes")

    if not SIGNING_KEY_PATH.exists() or not SIGNING_PUB_PATH.exists():
        priv = ed25519.Ed25519PrivateKey.generate()
        SIGNING_KEY_PATH.write_bytes(priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        SIGNING_PUB_PATH.write_bytes(priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
        _signing_private = priv
    else:
        _signing_private = serialization.load_pem_private_key(
            SIGNING_KEY_PATH.read_bytes(), password=None)
    _signing_public = _signing_private.public_key()
    _perm_600(MASTER_KEY_PATH)
    _perm_600(SIGNING_KEY_PATH)
    _perm_600(SIGNING_PUB_PATH)


def master_key() -> bytes:
    if _master_key is None:
        ensure_keys()
    assert _master_key is not None
    return _master_key


def public_key_pem() -> str:
    if _signing_public is None:
        ensure_keys()
    return SIGNING_PUB_PATH.read_text()


def public_key_raw_b64() -> str:
    """Raw 32-byte Ed25519 public key, base64 — for runtimes that verify with
    libsodium (sodium_crypto_sign_verify_detached) instead of OpenSSL."""
    if _signing_public is None:
        ensure_keys()
    assert _signing_public is not None
    raw = _signing_public.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode()


def public_key_fingerprint() -> str:
    return hashlib.sha256(SIGNING_PUB_PATH.read_bytes()).hexdigest()


# ---------------- signing ----------------

def sign_bytes(data: bytes) -> str:
    """Ed25519 signature, base64."""
    if _signing_private is None:
        ensure_keys()
    assert _signing_private is not None
    return base64.b64encode(_signing_private.sign(data)).decode()


def verify_bytes(data: bytes, sig_b64: str, pub_pem: str | None = None) -> bool:
    """Verify against the server key by default; pass pub_pem to verify with a
    distributed public key (defense-in-depth: runtime re-verifies tokens)."""
    try:
        if pub_pem is not None:
            pub = serialization.load_pem_public_key(pub_pem.encode())
        else:
            if _signing_public is None:
                ensure_keys()
            pub = _signing_public
        pub.verify(base64.b64decode(sig_b64), data)
        return True
    except Exception:
        return False


def canonical_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


# ---------------- AES-GCM ----------------

def aes_gcm_seal(key: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[str, str]:
    """Authenticated encryption. Returns (nonce_b64, ciphertext_b64) — tag included."""
    nonce = secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return base64.b64encode(nonce).decode(), base64.b64encode(ct).decode()


def aes_gcm_open(key: bytes, nonce_b64: str, ciphertext_b64: str, aad: bytes = b"") -> bytes:
    return AESGCM(key).decrypt(base64.b64decode(nonce_b64), base64.b64decode(ciphertext_b64), aad)


def wrap_key(master: bytes, key: bytes) -> str:
    nonce, ct = aes_gcm_seal(master, key)
    return f"{nonce}.{ct}"


def unwrap_key(master: bytes, wrapped: str) -> bytes:
    nonce, ct = wrapped.split(".", 1)
    return aes_gcm_open(master, nonce, ct)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------- authorization tokens ----------------

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def make_authz_token(payload: dict) -> str:
    header = {"alg": "Ed25519", "typ": "sfg-authz-v1"}
    h = _b64url(canonical_json(header))
    p = _b64url(canonical_json(payload))
    sig = sign_bytes(f"{h}.{p}".encode())
    return f"{h}.{p}.{_b64url(base64.b64decode(sig))}"


def decode_authz_token(token: str, pub_pem: str | None = None) -> tuple[dict | None, str]:
    """Returns (payload, error). Error in {TOKEN_MALFORMED, SIGNATURE_INVALID, ...}."""
    try:
        h, p, s = token.split(".")
    except Exception:
        return None, "TOKEN_MALFORMED"
    try:
        header = json.loads(_b64url_decode(h))
        payload = json.loads(_b64url_decode(p))
        if header.get("alg") != "Ed25519" or header.get("typ") != "sfg-authz-v1":
            return None, "TOKEN_MALFORMED"
    except Exception:
        return None, "TOKEN_MALFORMED"
    if not verify_bytes(f"{h}.{p}".encode(), _b64url_to_b64(s), pub_pem):
        return None, "SIGNATURE_INVALID"
    return payload, ""


def _b64url_to_b64(s: str) -> str:
    pad = "=" * (-len(s) % 4)
    return base64.b64encode(base64.urlsafe_b64decode(s + pad)).decode()


def token_now() -> int:
    return int(time.time())

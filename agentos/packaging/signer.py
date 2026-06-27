"""
signer.py — Ed25519 signing and verification for .agentpack files.

IMPORTANT: This proves authenticity and integrity (the pack hasn't been
tampered with since signing, and identifies who signed it). It does NOT
prevent redistribution or copying. This is NOT DRM. See PHASE3_LIMITATIONS.md.

Uses Python's `cryptography` library with Ed25519 — simple, fast, no cert
chain complexity needed for this use case.
"""

import base64
import hashlib
import json
import os
import zipfile
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------

DEFAULT_KEYS_DIR = Path.home() / ".agentos" / "keys"


def _keys_dir() -> Path:
    d = DEFAULT_KEYS_DIR
    d.mkdir(parents=True, exist_ok=True)
    return d


def generate_keypair(keys_dir: Optional[str] = None) -> tuple:
    """
    Generate an Ed25519 keypair and write to the user's config directory.

    WARNING: The private key (private.pem) must NEVER be committed to git.
    Add ~/.agentos/keys/private.pem to your global .gitignore.

    Returns:
        (private_key_path, public_key_path)
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PrivateFormat, PublicFormat, NoEncryption,
    )

    kdir = Path(keys_dir) if keys_dir else _keys_dir()
    kdir.mkdir(parents=True, exist_ok=True)

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_path = kdir / "private.pem"
    pub_path = kdir / "public.pem"

    with open(priv_path, "wb") as f:
        f.write(private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))

    with open(pub_path, "wb") as f:
        f.write(public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))

    return str(priv_path), str(pub_path)


def _load_private_key(path: str):
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    with open(path, "rb") as f:
        return load_pem_private_key(f.read(), password=None)


def _load_public_key(path: str):
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    with open(path, "rb") as f:
        return load_pem_public_key(f.read())


# ---------------------------------------------------------------------------
# Pack content hash (excludes the signature field itself)
# ---------------------------------------------------------------------------

_SIGNING_FIELDS = {"signature", "public_key_fingerprint", "_public_key_raw"}


def _compute_pack_hash(pack_path: str) -> bytes:
    """
    Hash all zip entry contents (sorted by name) except the signature fields.
    The manifest.json is included but with ALL signing fields stripped so the
    hash is IDENTICAL before and after signing.
    """
    h = hashlib.sha256()
    with zipfile.ZipFile(pack_path, "r") as zf:
        for name in sorted(zf.namelist()):
            h.update(name.encode())
            if name == "manifest.json":
                raw = json.loads(zf.read(name).decode())
                for field in _SIGNING_FIELDS:
                    raw.pop(field, None)
                h.update(json.dumps(raw, sort_keys=True).encode())
            else:
                h.update(zf.read(name))
    return h.digest()


# ---------------------------------------------------------------------------
# Sign / Verify
# ---------------------------------------------------------------------------

def sign_pack(pack_path: str, private_key_path: str) -> None:
    """
    Hash the pack contents and sign with Ed25519. Writes the base64 signature
    and public key fingerprint back into manifest.json inside the zip.

    Args:
        pack_path: Path to the .agentpack file.
        private_key_path: Path to the Ed25519 private.pem key.
    """
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat,
    )

    private_key = _load_private_key(private_key_path)
    public_key = private_key.public_key()

    digest = _compute_pack_hash(pack_path)
    sig_bytes = private_key.sign(digest)
    sig_b64 = base64.b64encode(sig_bytes).decode()

    pub_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    fingerprint = hashlib.sha256(pub_bytes).hexdigest()[:16]

    # Embed back into manifest.json inside the zip
    _update_manifest_in_zip(pack_path, {
        "signature": sig_b64,
        "public_key_fingerprint": fingerprint,
        "_public_key_raw": base64.b64encode(pub_bytes).decode(),
    })


def verify_pack(pack_path: str) -> bool:
    """
    Recompute the pack hash and verify the embedded Ed25519 signature.

    Returns False on any mismatch or if the pack is unsigned — never raises.
    The CALLER decides whether to block or just warn on False.
    """
    try:
        with zipfile.ZipFile(pack_path, "r") as zf:
            if "manifest.json" not in zf.namelist():
                return False
            manifest = json.loads(zf.read("manifest.json").decode())

        sig_b64 = manifest.get("signature")
        pub_raw_b64 = manifest.get("_public_key_raw")
        if not sig_b64 or not pub_raw_b64:
            return False  # Unsigned pack

        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        from cryptography.exceptions import InvalidSignature

        pub_bytes = base64.b64decode(pub_raw_b64)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        public_key = Ed25519PublicKey.from_public_bytes(pub_bytes)

        digest = _compute_pack_hash(pack_path)
        sig_bytes = base64.b64decode(sig_b64)
        public_key.verify(sig_bytes, digest)
        return True

    except Exception:
        return False


def get_signer_fingerprint(pack_path: str) -> Optional[str]:
    """Return the signer's public key fingerprint from the manifest."""
    try:
        with zipfile.ZipFile(pack_path, "r") as zf:
            manifest = json.loads(zf.read("manifest.json").decode())
        return manifest.get("public_key_fingerprint")
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _update_manifest_in_zip(pack_path: str, updates: dict) -> None:
    """Replace manifest.json inside an existing zip with updated fields."""
    import tempfile, shutil

    tmp_path = pack_path + ".tmp"
    with zipfile.ZipFile(pack_path, "r") as zin, zipfile.ZipFile(tmp_path, "w", zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            if item.filename == "manifest.json":
                data = json.loads(zin.read(item.filename).decode())
                data.update(updates)
                zout.writestr(item.filename, json.dumps(data, indent=2))
            else:
                zout.writestr(item, zin.read(item.filename))

    os.replace(tmp_path, pack_path)

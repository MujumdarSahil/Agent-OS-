"""
license_check.py — Local offline license key model for .agentpack packs.

A license key is a signed JSON blob:
  {pack_name, pack_version, licensed_to, issued_at, expires_at}

Signed with the SAME Ed25519 scheme as pack signing.

DESIGN PHILOSOPHY (please read):
  - No network calls. No phone-home. No central server.
  - This proves that the key was issued by whoever holds the private key
    corresponding to the embedded public key.
  - It does NOT prevent copying or redistribution of the license key itself.
  - It does NOT prevent reverse-engineering.
  - This is authenticity and access control, not copy protection or DRM.
  - Document this plainly so users know exactly what they're getting.
  - Works fully offline — no infrastructure cost.

See PHASE3_LIMITATIONS.md for the full documented tradeoffs.
"""

import base64
import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from agentos.packaging.signer import _load_private_key


def generate_license(
    pack_name: str,
    pack_version: str,
    licensed_to: str,
    private_key_path: str,
    expires_at: Optional[str] = None,
) -> str:
    """
    Generate a signed license key string.

    Args:
        pack_name: The pack this license is for.
        pack_version: Pack version string.
        licensed_to: Name/email of the licensee.
        private_key_path: Path to the issuer's Ed25519 private.pem.
        expires_at: ISO 8601 expiry datetime, or None for no expiry.

    Returns:
        A base64-encoded JSON+signature string — this IS the license key.
        Distribute this string to your customers.
    """
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    private_key = _load_private_key(private_key_path)
    public_key = private_key.public_key()

    payload = {
        "pack_name": pack_name,
        "pack_version": pack_version,
        "licensed_to": licensed_to,
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": expires_at,
    }
    payload_bytes = json.dumps(payload, sort_keys=True).encode()
    sig_bytes = private_key.sign(payload_bytes)

    pub_raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    blob = {
        "payload": payload,
        "signature": base64.b64encode(sig_bytes).decode(),
        "public_key_raw": base64.b64encode(pub_raw).decode(),
    }
    return base64.b64encode(json.dumps(blob).encode()).decode()


def verify_license_str(license_key_str: str, pack_manifest: Dict[str, Any]) -> bool:
    """
    Verify a license key string against a pack manifest.

    Checks:
    1. Ed25519 signature is valid.
    2. pack_name and pack_version match the manifest.
    3. License has not expired (if expires_at is set).

    Returns False on any failure — never raises.
    """
    try:
        blob = json.loads(base64.b64decode(license_key_str).decode())
        payload = blob["payload"]
        sig_bytes = base64.b64decode(blob["signature"])
        pub_raw = base64.b64decode(blob["public_key_raw"])

        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        public_key = Ed25519PublicKey.from_public_bytes(pub_raw)

        payload_bytes = json.dumps(payload, sort_keys=True).encode()
        public_key.verify(sig_bytes, payload_bytes)  # raises on invalid

        # Check pack name/version match
        if payload.get("pack_name") != pack_manifest.get("name"):
            return False
        if payload.get("pack_version") != pack_manifest.get("version"):
            return False

        # Check expiry
        expires = payload.get("expires_at")
        if expires:
            expiry_dt = datetime.fromisoformat(expires)
            if expiry_dt.tzinfo is None:
                expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) > expiry_dt:
                return False

        return True

    except Exception:
        return False


def check_license_before_run(
    project_path: str,
    mission_name: str,
    license_key: Optional[str],
) -> None:
    """
    Pre-run license guard. Raises PermissionError if a license is required
    but missing or invalid. No-op if the project/mission doesn't require one.
    """
    from agentos.packaging.pack_format import find_pack_manifest_for_mission
    manifest = find_pack_manifest_for_mission(project_path, mission_name)
    if manifest is None:
        return  # Free project, no license needed

    if not manifest.get("license_required"):
        return

    if not license_key:
        raise PermissionError(
            f"Mission '{mission_name}' uses agents/crews from a commercial pack "
            f"'{manifest.get('name')}' that requires a license key. "
            "Pass --license-key <key> to proceed."
        )

    if not verify_license_str(license_key, manifest):
        raise PermissionError(
            f"License key is invalid or expired for pack '{manifest.get('name')}'. "
            "Obtain a valid license from the pack author."
        )

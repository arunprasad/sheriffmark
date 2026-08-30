"""Signing keypair for the local auth provider's self-issued JWTs.

Generated lazily on first use and persisted in the `signing_keys` table
(not a mounted file/secret) so a plain `docker run`/Cloud Run deployment
with no attached volume still survives restarts without invalidating
every existing session. One active key is enough for now — rotation
support (publishing an old key in the JWKS for a grace period while
signing with a new one) is a clearly-scoped future addition, not
attempted here.
"""

import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy.orm import Session

from shared.models import SigningKey


def get_or_create_signing_key(session: Session) -> SigningKey:
    existing = session.query(SigningKey).order_by(SigningKey.created_at.asc()).first()
    if existing is not None:
        return existing

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )

    key = SigningKey(
        kid=str(uuid.uuid4()),
        private_key_pem=private_pem,
        public_key_pem=public_pem,
    )
    session.add(key)
    session.commit()
    return key

"""Credential encryption shared by the web process and SMB connections."""
import base64
import hashlib

from cryptography.fernet import Fernet


def credential_cipher(secret_key):
    secret = secret_key.encode() if isinstance(secret_key, str) else secret_key
    key = hashlib.sha256(b"ismanager.credentials.v1:" + secret).digest()
    return Fernet(base64.urlsafe_b64encode(key))

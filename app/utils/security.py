from app.core.config import settings
import base64
import json
import uuid
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# Base64 decode
def decode_kdata(kdata_b64: str) -> dict:
    try:
        decoded_bytes = base64.b64decode(kdata_b64)
        return json.loads(decoded_bytes.decode('utf-8'))
    except Exception as e:
        raise ValueError("Invalid kdata format") from e

# Generate irreversible UUID tokens for fields
def generate_token() -> str:
    return str(uuid.uuid4())

def tokenize_fields(data: dict) -> dict:
    return {key: generate_token() for key in data.keys()}

# AES-256-GCM encryption
def encrypt_data(data: str) -> str:
    # print(base64.b64encode(os.urandom(32)).decode())
    key = base64.b64decode(settings.ENC_SECRET_KEY)
    if len(key) != 32:
        raise ValueError("Encryption key must be 32 bytes for AES-256")
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, data.encode(), None)
    return base64.b64encode(nonce + ct).decode()

def decrypt_data(enc_data: str) -> str:
    # Decode the encryption key from config
    key = base64.b64decode(settings.ENC_SECRET_KEY)
    if len(key) != 32:
        raise ValueError("Encryption key must be 32 bytes for AES-256")

    # Decode the encrypted input (base64)
    decoded_data = base64.b64decode(enc_data)

    # Extract nonce (first 12 bytes), and ciphertext (rest)
    nonce = decoded_data[:12]
    ciphertext = decoded_data[12:]

    # Decrypt using AES-GCM
    aesgcm = AESGCM(key)
    decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)

    return decrypted_data.decode()
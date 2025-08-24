import base64
import secrets
import string
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


# 🔐 Function to generate strong random passwords
def generate_password(length=16):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(characters) for _ in range(length))


# 🔐 Derive encryption key from password using PBKDF2-HMAC with SHA256
def derive_key_from_password(password: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'static_salt',  # You can use a unique salt per user if needed
        iterations=100000,
        backend=default_backend()  # ✅ Required backend
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

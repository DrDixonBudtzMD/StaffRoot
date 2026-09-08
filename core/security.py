import hashlib
import hmac
import os

SCHEME = "pbkdf2_sha256"
ITERATIONS = 310_000

def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS)
    return "$".join((SCHEME, str(ITERATIONS), salt.hex(), digest.hex()))

def verify_password(password: str, stored_hash: str) -> bool:
    try:
        if stored_hash.startswith(SCHEME + "$"):
            _scheme, rounds, salt_hex, digest_hex = stored_hash.split("$", 3)
            iterations = int(rounds)
            if not 100_000 <= iterations <= 2_000_000:
                return False
        else:
            # Backward-compatible verification for the original 120k format.
            salt_hex, digest_hex = stored_hash.split(":", 1)
            iterations = 120_000
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except (AttributeError, TypeError, ValueError):
        return False
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(digest, expected)

def password_needs_upgrade(stored_hash: str) -> bool:
    try:
        return not stored_hash.startswith(SCHEME + "$" + str(ITERATIONS) + "$")
    except (AttributeError, TypeError):
        return True

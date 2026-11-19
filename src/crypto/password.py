"""
Hash e verifica delle password con PBKDF2-HMAC-SHA256 (libreria standard).

Formato salvato:  pbkdf2_sha256$<iterazioni>$<salt hex>$<hash hex>

Il numero di iterazioni è memorizzato nell'hash: si può aumentare in futuro
senza invalidare le password già registrate. Si usano 600.000 iterazioni,
valore raccomandato da OWASP (2023) per PBKDF2-HMAC-SHA256.

Il vecchio formato "<salt hex>:<hash hex>" (100.000 iterazioni) resta
verificabile per compatibilità con i file voters.json già esistenti.
"""

import hashlib
import hmac
import os

ALGORITHM = "pbkdf2_sha256"
ITERATIONS = 600_000
LEGACY_ITERATIONS = 100_000


def hash_password(password: str) -> str:
    """Calcola l'hash di una password con un salt casuale di 16 byte."""
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS)
    return f"{ALGORITHM}${ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(stored_password: str, provided_password: str) -> bool:
    """
    Verifica una password contro l'hash salvato.

    Il confronto avviene con hmac.compare_digest (tempo costante), così il
    tempo di risposta non rivela quanti byte dell'hash coincidono.
    """
    try:
        if stored_password.startswith(ALGORITHM + "$"):
            _, iterations, salt_hex, digest_hex = stored_password.split("$")
            iterations = int(iterations)
        else:
            salt_hex, digest_hex = stored_password.split(":")
            iterations = LEGACY_ITERATIONS
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
        computed = hashlib.pbkdf2_hmac("sha256", provided_password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(computed, expected)
    except (ValueError, AttributeError):
        return False

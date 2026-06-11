
"""
Modulo per la cifratura e decifratura RSA-OAEP.

RSA-OAEP (Optimal Asymmetric Encryption Padding) è un metodo di padding
per RSA che garantisce maggiore sicurezza rispetto al padding PKCS#1 v1.5.
Utilizza SHA-256 come funzione hash e MGF1 (Mask Generation Function).

Questo modulo viene utilizzato dal client per cifrare il voto e il seed,
e dall'Autorità Elettorale (AE) per decifrarli solo dopo la chiusura delle urne.
"""

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


def encrypt(public_key: RSAPublicKey, plaintext_bytes: bytes) -> bytes:
    """
    Cifra un messaggio in bytes con RSA-OAEP.

    Args:
        public_key: Chiave pubblica RSA da utilizzare per la cifratura
        plaintext_bytes (bytes): Messaggio da cifrare (deve essere in bytes)

    Returns:
        bytes: Messaggio cifrato (ciphertext)

    Note:
        La dimensione massima del messaggio che può essere cifrato con RSA 2048
        è di circa 245 byte (a causa del padding OAEP). Per messaggi più grandi
        è necessario usare una cifratura ibrida (AES + RSA).
    """
    return public_key.encrypt(
        plaintext_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def decrypt(private_key: RSAPrivateKey, ciphertext_bytes: bytes) -> bytes:
    """
    Decifra un messaggio cifrato con RSA-OAEP.

    Il complementare di encrypt().

    Args:
        private_key: Chiave privata RSA corrispondente alla chiave pubblica
        ciphertext_bytes (bytes): Messaggio cifrato da decifrare

    Returns:
        bytes: Messaggio originale in chiaro

    Note:
        La chiave privata deve essere la corrispondente della chiave pubblica
        utilizzata per cifrare il messaggio.
    """
    return private_key.decrypt(
        ciphertext_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


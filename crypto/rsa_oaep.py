
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


def encrypt(public_key, plaintext_bytes):
    """
    Cifra un messaggio con RSA-OAEP usando SHA-256 come hash e MGF1
    """
    return public_key.encrypt(
        plaintext_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def decrypt(private_key, ciphertext_bytes):
    """
    Decifra un messaggio cifrato con RSA-OAEP usando SHA-256 come hash e MGF1
    """
    return private_key.decrypt(
        ciphertext_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

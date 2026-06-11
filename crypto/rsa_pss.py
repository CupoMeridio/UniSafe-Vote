
"""
Modulo per la firma e verifica RSA-PSS.

RSA-PSS (Probabilistic Signature Scheme) è un metodo di firma digitale
che fornisce maggiore sicurezza rispetto a PKCS#1 v1.5, specialmente
in scenari di attacco adattivo. Utilizza SHA-256 come funzione hash
e salt di lunghezza massima.

Questo modulo viene utilizzato:
- Dal SA per firmare i token di autenticazione
- Dall'AE per firmare i blocchi del Bulletin Board e le ricevute di voto
- Dal client e dall'Observer per verificare le firme
"""

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


def sign(private_key: RSAPrivateKey, message_bytes: bytes) -> bytes:
    """
    Firma un messaggio con RSA-PSS.

    Crea una firma digitale che attesta l'autenticità e l'integrità
    del messaggio. Solo chi possiede la chiave privata può creare
    una firma valida.

    Args:
        private_key: Chiave privata RSA da utilizzare per la firma
        message_bytes (bytes): Messaggio da firmare (deve essere in bytes)

    Returns:
        bytes: Firma digitale del messaggio
    """
    return private_key.sign(
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def verify(public_key: RSAPublicKey, message_bytes: bytes, signature_bytes: bytes) -> bool:
    """
    Verifica la validità di una firma RSA-PSS.

    Utilizza la chiave pubblica corrispondente alla chiave privata
    utilizzata per firmare il messaggio.

    Args:
        public_key: Chiave pubblica RSA per la verifica
        message_bytes (bytes): Messaggio originale
        signature_bytes (bytes): Firma da verificare

    Returns:
        bool: True se la firma è valida, False altrimenti
    """
    try:
        public_key.verify(
            signature_bytes,
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        # Qualsiasi eccezione (verifica fallita, formato non valido, ecc.)
        # restituisce False
        return False


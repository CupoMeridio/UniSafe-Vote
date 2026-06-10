
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


def generate_rsa_keypair(key_size=2048):
    """
    Genera una coppia di chiavi RSA (2048 bit)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def save_keypair(private_key, public_key, name, base_path="data/keys"):
    """
    Salva una coppia di chiavi in formato PEM
    """
    # Crea la cartella se non esiste
    os.makedirs(base_path, exist_ok=True)

    # Salva chiave privata
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(os.path.join(base_path, f"{name}_private.pem"), "wb") as f:
        f.write(private_pem)

    # Salva chiave pubblica
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(os.path.join(base_path, f"{name}_public.pem"), "wb") as f:
        f.write(public_pem)


def load_private_key(name, base_path="data/keys"):
    """
    Carica una chiave privata da file PEM
    """
    with open(os.path.join(base_path, f"{name}_private.pem"), "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    return private_key


def load_public_key(name, base_path="data/keys"):
    """
    Carica una chiave pubblica da file PEM
    """
    with open(os.path.join(base_path, f"{name}_public.pem"), "rb") as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    return public_key


def serialize_public_key(public_key):
    """
    Serializza una chiave pubblica in formato PEM come stringa
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')


def deserialize_public_key(pem_str):
    """
    Deserializza una chiave pubblica da stringa PEM
    """
    return serialization.load_pem_public_key(
        pem_str.encode('utf-8'),
        backend=default_backend()
    )

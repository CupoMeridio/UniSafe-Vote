
"""
Modulo per la gestione delle chiavi RSA.

Questo modulo si occupa di:
- Generazione di coppie di chiavi RSA (2048 bit)
- Salvataggio delle chiavi in formato PEM
- Caricamento delle chiavi da file
- Serializzazione/deserializzazione delle chiavi pubbliche
"""

import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


def generate_rsa_keypair(key_size=2048):
    """
    Genera una coppia di chiavi RSA (pubblica e privata).

    Utilizza l'esponente pubblico standard 65537 (F4), che è un
    compromesso tra sicurezza ed efficienza.

    Args:
        key_size (int, optional): Dimensione della chiave in bit. Defaults to 2048.

    Returns:
        tuple: (private_key, public_key) - coppia di chiavi RSA
    """
    # Genera la chiave privata
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    # Estrae la chiave pubblica dalla chiave privata
    public_key = private_key.public_key()
    return private_key, public_key


def save_keypair(private_key, public_key, name, base_path="data/keys"):
    """
    Salva una coppia di chiavi in file separati in formato PEM.

    I file verranno chiamati:
        - {name}_private.pem (chiave privata)
        - {name}_public.pem (chiave pubblica)

    Args:
        private_key: Chiave privata RSA da salvare
        public_key: Chiave pubblica RSA da salvare
        name (str): Nome base per i file (es. "sa_sign", "ae_encrypt")
        base_path (str, optional): Cartella dove salvare le chiavi. Defaults to "data/keys".
    """
    # Crea la cartella di destinazione se non esiste
    os.makedirs(base_path, exist_ok=True)

    # Salva la chiave privata in formato PKCS8 non criptato
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(os.path.join(base_path, f"{name}_private.pem"), "wb") as f:
        f.write(private_pem)

    # Salva la chiave pubblica
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(os.path.join(base_path, f"{name}_public.pem"), "wb") as f:
        f.write(public_pem)


def load_private_key(name, base_path="data/keys"):
    """
    Carica una chiave privata da un file PEM.

    Args:
        name (str): Nome base del file (senza "_private.pem")
        base_path (str, optional): Cartella dove cercare il file. Defaults to "data/keys".

    Returns:
        private_key: Chiave privata RSA caricata
    """
    file_path = os.path.join(base_path, f"{name}_private.pem")
    with open(file_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    return private_key


def load_public_key(name, base_path="data/keys"):
    """
    Carica una chiave pubblica da un file PEM.

    Args:
        name (str): Nome base del file (senza "_public.pem")
        base_path (str, optional): Cartella dove cercare il file. Defaults to "data/keys".

    Returns:
        public_key: Chiave pubblica RSA caricata
    """
    file_path = os.path.join(base_path, f"{name}_public.pem")
    with open(file_path, "rb") as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    return public_key


def serialize_public_key(public_key):
    """
    Serializza una chiave pubblica in una stringa PEM.

    Utile per salvare la chiave pubblica nel Bulletin Board o
    trasmetterla in messaggi JSON.

    Args:
        public_key: Chiave pubblica RSA da serializzare

    Returns:
        str: Chiave pubblica in formato PEM come stringa
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')


def deserialize_public_key(pem_str):
    """
    Deserializza una chiave pubblica da una stringa PEM.

    Il complementare di serialize_public_key().

    Args:
        pem_str (str): Stringa PEM della chiave pubblica

    Returns:
        public_key: Chiave pubblica RSA deserializzata
    """
    return serialization.load_pem_public_key(
        pem_str.encode('utf-8'),
        backend=default_backend()
    )



"""
Modulo per la gestione delle chiavi RSA.

Questo modulo si occupa di:
- Generazione di coppie di chiavi RSA (2048 bit)
- Salvataggio delle chiavi in formato PEM
- Caricamento delle chiavi da file
- Serializzazione/deserializzazione delle chiavi pubbliche
"""

import os
from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


def generate_rsa_keypair(key_size: int = 2048) -> Tuple[RSAPrivateKey, RSAPublicKey]:
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


def save_keypair(private_key: RSAPrivateKey, public_key: RSAPublicKey, name: str, base_path: str = "data/keys") -> None:
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


def save_encrypted_private_key(private_key: RSAPrivateKey, name: str,
                               ikm: bytes, base_path: str = "data/keys") -> None:
    """
    Cifra una chiave privata RSA con AES-GCM e la salva su disco.

    La chiave simmetrica AES-256 è derivata con HKDF-SHA256 dal materiale
    chiave in ingresso (ikm), tipicamente la firma di un blocco pubblico
    (es. firma della Merkle Root). Finché quel blocco non è stato pubblicato,
    il materiale non è disponibile e la chiave privata non può essere decifrata.

    Formato file:
        [12 byte nonce GCM] || [n byte ciphertext+tag]

    Args:
        private_key: Chiave privata RSA da proteggere.
        name: Nome base del file (senza suffisso).
        ikm: Input Key Material da cui derivare la chiave AES-256.
        base_path: Cartella di destinazione.
    """
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    # Serializza la chiave privata in PEM
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Deriva una chiave AES-256 via HKDF-SHA256
    hkdf = HKDF(
        algorithm=_hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ae_encrypt_private_key_escrow",
        backend=default_backend()
    )
    aes_key = hkdf.derive(ikm)

    # Cifra con AES-256-GCM
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)  # 96-bit nonce raccomandato per GCM
    ciphertext = aesgcm.encrypt(nonce, private_pem, None)

    # Salva: nonce || ciphertext (include il GCM tag di autenticazione)
    os.makedirs(base_path, exist_ok=True)
    with open(os.path.join(base_path, f"{name}_private.enc"), "wb") as f:
        f.write(nonce + ciphertext)


def load_and_decrypt_private_key(name: str, ikm: bytes,
                                 base_path: str = "data/keys") -> RSAPrivateKey:
    """
    Decifra e carica una chiave privata protetta con AES-GCM.

    Inverte save_encrypted_private_key(): usa lo stesso IKM per derivare la
    chiave AES e decifrare il file. Se l'IKM è errato (o il file manomesso),
    AESGCM solleva un'eccezione di autenticazione.

    Args:
        name: Nome base del file (senza suffisso).
        ikm: Input Key Material identico a quello usato in salvataggio.
        base_path: Cartella da cui leggere il file.

    Returns:
        RSAPrivateKey: Chiave privata RSA in memoria (mai scritta in chiaro).

    Raises:
        cryptography.exceptions.InvalidTag: Se il ciphertext è manomesso o IKM errato.
        FileNotFoundError: Se il file cifrato non esiste.
    """
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    # Deriva la stessa chiave AES-256
    hkdf = HKDF(
        algorithm=_hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ae_encrypt_private_key_escrow",
        backend=default_backend()
    )
    aes_key = hkdf.derive(ikm)

    # Leggi nonce + ciphertext dal file
    file_path = os.path.join(base_path, f"{name}_private.enc")
    with open(file_path, "rb") as f:
        blob = f.read()
    nonce, ciphertext = blob[:12], blob[12:]

    # Decifra e autentica (l'eccezione InvalidTag indica IKM errato o file corrotto)
    aesgcm = AESGCM(aes_key)
    private_pem = aesgcm.decrypt(nonce, ciphertext, None)

    return serialization.load_pem_private_key(
        private_pem,
        password=None,
        backend=default_backend()
    )


def load_private_key(name: str, base_path: str = "data/keys") -> RSAPrivateKey:
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


def load_public_key(name: str, base_path: str = "data/keys") -> RSAPublicKey:
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


def serialize_public_key(public_key: RSAPublicKey) -> str:
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


def deserialize_public_key(pem_str: str) -> RSAPublicKey:
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


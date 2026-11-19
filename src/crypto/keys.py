
"""
Modulo per la gestione delle chiavi RSA.

Questo modulo si occupa di:
- Generazione di coppie di chiavi RSA (2048 bit)
- Salvataggio delle chiavi in formato PEM
- Caricamento delle chiavi da file
- Serializzazione/deserializzazione delle chiavi pubbliche
- Escrow a soglia (Shamir k-su-n) della chiave privata di decifratura dell'AE
"""

import os
import json
import hashlib
from typing import Dict, List, Tuple
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


def escrow_private_key(private_key: RSAPrivateKey, election_id: str, trustees: int = 3,
                       threshold: int = 2, name: str = "ae_encrypt",
                       base_path: str = "data/keys") -> List[Dict]:
    """
    Protegge la chiave privata di decifratura dell'AE con un escrow a soglia.

    1. Si genera una chiave AES-256 casuale e con essa si cifra (AES-GCM) la
       chiave privata RSA. L'ID dell'elezione è usato come dato associato
       (AAD): il file cifrato non può essere riutilizzato per un'altra elezione.
    2. La chiave AES viene divisa con Shamir Secret Sharing in `trustees` quote,
       di cui `threshold` sufficienti a ricostruirla, e la chiave AES viene
       scartata: non esiste più in nessun luogo come valore intero.
    3. Ogni quota è destinata a uno scrutatore diverso. Nel PoC le quote sono
       salvate in data/keys/trustees/ per simulare la consegna; in un sistema
       reale ciascuna verrebbe consegnata al proprio scrutatore e non
       risiederebbe sulla macchina dell'AE.

    Formato del file cifrato: [12 byte nonce GCM] || [ciphertext + tag].

    Returns:
        List[Dict]: le quote, ognuna come documento JSON-serializzabile.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from crypto.shamir import split_secret

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)  # 96-bit nonce raccomandato per GCM
    ciphertext = AESGCM(aes_key).encrypt(nonce, private_pem, election_id.encode("utf-8"))

    os.makedirs(base_path, exist_ok=True)
    with open(os.path.join(base_path, f"{name}_private.enc"), "wb") as f:
        f.write(nonce + ciphertext)

    shares = []
    for x, y in split_secret(aes_key, trustees, threshold):
        shares.append({
            "election_id": election_id,
            "trustee": x,
            "threshold": threshold,
            "trustees": trustees,
            "x": x,
            "y": format(y, "x"),
        })
    del aes_key

    trustees_dir = os.path.join(base_path, "trustees")
    os.makedirs(trustees_dir, exist_ok=True)
    for share in shares:
        with open(os.path.join(trustees_dir, f"trustee_{share['trustee']}.json"), "w", encoding="utf-8") as f:
            json.dump(share, f, indent=2)
    return shares


def share_commitment(share: Dict) -> str:
    """
    Impegno pubblico su una quota: SHA-256 della sua serializzazione canonica.

    Gli impegni vengono pubblicati nel blocco init del Bulletin Board: al
    momento dello scrutinio l'AE (e chiunque) può verificare che le quote
    consegnate dagli scrutatori siano quelle originali e non quote manomesse.
    """
    canonical = json.dumps(share, sort_keys=True).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def escrow_public_info(shares: List[Dict]) -> Dict:
    """
    Parametri pubblici dell'escrow da inserire nel blocco init (firmato) del
    Bulletin Board: schema, soglia, numero di scrutatori e impegni sulle quote.
    """
    return {
        "scheme": "shamir",
        "threshold": shares[0]["threshold"],
        "trustees": shares[0]["trustees"],
        "share_commitments": [share_commitment(s) for s in shares],
    }


def load_trustee_shares(base_path: str = "data/keys") -> List[Dict]:
    """Legge le quote degli scrutatori salvate in data/keys/trustees/ (simulazione PoC)."""
    trustees_dir = os.path.join(base_path, "trustees")
    if not os.path.isdir(trustees_dir):
        return []
    shares = []
    for filename in sorted(os.listdir(trustees_dir)):
        if filename.endswith(".json"):
            with open(os.path.join(trustees_dir, filename), "r", encoding="utf-8") as f:
                shares.append(json.load(f))
    return shares


def recover_private_key(shares: List[Dict], election_id: str, name: str = "ae_encrypt",
                        base_path: str = "data/keys") -> RSAPrivateKey:
    """
    Ricostruisce la chiave privata dell'AE a partire dalle quote degli scrutatori.

    La chiave AES viene ricostruita con l'interpolazione di Lagrange e usata
    per decifrare il file: se le quote sono meno della soglia, manomesse o di
    un'altra elezione, AES-GCM fallisce l'autenticazione (InvalidTag).

    Raises:
        cryptography.exceptions.InvalidTag: quote insufficienti o non valide.
        ValueError: quote duplicate o malformate.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from crypto.shamir import combine_shares

    points = [(int(s["x"]), int(s["y"], 16)) for s in shares]
    aes_key = combine_shares(points, secret_length=32)

    with open(os.path.join(base_path, f"{name}_private.enc"), "rb") as f:
        blob = f.read()
    nonce, ciphertext = blob[:12], blob[12:]
    private_pem = AESGCM(aes_key).decrypt(nonce, ciphertext, election_id.encode("utf-8"))
    return serialization.load_pem_private_key(private_pem, password=None, backend=default_backend())


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


"""
Funzioni condivise dai test: creazione dell'elezione di test, quote degli
scrutatori, pulizia dello stato.

Ogni test crea la propria elezione con questa unica implementazione,
allineata a init_election.py: chiavi, Bulletin Board con i parametri
dell'escrow, pin, elettori e stato dell'AE sono identici a quelli di
un'elezione reale, e la chiave privata di decifratura dell'AE esiste su disco
solo cifrata. I test verificano così il sistema esattamente com'è.
"""

import hashlib
import json
import os
import sys
from datetime import datetime, timedelta, UTC
from typing import Dict, List, Optional

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(PROJECT_ROOT, "src")
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
KEYS_DIR = os.path.join(DATA_DIR, "keys")
BULLETIN_BOARD_PATH = os.path.join(DATA_DIR, "bulletin_board.json")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from cryptography.hazmat.primitives import serialization  # noqa: E402
from crypto.keys import (generate_rsa_keypair, save_keypair, serialize_public_key,  # noqa: E402
                         deserialize_public_key, escrow_private_key, escrow_public_info,
                         load_trustee_shares)
from crypto.password import hash_password  # noqa: E402
from crypto.rsa_pss import sign  # noqa: E402

DEFAULT_CANDIDATES = ["Lista A", "Lista B", "Lista C"]
STATE_FILES = ["bulletin_board.json", "voters.json", "ae_state.json", "pins.json"]


def compute_public_key_fingerprint(pem_str: str) -> str:
    """Impronta SHA-256 (DER SubjectPublicKeyInfo) di una chiave pubblica RSA."""
    der = deserialize_public_key(pem_str).public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def clean_election_state() -> None:
    """Rimuove Bulletin Board, elettori, stato AE, pin, chiavi e quote di test."""
    for fname in STATE_FILES:
        path = os.path.join(DATA_DIR, fname)
        if os.path.exists(path):
            os.remove(path)
    if os.path.isdir(KEYS_DIR):
        for root, _dirs, files in os.walk(KEYS_DIR, topdown=False):
            for f in files:
                if not (root == KEYS_DIR and f == ".gitkeep"):
                    os.remove(os.path.join(root, f))
            if root != KEYS_DIR:
                os.rmdir(root)


def create_test_election(election_id: str, voters: List[Dict], candidates: Optional[List[str]] = None,
                         duration_hours: float = 24, opens_in_minutes: float = 0) -> Dict:
    """
    Crea da zero un'elezione di test, con lo stesso schema di init_election.py:
    - coppie RSA-2048 per la firma del SA e per firma/cifratura dell'AE;
    - chiave privata di decifratura protetta SOLO dall'escrow Shamir 2-su-3
      (nessuna copia in chiaro su disco);
    - blocco init firmato con i parametri pubblici dell'escrow;
    - pin trusted delle chiavi AE, elettori con password hashate, stato AE vuoto.

    Returns:
        Dict: i dati del blocco init.
    """
    os.makedirs(KEYS_DIR, exist_ok=True)
    clean_election_state()

    sa_sign_priv, sa_sign_pub = generate_rsa_keypair()
    ae_enc_priv, ae_enc_pub = generate_rsa_keypair()
    ae_sign_priv, ae_sign_pub = generate_rsa_keypair()
    save_keypair(sa_sign_priv, sa_sign_pub, "sa_sign", base_path=KEYS_DIR)
    save_keypair(ae_sign_priv, ae_sign_pub, "ae_sign", base_path=KEYS_DIR)
    with open(os.path.join(KEYS_DIR, "ae_encrypt_public.pem"), "w", encoding="utf-8") as f:
        f.write(serialize_public_key(ae_enc_pub))
    shares = escrow_private_key(ae_enc_priv, election_id, trustees=3, threshold=2, base_path=KEYS_DIR)
    del ae_enc_priv

    init_data = {
        "election_id": election_id,
        "candidates": list(candidates or DEFAULT_CANDIDATES),
        "opening_time": (datetime.now(UTC) + timedelta(minutes=opens_in_minutes)).isoformat(),
        "closing_time": (datetime.now(UTC) + timedelta(minutes=opens_in_minutes)
                         + timedelta(hours=duration_hours)).isoformat(),
        "sa_sign_public": serialize_public_key(sa_sign_pub),
        "ae_encrypt_public": serialize_public_key(ae_enc_pub),
        "ae_sign_public": serialize_public_key(ae_sign_pub),
        "escrow": escrow_public_info(shares),
    }
    init_signature = sign(ae_sign_priv, json.dumps(init_data, sort_keys=True).encode("utf-8"))
    with open(BULLETIN_BOARD_PATH, "w", encoding="utf-8") as f:
        json.dump([{"type": "init", "timestamp": datetime.now(UTC).isoformat(),
                    "data": init_data, "signature": init_signature.hex()}], f, indent=2, ensure_ascii=False)

    pins = {
        "ae_encrypt_public": "sha256:" + compute_public_key_fingerprint(init_data["ae_encrypt_public"]),
        "ae_sign_public": "sha256:" + compute_public_key_fingerprint(init_data["ae_sign_public"]),
    }
    with open(os.path.join(DATA_DIR, "pins.json"), "w", encoding="utf-8") as f:
        json.dump(pins, f, indent=2)

    stored_voters = []
    for v in voters:
        vc = dict(v)
        vc["password"] = hash_password(vc["password"])
        stored_voters.append(vc)
    with open(os.path.join(DATA_DIR, "voters.json"), "w", encoding="utf-8") as f:
        json.dump(stored_voters, f, indent=2, ensure_ascii=False)

    with open(os.path.join(DATA_DIR, "ae_state.json"), "w", encoding="utf-8") as f:
        json.dump({"used_tokens": []}, f, indent=2)
    return init_data


def trustee_shares(count: int = 2) -> List[Dict]:
    """
    Quote consegnate dagli scrutatori per lo scrutinio (simulazione PoC):
    le prime `count` quote salvate in data/keys/trustees/.
    """
    return load_trustee_shares(KEYS_DIR)[:count]


def close_payload(count: int = 2) -> Dict:
    """Corpo JSON per /close dell'AE: le quote degli scrutatori."""
    return {"trustee_shares": trustee_shares(count)}


def get_pow_challenge(ae_url: str = "https://localhost:5002", verify=None):
    """
    Chiede all'AE una challenge per la Proof of Work.

    Returns:
        tuple: (challenge esadecimale, difficoltà in bit)
    """
    import requests
    if verify is None:
        cert = os.path.join(DATA_DIR, "tls", "ae_cert.pem")
        verify = cert if os.path.exists(cert) else True
    body = requests.get(f"{ae_url}/pow_challenge", timeout=10, verify=verify).json()
    return body["challenge"], int(body["difficulty"])


def solve_pow(challenge_hex: str, enc_vote_hex: str, difficulty: int) -> str:
    """
    Trova un nonce di 8 byte tale che SHA-256(challenge || enc_vote || nonce)
    abbia i primi `difficulty` bit a zero (stesso calcolo verificato dall'AE).
    """
    prefix = bytes.fromhex(challenge_hex) + bytes.fromhex(enc_vote_hex)
    shift = 256 - difficulty
    nonce = 0
    while True:
        nonce_bytes = nonce.to_bytes(8, "big")
        if int.from_bytes(hashlib.sha256(prefix + nonce_bytes).digest(), "big") >> shift == 0:
            return nonce_bytes.hex()
        nonce += 1


def pow_fields(enc_vote_hex: str) -> Dict:
    """Challenge + nonce pronti da inserire nel payload di /vote."""
    challenge, difficulty = get_pow_challenge()
    return {"pow_challenge": challenge, "pow_nonce": solve_pow(challenge, enc_vote_hex, difficulty)}


SA_URL = "https://localhost:5001"
AE_URL = "https://localhost:5002"


def _cert(name: str):
    path = os.path.join(DATA_DIR, "tls", f"{name}_cert.pem")
    return path if os.path.exists(path) else True


def wait_server(url: str, timeout: float = 20) -> bool:
    """Attende che il server risponda su /status."""
    import time
    import requests
    verify = _cert("sa" if url.endswith("5001") else "ae")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if requests.get(f"{url}/status", timeout=0.5, verify=verify).status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def start_servers(sa: bool = True, ae: bool = True) -> Dict:
    """Avvia SA e/o AE come sottoprocessi e attende che rispondano."""
    import subprocess
    procs = {}
    for name, url, wanted in (("sa", SA_URL, sa), ("ae", AE_URL, ae)):
        if not wanted:
            continue
        procs[name] = subprocess.Popen([sys.executable, os.path.join(SRC_DIR, f"{name}.py")], cwd=PROJECT_ROOT,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not wait_server(url):
            stop_servers(procs)
            raise RuntimeError(f"{name.upper()} non risponde")
    return procs


def stop_servers(procs: Dict) -> None:
    """Spegne i server avviati con start_servers (shutdown autenticato, poi terminate/kill)."""
    import subprocess
    import requests
    token_path = os.path.join(KEYS_DIR, "admin_token")
    headers = {}
    if os.path.exists(token_path):
        with open(token_path, "r", encoding="utf-8") as f:
            headers = {"X-Admin-Token": f.read().strip()}
    for name, proc in procs.items():
        url = SA_URL if name == "sa" else AE_URL
        try:
            requests.post(f"{url}/shutdown", headers=headers, timeout=2, verify=_cert(name))
        except Exception:
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

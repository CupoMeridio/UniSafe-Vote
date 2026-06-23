"""
Test per dimostrare la vulnerabilità DoS (Denial of Service) dell'Observer
causata da un elettore malevolo che invia un seed spazzatura.
"""

import os
import sys
import json
import time
import hashlib
import subprocess
import requests
from datetime import datetime, timedelta, UTC

PROJECT_ROOT  = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SRC_DIR       = os.path.join(PROJECT_ROOT, "src")
DATA_DIR      = os.path.join(PROJECT_ROOT, "data")
KEYS_DIR      = os.path.join(DATA_DIR, "keys")
TESTS_SEC_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SRC_DIR)
sys.path.insert(0, TESTS_SEC_DIR)

from crypto.keys import (generate_rsa_keypair, save_keypair, serialize_public_key,
                          deserialize_public_key, save_encrypted_private_key,
                          load_public_key, load_private_key)
from crypto.rsa_oaep import encrypt
from crypto.rsa_pss import sign
from crypto.password import hash_password
from cryptography.hazmat.primitives import serialization

import sys as _sys
_sys.path.insert(0, os.path.join(PROJECT_ROOT, "tests"))
from tls_config import SA_URL, AE_URL, sa_verify, ae_verify, ensure_tls_certs

BULLETIN_BOARD_PATH = os.path.join(DATA_DIR, "bulletin_board.json")
VOTERS_PATH         = os.path.join(DATA_DIR, "voters.json")

SERVER_STARTUP_SEC = 15

VOTERS = [
    {"id": "v001", "email": "hacker@studenti.unisa.it",
     "username": "hacker",  "password": "password123"},
]
CANDIDATES = ["Lista A", "Lista B", "Lista C"]

sa_process = None
ae_process = None

def compute_public_key_fingerprint(pem_str: str) -> str:
    pubkey = deserialize_public_key(pem_str)
    pubkey_bytes = pubkey.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(pubkey_bytes).hexdigest()

def _wait_server(url: str, name: str, timeout: int = SERVER_STARTUP_SEC) -> bool:
    _cert = ae_verify() if "5002" in url else sa_verify()
    for _ in range(timeout * 2):
        try:
            if requests.get(f"{url}/status", timeout=0.5, verify=_cert).status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False

def setup():
    global sa_process, ae_process
    print("\n[SETUP] Inizializzazione elezione...")
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(KEYS_DIR, exist_ok=True)
    ensure_tls_certs()
    for fname in ["bulletin_board.json", "voters.json", "ae_state.json", "pins.json"]:
        p = os.path.join(DATA_DIR, fname)
        if os.path.exists(p):
            os.remove(p)
    for f in os.listdir(KEYS_DIR):
        if f != ".gitkeep":
            os.remove(os.path.join(KEYS_DIR, f))

    sa_sign_priv,  sa_sign_pub  = generate_rsa_keypair()
    ae_enc_priv,   ae_enc_pub   = generate_rsa_keypair()
    ae_sign_priv,  ae_sign_pub  = generate_rsa_keypair()

    save_keypair(sa_sign_priv, sa_sign_pub,  "sa_sign")
    save_keypair(ae_enc_priv,  ae_enc_pub,   "ae_encrypt")
    save_keypair(ae_sign_priv, ae_sign_pub,  "ae_sign")

    opening = datetime.now(UTC).isoformat()
    closing = (datetime.now(UTC) + timedelta(hours=24)).isoformat()

    init_data = {
        "election_id":       "dos_attack_test",
        "candidates":        CANDIDATES,
        "opening_time":      opening,
        "closing_time":      closing,
        "sa_sign_public":    serialize_public_key(sa_sign_pub),
        "ae_encrypt_public": serialize_public_key(ae_enc_pub),
        "ae_sign_public":    serialize_public_key(ae_sign_pub),
    }
    init_json      = json.dumps(init_data, sort_keys=True).encode("utf-8")
    init_signature = sign(ae_sign_priv, init_json)

    bb = [{
        "type":      "init",
        "timestamp": datetime.now(UTC).isoformat(),
        "data":      init_data,
        "signature": init_signature.hex(),
    }]
    with open(BULLETIN_BOARD_PATH, "w", encoding="utf-8") as f:
        json.dump(bb, f, indent=2)

    pins = {
        "ae_encrypt_public": "sha256:" + compute_public_key_fingerprint(init_data["ae_encrypt_public"]),
        "ae_sign_public":    "sha256:" + compute_public_key_fingerprint(init_data["ae_sign_public"]),
    }
    with open(os.path.join(DATA_DIR, "pins.json"), "w", encoding="utf-8") as f:
        json.dump(pins, f, indent=2)

    save_encrypted_private_key(ae_enc_priv, "ae_encrypt", init_signature)

    voters_data = []
    for v in VOTERS:
        vc = v.copy()
        vc["password"] = hash_password(vc["password"])
        voters_data.append(vc)
    with open(VOTERS_PATH, "w", encoding="utf-8") as f:
        json.dump(voters_data, f, indent=2)

    with open(os.path.join(DATA_DIR, "ae_state.json"), "w", encoding="utf-8") as f:
        json.dump({"used_tokens": []}, f, indent=2)

    sa_process = subprocess.Popen(
        [sys.executable, os.path.join(SRC_DIR, "sa.py")],
        cwd=PROJECT_ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    assert _wait_server(SA_URL, "SA"), "SA non risponde."

    ae_process = subprocess.Popen(
        [sys.executable, os.path.join(SRC_DIR, "ae.py")],
        cwd=PROJECT_ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    assert _wait_server(AE_URL, "AE"), "AE non risponde."

def teardown():
    global sa_process, ae_process
    print("\n[TEARDOWN] Chiusura server...")
    for url, proc, name in [(SA_URL, sa_process, "SA"), (AE_URL, ae_process, "AE")]:
        try:
            requests.post(f"{url}/shutdown", timeout=1,
                          verify=(ae_verify() if "5002" in url else sa_verify()))
        except Exception:
            pass
        if proc:
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
    for fname in ["bulletin_board.json", "voters.json", "ae_state.json", "pins.json"]:
        p = os.path.join(DATA_DIR, fname)
        if os.path.exists(p):
            os.remove(p)
    for f in os.listdir(KEYS_DIR):
        if f != ".gitkeep":
            os.remove(os.path.join(KEYS_DIR, f))

def solve_pow(enc_vote_hex: str, difficulty: int = 4) -> str:
    enc_vote_bytes = bytes.fromhex(enc_vote_hex)
    nonce = 0
    while True:
        nonce_bytes = nonce.to_bytes(8, byteorder="big")
        combined = enc_vote_bytes + nonce_bytes
        hash_result = hashlib.sha256(combined).digest()
        required_zeros = difficulty // 8
        required_bits = difficulty % 8
        valid = True
        for i in range(required_zeros):
            if hash_result[i] != 0:
                valid = False
                break
        if valid and required_bits > 0:
            mask = (0xFF << (8 - required_bits)) & 0xFF
            if (hash_result[required_zeros] & mask) != 0:
                valid = False
        if valid:
            return nonce_bytes.hex()
        nonce += 1

def main():
    print("=" * 80)
    print("  TEST MITIGAZIONE DOS DA ELETTORE MALEVOLO (SEED CORROTTO)")
    print("=" * 80)
    try:
        setup()

        with open(BULLETIN_BOARD_PATH, "r", encoding="utf-8") as f:
            bb = json.load(f)
        ae_pubkey = deserialize_public_key(bb[0]["data"]["ae_encrypt_public"])

        print("\n[1] L'attaccante si autentica regolarmente presso il SA...")
        r1 = requests.post(f"{SA_URL}/authenticate",
                           json={"username": VOTERS[0]["username"],
                                 "password": VOTERS[0]["password"]},
                           verify=sa_verify())
        print(f"Status code: {r1.status_code}, Response: {r1.text}")
        assert r1.status_code == 200
        token = r1.json()["token"]
        signature = r1.json()["signature"]

        print("[2] L'attaccante costruisce una scheda compromessa...")
        # L'attaccante cifra un voto valido (Lista A, indice 0)
        voto = b"\x00"
        seed_reale = os.urandom(32)
        enc_vote_bytes = encrypt(ae_pubkey, voto, seed=seed_reale)
        
        # INVECE di cifrare il seed_reale, l'attaccante cifra un seed casuale (o spazzatura)
        seed_falso = os.urandom(32)
        enc_seed_bytes = encrypt(ae_pubkey, seed_falso)

        enc_vote_hex = enc_vote_bytes.hex()
        enc_seed_hex = enc_seed_bytes.hex()

        print("[3] L'attaccante risolve la PoW...")
        pow_nonce = solve_pow(enc_vote_hex)

        payload = {
            "enc_vote": enc_vote_hex,
            "enc_seed": enc_seed_hex,
            "token": token,
            "token_signature": signature,
            "pow_nonce": pow_nonce
        }

        print("[4] L'attaccante invia il voto all'AE...")
        r_vote = requests.post(f"{AE_URL}/vote", json=payload, verify=ae_verify())
        
        print(f"    Risposta AE: HTTP {r_vote.status_code}")
        assert r_vote.status_code == 200, "L'AE dovrebbe accettare il voto senza accorgersi della corruzione!"
        print("    L'AE ha accettato il voto con seed fittizio senza errori.")

        print("\n[5] Chiusura delle urne e Scrutinio...")
        requests.post(f"{SA_URL}/reconcile", verify=sa_verify())
        r_close = requests.post(f"{AE_URL}/close", verify=ae_verify())
        assert r_close.status_code == 200

        with open(BULLETIN_BOARD_PATH, "r", encoding="utf-8") as f:
            bb = json.load(f)
        
        scrutinio_block = next((b for b in bb if b["type"] == "scrutinio"), None)
        assert scrutinio_block is not None
        voti_verificati = scrutinio_block["data"]["voti_verificati"]
        print(f"    Voti scrutinati: {len(voti_verificati)}")
        voto_chiaro = voti_verificati[0]["voto_chiaro"]
        print(f"    Il voto malevolo è stato conteggiato per: {voto_chiaro}")
        assert voto_chiaro == "Scheda nulla", (
            "L'AE avrebbe dovuto classificare la scheda come nulla per incongruenza crittografica."
        )

        print("\n[6] Esecuzione dell'Observer (Verifica Universale)...")
        result = subprocess.run([sys.executable, os.path.join(SRC_DIR, "observer.py")],
                              cwd=PROJECT_ROOT, capture_output=True, text=True, input="\n")

        print("-" * 40)
        print("OUTPUT OBSERVER:")
        print(result.stdout)
        print("-" * 40)

        observer_ok = "TUTTE LE VERIFICHE PUBBLICHE SONO RIUSCITE" in result.stdout
        if observer_ok:
            print("\n[SUCCESS] Mitigazione attiva: l'AE ha accettato il voto in fase di "
                  "deposito (non può verificare il seed senza chiave privata), ma durante "
                  "lo scrutinio ha rilevato l'incongruenza seed/voto e classificato la scheda "
                  "come nulla. L'Observer completa la verifica universale senza bloccare "
                  "l'intera elezione.")
        else:
            print("\n[FAIL] L'Observer non ha superato la verifica universale: "
                  "un singolo elettore malevolo potrebbe compromettere l'elezione per tutti.")
            sys.exit(1)

    finally:
        teardown()

if __name__ == "__main__":
    os.chdir(PROJECT_ROOT)
    main()

"""
Script di simulazione attacco "Double Voting" e "Token Replay"
contro l'Autorità Elettorale (AE) di UniSafe-Vote.

Questo script dimostra che il sistema è protetto da attacchi di riutilizzo token:
- Il primo voto viene accettato
- Il secondo voto con lo stesso token viene rifiutato con errore "Token già usato"
"""

import os
import sys
import json
import hashlib
import subprocess
import time
import requests
from datetime import datetime, timedelta, UTC

# ---------------------------------------------------------------------------
# Path setup — il test gira da qualsiasi directory
# ---------------------------------------------------------------------------
PROJECT_ROOT  = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SRC_DIR       = os.path.join(PROJECT_ROOT, "src")
DATA_DIR      = os.path.join(PROJECT_ROOT, "data")
KEYS_DIR      = os.path.join(DATA_DIR, "keys")
TESTS_SEC_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SRC_DIR)
sys.path.insert(0, TESTS_SEC_DIR)

from test_reporter import save_report

from crypto.keys import (generate_rsa_keypair, save_keypair, serialize_public_key,
                          deserialize_public_key, save_encrypted_private_key,
                          load_private_key, load_public_key)
from crypto.rsa_oaep import encrypt
from crypto.rsa_pss import sign
from crypto.password import hash_password
from cryptography.hazmat.primitives import serialization


# ---------------------------------------------------------------------------
# compute_public_key_fingerprint inline (evita import da client)
# ---------------------------------------------------------------------------

def compute_public_key_fingerprint(pem_str: str) -> str:
    """Calcola l'impronta SHA-256 DER di una chiave pubblica RSA."""
    # Si converte la chiave PEM in formato DER e si calcola l'hash SHA-256,
    # ottenendo un'impronta univoca usata per il certificate pinning.
    pubkey = deserialize_public_key(pem_str)
    pubkey_bytes = pubkey.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(pubkey_bytes).hexdigest()


# ---------------------------------------------------------------------------
# Configurazione
# ---------------------------------------------------------------------------
import sys as _sys
_sys.path.insert(0, os.path.join(PROJECT_ROOT, "tests"))
from tls_config import AE_URL, SA_URL, ae_verify, sa_verify, ensure_tls_certs

BULLETIN_BOARD_PATH = os.path.join(DATA_DIR, "bulletin_board.json")

SERVER_STARTUP_SEC = 15  # Aumentato a 15s per overhead inizializzazione TLS

VOTERS = [
    {"id": "v001", "email": "v.postiglione7@studenti.unisa.it",
     "username": "vitto.posti",  "password": "password123"},
    {"id": "v002", "email": "mattia.sanzari@unisa.it",
     "username": "matty.sanz",   "password": "password456"},
    {"id": "v003", "email": "c.deluca92@studenti.unisa.it",
     "username": "carlo.deluca", "password": "pass_cDL92"},
]
CANDIDATES = ["Lista A", "Lista B", "Lista C"]

sa_process = None
ae_process = None


# ---------------------------------------------------------------------------
# Setup / Teardown
# ---------------------------------------------------------------------------

def _wait_server(url: str, name: str, timeout: int = SERVER_STARTUP_SEC) -> bool:
    """Attende che il server risponda sull'endpoint /status entro il timeout."""
    _cert = ae_verify() if "5002" in url else sa_verify()
    for _ in range(timeout * 2):
        try:
            if requests.get(f"{url}/status", timeout=0.5, verify=_cert).status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(0.5)
    print(f"  [ERRORE] {name} non risponde dopo {timeout}s.")
    return False


def setup():
    """Inizializza l'elezione da zero e avvia SA e AE come sottoprocessi."""
    global sa_process, ae_process

    print("\n[SETUP] Inizializzazione elezione...")

    # Si creano le directory e si elimina ogni stato residuo
    # di esecuzioni precedenti per garantire riproducibilità.
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(KEYS_DIR, exist_ok=True)

    # Genera i certificati TLS self-signed se non presenti (necessari per HTTPS).
    ensure_tls_certs()

    for fname in ["bulletin_board.json", "voters.json", "ae_state.json", "pins.json"]:
        p = os.path.join(DATA_DIR, fname)
        if os.path.exists(p):
            os.remove(p)
    for f in os.listdir(KEYS_DIR):
        if f == ".gitkeep":
            continue
        os.remove(os.path.join(KEYS_DIR, f))

    # Si generano tre coppie RSA-2048: firma SA, cifratura AE e firma AE.
    sa_sign_priv,  sa_sign_pub  = generate_rsa_keypair()
    ae_enc_priv,   ae_enc_pub   = generate_rsa_keypair()
    ae_sign_priv,  ae_sign_pub  = generate_rsa_keypair()

    save_keypair(sa_sign_priv, sa_sign_pub,  "sa_sign")
    save_keypair(ae_enc_priv,  ae_enc_pub,   "ae_encrypt")
    save_keypair(ae_sign_priv, ae_sign_pub,  "ae_sign")

    # L'elezione apre immediatamente e chiude tra 24 ore.
    opening = datetime.now(UTC).isoformat()
    closing = (datetime.now(UTC) + timedelta(hours=24)).isoformat()

    # Si compone e firma il blocco di inizializzazione del Bulletin Board.
    init_data = {
        "election_id":       "elezione_test_double_voting",
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

    # Si calcolano le impronte delle chiavi AE e si salvano in pins.json
    # per simulare il canale di distribuzione trusted (certificate pinning).
    pins = {
        "ae_encrypt_public": "sha256:" + compute_public_key_fingerprint(init_data["ae_encrypt_public"]),
        "ae_sign_public":    "sha256:" + compute_public_key_fingerprint(init_data["ae_sign_public"]),
    }
    with open(os.path.join(DATA_DIR, "pins.json"), "w", encoding="utf-8") as f:
        json.dump(pins, f, indent=2)

    # La chiave privata di cifratura AE viene salvata cifrata con AES-GCM
    # usando la firma del blocco init come IKM (WP3 §3.3).
    save_encrypted_private_key(ae_enc_priv, "ae_encrypt", init_signature)

    # Le password vengono salvate come hash Argon2, mai in chiaro.
    voters_data = []
    for v in VOTERS:
        vc = v.copy()
        vc["password"] = hash_password(vc["password"])
        voters_data.append(vc)
    with open(os.path.join(DATA_DIR, "voters.json"), "w", encoding="utf-8") as f:
        json.dump(voters_data, f, indent=2)

    # Si inizializza lo stato privato dell'AE con la lista dei token usati vuota.
    with open(os.path.join(DATA_DIR, "ae_state.json"), "w", encoding="utf-8") as f:
        json.dump({"used_tokens": []}, f, indent=2)

    # Si avvia il SA e si attende che Flask risponda su /status.
    sa_process = subprocess.Popen(
        [sys.executable, os.path.join(SRC_DIR, "sa.py")],
        cwd=PROJECT_ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    print(f"[SETUP] SA avviato (PID {sa_process.pid}), attendo...", end=" ", flush=True)
    assert _wait_server(SA_URL, "SA"), "SA non risponde."
    print("OK")

    # Si avvia l'AE e si attende che Flask risponda su /status.
    ae_process = subprocess.Popen(
        [sys.executable, os.path.join(SRC_DIR, "ae.py")],
        cwd=PROJECT_ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    print(f"[SETUP] AE avviata (PID {ae_process.pid}), attendo...", end=" ", flush=True)
    assert _wait_server(AE_URL, "AE"), "AE non risponde."
    print("OK")


def teardown():
    """Invia il segnale di shutdown a SA e AE e termina i processi."""
    global sa_process, ae_process
    print("\n[TEARDOWN] Chiusura server...")
    for url, proc, name in [(SA_URL, sa_process, "SA"), (AE_URL, ae_process, "AE")]:
        # Si tenta prima lo shutdown HTTP controllato; se il server non risponde,
        # si termina il processo con terminate() e infine con kill().
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
        print(f"[TEARDOWN] {name} terminato.")


# ---------------------------------------------------------------------------
# Logica di test
# ---------------------------------------------------------------------------

def validate_pins(bulletin_board):
    """Verifica che le chiavi AE del Bulletin Board corrispondano ai pin trusted."""
    with open(os.path.join(DATA_DIR, "pins.json"), "r", encoding="utf-8") as f:
        pins = json.load(f)

    init_data = bulletin_board[0]["data"]

    # Si rimuove il prefisso "sha256:" per confrontare solo il valore hex.
    def normalize_pin(pin_value):
        return pin_value[7:] if pin_value.startswith("sha256:") else pin_value

    assert normalize_pin(pins["ae_encrypt_public"]) == compute_public_key_fingerprint(init_data["ae_encrypt_public"])
    assert normalize_pin(pins["ae_sign_public"]) == compute_public_key_fingerprint(init_data["ae_sign_public"])
    print("[OK] Pin trusted AE verificati con successo!")


def load_bulletin_board():
    """Carica il Bulletin Board e verifica il certificate pinning."""
    with open(BULLETIN_BOARD_PATH, "r", encoding="utf-8") as f:
        bulletin_board = json.load(f)
    validate_pins(bulletin_board)
    return bulletin_board


def solve_pow(enc_vote_hex: str, difficulty: int = 4) -> str:
    """
    Calcola il nonce della Proof of Work per un voto cifrato.
    Si cerca un valore tale che SHA-256(enc_vote || nonce) abbia
    i primi 'difficulty' bit a zero.
    """
    enc_vote_bytes = bytes.fromhex(enc_vote_hex)
    nonce = 0
    while True:
        nonce_bytes = nonce.to_bytes(8, byteorder='big')
        combined = enc_vote_bytes + nonce_bytes
        hash_result = hashlib.sha256(combined).digest()
        # Si verifica prima i byte interi a zero, poi i bit rimanenti.
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


def get_pow_difficulty():
    """Interroga l'AE per ottenere la difficoltà PoW adattiva corrente."""
    try:
        response = requests.get(f"{AE_URL}/status", timeout=5, verify=ae_verify())
        if response.status_code == 200:
            return int(response.json().get("pow_difficulty", 4))
    except requests.exceptions.RequestException:
        pass
    return 4


def get_valid_token():
    """Ottieni un token valido autenticandosi al SA usando la password in chiaro."""
    # La password in chiaro viene presa dalla costante VOTERS, non da voters.json
    # che contiene già l'hash Argon2 salvato dal setup.
    voter_plain = VOTERS[0]
    print(f"  Autenticazione elettore: {voter_plain['username']}")
    response = requests.post(
        f"{SA_URL}/authenticate",
        json={"username": voter_plain["username"], "password": voter_plain["password"]},
        timeout=5,
        verify=sa_verify()
    )
    if response.status_code == 200:
        data = response.json()
        print("  Token ottenuto dal SA.")
        return data["token"], data["signature"]

    print(f"  [ERRORE] Autenticazione SA fallita: HTTP {response.status_code}")
    sys.exit(1)


def create_vote_payload(token: str, token_signature: str, candidate_index: int = 0):
    """
    Costruisce il payload completo per un voto:
    - cifra il voto e il seed con RSA-OAEP
    - calcola la PoW alla difficoltà adattiva corrente
    """
    bb = load_bulletin_board()
    # Si deserializza la chiave pubblica di cifratura dell'AE dal Bulletin Board.
    ae_encrypt_public = deserialize_public_key(bb[0]["data"]["ae_encrypt_public"])

    # Si genera un seed casuale di 32 byte usato come randomness di padding OAEP.
    # Grazie al seed, due cifrature dello stesso voto producono ciphertext diversi.
    seed = os.urandom(32)
    vote_byte = candidate_index.to_bytes(1, byteorder='big')

    # Si cifra il voto con il seed esplicito (cifratura deterministica e verificabile).
    enc_vote_bytes = encrypt(ae_encrypt_public, vote_byte, seed=seed)
    # Si cifra il seed separatamente: l'AE lo decifrerà a urne chiuse per
    # pubblicare la tripla (enc_vote, voto_chiaro, seed) necessaria alla
    # verifica universale (WP2 Fase 4).
    enc_seed_bytes = encrypt(ae_encrypt_public, seed)
    enc_vote_hex = enc_vote_bytes.hex()
    enc_seed_hex = enc_seed_bytes.hex()

    # Si calcola la PoW alla difficoltà adattiva corrente restituita dall'AE.
    difficulty = get_pow_difficulty()
    pow_nonce = solve_pow(enc_vote_hex, difficulty)

    return {
        "enc_vote": enc_vote_hex,
        "enc_seed": enc_seed_hex,
        "token": token,
        "token_signature": token_signature,
        "pow_nonce": pow_nonce
    }




def main():
    global sa_process, ae_process
    try:
        setup()

        print("\n" + "=" * 70)
        print("  TEST DOUBLE VOTING / TOKEN REPLAY ATTACK")
        print("=" * 70)

        # ------------------------------------------------------------------ #
        # FASE 1 — Autenticazione e ottenimento token                         #
        # ------------------------------------------------------------------ #
        print("\n" + "-" * 70)
        print("FASE 1 — Autenticazione e ottenimento token")
        print("-" * 70)
        token, token_signature = get_valid_token()
        token_obj = json.loads(token)
        print(f"\n  Token ottenuto (contenuto):")
        print(f"    election_id: {token_obj.get('election_id')}")
        print(f"    nonce:       {token_obj.get('nonce')}")
        print(f"    expires_at:  {token_obj.get('expires_at')}")
        print(f"  Firma SA (prime 64 hex): {token_signature[:64]}...")

        # ------------------------------------------------------------------ #
        # FASE 2 — Primo voto (legittimo)                                     #
        # ------------------------------------------------------------------ #
        print("\n" + "-" * 70)
        print("FASE 2 — Primo voto (legittimo, candidato 0 — Lista A)")
        print("-" * 70)
        payload1 = create_vote_payload(token, token_signature, candidate_index=0)
        print(f"  enc_vote (prime 60 hex): {payload1['enc_vote'][:60]}...")
        print(f"  pow_nonce:               {payload1['pow_nonce']}")
        print(f"  Invio voto 1...")
        response1 = requests.post(f"{AE_URL}/vote", json=payload1, timeout=10, verify=ae_verify())
        print(f"\n  Risposta AE — HTTP {response1.status_code}:")
        print(f"  {json.dumps(response1.json(), indent=4, ensure_ascii=False)}")

        # ------------------------------------------------------------------ #
        # FASE 3 — Secondo voto con lo stesso token (attacco)                 #
        # ------------------------------------------------------------------ #
        print("\n" + "-" * 70)
        print("FASE 3 — Secondo voto con lo STESSO token (candidato 1 — Lista B)")
        print("-" * 70)
        print("  L'attaccante riutilizza il token già consumato per votare di nuovo.")
        print(f"  Nonce del token (già marcato come usato dall'AE): {token_obj.get('nonce')}")
        payload2 = create_vote_payload(token, token_signature, candidate_index=1)
        print(f"  enc_vote (prime 60 hex): {payload2['enc_vote'][:60]}...")
        print(f"  pow_nonce:               {payload2['pow_nonce']}")
        print(f"  Invio voto 2...")
        response2 = requests.post(f"{AE_URL}/vote", json=payload2, timeout=10, verify=ae_verify())
        print(f"\n  Risposta AE — HTTP {response2.status_code}:")
        print(f"  {json.dumps(response2.json(), indent=4, ensure_ascii=False)}")

        # ------------------------------------------------------------------ #
        # Riepilogo                                                           #
        # ------------------------------------------------------------------ #
        print("\n" + "=" * 70)
        print("RIEPILOGO")
        print("=" * 70)
        voto1_ok   = response1.status_code == 200
        voto2_rej  = response2.status_code == 409
        passed     = voto1_ok and voto2_rej

        print(f"  Voto 1 (legittimo):  HTTP {response1.status_code}  — {'✓ accettato' if voto1_ok  else '✗ errore inatteso'}")
        print(f"  Voto 2 (replay):     HTTP {response2.status_code}  — {'✓ rifiutato (409 Token già usato)' if voto2_rej else '✗ accettato — sistema vulnerabile!'}")

        if passed:
            print("\n  [SUCCESS] Il sistema è protetto contro il double voting.")
            print("  Il nonce del token viene marcato come usato dopo il primo voto:")
            print("  qualsiasi replay dello stesso token viene bloccato con HTTP 409.")
        else:
            print("\n  [FAIL] Il sistema non ha risposto come atteso.")
        print("=" * 70)

        save_report(
            test_id="double_voting",
            test_name="Double Voting / Token Replay Attack",
            outcome="PASS" if passed else "FAIL",
            details={
                "token_nonce": token_obj.get("nonce"),
                "token_expires_at": token_obj.get("expires_at"),
                "first_vote": {
                    "candidate_index": 0,
                    "http_status": response1.status_code,
                    "accepted": voto1_ok,
                    "response": response1.json(),
                },
                "second_vote": {
                    "candidate_index": 1,
                    "http_status": response2.status_code,
                    "rejected": voto2_rej,
                    "response": response2.json(),
                },
                "protection_mechanism": "Token nonce blacklist (ae_state.json used_tokens)",
            },
        )

    finally:
        teardown()


if __name__ == "__main__":
    os.chdir(PROJECT_ROOT)
    try:
        main()
    except Exception as e:
        print(f"\n[ERRORE] {e}")
    finally:
        input("\nPremi Invio per chiudere...")

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
AE_URL              = "http://localhost:5002"
SA_URL              = "http://localhost:5001"
BULLETIN_BOARD_PATH = os.path.join(DATA_DIR, "bulletin_board.json")

SERVER_STARTUP_SEC = 6

VOTERS = [
    {"id": "v001", "email": "mario.rossi@studenti.unisa.it",
     "username": "mario.rossi",   "password": "password123"},
    {"id": "v002", "email": "luigi.bianchi@unisa.it",
     "username": "luigi.bianchi", "password": "password456"},
]
CANDIDATES = ["Lista A", "Lista B", "Lista C"]

sa_process = None
ae_process = None


# ---------------------------------------------------------------------------
# Setup / Teardown
# ---------------------------------------------------------------------------

def _wait_server(url: str, name: str, timeout: int = SERVER_STARTUP_SEC) -> bool:
    """Attende che il server risponda sull'endpoint /status entro il timeout."""
    for _ in range(timeout * 2):
        try:
            if requests.get(f"{url}/status", timeout=0.5).status_code == 200:
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

    for fname in ["bulletin_board.json", "voters.json", "ae_state.json", "pins.json"]:
        p = os.path.join(DATA_DIR, fname)
        if os.path.exists(p):
            os.remove(p)
    for f in os.listdir(KEYS_DIR):
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
            requests.post(f"{url}/shutdown", timeout=1)
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
        response = requests.get(f"{AE_URL}/status", timeout=5)
        if response.status_code == 200:
            return int(response.json().get("pow_difficulty", 4))
    except requests.exceptions.RequestException:
        pass
    return 4


def get_valid_token():
    """Ottieni un token valido autenticandosi al SA (avviato dal setup)."""
    # Si legge il primo elettore da voters.json per ottenere le credenziali.
    with open(os.path.join(DATA_DIR, "voters.json"), "r", encoding="utf-8") as f:
        voters = json.load(f)

    test_voter = voters[0]
    print(f"[INFO] Autenticazione utente: {test_voter['username']}")
    # Si invia la richiesta di autenticazione al SA: se le credenziali sono
    # valide, il SA restituisce il token firmato con RSA-PSS.
    response = requests.post(
        f"{SA_URL}/authenticate",
        json={"username": test_voter["username"], "password": test_voter["password"]},
        timeout=5
    )
    if response.status_code == 200:
        data = response.json()
        print("[SUCCESS] Token ottenuto con successo dal SA!")
        return data["token"], data["signature"]

    print(f"[ERROR] Autenticazione SA fallita: {response.status_code}")
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


def send_vote(payload, vote_number):
    """Invia un voto all'AE e stampa la risposta ricevuta."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
    print(f"\n{'='*60}")
    print(f"[INVIO VOTO {vote_number}] - {timestamp}")
    print(f"{'='*60}")
    print(f"Payload: {json.dumps(payload, indent=2, ensure_ascii=False)}")

    try:
        response = requests.post(f"{AE_URL}/vote", json=payload, timeout=10)
        print(f"\nRisposta AE:")
        print(f"  Status Code: {response.status_code}")
        print(f"  Contenuto: {json.dumps(response.json(), indent=2, ensure_ascii=False)}")
        return response
    except requests.exceptions.RequestException as e:
        print(f"\n[ERRORE] Impossibile connettersi all'AE: {e}")
        sys.exit(1)


def main():
    global sa_process, ae_process
    try:
        # Si esegue il setup completo: init elezione, avvio SA e AE.
        setup()

        print("\n" + "="*60)
        print("SIMULAZIONE ATTACCO DOUBLE VOTING / TOKEN REPLAY")
        print("="*60)

        # Si ottiene un token valido autenticandosi al SA con le credenziali
        # del primo elettore presente in voters.json.
        token, token_signature = get_valid_token()

        # PASSO 1: Si invia il primo voto con il token appena ottenuto.
        # L'AE deve accettarlo (HTTP 200) e marcare il token come usato.
        payload1 = create_vote_payload(token, token_signature, candidate_index=0)
        response1 = send_vote(payload1, 1)

        # PASSO 2: Si tenta di votare una seconda volta con lo stesso token,
        # ma per un candidato diverso. Questo simula l'attacco di double voting.
        # L'AE deve rifiutare la richiesta con HTTP 409 "Token già usato",
        # perché il nonce del token è già presente nello stato privato dell'AE.
        print("\n" + "="*60)
        print("ATTACCO: INVIO SECONDO VOTO CON LO STESSO TOKEN!")
        print("="*60)
        payload2 = create_vote_payload(token, token_signature, candidate_index=1)
        response2 = send_vote(payload2, 2)

        # Si valuta l'esito: il test è superato se il primo voto è stato
        # accettato e il secondo rifiutato con il codice corretto.
        print("\n" + "="*60)
        print("RISULTATO DELL'ATTACCO")
        print("="*60)
        if response1.status_code == 200 and response2.status_code == 409:
            print("[SUCCESS] Il sistema è protetto!")
            print("  - Primo voto: ACCETTATO (status 200)")
            print("  - Secondo voto: RIFIUTATO (status 409, 'Token già usato')")
            passed = True
        else:
            print("[FALLIMENTO] Il sistema NON è protetto correttamente!")
            passed = False

        print("\n" + "="*60)

        save_report(
            test_id="double_voting",
            test_name="Double Voting / Token Replay Attack",
            outcome="PASS" if passed else "FAIL",
            details={
                "first_vote": {
                    "http_status": response1.status_code,
                    "candidate_index": 0,
                    "accepted": response1.status_code == 200,
                },
                "second_vote": {
                    "http_status": response2.status_code,
                    "candidate_index": 1,
                    "rejected": response2.status_code == 409,
                    "error": response2.json().get("error") if response2.content else None,
                },
                "protection_mechanism": "Token nonce blacklist (ae_state.json used_tokens)",
            },
        )

    finally:
        # Il teardown viene eseguito sempre, anche in caso di errore.
        teardown()


if __name__ == "__main__":
    os.chdir(PROJECT_ROOT)
    try:
        main()
    except Exception as e:
        print(f"\n[ERRORE] {e}")
    finally:
        input("\nPremi Invio per chiudere...")

"""
Test per Token Hoarding & Expired Token Exploitation (Use-it-or-Lose-it Policy).

Verifica tre proprietà del sistema:
1. Il SA non emette un secondo token distinto allo stesso elettore.
2. L'AE rifiuta token con firma valida ma scaduti (expires_at nel passato).
3. Un token valido viene accettato normalmente per il voto.
"""

import os
import sys
import json
import time
import hashlib
import subprocess
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
                          load_public_key, load_private_key)
from crypto.rsa_oaep import encrypt
from crypto.rsa_pss import sign, verify
from crypto.password import hash_password
from cryptography.hazmat.primitives import serialization


# ---------------------------------------------------------------------------
# compute_public_key_fingerprint inline (evita import da client)
# ---------------------------------------------------------------------------

def compute_public_key_fingerprint(pem_str: str) -> str:
    """Calcola l'impronta SHA-256 DER di una chiave pubblica RSA."""
    # Si converte la chiave PEM in formato DER e se ne calcola l'hash SHA-256.
    pubkey = deserialize_public_key(pem_str)
    pubkey_bytes = pubkey.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(pubkey_bytes).hexdigest()


# ---------------------------------------------------------------------------
# Configurazione
# ---------------------------------------------------------------------------
SA_URL              = "http://localhost:5001"
AE_URL              = "http://localhost:5002"
BULLETIN_BOARD_PATH = os.path.join(DATA_DIR, "bulletin_board.json")
VOTERS_PATH         = os.path.join(DATA_DIR, "voters.json")

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
        "election_id":       "token_hoarding_test",
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
    with open(VOTERS_PATH, "w", encoding="utf-8") as f:
        json.dump(voters_data, f, indent=2)

    # Si inizializza lo stato privato dell'AE con la lista dei token usati vuota.
    with open(os.path.join(DATA_DIR, "ae_state.json"), "w", encoding="utf-8") as f:
        json.dump({"used_tokens": []}, f, indent=2)

    # Si avvia il SA e si attende che risponda su /status.
    sa_process = subprocess.Popen(
        [sys.executable, os.path.join(SRC_DIR, "sa.py")],
        cwd=PROJECT_ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    print(f"[SETUP] SA avviato (PID {sa_process.pid}), attendo...", end=" ", flush=True)
    assert _wait_server(SA_URL, "SA"), "SA non risponde."
    print("OK")

    # Si avvia l'AE e si attende che risponda su /status.
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
    print("    Pin trusted AE verificati con successo!")


def solve_pow(enc_vote_hex: str, difficulty: int = 4) -> str:
    """
    Calcola il nonce della Proof of Work per un voto cifrato.
    Si cerca un nonce tale che SHA-256(enc_vote || nonce) abbia
    i primi 'difficulty' bit a zero.
    """
    enc_vote_bytes = bytes.fromhex(enc_vote_hex)
    nonce = 0
    while True:
        nonce_bytes = nonce.to_bytes(8, byteorder="big")
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


def get_pow_difficulty() -> int:
    """Interroga l'AE per ottenere la difficoltà PoW adattiva corrente."""
    try:
        response = requests.get(f"{AE_URL}/status", timeout=2)
        if response.status_code == 200:
            return int(response.json().get("pow_difficulty", 4))
    except Exception:
        pass
    return 4


def create_vote_payload(token: str, token_signature: str, ae_pubkey) -> dict:
    """
    Costruisce il payload completo per un voto:
    - cifra il voto e il seed con RSA-OAEP
    - calcola la PoW alla difficoltà corrente
    """
    # Si genera un seed casuale di 32 byte come randomness di padding OAEP.
    seed = os.urandom(32)
    vote_byte = b"\x00"  # Voto per il primo candidato (indice 0)
    # Si cifra il voto con il seed esplicito (cifratura deterministica).
    enc_vote_bytes = encrypt(ae_pubkey, vote_byte, seed=seed)
    # Si cifra il seed separatamente per abilitare la verifica universale.
    enc_seed_bytes = encrypt(ae_pubkey, seed)
    enc_vote_hex = enc_vote_bytes.hex()
    enc_seed_hex = enc_seed_bytes.hex()
    # Si risolve la PoW alla difficoltà adattiva corrente.
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
        # Si esegue il setup completo: init elezione, avvio SA e AE.
        setup()

        print("=" * 80)
        print("TEST TOKEN HOARDING & EXPIRED TOKEN EXPLOITATION")
        print("(Use-it-or-Lose-it Policy)")
        print("=" * 80)

        # Si caricano il Bulletin Board e le chiavi necessarie per il test.
        print("\n[3] Caricamento chiavi...")
        with open(BULLETIN_BOARD_PATH, "r", encoding="utf-8") as f:
            bb = json.load(f)
        validate_pins(bb)
        # Si deserializza la chiave pubblica di cifratura dell'AE dal BB.
        ae_pubkey = deserialize_public_key(bb[0]["data"]["ae_encrypt_public"])
        # Si carica la chiave privata di firma del SA per creare token scaduti
        # con firma valida (necessario per il TEST 2).
        sa_privkey = load_private_key("sa_sign")
        print("    Chiavi caricate!")

        with open(VOTERS_PATH, "r", encoding="utf-8") as f:
            voters = json.load(f)
        test_voter = voters[0]
        # La password in chiaro viene presa dalla costante VOTERS (non da voters.json,
        # che contiene già l'hash Argon2 salvato dal setup).
        test_voter_password = VOTERS[0]["password"]
        print(f"\n[4] Utilizzando l'elettore di test: {test_voter['username']}")

        # Si autentica l'elettore presso il SA per ottenere il primo token.
        print("\n[5] Autenticazione al SA per ottenere token valido...")
        auth_response1 = requests.post(
            f"{SA_URL}/authenticate",
            json={"username": test_voter["username"], "password": test_voter_password}
        )
        assert auth_response1.status_code == 200, "Prima autenticazione fallita!"
        auth_data1 = auth_response1.json()
        token1 = auth_data1["token"]
        signature1 = auth_data1["signature"]
        print(f"    Token 1 ricevuto!")

        # TEST 1: Si tenta una seconda autenticazione con le stesse credenziali.
        # Il SA deve restituire lo stesso token (non un nuovo token distinto),
        # impedendo così il "token hoarding" (accumulare più credenziali di voto).
        print("\n[6] TEST 1: Tentativo di RI-AUTENTICARSI al SA per ottenere nuovo token...")
        auth_response2 = requests.post(
            f"{SA_URL}/authenticate",
            json={"username": test_voter["username"], "password": test_voter_password}
        )
        assert auth_response2.status_code == 200, "Seconda autenticazione fallita!"
        auth_data2 = auth_response2.json()
        token2 = auth_data2["token"]

        print(f"    Token 1: {token1[:80]}...")
        print(f"    Token 2: {token2[:80]}...")

        # Si verifica che i due token siano identici: il SA non deve mai
        # emettere una seconda credenziale distinta per lo stesso elettore.
        assert token1 == token2, "SA ha emesso due token distinti!"
        print("\n    [OK] TEST 1 PASS: SA restituisce sempre LO STESSO token (nessun token nuovo)")

        # TEST 2: Si costruisce un token con firma RSA-PSS valida ma con
        # expires_at nel passato (31 minuti fa). L'AE deve rifiutarlo con
        # HTTP 401 "Token scaduto" anche se la firma è crittograficamente corretta,
        # dimostrando che la validità temporale è verificata indipendentemente.
        print("\n[7] TEST 2: Creazione token SCADUTO (firma valida) e invio ad AE...")
        election_id = bb[0]["data"]["election_id"]
        expired_token_obj = {
            "election_id": election_id,
            "nonce": os.urandom(16).hex(),
            # Il token è stato emesso un'ora fa ed è scaduto 31 minuti fa.
            "issued_at": (datetime.now(UTC) - timedelta(hours=1)).isoformat(),
            "expires_at": (datetime.now(UTC) - timedelta(minutes=31)).isoformat(),
        }
        expired_token_str = json.dumps(expired_token_obj, sort_keys=True)
        # Si firma il token con la chiave privata del SA: la firma è valida,
        # ma la finestra temporale è già scaduta.
        expired_signature = sign(sa_privkey, expired_token_str.encode("utf-8")).hex()

        expired_payload = create_vote_payload(expired_token_str, expired_signature, ae_pubkey)
        expired_response = requests.post(f"{AE_URL}/vote", json=expired_payload)

        print(f"    Risposta AE: {expired_response.status_code}")
        print(f"    Contenuto: {json.dumps(expired_response.json(), indent=2, ensure_ascii=False)}")

        # Si verifica che l'AE abbia rifiutato il token scaduto con HTTP 401.
        assert expired_response.status_code == 401, "AE non ha bloccato token scaduto!"
        assert "Token scaduto" in expired_response.json().get("error", ""), "Messaggio non corretto!"
        print("\n    [OK] TEST 2 PASS: AE blocca token scaduto con firma valida!")

        # TEST 3: Si invia un voto con il token valido ottenuto al passo [5].
        # L'AE deve accettarlo con HTTP 200, confermando che il sistema
        # funziona normalmente per gli elettori legittimi.
        print("\n[8] TEST 3: Utilizziamo il token valido per votare (per vedere che funziona)...")
        valid_payload = create_vote_payload(token1, signature1, ae_pubkey)
        valid_response = requests.post(f"{AE_URL}/vote", json=valid_payload)
        print(f"    Risposta AE: {valid_response.status_code}")
        assert valid_response.status_code == 200, "Voto valido rifiutato!"
        print("\n    [OK] TEST 3 PASS: Voto valido accettato!")

        print("\n" + "=" * 80)
        print("TEST COMPLETATO CON SUCCESSO!")
        print("\nRISULTATI:")
        print("  1. SA non emette nuovi token dopo il primo (previene Token Hoarding)")
        print("  2. AE rifiuta token scaduti (Use-it-or-Lose-it, 30 minuti di validità)")
        print("  3. Voti validi sono accettati normalmente")
        print("=" * 80)

        save_report(
            test_id="token_hoarding",
            test_name="Token Hoarding & Expired Token Exploitation (Use-it-or-Lose-it Policy)",
            outcome="PASS",
            details={
                "test1_hoarding": {
                    "description": "SA restituisce lo stesso token alla seconda autenticazione",
                    "token1_prefix": token1[:40] + "...",
                    "token2_prefix": token2[:40] + "...",
                    "tokens_identical": token1 == token2,
                    "passed": True,
                },
                "test2_expired_token": {
                    "description": "AE rifiuta token con firma valida ma expires_at nel passato",
                    "http_status": expired_response.status_code,
                    "error_message": expired_response.json().get("error"),
                    "passed": expired_response.status_code == 401,
                },
                "test3_valid_vote": {
                    "description": "Voto con token valido accettato normalmente",
                    "http_status": valid_response.status_code,
                    "passed": valid_response.status_code == 200,
                },
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

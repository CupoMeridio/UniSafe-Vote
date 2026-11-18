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
                          deserialize_public_key,
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
import sys as _sys
_sys.path.insert(0, os.path.join(PROJECT_ROOT, "tests"))
from tls_config import SA_URL, AE_URL, sa_verify, ae_verify, ensure_tls_certs, admin_headers
from common import create_test_election, close_payload, clean_election_state

BULLETIN_BOARD_PATH = os.path.join(DATA_DIR, "bulletin_board.json")
VOTERS_PATH         = os.path.join(DATA_DIR, "voters.json")

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
EXPIRED_VOTER_NONCE = "e" * 32  # nonce del token già scaduto di VOTERS[2] (TEST 4)


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

    # Elezione di test creata dal modulo condiviso: stesso schema di
    # init_election.py, chiave di decifratura protetta solo dall'escrow
    # Shamir (nessuna copia in chiaro su disco).
    init_data = create_test_election("token_hoarding_test", VOTERS, CANDIDATES)

    # Per il TEST 4 l'elettore VOTERS[2] risulta essersi autenticato più di
    # 30 minuti fa senza votare: il suo token è già scaduto all'avvio del SA.
    with open(VOTERS_PATH, "r", encoding="utf-8") as f:
        stored = json.load(f)
    stored[2]["token"] = {
        "election_id": "token_hoarding_test",
        "nonce": EXPIRED_VOTER_NONCE,
        "issued_at": (datetime.now(UTC) - timedelta(hours=1)).isoformat(),
        "expires_at": (datetime.now(UTC) - timedelta(minutes=30)).isoformat(),
    }
    with open(VOTERS_PATH, "w", encoding="utf-8") as f:
        json.dump(stored, f, indent=2)

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
    """Invia il segnale di shutdown a SA e AE e termina i processi, poi pulisce i file di stato."""
    global sa_process, ae_process
    print("\n[TEARDOWN] Chiusura server...")
    for url, proc, name in [(SA_URL, sa_process, "SA"), (AE_URL, ae_process, "AE")]:
        try:
            requests.post(f"{url}/shutdown", headers=admin_headers(), timeout=1,
                          verify=(ae_verify() if "5002" in url else sa_verify()))
        except Exception:
            pass
        if proc:
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
        print(f"[TEARDOWN] {name} terminato.")
    # Pulizia dei file di stato lasciati dal test.
    for fname in ["bulletin_board.json", "voters.json", "ae_state.json", "pins.json"]:
        p = os.path.join(DATA_DIR, fname)
        if os.path.exists(p):
            os.remove(p)
    clean_election_state()  # rimuove anche le quote in data/keys/trustees/
    print("[TEARDOWN] File di stato rimossi.")


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
        response = requests.get(f"{AE_URL}/status", timeout=2, verify=ae_verify())
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
    print("=" * 80)
    print("  TEST TOKEN HOARDING & EXPIRED TOKEN EXPLOITATION")
    print("  (Use-it-or-Lose-it Policy)")
    print("=" * 80)
    try:
        setup()

        # Caricamento chiavi e dati
        with open(BULLETIN_BOARD_PATH, "r", encoding="utf-8") as f:
            bb = json.load(f)
        validate_pins(bb)
        ae_pubkey  = deserialize_public_key(bb[0]["data"]["ae_encrypt_public"])
        sa_privkey = load_private_key("sa_sign")
        election_id = bb[0]["data"]["election_id"]

        with open(VOTERS_PATH, "r", encoding="utf-8") as f:
            voters = json.load(f)
        test_voter          = voters[0]
        test_voter_password = VOTERS[0]["password"]

        print(f"\n  Elettore di test: {test_voter['username']}  (id: {test_voter['id']})")
        print(f"  Elezione:         {election_id}")

        # ------------------------------------------------------------------ #
        # TEST 1 — Token Hoarding: il SA non emette una seconda credenziale   #
        # ------------------------------------------------------------------ #
        print("\n" + "-" * 80)
        print("TEST 1 — Token Hoarding (il SA non può rilasciare due token distinti)")
        print("-" * 80)

        print("\n  Prima autenticazione...")
        r1 = requests.post(f"{SA_URL}/authenticate",
                           json={"username": test_voter["username"],
                                 "password": test_voter_password},
                           verify=sa_verify())
        assert r1.status_code == 200, "Prima autenticazione fallita!"
        token1     = r1.json()["token"]
        signature1 = r1.json()["signature"]
        token1_obj = json.loads(token1)

        print(f"  HTTP {r1.status_code} — token ricevuto:")
        print(f"    nonce:      {token1_obj['nonce']}")
        print(f"    issued_at:  {token1_obj['issued_at']}")
        print(f"    expires_at: {token1_obj['expires_at']}")
        print(f"  Firma SA (prime 48 hex): {signature1[:48]}...")

        print("\n  Seconda autenticazione con le stesse credenziali...")
        r2 = requests.post(f"{SA_URL}/authenticate",
                           json={"username": test_voter["username"],
                                 "password": test_voter_password},
                           verify=sa_verify())
        assert r2.status_code == 200, "Seconda autenticazione fallita!"
        token2     = r2.json()["token"]
        token2_obj = json.loads(token2)

        print(f"  HTTP {r2.status_code} — token ricevuto:")
        print(f"    nonce:      {token2_obj['nonce']}")
        print(f"    issued_at:  {token2_obj['issued_at']}")
        print(f"    expires_at: {token2_obj['expires_at']}")

        tokens_identical = (token1 == token2)
        print(f"\n  Nonce token 1:  {token1_obj['nonce']}")
        print(f"  Nonce token 2:  {token2_obj['nonce']}")
        print(f"  Token identici: {'✓ sì — stesso nonce, stessa finestra temporale' if tokens_identical else '✗ no — SA ha emesso una nuova credenziale!'}")

        assert tokens_identical, "SA ha emesso due token distinti!"
        print("\n  [PASS] TEST 1: il SA restituisce sempre lo stesso token.")
        print("  Un attaccante non può accumulare più credenziali di voto.")

        # ------------------------------------------------------------------ #
        # TEST 2 — Token scaduto con firma valida                             #
        # ------------------------------------------------------------------ #
        print("\n" + "-" * 80)
        print("TEST 2 — Token scaduto (firma RSA-PSS valida, expires_at nel passato)")
        print("-" * 80)

        expired_nonce = os.urandom(16).hex()
        issued_at_exp  = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
        expires_at_exp = (datetime.now(UTC) - timedelta(minutes=31)).isoformat()

        expired_token_obj = {
            "election_id": election_id,
            "nonce":       expired_nonce,
            "issued_at":   issued_at_exp,
            "expires_at":  expires_at_exp,
        }
        expired_token_str = json.dumps(expired_token_obj, sort_keys=True)
        expired_sig       = sign(sa_privkey, expired_token_str.encode()).hex()

        print(f"\n  Token costruito dall'attaccante:")
        print(f"    nonce:      {expired_nonce}")
        print(f"    issued_at:  {issued_at_exp}  (1 ora fa)")
        print(f"    expires_at: {expires_at_exp}  (scaduto 31 minuti fa)")
        print(f"  Firma SA sul token scaduto (prime 48 hex): {expired_sig[:48]}...")
        print(f"  (La firma è crittograficamente valida — è firmata con la chiave SA reale)")

        expired_payload = create_vote_payload(expired_token_str, expired_sig, ae_pubkey)
        print(f"\n  Invio voto con token scaduto all'AE...")
        expired_resp = requests.post(f"{AE_URL}/vote", json=expired_payload, verify=ae_verify())

        print(f"\n  Risposta AE — HTTP {expired_resp.status_code}:")
        print(f"  {json.dumps(expired_resp.json(), indent=4, ensure_ascii=False)}")

        assert expired_resp.status_code == 401, "AE non ha bloccato il token scaduto!"
        assert "Token scaduto" in expired_resp.json().get("error", "")
        print("\n  [PASS] TEST 2: l'AE ha rifiutato il token nonostante la firma valida.")
        print("  La scadenza temporale è verificata indipendentemente dalla firma.")

        # ------------------------------------------------------------------ #
        # TEST 3 — Voto legittimo accettato normalmente                       #
        # ------------------------------------------------------------------ #
        print("\n" + "-" * 80)
        print("TEST 3 — Voto legittimo con token valido")
        print("-" * 80)

        print(f"\n  Token valido (nonce: {token1_obj['nonce']})")
        print(f"  expires_at: {token1_obj['expires_at']}")
        valid_payload = create_vote_payload(token1, signature1, ae_pubkey)
        print(f"  enc_vote (prime 60 hex): {valid_payload['enc_vote'][:60]}...")
        print(f"  pow_nonce: {valid_payload['pow_nonce']}")
        print(f"\n  Invio voto all'AE...")
        valid_resp = requests.post(f"{AE_URL}/vote", json=valid_payload, verify=ae_verify())

        print(f"\n  Risposta AE — HTTP {valid_resp.status_code}:")
        print(f"  {json.dumps(valid_resp.json(), indent=4, ensure_ascii=False)}")

        assert valid_resp.status_code == 200, "Voto valido rifiutato!"
        receipt = valid_resp.json()
        print(f"\n  Ricevuta:")
        print(f"    leaf_index:   {receipt.get('leaf_index')}")
        print(f"    merkle_proof: {len(receipt.get('merkle_proof', []))} nodi")
        print(f"    ae_signature (prime 48 hex): {receipt.get('ae_signature', '')[:48]}...")
        print("\n  [PASS] TEST 3: voto legittimo accettato e ricevuta firmata dall'AE.")

        # ------------------------------------------------------------------ #
        # TEST 4 — Rinnovo del token scaduto con lo STESSO nonce              #
        # ------------------------------------------------------------------ #
        print("\n" + "-" * 80)
        print("TEST 4 — Token scaduto senza aver votato: rinnovo con lo stesso nonce")
        print("-" * 80)
        late_voter = VOTERS[2]
        print(f"  {late_voter['username']} si era autenticato 1 ora fa (token scaduto da 30 minuti, nonce {EXPIRED_VOTER_NONCE[:12]}...)")
        r_renew = requests.post(f"{SA_URL}/authenticate",
                                json={"username": late_voter["username"], "password": late_voter["password"]},
                                verify=sa_verify())
        renewed_token = r_renew.json()["token"]
        renewed_obj = json.loads(renewed_token)
        same_nonce = renewed_obj["nonce"] == EXPIRED_VOTER_NONCE
        not_expired = datetime.fromisoformat(renewed_obj["expires_at"]) > datetime.now(UTC)
        print(f"  Token restituito: nonce {renewed_obj['nonce'][:12]}... (stesso: {same_nonce}), "
              f"scadenza {renewed_obj['expires_at']} (valido: {not_expired})")
        r_first = requests.post(f"{AE_URL}/vote", json=create_vote_payload(renewed_token, r_renew.json()["signature"], ae_pubkey),
                                verify=ae_verify())
        print(f"  Voto con il token rinnovato:                    HTTP {r_first.status_code}")
        r_again = requests.post(f"{SA_URL}/authenticate",
                                json={"username": late_voter["username"], "password": late_voter["password"]},
                                verify=sa_verify())
        r_second = requests.post(f"{AE_URL}/vote", json=create_vote_payload(r_again.json()["token"], r_again.json()["signature"], ae_pubkey),
                                 verify=ae_verify())
        print(f"  Secondo voto dopo una nuova autenticazione:      HTTP {r_second.status_code} — {r_second.json().get('error')}")
        test4_pass = same_nonce and not_expired and r_first.status_code == 200 and r_second.status_code == 409
        print(f"\n  {'[PASS]' if test4_pass else '[FAIL]'} TEST 4: l'elettore ritardatario può votare una sola volta.")

        # ------------------------------------------------------------------ #
        # Riepilogo                                                           #
        # ------------------------------------------------------------------ #
        print("\n" + "=" * 80)
        print("RIEPILOGO")
        print("=" * 80)
        print(f"  TEST 1 — Token Hoarding:     [PASS]  stesso nonce ({token1_obj['nonce'][:16]}...)")
        print(f"  TEST 2 — Token scaduto:      [PASS]  HTTP 401 — {expired_resp.json().get('error')}")
        print(f"  TEST 3 — Voto legittimo:     [PASS]  HTTP 200 — leaf_index {receipt.get('leaf_index')}")
        print(f"  TEST 4 — Rinnovo token:      [{'PASS' if test4_pass else 'FAIL'}]  stesso nonce, "
              f"voto {r_first.status_code}, secondo voto {r_second.status_code}")
        print("\n  La politica use-it-or-lose-it è rispettata:")
        print("  · un elettore ottiene al massimo un token per elezione;")
        print("  · il token ha una finestra temporale di 30 minuti;")
        print("  · fuori finestra, anche una firma valida viene rifiutata.")
        print("=" * 80)

        save_report(
            test_id="token_hoarding",
            test_name="Token Hoarding & Expired Token Exploitation (Use-it-or-Lose-it Policy)",
            # I test 1-3 interrompono l'esecuzione con assert se falliscono.
            outcome="PASS" if test4_pass else "FAIL",
            details={
                "voter": test_voter["username"],
                "test1_hoarding": {
                    "token1_nonce":      token1_obj["nonce"],
                    "token2_nonce":      token2_obj["nonce"],
                    "tokens_identical":  tokens_identical,
                    "passed":            True,
                },
                "test2_expired_token": {
                    "expired_nonce":     expired_nonce,
                    "issued_at":         issued_at_exp,
                    "expires_at":        expires_at_exp,
                    "signature_valid":   True,
                    "http_status":       expired_resp.status_code,
                    "error_message":     expired_resp.json().get("error"),
                    "passed":            expired_resp.status_code == 401,
                },
                "test3_valid_vote": {
                    "token_nonce":       token1_obj["nonce"],
                    "http_status":       valid_resp.status_code,
                    "leaf_index":        receipt.get("leaf_index"),
                    "merkle_proof_nodes": len(receipt.get("merkle_proof", [])),
                    "passed":            valid_resp.status_code == 200,
                },
                "test4_expired_token_renewal": {
                    "same_nonce":            same_nonce,
                    "renewed_not_expired":   not_expired,
                    "vote_http_status":      r_first.status_code,
                    "second_vote_http_status": r_second.status_code,
                    "passed":                test4_pass,
                },
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

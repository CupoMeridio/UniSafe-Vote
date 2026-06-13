
"""
Test per Token Hoarding & Expired Token Exploitation (Use-it-or-Lose-it Policy)
"""

import os
import sys
import json
import time
import hashlib
import requests
import subprocess
from datetime import datetime, timedelta, UTC

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto.keys import load_public_key, load_private_key, deserialize_public_key
from crypto.rsa_oaep import encrypt
from crypto.rsa_pss import sign, verify
from client import compute_public_key_fingerprint


def validate_pins(bulletin_board):
    """Verifica che le chiavi AE del Bulletin Board corrispondano ai pin trusted."""
    with open("data/pins.json", "r", encoding="utf-8") as f:
        pins = json.load(f)

    init_data = bulletin_board[0]["data"]

    def normalize_pin(pin_value):
        return pin_value[7:] if pin_value.startswith("sha256:") else pin_value

    assert normalize_pin(pins["ae_encrypt_public"]) == compute_public_key_fingerprint(init_data["ae_encrypt_public"])
    assert normalize_pin(pins["ae_sign_public"]) == compute_public_key_fingerprint(init_data["ae_sign_public"])
    print("    Pin trusted AE verificati con successo!")


SA_URL = "http://localhost:5001"
AE_URL = "http://localhost:5002"
BULLETIN_BOARD_PATH = "data/bulletin_board.json"
VOTERS_PATH = "data/voters.json"

sa_process = None
ae_process = None


def solve_pow(enc_vote_hex: str, difficulty: int = 4) -> str:
    """Risolvi la Proof of Work per un voto cifrato"""
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


def get_pow_difficulty() -> int:
    """Ottieni la difficoltà PoW corrente dall'AE"""
    try:
        response = requests.get(f"{AE_URL}/status", timeout=2)
        if response.status_code == 200:
            return int(response.json().get("pow_difficulty", 4))
    except Exception:
        pass
    return 4


def create_vote_payload(token: str, token_signature: str, ae_pubkey) -> dict:
    """Crea un payload di voto completo con PoW valido"""
    seed = os.urandom(32)
    vote_byte = b"\x00"
    enc_vote_bytes = encrypt(ae_pubkey, vote_byte, seed=seed)
    enc_seed_bytes = encrypt(ae_pubkey, seed)
    enc_vote_hex = enc_vote_bytes.hex()
    enc_seed_hex = enc_seed_bytes.hex()

    difficulty = get_pow_difficulty()
    pow_nonce = solve_pow(enc_vote_hex, difficulty)

    return {
        "enc_vote": enc_vote_hex,
        "enc_seed": enc_seed_hex,
        "token": token,
        "token_signature": token_signature,
        "pow_nonce": pow_nonce
    }


def start_server(script_name: str, port: int) -> subprocess.Popen:
    """Avvia un server come sottoprocesso e attende che sia pronto"""
    python_exe = sys.executable
    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), script_name)
    proc = subprocess.Popen([python_exe, script_path],
                            creationflags=subprocess.CREATE_NEW_CONSOLE if os.name == "nt" else 0)

    # Attendi che il server sia pronto (polling /status endpoint)
    url = f"http://localhost:{port}/status"
    for _ in range(30):
        try:
            resp = requests.get(url, timeout=1)
            if resp.status_code == 200:
                time.sleep(1)
                return proc
        except Exception:
            pass
        time.sleep(1)
    raise Exception(f"Server {script_name} non si è avviato in tempo!")


def stop_server(proc: subprocess.Popen):
    """Ferma un processo server"""
    if proc:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            proc.kill()


def main():
    global sa_process, ae_process
    try:
        print("=" * 80)
        print("TEST TOKEN HOARDING & EXPIRED TOKEN EXPLOITATION")
        print("(Use-it-or-Lose-it Policy)")
        print("=" * 80)

        print("\n[1] Re-inizializzazione dell'elezione per il test pulito...")
        # Reinizializza l'elezione per cominciare pulito
        from init_election_non_interactive import main as init_election
        init_election()
        print("    Elezione reinizializzata con successo!")

        print("\n[2] Avvio server SA e AE...")
        sa_process = start_server("sa.py", 5001)
        ae_process = start_server("ae.py", 5002)
        print("    Server avviati con successo!")

        print("\n[3] Caricamento chiavi...")
        with open(BULLETIN_BOARD_PATH, "r", encoding="utf-8") as f:
            bb = json.load(f)
        validate_pins(bb)
        ae_pubkey = deserialize_public_key(bb[0]["data"]["ae_encrypt_public"])
        sa_privkey = load_private_key("sa_sign")
        print("    Chiavi caricate!")

        with open(VOTERS_PATH, "r", encoding="utf-8") as f:
            voters = json.load(f)
        test_voter = voters[0]
        print(f"\n[4] Utilizzando l'elettore di test: {test_voter['username']}")

        print("\n[5] Autenticazione al SA per ottenere token valido...")
        auth_response1 = requests.post(
            f"{SA_URL}/authenticate",
            json={"username": test_voter["username"], "password": test_voter["password"]}
        )
        assert auth_response1.status_code == 200, "Prima autenticazione fallita!"
        auth_data1 = auth_response1.json()
        token1 = auth_data1["token"]
        signature1 = auth_data1["signature"]
        print(f"    Token 1 ricevuto!")

        print("\n[6] TEST 1: Tentativo di RI-AUTENTICARSI al SA per ottenere nuovo token...")
        auth_response2 = requests.post(
            f"{SA_URL}/authenticate",
            json={"username": test_voter["username"], "password": test_voter["password"]}
        )
        assert auth_response2.status_code == 200, "Seconda autenticazione fallita!"
        auth_data2 = auth_response2.json()
        token2 = auth_data2["token"]

        print(f"    Token 1: {token1[:80]}...")
        print(f"    Token 2: {token2[:80]}...")

        assert token1 == token2, "SA ha emesso due token distinti!"
        print("\n    [OK] TEST 1 PASS: SA restituisce sempre LO STESSO token (nessun token nuovo)")

        print("\n[7] TEST 2: Creazione token SCADUTO (firma valida) e invio ad AE...")
        # Creiamo un token con expires_at nel passato, ma firma valida
        election_id = bb[0]["data"]["election_id"]
        expired_token_obj = {
            "election_id": election_id,
            "nonce": os.urandom(16).hex(),
            "issued_at": (datetime.now(UTC) - timedelta(hours=1)).isoformat(),
            "expires_at": (datetime.now(UTC) - timedelta(minutes=31)).isoformat(),
        }
        expired_token_str = json.dumps(expired_token_obj, sort_keys=True)
        expired_signature = sign(sa_privkey, expired_token_str.encode("utf-8")).hex()

        expired_payload = create_vote_payload(expired_token_str, expired_signature, ae_pubkey)
        expired_response = requests.post(f"{AE_URL}/vote", json=expired_payload)

        print(f"    Risposta AE: {expired_response.status_code}")
        print(f"    Contenuto: {json.dumps(expired_response.json(), indent=2, ensure_ascii=False)}")

        assert expired_response.status_code == 401, "AE non ha bloccato token scaduto!"
        assert "Token scaduto" in expired_response.json().get("error", ""), "Messaggio non corretto!"
        print("\n    [OK] TEST 2 PASS: AE blocca token scaduto con firma valida!")

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
    finally:
        # Assicurati di fermare i server anche in caso di errore
        stop_server(sa_process)
        stop_server(ae_process)
        print("\nServer fermati.")


if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    main()


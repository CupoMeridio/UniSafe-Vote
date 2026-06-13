
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
import requests
from datetime import datetime, timedelta, UTC

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto.keys import load_private_key, load_public_key, deserialize_public_key
from crypto.rsa_oaep import encrypt
from crypto.rsa_pss import sign


# Configurazione
AE_URL = "http://localhost:5002"
SA_URL = "http://localhost:5001"
BULLETIN_BOARD_PATH = "data/bulletin_board.json"


def load_bulletin_board():
    """Carica il Bulletin Board per ottenere chiavi pubbliche e parametri."""
    with open(BULLETIN_BOARD_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def solve_pow(enc_vote_hex: str, difficulty: int = 4) -> str:
    """Risolvi la Proof of Work per un voto cifrato."""
    enc_vote_bytes = bytes.fromhex(enc_vote_hex)
    nonce = 0

    while True:
        nonce_bytes = nonce.to_bytes(8, byteorder='big')
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


def get_pow_difficulty():
    """Ottieni la difficoltà PoW corrente dall'AE."""
    try:
        response = requests.get(f"{AE_URL}/status", timeout=5)
        if response.status_code == 200:
            return int(response.json().get("pow_difficulty", 4))
    except requests.exceptions.RequestException:
        pass
    return 4


def get_valid_token():
    """
    Ottieni un token valido in uno dei due modi:
    1. Se il SA è in esecuzione, autenticati con un utente di test
    2. Altrimenti, crea un token dummy usando le chiavi del SA (se disponibili)
    """
    # Prima prova: autenticati con il SA
    try:
        # Prima carica i voters per vedere se c'è un utente di test
        with open("data/voters.json", "r", encoding="utf-8") as f:
            voters = json.load(f)
        
        if voters:
            test_voter = voters[0]
            print(f"[INFO] Trovato utente di test: {test_voter['username']}")
            response = requests.post(
                f"{SA_URL}/authenticate",
                json={"username": test_voter["username"], "password": test_voter["password"]},
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                print("[SUCCESS] Token ottenuto con successo dal SA!")
                return data["token"], data["signature"]
    except Exception as e:
        print(f"[WARNING] Impossibile ottenere token dal SA: {e}")

    # Seconda opzione: crea un token dummy usando le chiavi del SA
    try:
        print("[INFO] Creazione token dummy con chiavi del SA...")
        bb = load_bulletin_board()
        election_id = bb[0]["data"]["election_id"]
        sa_private = load_private_key("sa_sign")
        
        # Crea token
        nonce = os.urandom(16).hex()
        issued_at = datetime.now(UTC).isoformat()
        expires_at = (datetime.now(UTC) + timedelta(minutes=30)).isoformat()
        token_dict = {
            "election_id": election_id,
            "nonce": nonce,
            "issued_at": issued_at,
            "expires_at": expires_at
        }
        token_str = json.dumps(token_dict, sort_keys=True)
        
        # Firma token
        signature = sign(sa_private, token_str.encode('utf-8'))
        print("[SUCCESS] Token dummy creato con successo!")
        return token_str, signature.hex()
    except Exception as e:
        print(f"[ERROR] Impossibile creare token: {e}")
        sys.exit(1)


def create_vote_payload(token: str, token_signature: str, candidate_index: int = 0):
    """Crea un payload di voto completo."""
    bb = load_bulletin_board()
    ae_encrypt_public = deserialize_public_key(bb[0]["data"]["ae_encrypt_public"])
    
    # Crea voto e seed
    seed = os.urandom(32)
    vote_byte = candidate_index.to_bytes(1, byteorder='big')
    
    # Cifra
    enc_vote_bytes = encrypt(ae_encrypt_public, vote_byte, seed=seed)
    enc_seed_bytes = encrypt(ae_encrypt_public, seed)
    enc_vote_hex = enc_vote_bytes.hex()
    enc_seed_hex = enc_seed_bytes.hex()
    
    # Risolvi PoW
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
    """Invia un voto all'AE e stampa la risposta."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
    print(f"\n{'='*60}")
    print(f"[INVIO VOTO {vote_number}] - {timestamp}")
    print(f"{'='*60}")
    print(f"Payload: {json.dumps(payload, indent=2, ensure_ascii=False)}")
    
    try:
        response = requests.post(
            f"{AE_URL}/vote",
            json=payload,
            timeout=10
        )
        print(f"\nRisposta AE:")
        print(f"  Status Code: {response.status_code}")
        print(f"  Contenuto: {json.dumps(response.json(), indent=2, ensure_ascii=False)}")
        return response
    except requests.exceptions.RequestException as e:
        print(f"\n[ERRORE] Impossibile connettersi all'AE: {e}")
        sys.exit(1)


def main():
    print("\n" + "="*60)
    print("SIMULAZIONE ATTACCO DOUBLE VOTING / TOKEN REPLAY")
    print("="*60)
    
    # Verifica che l'elezione sia inizializzata
    if not os.path.exists(BULLETIN_BOARD_PATH):
        print("[ERRORE] Elezione non inizializzata! Esegui 'python init_election.py' prima.")
        sys.exit(1)
    
    # Verifica che AE sia in esecuzione
    try:
        requests.get(f"{AE_URL}/status", timeout=2)
    except requests.exceptions.RequestException:
        print("[ERRORE] Autorità Elettorale (AE) non in esecuzione! Avviala prima.")
        sys.exit(1)
    
    # Ottieni token valido
    token, token_signature = get_valid_token()
    
    # 1. Primo voto (valido)
    payload1 = create_vote_payload(token, token_signature, candidate_index=0)
    response1 = send_vote(payload1, 1)
    
    # 2. Secondo voto con lo stesso token ma candidato diverso
    print("\n" + "="*60)
    print("ATTACCO: INVIO SECONDO VOTO CON LO STESSO TOKEN!")
    print("="*60)
    payload2 = create_vote_payload(token, token_signature, candidate_index=1)
    response2 = send_vote(payload2, 2)
    
    # Verifica risultato
    print("\n" + "="*60)
    print("RISULTATO DELL'ATTACCO")
    print("="*60)
    if response1.status_code == 200 and response2.status_code == 409:
        print("[SUCCESS] Il sistema è protetto!")
        print("  - Primo voto: ACCETTATO (status 200)")
        print("  - Secondo voto: RIFIUTATO (status 409, 'Token già usato')")
    else:
        print("[FALLIMENTO] Il sistema NON è protetto correttamente!")
    
    print("\n" + "="*60)


if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    main()


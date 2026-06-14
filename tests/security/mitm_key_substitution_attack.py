"""
Test script for Man-in-the-Middle Key Substitution Attack.

Verifica che il certificate pinning del client rilevi correttamente
la sostituzione delle chiavi pubbliche dell'AE nel Bulletin Board.
"""

import os
import sys
import json
import hashlib

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
                          deserialize_public_key, save_encrypted_private_key)
from crypto.rsa_pss import sign
from crypto.password import hash_password
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta, UTC


# ---------------------------------------------------------------------------
# compute_public_key_fingerprint inline (evita import da client)
# ---------------------------------------------------------------------------

def compute_public_key_fingerprint(pem_str: str) -> str:
    """Calcola l'impronta SHA-256 DER di una chiave pubblica RSA."""
    # Si converte la chiave PEM in formato DER e se ne calcola l'hash SHA-256,
    # ottenendo l'impronta usata per il certificate pinning (WP3 §3.4).
    pubkey = deserialize_public_key(pem_str)
    pubkey_bytes = pubkey.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(pubkey_bytes).hexdigest()


# ---------------------------------------------------------------------------
# Logica di inizializzazione inline (path assoluti, nessun import con cwd sbagliato)
# ---------------------------------------------------------------------------

VOTERS = [
    {"id": "v001", "email": "mario.rossi@studenti.unisa.it",
     "username": "mario.rossi",   "password": "password123"},
    {"id": "v002", "email": "luigi.bianchi@unisa.it",
     "username": "luigi.bianchi", "password": "password456"},
]
CANDIDATES = ["Lista A", "Lista B", "Lista C"]

BULLETIN_BOARD_PATH = os.path.join(DATA_DIR, "bulletin_board.json")


def init_election():
    """
    Inizializza l'elezione: genera chiavi, scrive tutti i file di configurazione.
    Usa path assoluti — funziona da qualsiasi directory corrente.
    """
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

    # Si compone il blocco di inizializzazione con i parametri pubblici
    # dell'elezione e le chiavi pubbliche dei componenti, poi lo si firma.
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
        json.dump(bb, f, indent=2, ensure_ascii=False)

    # Si calcolano le impronte SHA-256 delle chiavi pubbliche AE e si salvano
    # in pins.json, simulando il canale di distribuzione trusted separato
    # dal Bulletin Board (certificate pinning, WP3 §3.4).
    pins = {
        "ae_encrypt_public": "sha256:" + compute_public_key_fingerprint(init_data["ae_encrypt_public"]),
        "ae_sign_public":    "sha256:" + compute_public_key_fingerprint(init_data["ae_sign_public"]),
    }
    with open(os.path.join(DATA_DIR, "pins.json"), "w", encoding="utf-8") as f:
        json.dump(pins, f, indent=2, ensure_ascii=False)

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
        json.dump(voters_data, f, indent=2, ensure_ascii=False)

    # Si inizializza lo stato privato dell'AE con la lista dei token usati vuota.
    with open(os.path.join(DATA_DIR, "ae_state.json"), "w", encoding="utf-8") as f:
        json.dump({"used_tokens": []}, f, indent=2, ensure_ascii=False)

    print("Elezioni inizializzate con successo!")


# ---------------------------------------------------------------------------
# Import Client dopo sys.path.insert — funziona da qualsiasi directory
# ---------------------------------------------------------------------------
# Si importa Client da src/client.py dopo aver aggiunto SRC_DIR al path.
# L'import avviene qui (e non in cima al file) perché dipende da sys.path.insert.
from client import Client, SecurityError


def main():
    # Si imposta la directory corrente alla root del progetto affinché
    # Client() trovi correttamente i file in data/ e data/pins.json.
    os.chdir(PROJECT_ROOT)

    print("=" * 80)
    print("TEST: Man-in-the-Middle Key Substitution Attack")
    print("=" * 80)

    # PASSO 1: Si inizializza una nuova elezione con chiavi fresche.
    # Questo garantisce che pins.json contenga le impronte delle chiavi
    # legittime appena generate.
    print("\n[1] Initialize a new election to set up baseline")
    init_election()

    # PASSO 2: Si istanzia il client e si verifica che il caricamento del
    # Bulletin Board avvenga correttamente con le chiavi legittime.
    # Il client legge pins.json e confronta le impronte con quelle nel BB.
    print("\n[2] Baseline client setup: load keys and validate trusted pins")
    client = Client()
    print(f"Trusted pin for AE encrypt key: {client.trusted_pins['ae_encrypt_public']}")
    print(f"Trusted pin for AE sign key: {client.trusted_pins['ae_sign_public']}")

    # PASSO 3: L'attaccante genera una coppia di chiavi RSA contraffatte,
    # che userà per sostituire le chiavi pubbliche legittime dell'AE nel BB.
    # Con queste chiavi false, l'attaccante potrebbe decifrare i voti.
    print("\n[3] Attacker step 1: generate malicious RSA key pair (fake AE keys)")
    fake_ae_encrypt_priv, fake_ae_encrypt_pub = generate_rsa_keypair()
    fake_ae_sign_priv, fake_ae_sign_pub = generate_rsa_keypair()
    fake_ae_encrypt_pem = serialize_public_key(fake_ae_encrypt_pub)
    fake_ae_sign_pem = serialize_public_key(fake_ae_sign_pub)
    print("Attacker generated fake AE keys!")

    # PASSO 4: L'attaccante intercetta il Bulletin Board e sostituisce
    # le chiavi pubbliche legittime dell'AE con quelle contraffatte.
    # In uno scenario reale questo avverrebbe tramite un attacco MitM
    # sulla rete o una compromissione del server che distribuisce il BB.
    print("\n[4] Simulate MitM intercepting Bulletin Board: replace AE public keys")
    with open(BULLETIN_BOARD_PATH, "r", encoding="utf-8") as f:
        tampered_bb = json.load(f)

    # Si sostituiscono le chiavi nel blocco init del Bulletin Board.
    tampered_bb[0]["data"]["ae_encrypt_public"] = fake_ae_encrypt_pem
    tampered_bb[0]["data"]["ae_sign_public"] = fake_ae_sign_pem

    with open(BULLETIN_BOARD_PATH, "w", encoding="utf-8") as f:
        json.dump(tampered_bb, f, indent=2, ensure_ascii=False)
    print("Tampered Bulletin Board saved (fake AE keys injected)!")

    # PASSO 5: Si verifica che il client rilevi la sostituzione delle chiavi.
    # Quando il client carica il BB manomesso, deve confrontare le impronte
    # delle chiavi ricevute con quelle in pins.json: le chiavi contraffatte
    # non corrispondono ai pin trusted, quindi deve sollevare SecurityError.
    print("\n[5] Client loads bulletin board (now tampered!)")
    try:
        client.load_bulletin_board()
        # Se il client accetta le chiavi false, il test è fallito.
        print("ERROR: Client accepted tampered keys! That's BAD!")
        sys.exit(1)
    except SecurityError as e:
        # Il client ha correttamente rilevato la discrepanza e ha bloccato
        # l'operazione prima di usare le chiavi contraffatte.
        print("SUCCESS: Client raised SecurityError!")
        print(f"Error message: {str(e)}")
        print("\nThis means the Certificate Pinning worked!")
        print("The client detected key substitution and stopped before proceeding!")

    # PASSO 6: Si ripristina il Bulletin Board con chiavi legittime
    # per lasciare lo stato del sistema pulito dopo il test.
    print("\n[6] Cleanup: restore original bulletin board")
    init_election()

    print("\n" + "=" * 80)
    print("[SUCCESS] MitM Key Substitution Attack test PASSED!")
    print("[SUCCESS] Certificate Pinning successfully blocked the attack!")
    print("=" * 80)

    save_report(
        test_id="mitm_key_substitution",
        test_name="Attacco MitM / Sostituzione Chiave Pubblica (Certificate Pinning)",
        outcome="PASS",
        details={
            "steps": [
                "Elezione inizializzata con chiavi legittime",
                "Client carica BB con chiavi legittime: OK",
                "Attaccante sostituisce chiavi AE nel BB con chiavi false",
                "Client rileva discrepanza con pins.json e solleva SecurityError",
                "BB ripristinato con chiavi legittime",
            ],
            "security_mechanism": "Certificate Pinning (SHA-256 DER fingerprint)",
            "error_raised": "SecurityError",
        },
    )


if __name__ == "__main__":
    os.chdir(PROJECT_ROOT)
    try:
        main()
    except Exception as e:
        print(f"\n[ERRORE] {e}")
    finally:
        input("\nPremi Invio per chiudere...")

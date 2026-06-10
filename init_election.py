
#!/usr/bin/env python3
import os
import json
import hashlib
from datetime import datetime, timedelta
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto.keys import generate_rsa_keypair, save_keypair, serialize_public_key
from crypto.rsa_pss import sign


def main():
    print("=== FASE 1: INIZIALIZZAZIONE ELEZIONE ===")

    # 1. Genera tre coppie di chiavi RSA-2048
    print("\nGenerazione chiavi RSA...")
    sa_sign_private, sa_sign_public = generate_rsa_keypair()
    ae_encrypt_private, ae_encrypt_public = generate_rsa_keypair()
    ae_sign_private, ae_sign_public = generate_rsa_keypair()

    # Salva le chiavi in data/keys/
    save_keypair(sa_sign_private, sa_sign_public, "sa_sign")
    save_keypair(ae_encrypt_private, ae_encrypt_public, "ae_encrypt")
    save_keypair(ae_sign_private, ae_sign_public, "ae_sign")
    print("  ✓ Chiavi salvate in data/keys/")

    # 2. Prepara il blocco init per il Bulletin Board
    election_id = "elezione_universitaria_2026"
    candidates = ["Lista A", "Lista B", "Lista C"]
    opening_time = datetime.utcnow().isoformat()
    closing_time = (datetime.utcnow() + timedelta(hours=24)).isoformat()

    init_data = {
        "election_id": election_id,
        "candidates": candidates,
        "opening_time": opening_time,
        "closing_time": closing_time,
        "sa_sign_public": serialize_public_key(sa_sign_public),
        "ae_encrypt_public": serialize_public_key(ae_encrypt_public),
        "ae_sign_public": serialize_public_key(ae_sign_public)
    }

    # Firma il blocco init con ae_sign_private
    init_data_json = json.dumps(init_data, sort_keys=True).encode('utf-8')
    init_signature = sign(ae_sign_private, init_data_json)

    bulletin_block = {
        "type": "init",
        "timestamp": datetime.utcnow().isoformat(),
        "data": init_data,
        "signature": init_signature.hex()
    }

    # Crea il Bulletin Board
    bulletin_board = [bulletin_block]
    with open("data/bulletin_board.json", "w", encoding="utf-8") as f:
        json.dump(bulletin_board, f, indent=2, ensure_ascii=False)
    print("  ✓ Bulletin Board inizializzato in data/bulletin_board.json")

    # 3. Crea voters.json con 5 elettori fittizi
    voters = [
        {"id": "v001", "username": "mario.rossi", "password": "password123"},
        {"id": "v002", "username": "luigi.bianchi", "password": "password456"},
        {"id": "v003", "username": "giulia.verdi", "password": "password789"},
        {"id": "v004", "username": "francesca.neri", "password": "password012"},
        {"id": "v005", "username": "paolo.gialli", "password": "password345"}
    ]

    with open("data/voters.json", "w", encoding="utf-8") as f:
        json.dump(voters, f, indent=2, ensure_ascii=False)
    print("  ✓ Lista elettori creata in data/voters.json")

    print("\n✅ Inizializzazione completata con successo!")


if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    main()

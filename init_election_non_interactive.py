
#!/usr/bin/env python3
"""
Script di inizializzazione non-interattivo di un'elezione per testing.
"""
import os
import json
from datetime import datetime, timedelta, UTC
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto.keys import generate_rsa_keypair, save_keypair, serialize_public_key
from crypto.rsa_pss import sign


def get_preconfigured_voters():
    return [
        {"id": "v001", "email": "mario.rossi@studenti.unisa.it", "username": "mario.rossi", "password": "password123"},
        {"id": "v002", "email": "luigi.bianchi@unisa.it", "username": "luigi.bianchi", "password": "password456"}
    ]


def get_preconfigured_candidates():
    return ["Lista A", "Lista B", "Lista C"]


def main():
    # 1. Genera chiavi
    sa_sign_private, sa_sign_public = generate_rsa_keypair()
    ae_encrypt_private, ae_encrypt_public = generate_rsa_keypair()
    ae_sign_private, ae_sign_public = generate_rsa_keypair()
    save_keypair(sa_sign_private, sa_sign_public, "sa_sign")
    save_keypair(ae_encrypt_private, ae_encrypt_public, "ae_encrypt")
    save_keypair(ae_sign_private, ae_sign_public, "ae_sign")

    # 2. Configura elezione
    election_id = "elezione_test_double_voting"
    candidates = get_preconfigured_candidates()
    voters = get_preconfigured_voters()
    opening_time = datetime.now(UTC).isoformat()
    closing_time = (datetime.now(UTC) + timedelta(hours=24)).isoformat()

    init_data = {
        "election_id": election_id,
        "candidates": candidates,
        "opening_time": opening_time,
        "closing_time": closing_time,
        "sa_sign_public": serialize_public_key(sa_sign_public),
        "ae_encrypt_public": serialize_public_key(ae_encrypt_public),
        "ae_sign_public": serialize_public_key(ae_sign_public)
    }

    init_data_json = json.dumps(init_data, sort_keys=True).encode('utf-8')
    init_signature = sign(ae_sign_private, init_data_json)

    bulletin_block = {
        "type": "init",
        "timestamp": datetime.now(UTC).isoformat(),
        "data": init_data,
        "signature": init_signature.hex()
    }

    bulletin_board = [bulletin_block]
    with open("data/bulletin_board.json", "w", encoding="utf-8") as f:
        json.dump(bulletin_board, f, indent=2, ensure_ascii=False)

    with open("data/voters.json", "w", encoding="utf-8") as f:
        json.dump(voters, f, indent=2, ensure_ascii=False)
    
    with open("data/ae_state.json", "w", encoding="utf-8") as f:
        json.dump({"used_tokens": []}, f, indent=2, ensure_ascii=False)

    print("Elezioni inizializzate con successo!")


if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    main()


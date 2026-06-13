
#!/usr/bin/env python3
"""
Script di inizializzazione non-interattivo di un'elezione per testing.
"""
import os
import json
import hashlib
from datetime import datetime, timedelta, UTC
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cryptography.hazmat.primitives import serialization
from crypto.keys import generate_rsa_keypair, save_keypair, serialize_public_key, deserialize_public_key, save_encrypted_private_key
from crypto.rsa_pss import sign
from crypto.password import hash_password


def compute_public_key_fingerprint(pem_str: str) -> str:
    """Calcola l'impronta SHA-256 DER di una chiave pubblica RSA."""
    pubkey = deserialize_public_key(pem_str)
    pubkey_bytes = pubkey.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return "sha256:" + hashlib.sha256(pubkey_bytes).hexdigest()


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
    # ae_encrypt: salviamo SOLO la chiave pubblica in PEM (serve ai client per cifrare);
    # la chiave privata viene salvata cifrata con AES-GCM (IKM = firma blocco init).
    save_keypair(ae_encrypt_private, ae_encrypt_public, "ae_encrypt")  # salva entrambe per ora
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

    pins = {
        "ae_encrypt_public": compute_public_key_fingerprint(init_data["ae_encrypt_public"]),
        "ae_sign_public": compute_public_key_fingerprint(init_data["ae_sign_public"])
    }
    with open("data/pins.json", "w", encoding="utf-8") as f:
        json.dump(pins, f, indent=2, ensure_ascii=False)

    # Cifra la chiave privata di decifratura dell'AE con AES-GCM.
    # IKM = firma del blocco init: la chiave può essere decifrata solo da chi
    # possiede quella firma, ovvero l'AE stessa a urne chiuse.
    # Al /close, il nuovo IKM sarà la firma della Merkle Root finale, che include
    # i voti e può quindi esistere solo dopo la chiusura delle urne.
    # Per il salvataggio iniziale usiamo la firma del blocco init come placeholder:
    # ae.py sovrascriverà il .enc durante il /close con il nuovo IKM corretto.
    save_encrypted_private_key(ae_encrypt_private, "ae_encrypt", init_signature)

    with open("data/voters.json", "w", encoding="utf-8") as f:
        voters_to_save = []
        for v in voters:
            v_copy = v.copy()
            v_copy['password'] = hash_password(v_copy['password'])
            voters_to_save.append(v_copy)
        json.dump(voters_to_save, f, indent=2, ensure_ascii=False)
    
    with open("data/ae_state.json", "w", encoding="utf-8") as f:
        json.dump({"used_tokens": []}, f, indent=2, ensure_ascii=False)

    print("Elezioni inizializzate con successo!")


if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    main()


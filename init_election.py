
#!/usr/bin/env python3
import os
import json
import hashlib
from datetime import datetime, timedelta, UTC
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto.keys import generate_rsa_keypair, save_keypair, serialize_public_key
from crypto.rsa_pss import sign


def get_preconfigured_voters():
    """Restituisce la lista preconfigurata di elettori"""
    return [
        {"id": "v001", "email": "mario.rossi@studenti.unisa.it", "username": "mario.rossi", "password": "password123"},
        {"id": "v002", "email": "luigi.bianchi@unisa.it", "username": "luigi.bianchi", "password": "password456"},
        {"id": "v003", "email": "giulia.verdi@studenti.unisa.it", "username": "giulia.verdi", "password": "password789"},
        {"id": "v004", "email": "francesca.neri@unisa.it", "username": "francesca.neri", "password": "password012"},
        {"id": "v005", "email": "paolo.gialli@studenti.unisa.it", "username": "paolo.gialli", "password": "password345"}
    ]


def create_custom_voters():
    """Permette all'amministratore di creare una lista personalizzata di elettori"""
    print("\nCREAZIONE LISTA ELETTORI PERSONALIZZATA")
    print("-" * 40)
    voters = []
    voter_count = 0
    
    while True:
        voter_count += 1
        print(f"\nElettore {voter_count}:")
        voter_id = input(f"  ID elettore (es. v{voter_count:03d}): ") or f"v{voter_count:03d}"
        email = input("  Email UNISA (@studenti.unisa.it o @unisa.it: ")
        username = input("  Username: ")
        password = input("  Password: ")
        
        voters.append({
            "id": voter_id,
            "email": email,
            "username": username,
            "password": password
        })
        
        another = input("\nAggiungere un altro elettore? (s/n): ").lower().strip()
        if another != 's':
            break
    
    return voters


def main():
    print("FASE 1: INIZIALIZZAZIONE ELEZIONE")

    # 1. Genera tre coppie di chiavi RSA-2048
    print("\nGenerazione chiavi RSA...")
    print("  Generazione 3 coppie di chiavi RSA-2048:")
    print("   - Coppia per firma del Sistema di Autenticazione (SA)")
    print("   - Coppia per cifratura/decifratura dell'Autorita' Elettorale (AE)")
    print("   - Coppia per firma dell'Autorita' Elettorale (AE)")
    sa_sign_private, sa_sign_public = generate_rsa_keypair()
    ae_encrypt_private, ae_encrypt_public = generate_rsa_keypair()
    ae_sign_private, ae_sign_public = generate_rsa_keypair()

    # Salva le chiavi in data/keys/
    save_keypair(sa_sign_private, sa_sign_public, "sa_sign")
    save_keypair(ae_encrypt_private, ae_encrypt_public, "ae_encrypt")
    save_keypair(ae_sign_private, ae_sign_public, "ae_sign")
    print("  Chiavi salvate in data/keys/")

    # 2. Prepara il blocco init per il Bulletin Board
    election_id = "elezione_universitaria_2026"
    candidates = ["Lista A", "Lista B", "Lista C"]
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

    # Firma il blocco init con ae_sign_private
    init_data_json = json.dumps(init_data, sort_keys=True).encode('utf-8')
    init_signature = sign(ae_sign_private, init_data_json)

    bulletin_block = {
        "type": "init",
        "timestamp": datetime.now(UTC).isoformat(),
        "data": init_data,
        "signature": init_signature.hex()
    }

    # Crea il Bulletin Board
    bulletin_board = [bulletin_block]
    with open("data/bulletin_board.json", "w", encoding="utf-8") as f:
        json.dump(bulletin_board, f, indent=2, ensure_ascii=False)
    print("  Bulletin Board inizializzato in data/bulletin_board.json")

    # 3. Scelta lista elettori
    print("\nSCELTA LISTA ELETTORI")
    print("-" * 40)
    print("1. Usa lista preconfigurata (5 elettori di test)")
    print("2. Crea lista personalizzata")
    
    while True:
        choice = input("\nSeleziona un'opzione (1/2): ").strip()
        if choice == '1':
            voters = get_preconfigured_voters()
            print("\nLista preconfigurata caricata:")
            for v in voters:
                print(f"   - {v['username']} ({v['email']}) - password: {v['password']}")
            break
        elif choice == '2':
            voters = create_custom_voters()
            print(f"\nLista personalizzata creata:")
            for v in voters:
                print(f"   - ID: {v['id']}, {v['username']} ({v['email']})")
            break
        else:
            print("Opzione non valida, riprova.")
    
    # Salva la lista elettori
    with open("data/voters.json", "w", encoding="utf-8") as f:
        json.dump(voters, f, indent=2, ensure_ascii=False)
    print("\nLista elettori salvata in data/voters.json")

    print("\nInizializzazione completata con successo!")


if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    main()

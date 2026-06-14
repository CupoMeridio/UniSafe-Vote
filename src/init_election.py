
#!/usr/bin/env python3
"""
Script di inizializzazione di un'elezione.

Questo programma prepara tutti i dati necessari per avviare un'elezione:
1. Genera le coppie di chiavi RSA per il Sistema di Autenticazione (SA) e l'Autorità Elettorale (AE)
2. Crea il Bulletin Board (registro pubblico) con i parametri iniziali dell'elezione
3. Configura le liste/candidati e, se scelta, la lista degli elettori pre-registrati

Il Bulletin Board è un registro append-only che contiene:
- I parametri dell'elezione (ID, candidati, tempi)
- Le chiavi pubbliche di SA e AE
- Tutti i voti ricevuti (in forma cifrata)
- La Merkle Root per l'integrità
- I risultati finali dello scrutinio
"""
import os
import json
import hashlib
from datetime import datetime, timedelta, UTC
from typing import List, Dict
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


def get_preconfigured_voters() -> List[Dict[str, str]]:
    """Restituisce la lista preconfigurata di elettori"""
    return [
        {"id": "v001", "email": "mario.rossi@studenti.unisa.it", "username": "mario.rossi", "password": "password123"},
        {"id": "v002", "email": "luigi.bianchi@unisa.it", "username": "luigi.bianchi", "password": "password456"},
        {"id": "v003", "email": "giulia.verdi@studenti.unisa.it", "username": "giulia.verdi", "password": "password789"},
        {"id": "v004", "email": "francesca.neri@unisa.it", "username": "francesca.neri", "password": "password012"},
        {"id": "v005", "email": "paolo.gialli@studenti.unisa.it", "username": "paolo.gialli", "password": "password345"}
    ]


def get_preconfigured_candidates() -> List[str]:
    """Restituisce le liste preconfigurate per la demo."""
    return ["Lista A", "Lista B", "Lista C"]


def create_custom_candidates() -> List[str]:
    """Permette all'amministratore di configurare solo le liste tra cui votare."""
    print("\nCONFIGURAZIONE LISTE DI VOTO")
    print("-" * 40)
    print("In questa modalità non vengono pre-registrati elettori.")
    print("La registrazione avverrà successivamente tramite il SA, durante il flusso utente.")

    candidates: List[str] = []
    while len(candidates) < 2:
        print(f"\nLista {len(candidates) + 1}:")
        candidate = input("  Nome lista/candidato: ").strip()
        if not candidate:
            print("Inserisci un nome non vuoto.")
            continue
        if candidate in candidates:
            print("Questa lista è già presente.")
            continue
        candidates.append(candidate)

    while True:
        candidate = input("\nAggiungere un'altra lista? (s/n): ").strip().lower()
        if candidate == 's':
            name = input("  Nome lista/candidato: ").strip()
            if not name:
                print("Inserisci un nome non vuoto.")
                continue
            if name in candidates:
                print("Questa lista è già presente.")
                continue
            candidates.append(name)
        elif candidate == 'n':
            break
        else:
            print("Opzione non valida, riprova.")

    return candidates


def main() -> None:
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

    # 2. Scelta configurazione elezione
    print("\nSCELTA CONFIGURAZIONE ELEZIONE")
    print("-" * 40)
    print("1. Sistema preconfigurato (liste stock + utenti già registrati)")
    print("2. Solo liste di voto (registrazione utenti abilitata)")

    voters: List[Dict[str, str]] = []
    while True:
        choice = input("\nSeleziona un'opzione (1/2): ").strip()
        if choice == '1':
            election_id = "elezione_universitaria_2026_preconfigurata"
            candidates = get_preconfigured_candidates()
            voters = get_preconfigured_voters()
            print("\nConfigurazione preconfigurata caricata:")
            print(f"   Liste: {', '.join(candidates)}")
            print("   Utenti registrati:")
            for v in voters:
                print(f"   - {v['username']} ({v['email']}) - password: {v['password']}")
            break
        elif choice == '2':
            election_id = "elezione_universitaria_2026_solo_liste"
            candidates = create_custom_candidates()
            print("\nConfigurazione salvata:")
            print(f"   Liste: {', '.join(candidates)}")
            print("   Utenti registrati: nessuno")
            break
        else:
            print("Opzione non valida, riprova.")

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

    # Genera i pin trusted delle chiavi pubbliche AE. Questo file simula il
    # canale separato e sicuro con cui, in un sistema reale, le impronte
    # verrebbero distribuite agli elettori prima della consultazione.
    pins = {
        "ae_encrypt_public": compute_public_key_fingerprint(init_data["ae_encrypt_public"]),
        "ae_sign_public": compute_public_key_fingerprint(init_data["ae_sign_public"])
    }
    with open("data/pins.json", "w", encoding="utf-8") as f:
        json.dump(pins, f, indent=2, ensure_ascii=False)
    print("  Impronte AE salvate in data/pins.json")

    # Vincolo crittografico sull'escrow della chiave privata AE (WP3 - 3.3):
    # La chiave viene cifrata con AES-GCM; la chiave simmetrica è derivata
    # (HKDF-SHA256) dalla firma del blocco init. L'AE sovrascriverà il file
    # con il nuovo IKM (firma della Merkle Root finale) al momento del /close.
    save_encrypted_private_key(ae_encrypt_private, "ae_encrypt", init_signature)
    print("  Chiave privata AE cifrata e protetta in data/keys/ae_encrypt_private.enc")

    # I token NON vengono pre-generati in inizializzazione: ciascun token è
    # rilasciato dal SA solo al momento dell'autenticazione dell'elettore
    # (WP2 Fase 2), così che la finestra di validità decorra dal rilascio.

    # Salva la lista elettori. Nella modalità "solo liste" rimane vuota:
    # gli utenti potranno registrarsi successivamente tramite il SA, e il token
    # verrà rilasciato solo durante la loro autenticazione (WP2 Fase 2).
    with open("data/voters.json", "w", encoding="utf-8") as f:
        voters_to_save = []
        for v in voters:
            v_copy = v.copy()
            v_copy['password'] = hash_password(v_copy['password'])
            voters_to_save.append(v_copy)
        json.dump(voters_to_save, f, indent=2, ensure_ascii=False)
    if voters:
        print("\nLista elettori salvata in data/voters.json")
    else:
        print("\nNessun elettore salvato: file voters.json inizializzato vuoto.")

    print("\nInizializzazione completata con successo!")


if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    main()

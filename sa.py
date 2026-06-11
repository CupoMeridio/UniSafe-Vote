
"""
Sistema di Autenticazione (SA) - Server Flask.

Questo server gestisce due operazioni principali:
1. Registrazione di nuovi elettori (con validazione email @studenti.unisa.it o @unisa.it)
2. Autenticazione degli elettori e emissione di token firmati

Il SA è separato dall'Autorità Elettorale (AE) per garantire che non
ci siano correlazioni tra l'identità dell'elettore e il suo voto.

Funzionamento:
- Durante l'inizializzazione, carica la propria chiave privata per firmare i token
- Carica la lista degli elettori da data/voters.json
- Verifica le credenziali e, se valide, emette un token firmato RSA-PSS
- Tiene traccia dei token emessi per evitare che lo stesso elettore voti più volte
"""

import os
import json
import hashlib
from datetime import datetime, timedelta, UTC
from typing import Optional, List, Dict, Set
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from flask import Flask, request, jsonify
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto.keys import load_private_key
from crypto.rsa_pss import sign


app = Flask(__name__)

# Stato interno del server (in memoria)
issued_tokens: Set[str] = set()  # Set di ID elettori a cui è già stato emesso un token
sa_sign_private: Optional[RSAPrivateKey] = None  # Chiave privata del SA per firmare i token
voters_list: List[Dict[str, str]] = []  # Lista degli elettori (caricata da voters.json)
election_id: str = ""  # ID dell'elezione (caricato dal Bulletin Board)


def load_initial_data() -> None:
    """
    Carica i dati iniziali del server:
    - Chiave privata per la firma dei token
    - Lista degli elettori da voters.json
    - ID dell'elezione dal Bulletin Board
    """
    global sa_sign_private, voters_list, election_id
    print("[SA] Caricamento dati iniziali...")

    # Carica la chiave privata del SA
    sa_sign_private = load_private_key("sa_sign")

    # Carica la lista degli elettori registrati
    with open("data/voters.json", "r", encoding="utf-8") as f:
        voters_list = json.load(f)

    # Carica l'ID dell'elezione dal Bulletin Board
    with open("data/bulletin_board.json", "r", encoding="utf-8") as f:
        bb = json.load(f)
        election_id = bb[0]["data"]["election_id"]

    print("[SA] Pronto sulla porta 5001")


def is_valid_unisa_email(email: str) -> bool:
    """
    Verifica che un'email appartenga ai domini autorizzati.

    Gli elettori possono registrarsi solo con email:
    - @studenti.unisa.it (studenti)
    - @unisa.it (docenti e personale)

    Args:
        email (str): Indirizzo email da verificare

    Returns:
        bool: True se l'email è valida, False altrimenti
    """
    email = email.strip().lower()
    return email.endswith('@studenti.unisa.it') or email.endswith('@unisa.it')


@app.route('/register', methods=['POST'])
def register():
    """
    Endpoint per la registrazione di un nuovo elettore.

    Richiesta (JSON):
    {
        "email": "nome.cognome@studenti.unisa.it",
        "username": "nomeutente",
        "password": "password123"
    }

    Risposta (201 Created):
    {
        "message": "Registrazione avvenuta con successo!"
    }

    Risposte di errore (400, 409):
    {
        "error": "Messaggio di errore"
    }
    """
    global voters_list
    try:
        req_data = request.get_json()
        email = req_data.get("email")
        username = req_data.get("username")
        password = req_data.get("password")

        # 1. Validazione del dominio email
        if not email or not is_valid_unisa_email(email):
            print(f"[SA] {datetime.now().isoformat()} - Registrazione fallita: email non valida {email}")
            return jsonify({"error": "Email non valida. Usa un'email @studenti.unisa.it o @unisa.it"}), 400

        # 2. Verifica che tutti i campi siano presenti
        if not username or not password:
            print(f"[SA] {datetime.now().isoformat()} - Registrazione fallita: campi mancanti")
            return jsonify({"error": "Username e password sono obbligatori"}), 400

        # 3. Verifica che l'username non sia già in uso
        for v in voters_list:
            if v["username"] == username:
                print(f"[SA] {datetime.now().isoformat()} - Registrazione fallita: username {username} già esistente")
                return jsonify({"error": "Username già in uso"}), 409

        # 4. Verifica che l'email non sia già registrata
        for v in voters_list:
            if "email" in v and v["email"] == email:
                print(f"[SA] {datetime.now().isoformat()} - Registrazione fallita: email {email} già registrata")
                return jsonify({"error": "Email già registrata"}), 409

        # 5. Crea il nuovo elettore con un ID progressivo
        new_id = f"v{len(voters_list) + 1:03d}"
        new_voter = {
            "id": new_id,
            "email": email,
            "username": username,
            "password": password
        }
        voters_list.append(new_voter)

        # 6. Salva la lista aggiornata sul file
        with open("data/voters.json", "w", encoding="utf-8") as f:
            json.dump(voters_list, f, indent=2, ensure_ascii=False)

        print(f"[SA] {datetime.now().isoformat()} - Nuovo elettore registrato: {username} ({email})")
        return jsonify({"message": "Registrazione avvenuta con successo!"}), 201

    except Exception as e:
        print(f"[SA] Errore durante registrazione: {str(e)}")
        return jsonify({"error": "Errore interno"}), 500


@app.route('/authenticate', methods=['POST'])
def authenticate():
    """
    Endpoint per l'autenticazione e l'emissione del token di voto.

    Richiesta (JSON):
    {
        "username": "nomeutente",
        "password": "password123"
    }

    Risposta (200 OK):
    {
        "token": "{...}", // Token JSON in formato stringa
        "signature": "abc123..." // Firma RSA-PSS del token (esadecimale)
    }

    Risposte di errore (401, 409):
    {
        "error": "Messaggio di errore"
    }
    """
    global issued_tokens
    try:
        req_data = request.get_json()
        username = req_data.get("username")
        password = req_data.get("password")

        # 1. Verifica che le credenziali siano valide
        voter = None
        for v in voters_list:
            if v["username"] == username and v["password"] == password:
                voter = v
                break

        if not voter:
            print(f"[SA] {datetime.now().isoformat()} - Autenticazione fallita per username: {username}")
            return jsonify({"error": "Credenziali non valide"}), 401

        # 2. Verifica che l'elettore non abbia già ricevuto un token
        if voter["id"] in issued_tokens:
            print(f"[SA] {datetime.now().isoformat()} - Doppia autenticazione per voter_id: {voter['id']}")
            return jsonify({"error": "Token già emesso per questo elettore"}), 409

        # 3. Genera il token
        voter_id_hash = hashlib.sha256(voter["id"].encode('utf-8')).hexdigest()
        nonce = os.urandom(16).hex()
        issued_at = datetime.now(UTC).isoformat()
        expires_at = (datetime.now(UTC) + timedelta(minutes=30)).isoformat()

        token = {
            "election_id": election_id,
            "voter_id_hash": voter_id_hash,
            "nonce": nonce,
            "issued_at": issued_at,
            "expires_at": expires_at
        }

        # 4. Firma il token con la chiave privata del SA
        token_json = json.dumps(token, sort_keys=True).encode('utf-8')
        signature = sign(sa_sign_private, token_json)

        # 5. Registra l'elettore come servito (non potrà votare di nuovo)
        issued_tokens.add(voter["id"])

        print(f"[SA] {datetime.now().isoformat()} - Token emesso per voter_id: {voter['id']} (username: {username})")

        return jsonify({
            "token": json.dumps(token),
            "signature": signature.hex()
        }), 200

    except Exception as e:
        print(f"[SA] Errore: {str(e)}")
        return jsonify({"error": "Errore interno"}), 500


@app.route('/status', methods=['GET'])
def status():
    """
    Endpoint di stato semplice per verificare che il server sia in esecuzione.

    Returns:
        JSON con il numero di token emessi e la lista degli ID degli elettori serviti.
    """
    return jsonify({
        "tokens_issued": len(issued_tokens),
        "voters_served": list(issued_tokens)
    }), 200


if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    load_initial_data()
    # Avvia il server Flask sulla porta 5001, debug disabilitato per sicurezza
    app.run(port=5001, debug=False)


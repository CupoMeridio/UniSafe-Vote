
#!/usr/bin/env python3
import os
import json
import hashlib
from datetime import datetime, timedelta, UTC
from flask import Flask, request, jsonify
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto.keys import load_private_key
from crypto.rsa_pss import sign

app = Flask(__name__)

# Stato interno (in memoria)
issued_tokens: set = set()  # Set di voter_id già serviti
sa_sign_private = None
voters_list = []
election_id = ""


def load_initial_data():
    global sa_sign_private, voters_list, election_id
    print("[SA] Caricamento dati iniziali...")

    # Carica chiave privata del SA
    sa_sign_private = load_private_key("sa_sign")

    # Carica lista elettori
    with open("data/voters.json", "r", encoding="utf-8") as f:
        voters_list = json.load(f)

    # Carica election_id dal Bulletin Board
    with open("data/bulletin_board.json", "r", encoding="utf-8") as f:
        bb = json.load(f)
        election_id = bb[0]["data"]["election_id"]

    print("[SA] Pronto sulla porta 5001")


def is_valid_unisa_email(email: str) -> bool:
    """Verifica che l'email sia un dominio UNISA valido"""
    email = email.strip().lower()
    return email.endswith('@studenti.unisa.it') or email.endswith('@unisa.it')


@app.route('/register', methods=['POST'])
def register():
    try:
        req_data = request.get_json()
        email = req_data.get('email')
        username = req_data.get('username')
        password = req_data.get('password')

        # 1. Validazione email
        if not email or not is_valid_unisa_email(email):
            print(f"[SA] {datetime.now().isoformat()} - Registrazione fallita: email non valida {email}")
            return jsonify({"error": "Email non valida. Usa un'email @studenti.unisa.it o @unisa.it"}), 400

        # 2. Verifica campi obbligatori
        if not username or not password:
            print(f"[SA] {datetime.now().isoformat()} - Registrazione fallita: campi mancanti")
            return jsonify({"error": "Username e password sono obbligatori"}), 400

        # 3. Verifica che username non esista già
        for v in voters_list:
            if v['username'] == username:
                print(f"[SA] {datetime.now().isoformat()} - Registrazione fallita: username {username} già esistente")
                return jsonify({"error": "Username già in uso"}), 409

        # 4. Verifica che email non esista già
        for v in voters_list:
            if 'email' in v and v['email'] == email:
                print(f"[SA] {datetime.now().isoformat()} - Registrazione fallita: email {email} già registrata")
                return jsonify({"error": "Email già registrata"}), 409

        # 5. Crea nuovo elettore
        new_id = f"v{len(voters_list) + 1:03d}"
        new_voter = {
            "id": new_id,
            "email": email,
            "username": username,
            "password": password
        }
        voters_list.append(new_voter)

        # 6. Salva lista aggiornata
        with open("data/voters.json", "w", encoding="utf-8") as f:
            json.dump(voters_list, f, indent=2, ensure_ascii=False)

        print(f"[SA] {datetime.now().isoformat()} - Nuovo elettore registrato: {username} ({email})")
        return jsonify({"message": "Registrazione avvenuta con successo!"}), 201

    except Exception as e:
        print(f"[SA] Errore durante registrazione: {str(e)}")
        return jsonify({"error": "Errore interno"}), 500


@app.route('/authenticate', methods=['POST'])
def authenticate():
    global issued_tokens

    try:
        req_data = request.get_json()
        username = req_data.get('username')
        password = req_data.get('password')

        # 1. Verifica credenziali
        voter = None
        for v in voters_list:
            if v['username'] == username and v['password'] == password:
                voter = v
                break

        if not voter:
            print(f"[SA] {datetime.now().isoformat()} - Autenticazione fallita per username: {username}")
            return jsonify({"error": "Credenziali non valide"}), 401

        # 2. Controlla che non sia già stato autenticato
        if voter['id'] in issued_tokens:
            print(f"[SA] {datetime.now().isoformat()} - Doppia autenticazione per voter_id: {voter['id']}")
            return jsonify({"error": "Token già emesso per questo elettore"}), 409

        # 3. Genera il token
        voter_id_hash = hashlib.sha256(voter['id'].encode('utf-8')).hexdigest()
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

        # 4. Firma il token
        token_json = json.dumps(token, sort_keys=True).encode('utf-8')
        signature = sign(sa_sign_private, token_json)

        # 5. Registra il voter come servito
        issued_tokens.add(voter['id'])

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
    return jsonify({
        "tokens_issued": len(issued_tokens),
        "voters_served": list(issued_tokens)
    }), 200


if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    load_initial_data()
    app.run(port=5001, debug=False)

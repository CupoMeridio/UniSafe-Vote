
"""
Autorità Elettorale (AE) - Server Flask.

Questo server gestisce le operazioni legate alla raccolta e allo scrutinio dei voti.

Funzionalità principali:
1. Ricezione dei voti cifrati dai client
2. Verifica della Proof of Work (anti-spam)
3. Verifica e validità dei token di autenticazione
4. Salvataggio dei voti nel Bulletin Board (append-only)
5. Costruzione del Merkle Tree per l'integrità dei dati
6. Emissione di ricevute firmate per ogni voto
7. Scrutinio dei voti dopo la chiusura delle urne
8. Pubblicazione dei risultati sul Bulletin Board

Il Bulletin Board è un registro pubblico append-only che permette
a chiunque di verificare l'integrità delle operazioni.
"""

import os
import json
import hashlib
from datetime import datetime, UTC
from typing import Optional, Dict, List, Set, Literal
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from flask import Flask, request, jsonify
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto.keys import load_private_key, load_public_key, deserialize_public_key
from crypto.rsa_oaep import encrypt, decrypt
from crypto.rsa_pss import sign, verify
from crypto.merkle import MerkleTree


app = Flask(__name__)

# Stato interno del server (in memoria)
merkle_tree = MerkleTree()  # Albero di Merkle per i voti
used_tokens: Set[str] = set()  # Set di identificatori di token già usati
urn_open: bool = True  # Stato delle urne (True = aperte, False = chiuse)
ae_encrypt_private: Optional[RSAPrivateKey] = None  # Chiave privata per decifrare i voti (caricata solo a urne chiuse)
ae_sign_private: Optional[RSAPrivateKey] = None  # Chiave privata per firmare blocchi e ricevute
ae_sign_public: Optional[RSAPublicKey] = None  # Chiave pubblica per verificare le firme
sa_sign_public: Optional[RSAPublicKey] = None  # Chiave pubblica del SA per verificare i token
bulletin_board_path: str = "data/bulletin_board.json"  # Percorso del Bulletin Board


def load_initial_data() -> None:
    """
    Carica i dati iniziali del server:
    - Chiavi di firma dell'AE
    - Chiave pubblica del SA (per verificare i token)
    """
    global ae_encrypt_private, ae_sign_private, ae_sign_public, sa_sign_public
    print("[AE] Caricamento dati iniziali...")

    # Carica la coppia di chiavi per la firma dell'AE
    ae_sign_private = load_private_key("ae_sign")
    ae_sign_public = load_public_key("ae_sign")

    # Carica la chiave pubblica del SA dal Bulletin Board
    with open(bulletin_board_path, "r", encoding="utf-8") as f:
        bb = json.load(f)
        sa_sign_public_pem = bb[0]["data"]["sa_sign_public"]
        sa_sign_public = deserialize_public_key(sa_sign_public_pem)

    print("[AE] Pronto sulla porta 5002")


def append_to_bulletin_board(block_type: Literal["init", "vote", "merkle_root", "scrutinio"], block_data: Dict) -> Dict:
    """
    Appende un nuovo blocco firmato al Bulletin Board.

    Il Bulletin Board è un registro append-only: i dati possono solo essere
    aggiunti, mai modificati o cancellati. Ogni blocco è firmato dall'AE
    per garantirne l'integrità.

    Args:
        block_type (str): Tipo di blocco ("init", "vote", "merkle_root", "scrutinio")
        block_data (dict): Dati da includere nel blocco

    Returns:
        dict: Il nuovo blocco creato (con firma e timestamp)
    """
    # Leggi il Bulletin Board corrente
    with open(bulletin_board_path, "r", encoding="utf-8") as f:
        bb = json.load(f)

    # Prepara i dati e calcola la firma
    block_data_json = json.dumps(block_data, sort_keys=True).encode('utf-8')
    signature = sign(ae_sign_private, block_data_json)

    # Crea il nuovo blocco
    new_block = {
        "type": block_type,
        "timestamp": datetime.now(UTC).isoformat(),
        "data": block_data,
        "signature": signature.hex()
    }

    # Aggiungi il blocco al registro
    bb.append(new_block)

    # Salva il Bulletin Board aggiornato
    with open(bulletin_board_path, "w", encoding="utf-8") as f:
        json.dump(bb, f, indent=2, ensure_ascii=False)

    return new_block


def verify_pow(enc_vote_hex: str, pow_nonce_hex: str, difficulty: int = 4) -> bool:
    """
    Verifica la Proof of Work (PoW) inviata dal client.

    La PoW serve a prevenire spam e voti multipli automatizzati.
    Il client deve trovare un nonce tale che SHA-256(enc_vote || nonce)
    inizi con un certo numero di bit a zero (difficulty).

    Args:
        enc_vote_hex (str): Voto cifrato in esadecimale
        pow_nonce_hex (str): Nonce della PoW in esadecimale
        difficulty (int, optional): Numero di bit a zero richiesti. Default 4.

    Returns:
        bool: True se la PoW è valida, False altrimenti
    """
    enc_vote_bytes = bytes.fromhex(enc_vote_hex)
    pow_nonce_bytes = bytes.fromhex(pow_nonce_hex)
    # Concateniamo voto e nonce
    combined = enc_vote_bytes + pow_nonce_bytes
    hash_result = hashlib.sha256(combined).digest()

    # Verifica i primi 'difficulty' bit
    required_zeros = difficulty // 8  # Numero di byte interi a zero
    required_bits = difficulty % 8  # Bit rimanenti da verificare

    # Verifica i byte interi
    for i in range(required_zeros):
        if hash_result[i] != 0:
            return False

    # Verifica i bit rimanenti (se presenti)
    if required_bits > 0:
        mask = (0xFF << (8 - required_bits)) & 0xFF
        if (hash_result[required_zeros] & mask) != 0:
            return False

    return True


@app.route('/vote', methods=['POST'])
def vote():
    """
    Endpoint per la ricezione di un nuovo voto.

    Richiesta (JSON):
    {
        "enc_vote": "abc123...",  // Voto cifrato RSA-OAEP (esadecimale)
        "enc_seed": "def456...",  // Seed cifrato RSA-OAEP (esadecimale)
        "token": "{...}",         // Token di autenticazione firmato dal SA
        "token_signature": "789...", // Firma del token (esadecimale)
        "pow_nonce": "0123..."    // Nonce della Proof of Work (esadecimale)
    }

    Risposta (200 OK):
    {
        "leaf_index": 0,
        "enc_vote": "abc123...",
        "merkle_proof": [...],
        "ae_signature": "456..."
    }

    Risposte di errore (400, 401, 403, 409):
    {
        "error": "Messaggio di errore"
    }
    """
    global used_tokens, merkle_tree
    # Verifica che le urne siano aperte
    if not urn_open:
        return jsonify({"error": "Urne chiuse"}), 403

    try:
        req_data = request.get_json()
        enc_vote = req_data.get('enc_vote')
        enc_seed = req_data.get('enc_seed')
        token = req_data.get('token')
        token_signature = req_data.get('token_signature')
        pow_nonce = req_data.get('pow_nonce')

        # 1. Verifica la Proof of Work
        if not verify_pow(enc_vote, pow_nonce):
            print(f"[AE] {datetime.now().isoformat()} - PoW invalida")
            return jsonify({"error": "Proof of Work invalida"}), 400

        # 2. Verifica la firma del token con la chiave pubblica del SA
        token_bytes = token.encode('utf-8')
        token_signature_bytes = bytes.fromhex(token_signature)
        if not verify(sa_sign_public, token_bytes, token_signature_bytes):
            print(f"[AE] {datetime.now().isoformat()} - Firma token invalida")
            return jsonify({"error": "Firma token invalida"}), 401

        # 3. Verifica che il token non sia scaduto
        token_obj = json.loads(token)
        expires_at = datetime.fromisoformat(token_obj['expires_at'])
        if datetime.now(UTC) > expires_at:
            print(f"[AE] {datetime.now().isoformat()} - Token scaduto")
            return jsonify({"error": "Token scaduto"}), 401

        # 4. Verifica che il token non sia già stato usato
        token_identifier = token_obj['voter_id_hash'] + token_obj['nonce']
        if token_identifier in used_tokens:
            print(f"[AE] {datetime.now().isoformat()} - Token già usato")
            return jsonify({"error": "Token già usato"}), 409

        # 5. Tutte le verifiche sono andate a buon fine:
        # aggiungi il voto al Merkle Tree e al Bulletin Board
        vote_record = {
            "enc_vote": enc_vote,
            "enc_seed": enc_seed,
            "token_identifier": token_identifier
        }

        record_bytes = json.dumps(vote_record, sort_keys=True).encode('utf-8')
        leaf_index = merkle_tree.add_leaf(record_bytes)

        # Salva il voto sul Bulletin Board
        append_to_bulletin_board("vote", vote_record)

        # Marca il token come usato per evitare riutilizzi
        used_tokens.add(token_identifier)

        # Genera la ricevuta per l'elettore, con la Merkle Proof
        merkle_proof = merkle_tree.get_proof(leaf_index)
        receipt_data = {
            "leaf_index": leaf_index,
            "enc_vote": enc_vote,
            "merkle_proof": merkle_proof
        }

        # Firma la ricevuta con la chiave privata dell'AE
        receipt_json = json.dumps(receipt_data, sort_keys=True).encode('utf-8')
        receipt_signature = sign(ae_sign_private, receipt_json)

        print(f"[AE] {datetime.now().isoformat()} - Voto accettato, leaf index: {leaf_index}")

        return jsonify({
            "leaf_index": leaf_index,
            "enc_vote": enc_vote,
            "merkle_proof": merkle_proof,
            "ae_signature": receipt_signature.hex()
        }), 200

    except Exception as e:
        print(f"[AE] Errore: {str(e)}")
        return jsonify({"error": "Errore interno"}), 500


@app.route('/close', methods=['POST'])
def close():
    """
    Endpoint per la chiusura delle urne e l'inizio dello scrutinio.

    Una volta chiuse le urne:
    1. Viene pubblicata la Merkle Root finale sul Bulletin Board
    2. Viene caricata la chiave privata di decifratura
    3. Vengono decifrati tutti i voti
    4. Viene verificata la corrispondenza dei seed
    5. Vengono calcolati i risultati aggregati
    6. Viene pubblicato tutto sul Bulletin Board

    Returns:
        JSON con lo stato e i risultati aggregati
    """
    global urn_open, ae_encrypt_private
    # Importiamo serialization qui per evitare problemi di circular import
    from cryptography.hazmat.primitives import serialization

    # Verifica che le urne non siano già chiuse
    if not urn_open:
        return jsonify({"error": "Urne già chiuse"}), 400

    urn_open = False
    print(f"[AE] {datetime.now().isoformat()} - Urne chiuse")

    # 1. Pubblica la Merkle Root finale sul Bulletin Board
    merkle_root = merkle_tree.get_root()
    root_data = {"merkle_root": merkle_root}
    append_to_bulletin_board("merkle_root", root_data)

    # 2. Carica la chiave privata di decifratura (solo ora, a urne chiuse)
    ae_encrypt_private = load_private_key("ae_encrypt")

    # 3. Esegui lo scrutinio
    with open(bulletin_board_path, "r", encoding="utf-8") as f:
        bb = json.load(f)

    # Ottieni la lista dei candidati dal blocco di inizializzazione
    candidates = bb[0]["data"]["candidates"]
    vote_counts = {candidate: 0 for candidate in candidates}
    verified_votes = []

    # Elabora tutti i blocchi di voto dal Bulletin Board
    for block in bb:
        if block['type'] == 'vote':
            enc_vote_hex = block['data']['enc_vote']
            enc_seed_hex = block['data']['enc_seed']

            # Decifra il seed
            enc_seed_bytes = bytes.fromhex(enc_seed_hex)
            seed_bytes = decrypt(ae_encrypt_private, enc_seed_bytes)

            # Decifra il voto (che contiene [indice_voto][seed])
            enc_vote_bytes = bytes.fromhex(enc_vote_hex)
            vote_seed_bytes = decrypt(ae_encrypt_private, enc_vote_bytes)

            # Verifica che il seed nel voto corrisponda al seed cifrato separatamente
            if vote_seed_bytes[1:] != seed_bytes:
                print(f"[AE] Attenzione: seed non corrisponde per enc_vote: {enc_vote_hex}")
                continue

            # Ottieni l'indice del candidato (primo byte del voto decifrato)
            vote_index = vote_seed_bytes[0]
            if 0 <= vote_index < len(candidates):
                candidate = candidates[vote_index]
                vote_counts[candidate] += 1
                verified_votes.append({
                    "enc_vote": enc_vote_hex,
                    "voto_chiaro": candidate,
                    "seed": seed_bytes.hex()
                })

    # 4. Pubblica i risultati dello scrutinio sul Bulletin Board
    scrutinio_data = {
        "risultato_aggregato": vote_counts,
        "voti_verificati": verified_votes,
        # Pubblichiamo anche la chiave privata per permettere la verifica
        "ae_encrypt_private": ae_encrypt_private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
    }
    append_to_bulletin_board("scrutinio", scrutinio_data)

    print(f"[AE] Scrutinio completato: {vote_counts}")
    return jsonify({"status": "success", "result": vote_counts}), 200


@app.route('/status', methods=['GET'])
def status():
    """
    Endpoint di stato semplice per verificare che il server sia in esecuzione.

    Returns:
        JSON con il numero di voti ricevuti e lo stato delle urne.
    """
    return jsonify({
        "votes_received": len(used_tokens),
        "urn_open": urn_open
    }), 200


if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    load_initial_data()
    # Avvia il server Flask sulla porta 5002, debug disabilitato
    app.run(port=5002, debug=False)


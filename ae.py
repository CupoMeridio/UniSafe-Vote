
#!/usr/bin/env python3
import os
import json
import hashlib
from datetime import datetime, UTC
from flask import Flask, request, jsonify
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto.keys import load_private_key, load_public_key, deserialize_public_key
from crypto.rsa_oaep import encrypt, decrypt
from crypto.rsa_pss import sign, verify
from crypto.merkle import MerkleTree

app = Flask(__name__)

# Stato interno (in memoria)
merkle_tree = MerkleTree()
used_tokens: set = set()
urn_open = True
ae_encrypt_private = None  # Caricata solo a urne chiuse
ae_sign_private = None
ae_sign_public = None
sa_sign_public = None
bulletin_board_path = "data/bulletin_board.json"


def load_initial_data():
    global ae_encrypt_private, ae_sign_private, ae_sign_public, sa_sign_public
    print("[AE] Caricamento dati iniziali...")

    # Carica chiavi dell'AE
    ae_sign_private = load_private_key("ae_sign")
    ae_sign_public = load_public_key("ae_sign")

    # Carica chiave pubblica del SA dal Bulletin Board
    with open(bulletin_board_path, "r", encoding="utf-8") as f:
        bb = json.load(f)
        sa_sign_public_pem = bb[0]["data"]["sa_sign_public"]
        sa_sign_public = deserialize_public_key(sa_sign_public_pem)

    print("[AE] Pronto sulla porta 5002")


def append_to_bulletin_board(block_type, block_data):
    """
    Appende un blocco al Bulletin Board e lo firma con ae_sign
    """
    with open(bulletin_board_path, "r", encoding="utf-8") as f:
        bb = json.load(f)

    block_data_json = json.dumps(block_data, sort_keys=True).encode('utf-8')
    signature = sign(ae_sign_private, block_data_json)

    new_block = {
        "type": block_type,
        "timestamp": datetime.now(UTC).isoformat(),
        "data": block_data,
        "signature": signature.hex()
    }

    bb.append(new_block)

    with open(bulletin_board_path, "w", encoding="utf-8") as f:
        json.dump(bb, f, indent=2, ensure_ascii=False)

    return new_block


def verify_pow(enc_vote_hex: str, pow_nonce_hex: str, difficulty=4) -> bool:
    """
    Verifica la Proof of Work: SHA-256(enc_vote || pow_nonce) con difficulty bit a zero
    """
    enc_vote_bytes = bytes.fromhex(enc_vote_hex)
    pow_nonce_bytes = bytes.fromhex(pow_nonce_hex)
    combined = enc_vote_bytes + pow_nonce_bytes
    hash_result = hashlib.sha256(combined).digest()

    # Verifica i primi 'difficulty' bit
    required_zeros = difficulty // 8
    required_bits = difficulty % 8

    for i in range(required_zeros):
        if hash_result[i] != 0:
            return False

    if required_bits > 0:
        mask = (0xFF << (8 - required_bits)) & 0xFF
        if (hash_result[required_zeros] & mask) != 0:
            return False

    return True


@app.route('/vote', methods=['POST'])
def vote():
    global used_tokens, merkle_tree

    if not urn_open:
        return jsonify({"error": "Urne chiuse"}), 403

    try:
        req_data = request.get_json()
        enc_vote = req_data.get('enc_vote')
        enc_seed = req_data.get('enc_seed')
        token = req_data.get('token')
        token_signature = req_data.get('token_signature')
        pow_nonce = req_data.get('pow_nonce')

        # 1. Verifica Proof of Work
        if not verify_pow(enc_vote, pow_nonce):
            print(f"[AE] {datetime.now().isoformat()} - PoW invalida")
            return jsonify({"error": "Proof of Work invalida"}), 400

        # 2. Verifica firma del token
        token_bytes = token.encode('utf-8')
        token_signature_bytes = bytes.fromhex(token_signature)
        if not verify(sa_sign_public, token_bytes, token_signature_bytes):
            print(f"[AE] {datetime.now().isoformat()} - Firma token invalida")
            return jsonify({"error": "Firma token invalida"}), 401

        # 3. Verifica validità temporale del token
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

        # 5. Tutto ok: aggiungi la scheda al Merkle Tree e al Bulletin Board
        vote_record = {
            "enc_vote": enc_vote,
            "enc_seed": enc_seed,
            "token_identifier": token_identifier
        }

        record_bytes = json.dumps(vote_record, sort_keys=True).encode('utf-8')
        leaf_index = merkle_tree.add_leaf(record_bytes)

        # Aggiungi al Bulletin Board
        append_to_bulletin_board("vote", vote_record)

        # Marca token come usato
        used_tokens.add(token_identifier)

        # Genera ricevuta
        merkle_proof = merkle_tree.get_proof(leaf_index)
        receipt_data = {
            "leaf_index": leaf_index,
            "enc_vote": enc_vote,
            "merkle_proof": merkle_proof
        }

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
    global urn_open, ae_encrypt_private

    if not urn_open:
        return jsonify({"error": "Urne già chiuse"}), 400

    urn_open = False
    print(f"[AE] {datetime.now().isoformat()} - Urne chiuse")

    # 1. Pubblica Merkle root finale
    merkle_root = merkle_tree.get_root()
    root_data = {"merkle_root": merkle_root}
    append_to_bulletin_board("merkle_root", root_data)

    # 2. Carica chiave privata di decifratura
    ae_encrypt_private = load_private_key("ae_encrypt")

    # 3. Esegui scrutinio
    with open(bulletin_board_path, "r", encoding="utf-8") as f:
        bb = json.load(f)

    # Ottieni lista candidati
    candidates = bb[0]["data"]["candidates"]
    vote_counts = {candidate: 0 for candidate in candidates}
    verified_votes = []

    # Ottieni tutti i voti dal bulletin board
    for block in bb:
        if block['type'] == 'vote':
            enc_vote_hex = block['data']['enc_vote']
            enc_seed_hex = block['data']['enc_seed']

            # Decifra il seed
            enc_seed_bytes = bytes.fromhex(enc_seed_hex)
            seed_bytes = decrypt(ae_encrypt_private, enc_seed_bytes)

            # Decifra il voto + seed
            enc_vote_bytes = bytes.fromhex(enc_vote_hex)
            vote_seed_bytes = decrypt(ae_encrypt_private, enc_vote_bytes)

            # Verifica che il seed corrisponda
            if vote_seed_bytes[1:] != seed_bytes:
                print(f"[AE] Attenzione: seed non corrisponde per enc_vote: {enc_vote_hex}")
                continue

            # Ottieni l'indice del voto
            vote_index = vote_seed_bytes[0]
            if 0 <= vote_index < len(candidates):
                candidate = candidates[vote_index]
                vote_counts[candidate] += 1
                verified_votes.append({
                    "enc_vote": enc_vote_hex,
                    "voto_chiaro": candidate,
                    "seed": seed_bytes.hex()
                })

    # 4. Pubblica scrutinio sul Bulletin Board
    scrutinio_data = {
        "risultato_aggregato": vote_counts,
        "voti_verificati": verified_votes,
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
    return jsonify({
        "votes_received": len(used_tokens),
        "urn_open": urn_open
    }), 200


if __name__ == "__main__":
    from cryptography.hazmat.primitives import serialization  # Importato qui per evitare circular import
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    load_initial_data()
    app.run(port=5002, debug=False)

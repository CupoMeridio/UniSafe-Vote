
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
import time
from collections import deque
from datetime import datetime, UTC
from typing import Optional, Dict, Set, Literal, Deque
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from flask import Flask, request, jsonify
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto.keys import load_private_key, load_public_key, deserialize_public_key, load_and_decrypt_private_key, save_encrypted_private_key
from crypto.rsa_oaep import decrypt
from crypto.rsa_pss import sign, verify
from crypto.merkle import MerkleTree


app = Flask(__name__)

# Stato interno del server (in memoria)
used_tokens: Set[str] = set()  # Set di nonce di token già usati (privato AE)
merkle_tree = MerkleTree()  # Albero di Merkle per i voti
urn_open: bool = True  # Stato delle urne (True = aperte, False = chiuse)
ae_encrypt_private: Optional[RSAPrivateKey] = None  # Chiave privata per decifrare i voti (caricata solo a urne chiuse)
ae_sign_private: Optional[RSAPrivateKey] = None  # Chiave privata per firmare blocchi e ricevute
ae_sign_public: Optional[RSAPublicKey] = None  # Chiave pubblica per verificare le firme
sa_sign_public: Optional[RSAPublicKey] = None  # Chiave pubblica del SA per verificare i token
bulletin_board_path: str = "data/bulletin_board.json"  # Percorso del Bulletin Board
ae_state_path: str = "data/ae_state.json"  # Percorso dello stato privato AE
opening_time: Optional[datetime] = None  # Istante di apertura delle urne (da init)
closing_time: Optional[datetime] = None  # Istante di chiusura delle urne (da init)

# --- Proof of Work adattiva globale (mitigazione DoS) ---
POW_MIN_DIFFICULTY: int = 4   # Difficoltà minima (operatività standard, ~0.1s)
POW_MAX_DIFFICULTY: int = 24  # Tetto massimo per evitare di bloccare elettori onesti
POW_WINDOW_SECONDS: float = 10.0  # Finestra di osservazione del traffico
POW_RATE_THRESHOLD: int = 5  # Richieste/finestra oltre cui si considera traffico anomalo
request_timestamps: Deque[float] = deque()  # Timestamp delle richieste recenti


def current_pow_difficulty() -> int:
    """
    Calcola la difficoltà di Proof of Work corrente in base al carico globale.

    La strategia è adattiva: in condizioni normali la difficoltà è minima
    (POW_MIN_DIFFICULTY); quando il numero di richieste nella finestra di
    osservazione supera la soglia, la difficoltà cresce di 1 bit per ogni
    blocco di richieste oltre soglia (crescita esponenziale del costo per
    l'attaccante), fino a POW_MAX_DIFFICULTY.

    Returns:
        int: Numero di bit a zero richiesti dalla PoW.
    """
    now = time.monotonic()
    # Rimuovi i timestamp più vecchi della finestra
    while request_timestamps and now - request_timestamps[0] > POW_WINDOW_SECONDS:
        request_timestamps.popleft()

    recent = len(request_timestamps)
    if recent <= POW_RATE_THRESHOLD:
        return POW_MIN_DIFFICULTY

    extra = (recent - POW_RATE_THRESHOLD) // POW_RATE_THRESHOLD
    return min(POW_MIN_DIFFICULTY + extra, POW_MAX_DIFFICULTY)


def load_ae_state() -> None:
    """
    Carica lo stato privato AE necessario a impedire voti multipli.

    Lo stato contiene esclusivamente i nonce dei token già usati: sono
    identificatori opachi, privi di qualsiasi riferimento all'identità
    dell'elettore. Non viene pubblicato sul Bulletin Board, dove compaiono
    solo i dati necessari alla verifica universale (scheda cifrata, seed
    cifrato, timestamp).
    """
    global used_tokens
    if not os.path.exists(ae_state_path):
        return

    with open(ae_state_path, "r", encoding="utf-8") as f:
        state = json.load(f)

    used_tokens = set(state.get("used_tokens", []))


def save_ae_state() -> None:
    """Salva lo stato privato AE necessario a impedire voti multipli."""
    state = {
        "used_tokens": sorted(used_tokens)
    }
    with open(ae_state_path, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, ensure_ascii=False)


def load_initial_data() -> None:
    """
    Carica i dati iniziali del server:
    - Chiavi di firma dell'AE
    - Chiave pubblica del SA (per verificare i token)
    """
    global ae_encrypt_private, ae_sign_private, ae_sign_public, sa_sign_public
    global opening_time, closing_time
    print("[AE] Caricamento dati iniziali...")

    # Carica la coppia di chiavi per la firma dell'AE
    ae_sign_private = load_private_key("ae_sign")
    ae_sign_public = load_public_key("ae_sign")

    # Carica la chiave pubblica del SA e la finestra temporale dal Bulletin Board
    with open(bulletin_board_path, "r", encoding="utf-8") as f:
        bb = json.load(f)
        sa_sign_public_pem = bb[0]["data"]["sa_sign_public"]
        sa_sign_public = deserialize_public_key(sa_sign_public_pem)
        opening_time = datetime.fromisoformat(bb[0]["data"]["opening_time"])
        closing_time = datetime.fromisoformat(bb[0]["data"]["closing_time"])

    # Carica lo stato privato AE per impedire il riutilizzo dei token dopo
    # un eventuale riavvio del server, senza pubblicare identificatori nel
    # Bulletin Board.
    load_ae_state()

    print("[AE] Pronto sulla porta 5002")


def append_to_bulletin_board(block_type: Literal["init", "vote", "merkle_root", "scrutinio",
                                                   "reconciliation_ae", "reconciliation_sa"],
                             block_data: Dict,
                             precomputed_signature: bytes = None) -> Dict:
    """
    Appende un nuovo blocco firmato al Bulletin Board.

    Il Bulletin Board è un registro append-only: i dati possono solo essere
    aggiunti, mai modificati o cancellati. Ogni blocco è firmato dall'AE
    per garantirne l'integrità.

    Args:
        block_type (str): Tipo di blocco
        block_data (dict): Dati da includere nel blocco
        precomputed_signature (bytes, optional): Se fornita, non viene ricalcolata
            la firma (utile quando la firma stessa viene usata come IKM crittografico).

    Returns:
        dict: Il nuovo blocco creato (con firma e timestamp)
    """
    # Leggi il Bulletin Board corrente
    with open(bulletin_board_path, "r", encoding="utf-8") as f:
        bb = json.load(f)

    # Prepara i dati e calcola la firma (o usa quella precomputed)
    block_data_json = json.dumps(block_data, sort_keys=True).encode('utf-8')
    signature = precomputed_signature if precomputed_signature is not None else sign(ae_sign_private, block_data_json)

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


def verify_pow(enc_vote_hex: str, pow_nonce_hex: str, difficulty: int = POW_MIN_DIFFICULTY) -> bool:
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

        # Registra la richiesta per il calcolo della difficoltà PoW adattiva
        request_timestamps.append(time.monotonic())

        # 1. Verifica la Proof of Work alla difficoltà adattiva corrente
        if not verify_pow(enc_vote, pow_nonce, current_pow_difficulty()):
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

        # 3b. Verifica che il voto cada nella finestra temporale dell'elezione
        now = datetime.now(UTC)
        if opening_time is not None and now < opening_time:
            print(f"[AE] {datetime.now().isoformat()} - Voto prima dell'apertura delle urne")
            return jsonify({"error": "Urne non ancora aperte"}), 403
        if closing_time is not None and now > closing_time:
            print(f"[AE] {datetime.now().isoformat()} - Voto dopo la chiusura delle urne")
            return jsonify({"error": "Urne chiuse"}), 403

        # 4. Verifica che il token non sia già stato usato. L'unicità si basa
        # esclusivamente sul nonce opaco del token: poiché il SA rilascia al più
        # un token per elettore (controllo di unicità lato SA), un nonce non
        # ancora usato corrisponde a un elettore che non ha ancora votato. L'AE
        # non conosce alcun identificatore dell'elettore, preservando l'anonimato.
        token_identifier = token_obj['nonce']
        if token_identifier in used_tokens:
            print(f"[AE] {datetime.now().isoformat()} - Token già usato")
            return jsonify({"error": "Token già usato"}), 409

        # 5. Tutte le verifiche sono andate a buon fine:
        # aggiungi il voto al Merkle Tree e al Bulletin Board.
        # Il Bulletin Board resta pseudoanonimo: non pubblica il nonce del token,
        # che rimane solo nello stato privato AE.
        vote_record = {
            "enc_vote": enc_vote,
            "enc_seed": enc_seed,
            "timestamp": datetime.now(UTC).isoformat()
        }

        record_bytes = json.dumps(vote_record, sort_keys=True).encode('utf-8')
        leaf_index = merkle_tree.add_leaf(record_bytes)

        # Salva il voto sul Bulletin Board
        append_to_bulletin_board("vote", vote_record)

        # Marca il token come usato per evitare riutilizzi. Il nonce è un
        # identificatore opaco e non viene pubblicato sul Bulletin Board.
        used_tokens.add(token_identifier)
        save_ae_state()

        # Genera la ricevuta per l'elettore, con la Merkle Proof
        merkle_proof = merkle_tree.get_proof(leaf_index)
        timestamp_str = datetime.now(UTC).isoformat()
        receipt_data = {
            "leaf_index": leaf_index,
            "enc_vote": enc_vote,
            "merkle_proof": merkle_proof,
            "timestamp": timestamp_str
        }

        # Firma la ricevuta con la chiave privata dell'AE
        receipt_json = json.dumps(receipt_data, sort_keys=True).encode('utf-8')
        receipt_signature = sign(ae_sign_private, receipt_json)

        print(f"[AE] {datetime.now().isoformat()} - Voto accettato, leaf index: {leaf_index}")

        return jsonify({
            "leaf_index": leaf_index,
            "enc_vote": enc_vote,
            "merkle_proof": merkle_proof,
            "timestamp": timestamp_str,
            "ae_signature": receipt_signature.hex()
        }), 200

    except (ValueError, KeyError, TypeError, AttributeError) as e:
        print(f"[AE] Errore di validazione (400): {str(e)}")
        return jsonify({"error": "Formato richiesta non valido (Bad Request)"}), 400
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
    # Verifica che le urne non siano già chiuse
    if not urn_open:
        return jsonify({"error": "Urne già chiuse"}), 400

    urn_open = False
    print(f"[AE] {datetime.now().isoformat()} - Urne chiuse")

    # 0. Pubblica blocco di riconciliazione (totale voti ricevuti)
    total_votes = len(used_tokens)
    reconciliation_data = {"total_votes": total_votes}
    append_to_bulletin_board("reconciliation_ae", reconciliation_data)

    # 1. Calcola la Merkle Root finale e firmala — questa firma diventa l'IKM
    #    per decifrare la chiave privata dell'AE (vincolo crittografico WP3-3.3).
    merkle_root = merkle_tree.get_root()
    root_data = {"merkle_root": merkle_root}
    root_data_json = json.dumps(root_data, sort_keys=True).encode('utf-8')
    merkle_root_signature = sign(ae_sign_private, root_data_json)
    append_to_bulletin_board("merkle_root", root_data, precomputed_signature=merkle_root_signature)

    # 2. Decifra la chiave privata di decifratura usando la firma della Merkle Root
    #    come Input Key Material (HKDF-SHA256 → AES-256-GCM).
    #    Questa operazione fallisce se la firma non corrisponde a quella usata
    #    durante il salvataggio: in caso di esecuzione anticipata (urne ancora
    #    aperte) la root non è quella definitiva e la decifratura è impossibile.
    try:
        ae_encrypt_private = load_and_decrypt_private_key("ae_encrypt", merkle_root_signature)
    except Exception:
        # Prima esecuzione di /close: il file .enc è stato creato con IKM=init_signature.
        # Leggiamo la firma del blocco init dal Bulletin Board, la usiamo per decifrare
        # il file .enc iniziale, poi lo ri-cifriamo con l'IKM definitivo (Merkle Root).
        with open(bulletin_board_path, "r", encoding="utf-8") as _f:
            _bb = json.load(_f)
        init_signature_bytes = bytes.fromhex(_bb[0]["signature"])
        ae_encrypt_private = load_and_decrypt_private_key("ae_encrypt", init_signature_bytes)
        save_encrypted_private_key(ae_encrypt_private, "ae_encrypt", merkle_root_signature)
        print("[AE] Chiave privata AE ri-cifrata con IKM definitivo (Merkle Root firmata)")

    # 3. Esegui lo scrutinio
    with open(bulletin_board_path, "r", encoding="utf-8") as f:
        bb = json.load(f)

    # Ottieni la lista dei candidati dal blocco di inizializzazione.
    # "Scheda nulla" è una categoria di conteggio per i voti non conformi
    # al dominio dei voti validi (WP2 Fase 4).
    candidates = bb[0]["data"]["candidates"]
    NULL_LABEL = "Scheda nulla"
    vote_counts = {candidate: 0 for candidate in candidates}
    vote_counts[NULL_LABEL] = 0
    verified_votes = []

    # Elabora tutti i blocchi di voto dal Bulletin Board
    for block in bb:
        if block['type'] == 'vote':
            enc_vote_hex = block['data']['enc_vote']
            enc_seed_hex = block['data']['enc_seed']

            # Decifra il seed (randomness OAEP usata per cifrare il voto)
            enc_seed_bytes = bytes.fromhex(enc_seed_hex)
            seed_bytes = decrypt(ae_encrypt_private, enc_seed_bytes)

            # Decifra il voto (contiene il solo indice della lista, 1 byte)
            enc_vote_bytes = bytes.fromhex(enc_vote_hex)
            vote_plain = decrypt(ae_encrypt_private, enc_vote_bytes)

            # Determina il candidato; schede fuori dominio -> nulle (non scartate)
            if len(vote_plain) == 1 and 0 <= vote_plain[0] < len(candidates):
                candidate = candidates[vote_plain[0]]
            else:
                candidate = NULL_LABEL
                print(f"[AE] Scheda nulla rilevata per enc_vote: {enc_vote_hex}")

            vote_counts[candidate] += 1
            # Pubblica la tripla (scheda cifrata, voto in chiaro, seed) per ogni
            # scheda scrutinata: il seed abilita la verifica universale (ricifratura).
            verified_votes.append({
                "enc_vote": enc_vote_hex,
                "voto_chiaro": candidate,
                "seed": seed_bytes.hex()
            })

    # 4. Pubblica i risultati dello scrutinio sul Bulletin Board
    scrutinio_data = {
        "risultato_aggregato": vote_counts,
        "voti_verificati": verified_votes
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
        "urn_open": urn_open,
        "pow_difficulty": current_pow_difficulty()
    }), 200


@app.route('/shutdown', methods=['POST'])
def shutdown():
    """Termina il server AE in modo controllato (adatto all'uso locale)."""
    import threading
    threading.Timer(0.5, lambda: os._exit(0)).start()
    return jsonify({"status": "shutting down"}), 200


def print_server_banner() -> None:
    """Stampa una descrizione iniziale del terminale server AE."""
    print("\n" + "=" * 70)
    print("  AUTORITÀ ELETTORALE (AE)")
    print("=" * 70)
    print("Questo terminale ospita il server AE sulla porta 5002.")
    print("Ruolo: ricevere le schede cifrate, verificare token e Proof of Work,")
    print("registrare i voti nel Bulletin Board e, a urne chiuse, eseguire lo")
    print("scrutinio e pubblicare le prove.")
    print("\nIn questo terminale potrai visualizzare:")
    print("- il caricamento dei dati iniziali;")
    print("- l'avvio del server Flask;")
    print("- le richieste ricevute su /status, /vote, /close, /shutdown;")
    print("- eventuali schede nulle rilevate durante lo scrutinio;")
    print("- eventuali errori o messaggi diagnostici dell'AE.")
    print("\nNon serve interagire con questo terminale: chiudilo solo quando")
    print("hai terminato l'elezione o il test.")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    print_server_banner()
    load_initial_data()
    # Avvia il server Flask sulla porta 5002, debug disabilitato
    app.run(port=5002, debug=False)


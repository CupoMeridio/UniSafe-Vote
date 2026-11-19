
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
import hmac
import time
import threading
from collections import deque
from datetime import datetime, UTC
from typing import Optional, Dict, Set, Literal, Deque
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from flask import Flask, request, jsonify
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto.keys import load_private_key, load_public_key, deserialize_public_key, recover_private_key, share_commitment
from crypto.rsa_oaep import raw_decrypt, oaep_decode, is_valid_ciphertext, modulus_length
from crypto.rsa_pss import sign, verify
from crypto.merkle import MerkleTree
from admin_auth import get_or_create_admin_token, require_admin
from bb_chain import link_to_previous


app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # Limita le richieste a 1 MB per prevenire DoS Memory Exhaustion

# Stato interno del server (in memoria)
used_tokens: Set[str] = set()  # Set di nonce di token già usati (privato AE)
merkle_tree = MerkleTree()  # Albero di Merkle per i voti
urn_open: bool = True  # Stato delle urne (True = aperte, False = chiuse)
# Il server Flask gestisce le richieste in thread paralleli: questo lock rende
# atomiche le sezioni critiche (controllo/uso del token, Merkle Tree, scrittura
# del Bulletin Board e dello stato AE, chiusura delle urne). Senza di esso due
# richieste concorrenti con lo stesso token potrebbero superare entrambe il
# controllo di unicità (race condition check-then-act → doppio voto).
state_lock = threading.Lock()
pow_lock = threading.Lock()  # Protegge timestamp per IP e challenge usate della PoW
ae_encrypt_private: Optional[RSAPrivateKey] = None  # Chiave privata per decifrare i voti (caricata solo a urne chiuse)
ae_sign_private: Optional[RSAPrivateKey] = None  # Chiave privata per firmare blocchi e ricevute
ae_sign_public: Optional[RSAPublicKey] = None  # Chiave pubblica per verificare le firme
sa_sign_public: Optional[RSAPublicKey] = None  # Chiave pubblica del SA per verificare i token
ae_encrypt_public: Optional[RSAPublicKey] = None  # Chiave pubblica di cifratura (per validare le schede)
bulletin_board_path: str = "data/bulletin_board.json"  # Percorso del Bulletin Board
ae_state_path: str = "data/ae_state.json"  # Percorso dello stato privato AE
opening_time: Optional[datetime] = None  # Istante di apertura delle urne (da init)
closing_time: Optional[datetime] = None  # Istante di chiusura delle urne (da init)

# --- Proof of Work adattiva per IP, legata a una challenge del server ---
POW_MIN_DIFFICULTY: int = 4   # Difficoltà minima (operatività standard, ~0.1s)
POW_MAX_DIFFICULTY: int = 24  # Tetto massimo per evitare di bloccare elettori onesti
POW_WINDOW_SECONDS: float = 10.0  # Finestra di osservazione del traffico
POW_RATE_THRESHOLD: int = 5  # Richieste/finestra oltre cui si considera traffico anomalo
POW_CHALLENGE_TTL_SECONDS: int = 120  # Validità di una challenge emessa dal server
POW_MAX_TRACKED_IPS: int = 10000  # Oltre questa soglia si eliminano gli IP inattivi

# Timestamp delle PoW valide recenti, separati per IP. Con una difficoltà
# GLOBALE un attaccante che risolve PoW facili a raffica alzerebbe il costo per
# tutti gli elettori onesti (DoS per amplificazione): per IP, il costo cresce
# solo per chi genera il traffico anomalo.
request_timestamps: Dict[str, Deque[float]] = {}

# Chiave segreta con cui l'AE autentica le challenge (HMAC): le challenge sono
# verificabili senza memorizzarle, ma non falsificabili dal client. Una nuova
# chiave a ogni avvio invalida le challenge emesse prima del riavvio.
POW_SECRET: bytes = os.urandom(32)
# Challenge già usate, con la loro scadenza: ogni challenge vale per una sola PoW.
used_challenges: Dict[bytes, float] = {}


def current_pow_difficulty(ip: str) -> int:
    """
    Calcola la difficoltà di Proof of Work corrente per un IP.

    In condizioni normali la difficoltà è minima (POW_MIN_DIFFICULTY); quando
    le PoW valide inviate da quell'IP nella finestra di osservazione superano
    la soglia, la difficoltà cresce di 1 bit per ogni blocco di richieste oltre
    soglia (crescita esponenziale del costo per l'attaccante), fino a
    POW_MAX_DIFFICULTY.

    Returns:
        int: Numero di bit a zero richiesti dalla PoW.
    """
    now = time.monotonic()
    with pow_lock:
        timestamps = request_timestamps.get(ip)
        if not timestamps:
            return POW_MIN_DIFFICULTY
        # Rimuovi i timestamp più vecchi della finestra
        while timestamps and now - timestamps[0] > POW_WINDOW_SECONDS:
            timestamps.popleft()
        recent = len(timestamps)
    if recent <= POW_RATE_THRESHOLD:
        return POW_MIN_DIFFICULTY

    extra = (recent - POW_RATE_THRESHOLD) // POW_RATE_THRESHOLD
    return min(POW_MIN_DIFFICULTY + extra, POW_MAX_DIFFICULTY)


def record_valid_pow(ip: str) -> None:
    """Registra una PoW valida dell'IP per l'adattamento della difficoltà."""
    now = time.monotonic()
    with pow_lock:
        request_timestamps.setdefault(ip, deque()).append(now)
        if len(request_timestamps) > POW_MAX_TRACKED_IPS:
            for old_ip in [k for k, ts in request_timestamps.items()
                           if not ts or now - ts[-1] > POW_WINDOW_SECONDS]:
                del request_timestamps[old_ip]


def _ip_tag(ip: str) -> bytes:
    return hashlib.sha256(ip.encode("utf-8")).digest()[:8]


def issue_pow_challenge(ip: str) -> Dict:
    """
    Emette una challenge per la Proof of Work.

    Formato (byte): casuale(16) || scadenza(8, epoch s) || difficoltà(1)
                    || hash dell'IP(8) || HMAC-SHA256 dei campi precedenti(16)

    La PoW va calcolata su SHA-256(challenge || enc_vote || nonce). Legarla a una
    challenge del server con scadenza impedisce all'attaccante di PRECALCOLARE
    offline grandi quantità di PoW ad alta difficoltà da inviare tutte insieme;
    il legame con l'IP impedisce di distribuire una challenge a una botnet.
    """
    difficulty = current_pow_difficulty(ip)
    expires = int(time.time()) + POW_CHALLENGE_TTL_SECONDS
    body = os.urandom(16) + expires.to_bytes(8, "big") + bytes([difficulty]) + _ip_tag(ip)
    tag = hmac.new(POW_SECRET, body, hashlib.sha256).digest()[:16]
    return {"challenge": (body + tag).hex(), "difficulty": difficulty,
            "expires_in": POW_CHALLENGE_TTL_SECONDS}


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
    global ae_encrypt_private, ae_sign_private, ae_sign_public, sa_sign_public, ae_encrypt_public
    global opening_time, closing_time, merkle_tree, urn_open
    print("[AE] Caricamento dati iniziali...")

    # Carica la coppia di chiavi per la firma dell'AE
    ae_sign_private = load_private_key("ae_sign")
    ae_sign_public = load_public_key("ae_sign")

    # Carica la chiave pubblica del SA e la finestra temporale dal Bulletin Board
    with open(bulletin_board_path, "r", encoding="utf-8") as f:
        bb = json.load(f)
        sa_sign_public_pem = bb[0]["data"]["sa_sign_public"]
        sa_sign_public = deserialize_public_key(sa_sign_public_pem)
        ae_encrypt_public = deserialize_public_key(bb[0]["data"]["ae_encrypt_public"])
        opening_time = datetime.fromisoformat(bb[0]["data"]["opening_time"])
        closing_time = datetime.fromisoformat(bb[0]["data"]["closing_time"])

    # Carica lo stato privato AE per impedire il riutilizzo dei token dopo
    # un eventuale riavvio del server, senza pubblicare identificatori nel
    # Bulletin Board.
    load_ae_state()

    # Ricostruisce il Merkle Tree dai blocchi voto già presenti nel Bulletin
    # Board. Senza questo passaggio, dopo un riavvio l'albero ripartirebbe
    # vuoto: la Merkle Root finale escluderebbe i voti precedenti e la
    # verifica universale fallirebbe.
    merkle_tree = MerkleTree()
    for block in bb:
        if block.get("type") == "vote":
            record_bytes = json.dumps(block["data"], sort_keys=True).encode('utf-8')
            merkle_tree.add_leaf(record_bytes)
    if merkle_tree.leaves:
        print(f"[AE] Merkle Tree ricostruito dal Bulletin Board: {len(merkle_tree.leaves)} voti")

    # Se la Merkle Root finale è già stata pubblicata, le urne sono chiuse:
    # un riavvio non deve riaprirle.
    if any(block.get("type") == "merkle_root" for block in bb):
        urn_open = False
        print("[AE] Merkle Root finale già pubblicata: urne chiuse")

    print("[AE] Pronto sulla porta 5002")


def append_to_bulletin_board(block_type: Literal["init", "vote", "merkle_root", "scrutinio",
                                                   "reconciliation_ae", "reconciliation_sa"],
                             block_data: Dict) -> Dict:
    """
    Appende un nuovo blocco firmato al Bulletin Board.

    Il Bulletin Board è un registro append-only: i dati possono solo essere
    aggiunti, mai modificati o cancellati. Ogni blocco è firmato dall'AE
    per garantirne l'integrità.

    Args:
        block_type (str): Tipo di blocco
        block_data (dict): Dati da includere nel blocco

    Returns:
        dict: Il nuovo blocco creato (con firma e timestamp)
    """
    # Leggi il Bulletin Board corrente
    with open(bulletin_board_path, "r", encoding="utf-8") as f:
        bb = json.load(f)

    # Collega il blocco al precedente (prev_hash dentro i dati firmati) e firma.
    # block_data viene modificato in place: chi lo usa dopo (es. la foglia del
    # Merkle Tree per un voto) vede esattamente i dati pubblicati.
    link_to_previous(bb, block_data)
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


def _leading_zero_bits_ok(digest: bytes, difficulty: int) -> bool:
    """True se i primi `difficulty` bit di digest sono a zero."""
    return int.from_bytes(digest, "big") >> (len(digest) * 8 - difficulty) == 0 if difficulty else True


def verify_pow(challenge_hex: str, enc_vote_hex: str, pow_nonce_hex: str, ip: str) -> bool:
    """
    Verifica la Proof of Work inviata dal client.

    Controlli, in ordine dal più economico:
    1. la challenge è autentica (HMAC dell'AE), non scaduta ed emessa per
       questo IP;
    2. SHA-256(challenge || enc_vote || nonce) ha almeno D bit iniziali a zero,
       con D = max(difficoltà scritta nella challenge, difficoltà attuale
       dell'IP): una challenge ottenuta a bassa difficoltà prima di un flood
       non permette di continuare a inviare PoW facili;
    3. la challenge non è già stata usata (viene marcata come usata solo se
       la PoW è valida).

    La PoW serve a prevenire spam e flood automatizzati: ogni scheda costa
    all'inviante un lavoro computazionale proporzionale a 2^D.
    """
    try:
        challenge = bytes.fromhex(challenge_hex)
        enc_vote_bytes = bytes.fromhex(enc_vote_hex)
        pow_nonce_bytes = bytes.fromhex(pow_nonce_hex)
    except (TypeError, ValueError):
        return False
    if len(challenge) != 16 + 8 + 1 + 8 + 16:
        return False
    body, tag = challenge[:-16], challenge[-16:]
    if not hmac.compare_digest(tag, hmac.new(POW_SECRET, body, hashlib.sha256).digest()[:16]):
        return False
    expires = int.from_bytes(body[16:24], "big")
    if time.time() > expires or body[25:33] != _ip_tag(ip):
        return False

    difficulty = max(body[24], current_pow_difficulty(ip))
    digest = hashlib.sha256(challenge + enc_vote_bytes + pow_nonce_bytes).digest()
    if not _leading_zero_bits_ok(digest, difficulty):
        return False

    with pow_lock:
        now = time.time()
        for old in [c for c, exp in used_challenges.items() if exp < now]:
            del used_challenges[old]
        if challenge in used_challenges:
            return False
        used_challenges[challenge] = expires
    return True


@app.route('/pow_challenge', methods=['GET'])
def pow_challenge():
    """
    Emette una challenge per la Proof of Work del prossimo voto.

    Risposta (200 OK): {"challenge": "...", "difficulty": 4, "expires_in": 120}
    """
    return jsonify(issue_pow_challenge(request.remote_addr)), 200


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
        "pow_challenge": "...",   // Challenge ottenuta da GET /pow_challenge
        "pow_nonce": "0123..."    // Nonce della Proof of Work (esadecimale)
    }

    Risposta (200 OK): ricevuta firmata
    {
        "leaf_index": 0,
        "enc_vote": "abc123...",
        "merkle_proof": [...],         // relativa alla root al momento del voto
        "tree_size": 1,                // numero di voti al momento del voto
        "merkle_root_at_vote": "...",  // root al momento del voto
        "timestamp": "...",
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
        pow_challenge_hex = req_data.get('pow_challenge')
        client_ip = request.remote_addr

        # 1. Verifica la Proof of Work alla difficoltà adattiva corrente.
        # Il timestamp viene registrato SOLO se la PoW è valida: le richieste
        # con nonce casuale (attacco spazzatura) non contribuiscono al contatore
        # adattivo e non alzano la difficoltà per gli elettori legittimi.
        # La difficoltà aumenta esclusivamente quando un attaccante risolve
        # davvero la PoW a raffica (botnet), che è l'unico caso in cui il
        # meccanismo adattivo ha senso.
        if not verify_pow(pow_challenge_hex, enc_vote, pow_nonce, client_ip):
            print(f"[AE] {datetime.now().isoformat()} - PoW invalida")
            return jsonify({"error": "Proof of Work invalida"}), 400

        # PoW valida: registra la richiesta per l'adattamento della difficoltà
        record_valid_pow(client_ip)

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

        # 3c. La scheda deve essere un ciphertext RSA ben formato (k byte, minore
        # del modulo): altrimenti non esisterebbe una decifratura verificabile.
        if not is_valid_ciphertext(ae_encrypt_public, bytes.fromhex(enc_vote)):
            print(f"[AE] {datetime.now().isoformat()} - Scheda malformata")
            return jsonify({"error": "Scheda cifrata malformata"}), 400

        # 4. Verifica che il token non sia già stato usato. L'unicità si basa
        # esclusivamente sul nonce opaco del token: poiché il SA rilascia al più
        # un token per elettore (controllo di unicità lato SA), un nonce non
        # ancora usato corrisponde a un elettore che non ha ancora votato. L'AE
        # non conosce alcun identificatore dell'elettore, preservando l'anonimato.
        token_identifier = token_obj['nonce']

        # Sezione critica: controllo di unicità del token, inserimento nel
        # Merkle Tree, scrittura del Bulletin Board e marcatura del token devono
        # avvenire in modo atomico rispetto alle altre richieste e a /close.
        with state_lock:
            # Ricontrolla lo stato delle urne: /close potrebbe essere stato
            # eseguito mentre questa richiesta verificava PoW e firma.
            if not urn_open:
                return jsonify({"error": "Urne chiuse"}), 403

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

            # Salva il voto sul Bulletin Board (aggiunge prev_hash al record),
            # poi inserisce nel Merkle Tree esattamente il record pubblicato.
            append_to_bulletin_board("vote", vote_record)
            record_bytes = json.dumps(vote_record, sort_keys=True).encode('utf-8')
            leaf_index = merkle_tree.add_leaf(record_bytes)

            # Marca il token come usato per evitare riutilizzi. Il nonce è un
            # identificatore opaco e non viene pubblicato sul Bulletin Board.
            used_tokens.add(token_identifier)
            save_ae_state()

            # Fotografia dell'albero al momento del voto: proof, numero di
            # foglie e root corrispondente. La proof è valida rispetto a QUESTA
            # root, non alla root finale (che include i voti successivi).
            merkle_proof = merkle_tree.get_proof(leaf_index)
            tree_size = len(merkle_tree.leaves)
            merkle_root_at_vote = merkle_tree.get_root()

        # Genera la ricevuta per l'elettore. Includere (tree_size,
        # merkle_root_at_vote) nella ricevuta firmata permette all'elettore, a
        # urne chiuse, di verificare che i primi tree_size voti del Bulletin
        # Board producano ancora la stessa root (il registro non è stato
        # riscritto dopo il suo voto) e che il suo voto sia incluso nella root
        # finale.
        timestamp_str = datetime.now(UTC).isoformat()
        receipt_data = {
            "leaf_index": leaf_index,
            "enc_vote": enc_vote,
            "merkle_proof": merkle_proof,
            "tree_size": tree_size,
            "merkle_root_at_vote": merkle_root_at_vote,
            "timestamp": timestamp_str
        }

        # Firma la ricevuta con la chiave privata dell'AE
        receipt_json = json.dumps(receipt_data, sort_keys=True).encode('utf-8')
        receipt_signature = sign(ae_sign_private, receipt_json)

        print(f"[AE] {datetime.now().isoformat()} - Voto accettato, leaf index: {leaf_index}")

        return jsonify({**receipt_data, "ae_signature": receipt_signature.hex()}), 200

    except (ValueError, KeyError, TypeError, AttributeError) as e:
        print(f"[AE] Errore di validazione (400): {str(e)}")
        return jsonify({"error": "Formato richiesta non valido (Bad Request)"}), 400
    except Exception as e:
        print(f"[AE] Errore: {str(e)}")
        return jsonify({"error": "Errore interno"}), 500


@app.route('/close', methods=['POST'])
@require_admin
def close():
    """
    Endpoint per la chiusura delle urne e l'inizio dello scrutinio.

    Richiesta (JSON): {"trustee_shares": [quota, quota, ...]}
    Le quote degli scrutatori (Shamir) servono a ricostruire la chiave privata
    di decifratura: l'AE da sola non può decifrare le schede.

    Sequenza:
    1. Si verificano le quote contro gli impegni pubblicati nel blocco init e
       si ricostruisce la chiave privata. Con meno quote valide della soglia la
       richiesta è rifiutata e le urne restano aperte.
    2. Si chiudono le urne e si pubblicano riconciliazione e Merkle Root finale
    3. Si decifrano le schede, pubblicando per ognuna la decifratura
       verificabile (EM), e si calcolano i risultati aggregati
    4. Si pubblica lo scrutinio sul Bulletin Board

    Returns:
        JSON con lo stato e i risultati aggregati
    """
    # L'intera chiusura è eseguita sotto lock: nessun voto può essere aggiunto
    # tra il calcolo della Merkle Root finale e lo scrutinio, e due chiamate
    # concorrenti a /close non possono avviare due scrutini.
    with state_lock:
        return _close_locked()


def _close_locked():
    """Implementazione di /close; va chiamata solo tenendo state_lock."""
    global urn_open, ae_encrypt_private
    # Verifica che le urne non siano già chiuse
    if not urn_open:
        return jsonify({"error": "Urne già chiuse"}), 400

    # 1. Quote degli scrutatori. Ogni quota deve corrispondere a uno degli
    #    impegni (hash) pubblicati nel blocco init firmato: quote manomesse o
    #    di un'altra elezione vengono scartate. Servono almeno `threshold`
    #    quote di scrutatori distinti.
    with open(bulletin_board_path, "r", encoding="utf-8") as f:
        init_data = json.load(f)[0]["data"]
    escrow = init_data.get("escrow") or {}
    commitments = set(escrow.get("share_commitments", []))
    threshold = escrow.get("threshold", 0)

    req_data = request.get_json(silent=True) or {}
    received = req_data.get("trustee_shares") or []
    valid_shares = {}
    for share in received if isinstance(received, list) else []:
        if isinstance(share, dict) and share_commitment(share) in commitments:
            valid_shares[share.get("x")] = share  # una quota per scrutatore
    if not threshold or len(valid_shares) < threshold:
        print(f"[AE] {datetime.now().isoformat()} - Chiusura rifiutata: "
              f"{len(valid_shares)} quote valide su {threshold} necessarie")
        return jsonify({"error": f"Servono almeno {threshold} quote valide di scrutatori distinti "
                                 f"(ricevute valide: {len(valid_shares)})"}), 400
    try:
        ae_encrypt_private = recover_private_key(list(valid_shares.values()), init_data["election_id"])
    except Exception:
        return jsonify({"error": "Ricostruzione della chiave di decifratura fallita"}), 400
    print(f"[AE] Chiave di decifratura ricostruita con {len(valid_shares)} quote di scrutatori")

    urn_open = False
    print(f"[AE] {datetime.now().isoformat()} - Urne chiuse")

    # 2. Pubblica blocco di riconciliazione (totale voti ricevuti) e la
    #    Merkle Root finale firmata.
    total_votes = len(used_tokens)
    reconciliation_data = {"total_votes": total_votes}
    append_to_bulletin_board("reconciliation_ae", reconciliation_data)

    merkle_root = merkle_tree.get_root()
    append_to_bulletin_board("merkle_root", {"merkle_root": merkle_root})

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

    # Elabora tutti i blocchi di voto dal Bulletin Board.
    #
    # DECIFRATURA VERIFICABILE: per ogni scheda si pubblica il blocco decifrato
    # EM = c^d mod n (prima della decodifica OAEP). Chiunque può controllare con
    # la sola chiave pubblica che EM^e mod n == c e decodificare EM da sé,
    # ottenendo voto e seed: l'AE non può attribuire a una scheda un contenuto
    # diverso da quello reale né dichiarare nulla una scheda valida, perché per
    # ogni c esiste un solo EM che supera la verifica.
    #
    # Il seed è ricavato da EM stesso (fa parte del padding OAEP): il seed
    # cifrato a parte dall'elettore (enc_seed) non serve più per lo scrutinio.
    # Un elettore malevolo che invia un enc_seed incoerente non può quindi né
    # bloccare la verifica né far annullare la propria scheda.
    ae_encrypt_public = ae_encrypt_private.public_key()
    k = modulus_length(ae_encrypt_public)
    for block in bb:
        if block['type'] == 'vote':
            enc_vote_hex = block['data']['enc_vote']
            enc_vote_bytes = bytes.fromhex(enc_vote_hex)

            em_bytes = b""
            seed_bytes = b""
            vote_plain = b""
            if is_valid_ciphertext(ae_encrypt_public, enc_vote_bytes):
                em_bytes = raw_decrypt(ae_encrypt_private, enc_vote_bytes)
                try:
                    seed_bytes, vote_plain = oaep_decode(em_bytes, k)
                except ValueError:
                    pass  # padding OAEP non valido: scheda nulla (verificabile da EM)

            # Il voto è il solo indice della lista (1 byte); fuori dominio → nulla
            if len(vote_plain) == 1 and 0 <= vote_plain[0] < len(candidates):
                candidate = candidates[vote_plain[0]]
            else:
                candidate = NULL_LABEL
                print(f"[AE] Scheda nulla rilevata (contenuto fuori dominio o padding non valido) per enc_vote: {enc_vote_hex[:32]}...")

            vote_counts[candidate] += 1
            # Si pubblicano scheda cifrata, voto in chiaro, seed ed EM: il seed
            # abilita la ricifratura (verifica individuale del client), EM la
            # verifica pubblica della decifratura di OGNI scheda, nulle comprese.
            verified_votes.append({
                "enc_vote": enc_vote_hex,
                "voto_chiaro": candidate,
                "seed": seed_bytes.hex(),
                "em": em_bytes.hex()
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
        "pow_difficulty": current_pow_difficulty(request.remote_addr)
    }), 200


@app.route('/shutdown', methods=['POST'])
@require_admin
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
    print("\nIn questo terminale vengono visualizzati:")
    print("- il caricamento dei dati iniziali;")
    print("- l'avvio del server Flask;")
    print("- le richieste ricevute su /status, /vote, /close, /shutdown;")
    print("- eventuali schede nulle rilevate durante lo scrutinio;")
    print("- eventuali errori o messaggi diagnostici dell'AE.")
    print("\nNon è richiesta alcuna interazione con questo terminale: la chiusura")
    print("è consentita al termine dell'elezione o del test.")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    print_server_banner()
    load_initial_data()
    get_or_create_admin_token()

    # Certificati TLS self-signed per HTTPS
    tls_cert = os.path.join("data", "tls", "ae_cert.pem")
    tls_key  = os.path.join("data", "tls", "ae_key.pem")

    if os.path.exists(tls_cert) and os.path.exists(tls_key):
        ssl_ctx = (tls_cert, tls_key)
        print("[AE] TLS abilitato — in ascolto su https://localhost:5002")
    else:
        ssl_ctx = None
        print("[AE] Certificati TLS non trovati — avvio in HTTP (generare i certificati con generate_tls_certs.py)")

    # Avvia il server Flask sulla porta 5002, debug disabilitato
    app.run(port=5002, debug=False, ssl_context=ssl_ctx)


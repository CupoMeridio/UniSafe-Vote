
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
- Esegue il controllo di unicità: rilascia al più un token per elettore per
  elezione, registrando internamente l'avvenuto rilascio (WP2 Fase 2)
"""

import os
import json
from datetime import datetime, timedelta, UTC
from typing import Optional, List, Dict, Set
from collections import deque
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from flask import Flask, request, jsonify
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto.keys import load_private_key
from crypto.rsa_pss import sign
from crypto.password import hash_password, verify_password
from admin_auth import get_or_create_admin_token, require_admin
from bb_chain import link_to_previous


app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # Limita le richieste a 1 MB per prevenire DoS Memory Exhaustion
# Le operazioni amministrative (/reconcile, /shutdown) richiedono il token
# amministrativo (header X-Admin-Token, vedi admin_auth.py).

# Stato interno del server (in memoria)
issued_tokens: Set[str] = set()  # ID elettori a cui è già stato rilasciato un token
sa_sign_private: Optional[RSAPrivateKey] = None  # Chiave privata del SA per firmare i token
voters_list: List[Dict[str, str]] = []  # Lista degli elettori (caricata da voters.json)
election_id: str = ""  # ID dell'elezione (caricato dal Bulletin Board)
closing_time: Optional[datetime] = None  # Chiusura delle urne (dal blocco init)
reconciled: bool = False  # True dopo /reconcile: elezione conclusa, registrazioni chiuse
TOKEN_VALIDITY_MINUTES: int = 30  # Finestra di validità breve del token

# Rate Limiting configuration
RATE_LIMIT_WINDOW_SECONDS = 60  # 1 minute window
RATE_LIMIT_MAX_REQUESTS = 10     # Max 10 requests per window per IP
# Stores request timestamps per IP: { "127.0.0.1": deque([timestamps]) }
rate_limit_store: Dict[str, deque] = {}
RATE_LIMIT_MAX_TRACKED_IPS = 10000  # Oltre questa soglia si eliminano gli IP inattivi

# Header X-Forwarded-For: è impostato dal client e quindi falsificabile. Viene
# considerato SOLO se il server è avviato con UNISAFE_TRUST_PROXY_HEADERS=1
# (es. per i test di carico con Locust, che simulano IP diversi). In ogni altro
# caso si usa l'indirizzo reale della connessione: un attaccante non può più
# aggirare il rate limit cambiando l'header a ogni richiesta.
TRUST_PROXY_HEADERS = os.environ.get("UNISAFE_TRUST_PROXY_HEADERS") == "1"

# Protezione per account contro il brute force distribuito: il rate limit per
# IP non ferma un attaccante che prova password diverse sullo stesso account
# da molti IP. Dopo LOCKOUT_THRESHOLD tentativi falliti consecutivi l'account
# viene bloccato per un tempo che raddoppia a ogni ulteriore fallimento.
LOCKOUT_THRESHOLD = 5
LOCKOUT_BASE_SECONDS = 30
LOCKOUT_MAX_SECONDS = 15 * 60
# { username: {"failures": int, "locked_until": datetime | None} }
failed_logins: Dict[str, Dict] = {}
failed_logins_lock = threading.Lock()

# Hash fittizio usato quando lo username non esiste: si esegue comunque PBKDF2,
# così il tempo di risposta non rivela quali username sono registrati.
DUMMY_PASSWORD_HASH = hash_password(os.urandom(16).hex())

# Il server Flask è multi-thread: questo lock rende atomiche le sezioni che
# leggono e modificano lo stato condiviso (lista elettori, token emessi,
# file voters.json, rate limit). Senza di esso due autenticazioni concorrenti
# dello stesso elettore potrebbero ottenere due token distinti (doppio voto)
# e due registrazioni concorrenti potrebbero creare utenti duplicati.
state_lock = threading.Lock()
rate_limit_lock = threading.Lock()


def load_initial_data() -> None:
    """
    Carica i dati iniziali del server:
    - Chiave privata per la firma dei token
    - Lista degli elettori da voters.json
    - ID dell'elezione dal Bulletin Board
    """
    global sa_sign_private, voters_list, election_id, closing_time, reconciled
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
        closing_time = datetime.fromisoformat(bb[0]["data"]["closing_time"])
        reconciled = any(block.get("type") == "reconciliation_sa" for block in bb)

    # Ricostruisce l'elenco degli elettori a cui è già stato rilasciato un token
    # (persistito in voters.json) per far rispettare il controllo di unicità anche
    # dopo un riavvio del SA. I token NON vengono pre-generati: sono creati solo
    # al momento dell'autenticazione (WP2 Fase 2).
    for voter in voters_list:
        if isinstance(voter.get("token"), dict):
            issued_tokens.add(voter["id"])

    print("[SA] Pronto sulla porta 5001")


def save_voters_list() -> None:
    """Salva la lista elettori aggiornata su data/voters.json."""
    with open("data/voters.json", "w", encoding="utf-8") as f:
        json.dump(voters_list, f, indent=2, ensure_ascii=False)


def create_token_for_voter() -> Dict[str, str]:
    """
    Crea il token crittografico da rilasciare all'elettore.

    Il token è un identificatore opaco: contiene solo l'ID elezione, un nonce
    casuale non predicibile e la finestra di validità. NON contiene alcun
    riferimento all'identità dell'elettore (nemmeno in forma di hash), così che
    l'AE non possa correlare la scheda all'identità (WP1 §2.2, WP2 Fase 2).
    """
    nonce = os.urandom(16).hex()
    issued_at = datetime.now(UTC).isoformat()
    expires_at = (datetime.now(UTC) + timedelta(minutes=TOKEN_VALIDITY_MINUTES)).isoformat()

    return {
        "election_id": election_id,
        "nonce": nonce,
        "issued_at": issued_at,
        "expires_at": expires_at
    }


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


def check_rate_limit(ip_address: str) -> bool:
    """
    Check if IP address is within rate limits.
    Returns True if request is allowed, False otherwise.
    """
    now = datetime.now(UTC)
    with rate_limit_lock:
        # Clean up old timestamps first
        if ip_address not in rate_limit_store:
            rate_limit_store[ip_address] = deque()
        timestamps = rate_limit_store[ip_address]
        # Remove timestamps older than window
        while timestamps and (now - timestamps[0]).total_seconds() > RATE_LIMIT_WINDOW_SECONDS:
            timestamps.popleft()
        # Check if we're still over limit
        if len(timestamps) >= RATE_LIMIT_MAX_REQUESTS:
            return False
        # Add current timestamp and allow
        timestamps.append(now)

        # Evita che il dizionario cresca senza limiti (es. molti IP diversi):
        # oltre la soglia si eliminano gli IP senza richieste nella finestra.
        if len(rate_limit_store) > RATE_LIMIT_MAX_TRACKED_IPS:
            for ip in [ip for ip, ts in rate_limit_store.items()
                       if not ts or (now - ts[-1]).total_seconds() > RATE_LIMIT_WINDOW_SECONDS]:
                del rate_limit_store[ip]
        return True


def account_locked_for(username: str) -> int:
    """Restituisce i secondi di blocco residui dell'account (0 se non bloccato)."""
    with failed_logins_lock:
        entry = failed_logins.get(username)
        if not entry or not entry["locked_until"]:
            return 0
        remaining = (entry["locked_until"] - datetime.now(UTC)).total_seconds()
        return max(0, int(remaining) + 1) if remaining > 0 else 0


def register_failed_login(username: str) -> None:
    """Conta un tentativo fallito e, oltre la soglia, blocca l'account con backoff esponenziale."""
    with failed_logins_lock:
        entry = failed_logins.setdefault(username, {"failures": 0, "locked_until": None})
        entry["failures"] += 1
        excess = entry["failures"] - LOCKOUT_THRESHOLD
        if excess >= 0:
            seconds = min(LOCKOUT_BASE_SECONDS * (2 ** excess), LOCKOUT_MAX_SECONDS)
            entry["locked_until"] = datetime.now(UTC) + timedelta(seconds=seconds)


def reset_failed_logins(username: str) -> None:
    """Azzera i tentativi falliti dopo un'autenticazione riuscita."""
    with failed_logins_lock:
        failed_logins.pop(username, None)


def get_client_ip() -> str:
    """
    Recupera l'IP del client usato dal rate limit.

    Usa l'indirizzo reale della connessione. L'header X-Forwarded-For è letto
    solo se TRUST_PROXY_HEADERS è attivo (test di carico con Locust): altrimenti
    un attaccante potrebbe dichiarare un IP diverso a ogni richiesta.
    """
    if TRUST_PROXY_HEADERS:
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # Prende il primo IP se ce ne sono multipli separati da virgola
            return forwarded_for.split(',')[0].strip()
    return request.remote_addr






def append_to_bulletin_board(block_type: str, block_data: dict) -> dict:
    """Appende un nuovo blocco firmato al Bulletin Board."""
    with open("data/bulletin_board.json", "r", encoding="utf-8") as f:
        bb = json.load(f)

    link_to_previous(bb, block_data)  # prev_hash dentro i dati firmati
    block_data_json = json.dumps(block_data, sort_keys=True).encode('utf-8')
    signature = sign(sa_sign_private, block_data_json)

    new_block = {
        "type": block_type,
        "timestamp": datetime.now(UTC).isoformat(),
        "data": block_data,
        "signature": signature.hex()
    }

    bb.append(new_block)

    with open("data/bulletin_board.json", "w", encoding="utf-8") as f:
        json.dump(bb, f, indent=2, ensure_ascii=False)

    return new_block


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
        "message": "Registrazione completata con successo."
    }

    Risposte di errore (400, 409, 429):
    {
        "error": "Messaggio di errore"
    }
    """
    global voters_list
    # Check rate limit FIRST
    client_ip = get_client_ip()
    if not check_rate_limit(client_ip):
        print(f"[SA] {datetime.now().isoformat()} - Rate limit exceeded for IP {client_ip} (register)")
        return jsonify({"error": "Troppe richieste. È necessario riprovare più tardi."}), 429

    # Le registrazioni sono chiuse a elezione conclusa: dopo la chiusura delle
    # urne o la riconciliazione non avrebbe senso creare nuovi elettori, e un
    # account creato dopo la riconciliazione altererebbe il conteggio pubblicato.
    if reconciled or (closing_time is not None and datetime.now(UTC) > closing_time):
        return jsonify({"error": "Registrazioni chiuse: l'elezione è conclusa"}), 403

    try:
        req_data = request.get_json()
        email = req_data.get("email")
        username = req_data.get("username")
        password = req_data.get("password")

        # 1. Validazione del dominio email
        if not email or not is_valid_unisa_email(email):
            print(f"[SA] {datetime.now().isoformat()} - Registrazione fallita: email non valida {email}")
            return jsonify({"error": "Email non valida. È richiesto un indirizzo @studenti.unisa.it o @unisa.it"}), 400

        # 2. Verifica che tutti i campi siano presenti
        if not username or not password:
            print(f"[SA] {datetime.now().isoformat()} - Registrazione fallita: campi mancanti")
            return jsonify({"error": "Username e password sono obbligatori"}), 400

        # L'hash PBKDF2 (costoso) è calcolato fuori dal lock, per non
        # serializzare le registrazioni concorrenti.
        password_hash = hash_password(password)

        # Sezione critica: controlli di unicità, assegnazione dell'ID
        # progressivo e salvataggio devono essere atomici, altrimenti due
        # registrazioni concorrenti potrebbero superare entrambe i controlli.
        with state_lock:
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

            # 5. Crea il nuovo elettore con un ID progressivo. Il token NON viene
            #    generato qui: sarà rilasciato solo al momento dell'autenticazione
            #    (WP2 Fase 2), così che la sua finestra di validità decorra dal
            #    rilascio effettivo.
            new_id = f"v{len(voters_list) + 1:03d}"
            new_voter = {
                "id": new_id,
                "email": email,
                "username": username,
                "password": password_hash
            }
            voters_list.append(new_voter)

            # 6. Salva la lista aggiornata sul file
            save_voters_list()

        print(f"[SA] {datetime.now().isoformat()} - Nuovo elettore registrato: {username} ({email})")
        return jsonify({"message": "Registrazione completata con successo."}), 201

    except (ValueError, KeyError, TypeError, AttributeError) as e:
        print(f"[SA] Errore di validazione (400): {str(e)}")
        return jsonify({"error": "Formato richiesta non valido (Bad Request)"}), 400
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

    Risposte di errore (401, 409, 429):
    {
        "error": "Messaggio di errore"
    }
    """
    global issued_tokens
    # Check rate limit FIRST
    client_ip = get_client_ip()
    if not check_rate_limit(client_ip):
        print(f"[SA] {datetime.now().isoformat()} - Rate limit exceeded for IP {client_ip} (authenticate)")
        return jsonify({"error": "Troppe richieste. È necessario riprovare più tardi."}), 429

    try:
        req_data = request.get_json()
        username = req_data.get("username")
        password = req_data.get("password")

        if not isinstance(username, str) or not isinstance(password, str):
            return jsonify({"error": "Formato richiesta non valido (Bad Request)"}), 400

        # 0. Account bloccato per troppi tentativi falliti: la password non
        #    viene nemmeno verificata, così il brute force non avanza.
        locked_seconds = account_locked_for(username)
        if locked_seconds:
            print(f"[SA] {datetime.now().isoformat()} - Account bloccato ({locked_seconds}s residui): {username}")
            return jsonify({"error": "Troppi tentativi falliti: account temporaneamente bloccato.",
                            "retry_after_seconds": locked_seconds}), 429

        # 1. Verifica che le credenziali siano valide. PBKDF2 viene eseguito
        #    anche se lo username non esiste (hash fittizio): il tempo di
        #    risposta è lo stesso e non rivela quali username sono registrati.
        candidate = next((v for v in voters_list if v["username"] == username), None)
        stored_hash = candidate["password"] if candidate else DUMMY_PASSWORD_HASH
        password_ok = verify_password(stored_hash, password)
        voter = candidate if (candidate and password_ok) else None

        if not voter:
            # Il contatore vale anche per username inesistenti: il blocco si
            # comporta allo stesso modo e non permette di enumerare gli account.
            register_failed_login(username)
            print(f"[SA] {datetime.now().isoformat()} - Autenticazione fallita per username: {username}")
            return jsonify({"error": "Credenziali non valide"}), 401

        reset_failed_logins(username)

        # 2. Controllo di unicità e rilascio del token (WP2 Fase 2).
        # Se all'elettore non è ancora stato rilasciato alcun token, ne viene
        # creato uno nuovo e registrato l'avvenuto rilascio. Se un token esiste
        # già, viene restituito quello: il SA non rilascia mai una seconda
        # credenziale distinta (un elettore = un token), ma consente all'elettore
        # di recuperare la propria credenziale per la verifica della ricevuta.
        # Un token scaduto viene RINNOVATO mantenendo lo STESSO nonce: cambia
        # solo la finestra di validità. Il nonce è ciò su cui l'AE impone
        # l'unicità del voto, quindi il rinnovo non crea una seconda
        # credenziale: se l'elettore aveva già votato, il token rinnovato viene
        # rifiutato con 409. Così chi si è autenticato senza votare entro la
        # finestra non resta escluso dall'elezione, e la breve validità del
        # token continua a limitare l'utilità di un token intercettato.
        # Sezione critica: il controllo "token già rilasciato?" e il rilascio
        # devono essere atomici. Senza lock, due autenticazioni concorrenti
        # dello stesso elettore vedrebbero entrambe token assente e
        # otterrebbero due token distinti, entrambi validi presso l'AE.
        with state_lock:
            token = voter.get("token")
            if not isinstance(token, dict):
                token = create_token_for_voter()
                voter["token"] = token
                issued_tokens.add(voter["id"])
                save_voters_list()
            elif datetime.now(UTC) > datetime.fromisoformat(token["expires_at"]):
                renewed = create_token_for_voter()
                renewed["nonce"] = token["nonce"]  # stesso nonce: nessuna nuova credenziale
                token = renewed
                voter["token"] = token
                save_voters_list()
                print(f"[SA] {datetime.now().isoformat()} - Token scaduto rinnovato (stesso nonce) per voter_id: {voter['id']}")

        # 3. Firma il token con la chiave privata del SA
        token_json_str = json.dumps(token, sort_keys=True)
        token_json_bytes = token_json_str.encode('utf-8')
        signature = sign(sa_sign_private, token_json_bytes)

        print(f"[SA] {datetime.now().isoformat()} - Token restituito per voter_id: {voter['id']} (username: {username})")

        return jsonify({
            "token": token_json_str,
            "signature": signature.hex()
        }), 200

    except (ValueError, KeyError, TypeError, AttributeError) as e:
        print(f"[SA] Errore di validazione (400): {str(e)}")
        return jsonify({"error": "Formato richiesta non valido (Bad Request)"}), 400
    except Exception as e:
        print(f"[SA] Errore: {str(e)}")
        return jsonify({"error": "Errore interno"}), 500


@app.route('/status', methods=['GET'])
def status():
    """
    Endpoint di stato semplice per verificare che il server sia in esecuzione.

    Returns:
        JSON con il numero di token emessi (senza l'elenco degli elettori).
    """
    # Si espone solo il conteggio: l'elenco degli ID a cui è stato rilasciato
    # un token rivelerebbe a chiunque chi ha partecipato all'elezione.
    return jsonify({
        "status": "online",
        "issued_tokens": len(issued_tokens)
    }), 200


@app.route('/reconcile', methods=['POST'])
@require_admin
def reconcile():
    """
    Endpoint per la riconciliazione: il SA pubblica sul Bulletin Board il numero totale
    di token emessi, firmando digitalmente questo conteggio.
    """
    try:
        with state_lock:
            total_tokens = len(issued_tokens)
            block_data = {
                "total_tokens": total_tokens
            }
            append_to_bulletin_board("reconciliation_sa", block_data)
            global reconciled
            reconciled = True
        print(f"[SA] Riconciliazione completata: {total_tokens} token emessi")
        return jsonify({"status": "success", "total_tokens": total_tokens}), 200
    except Exception as e:
        print(f"[SA] Errore in riconciliazione: {str(e)}")
        return jsonify({"error": "Errore interno"}), 500


@app.route('/shutdown', methods=['POST'])
@require_admin
def shutdown():
    """Termina il server SA in modo controllato."""
    import threading
    threading.Timer(0.5, lambda: os._exit(0)).start()
    return jsonify({"status": "shutting down"}), 200


def print_server_banner() -> None:
    """Stampa una descrizione iniziale del terminale server SA."""
    print("\n" + "=" * 70)
    print("  SISTEMA DI AUTENTICAZIONE (SA)")
    print("=" * 70)
    print("Questo terminale ospita il server SA sulla porta 5001.")
    print("Ruolo: registrare gli elettori, autenticarli e rilasciare/recuperare")
    print("il token firmato usato successivamente per votare presso l'AE.")
    print("\nIn questo terminale vengono visualizzati:")
    print("- il caricamento dei dati iniziali;")
    print("- l'avvio del server Flask;")
    print("- le richieste ricevute su /status, /register, /authenticate, /shutdown;")
    print("- eventuali errori o messaggi diagnostici del SA.")
    print("\nNon è richiesta alcuna interazione con questo terminale: la chiusura")
    print("è consentita al termine dell'elezione o del test.")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    print_server_banner()
    load_initial_data()
    get_or_create_admin_token()
    if TRUST_PROXY_HEADERS:
        print("[SA] ATTENZIONE: X-Forwarded-For considerato attendibile (modalità test di carico)")

    # Certificati TLS self-signed per HTTPS
    tls_cert = os.path.join("data", "tls", "sa_cert.pem")
    tls_key  = os.path.join("data", "tls", "sa_key.pem")

    if os.path.exists(tls_cert) and os.path.exists(tls_key):
        ssl_ctx = (tls_cert, tls_key)
        print("[SA] TLS abilitato — in ascolto su https://localhost:5001")
    else:
        ssl_ctx = None
        print("[SA] Certificati TLS non trovati — avvio in HTTP (generare i certificati con generate_tls_certs.py)")

    # Avvia il server Flask sulla porta 5001, debug disabilitato per sicurezza
    app.run(port=5001, debug=False, ssl_context=ssl_ctx)


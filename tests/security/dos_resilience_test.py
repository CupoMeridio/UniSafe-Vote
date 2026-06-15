"""
Test di resilienza al DoS durante la votazione (WP2 Fase 3 / WP3 §2.4).

Verifica che il sistema mantenga la funzionalità per gli utenti onesti
anche durante un attacco volumetrico MISTO e SIMULTANEO contro l'AE.

L'attacco è composto da due vettori attivi contemporaneamente:

  - Thread SPAZZATURA: inviano nonce casuali (PoW invalida). Vengono
    rifiutati immediatamente con HTTP 400 prima di qualsiasi operazione
    costosa. Non alzano la difficoltà PoW (per design: il timestamp viene
    registrato solo DOPO verify_pow in ae.py). Simulano il vettore
    volumetrico puro, economico per l'attaccante.

  - Thread VALIDI: risolvono davvero la PoW e inviano richieste
    strutturalmente corrette fino alla verifica del token SA. Vengono
    rifiutati con HTTP 401 (firma token invalida), ma il contatore
    adattivo li registra e alza la difficoltà. Simulano il vettore
    sofisticato (botnet con risorse computazionali reali).

Entrambi i flood partono in parallelo PRIMA che gli utenti onesti inizino
a votare, così il voto avviene in condizioni di attacco reale: difficoltà
aumentata dai thread validi e rumore volumetrico dai thread spazzatura.

Struttura del test
------------------
  Setup     Inizializza l'elezione e avvia SA e AE in processi separati.

  Fase 1    Autenticazione utenti onesti presso il SA (pre-attacco).

  Fase 2    Avvio simultaneo flood SPAZZATURA + flood VALIDO in background.
            Attesa che il flood valido alzi la difficoltà, poi votazione
            degli utenti onesti in parallelo con l'attacco ancora attivo.
            Verifica che:
              - la difficoltà sia aumentata (flood valido conta)
              - tutti i voti legittimi vengano accettati nonostante
                la difficoltà più alta (grazie al retry automatico)
              - le richieste spazzatura siano rifiutate con 400 (≥95%)
              - le richieste valide dell'attaccante siano rifiutate con 401 (≥80%)

  Fase 3    Recovery: attende scadenza finestra e verifica ritorno al minimo.

  Teardown  Chiusura ordinata di SA e AE.

Risultato atteso
----------------
  - Tutti gli utenti onesti si autenticano e votano con successo.
  - La difficoltà aumenta durante l'attacco (flood valido conta).
  - La difficoltà torna al minimo dopo il cessare del traffico anomalo.
  - Le richieste spazzatura vengono rifiutate con 400.
  - Le richieste valide dell'attaccante vengono rifiutate con 401.
"""

import os
import sys
import json
import time
import hashlib
import struct
import threading
import subprocess
import requests
from datetime import datetime, timedelta, UTC
from typing import Optional, List, Dict, Tuple

# ---------------------------------------------------------------------------
# Path setup — il test gira da qualsiasi directory
# ---------------------------------------------------------------------------
PROJECT_ROOT  = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SRC_DIR       = os.path.join(PROJECT_ROOT, "src")
TESTS_SEC_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SRC_DIR)
sys.path.insert(0, TESTS_SEC_DIR)

from test_reporter import save_report

from crypto.keys import (generate_rsa_keypair, save_keypair, serialize_public_key,
                          deserialize_public_key, save_encrypted_private_key)
from crypto.rsa_pss  import sign
from crypto.rsa_oaep import encrypt
from crypto.password import hash_password
from cryptography.hazmat.primitives import serialization

# ---------------------------------------------------------------------------
# Costanti
# ---------------------------------------------------------------------------
import sys as _sys
_sys.path.insert(0, os.path.join(PROJECT_ROOT, "tests"))
from tls_config import SA_URL, AE_URL, sa_verify, ae_verify, ensure_tls_certs
DATA_DIR           = os.path.join(PROJECT_ROOT, "data")
KEYS_DIR           = os.path.join(DATA_DIR, "keys")
RECEIPTS_DIR       = os.path.join(DATA_DIR, "receipts")

POW_MIN_DIFFICULTY = 4
POW_WINDOW_SECONDS = 10.0
RECOVERY_WAIT_SEC  = 13.0
SERVER_STARTUP_SEC = 15

# Utenti onesti: autenticati prima dell'attacco, votano durante la fase 2.
HONEST_USERS = [
    {"id": "v001", "email": "v.postiglione7@studenti.unisa.it",
     "username": "vitto.posti",  "password": "password123"},
    {"id": "v002", "email": "mattia.sanzari@unisa.it",
     "username": "matty.sanz",   "password": "password456"},
    {"id": "v003", "email": "c.deluca92@studenti.unisa.it",
     "username": "carlo.deluca", "password": "pass_cDL92"},
    {"id": "v004", "email": "s.esposito@studenti.unisa.it",
     "username": "sara.espo",    "password": "pass_sE99"},
    {"id": "v005", "email": "luca.ferrante@unisa.it",
     "username": "luca.ferr",    "password": "pass_lF01"},
]
CANDIDATES = ["Lista A", "Lista B", "Lista C"]

# Flood spazzatura: nonce fisso, rifiutato subito, NON alza la difficoltà.
FLOOD_INVALID_THREADS = 20

# Flood valido: risolve davvero la PoW, ALZA la difficoltà.
# Più thread per garantire il superamento della soglia entro l'attesa iniziale.
FLOOD_VALID_THREADS   = 6


# ---------------------------------------------------------------------------
# Helpers crittografici
# ---------------------------------------------------------------------------

def compute_fingerprint(pem_str: str) -> str:
    """Calcola l'impronta SHA-256 DER della chiave pubblica per il certificate pinning."""
    pubkey = deserialize_public_key(pem_str)
    der = pubkey.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return "sha256:" + hashlib.sha256(der).hexdigest()


def solve_pow(enc_vote_bytes: bytes, difficulty: int) -> str:
    """Trova un nonce tale che SHA-256(enc_vote || nonce) abbia i primi
    'difficulty' bit a zero. Restituisce il nonce come stringa hex."""
    required_bytes = difficulty // 8
    required_bits  = difficulty % 8
    mask = (0xFF << (8 - required_bits)) & 0xFF if required_bits else 0
    for nonce_int in range(2 ** 64):
        nb = struct.pack(">Q", nonce_int)
        h  = hashlib.sha256(enc_vote_bytes + nb).digest()
        if all(h[i] == 0 for i in range(required_bytes)):
            if required_bits == 0 or (h[required_bytes] & mask) == 0:
                return nb.hex()
    raise RuntimeError("Nonce non trovato")


def get_pow_difficulty() -> int:
    """Interroga l'AE per ottenere la difficoltà PoW adattiva corrente."""
    r = requests.get(f"{AE_URL}/status", timeout=3, verify=ae_verify())
    return int(r.json().get("pow_difficulty", POW_MIN_DIFFICULTY))


# ---------------------------------------------------------------------------
# Setup / Teardown
# ---------------------------------------------------------------------------

def _wait_server(url: str, name: str, timeout: int = SERVER_STARTUP_SEC) -> bool:
    """Attende che il server risponda sull'endpoint /status entro il timeout."""
    _cert = ae_verify() if "5002" in url else sa_verify()
    for _ in range(timeout * 2):
        try:
            if requests.get(f"{url}/status", timeout=0.5, verify=_cert).status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(0.5)
    print(f"  [ERRORE] {name} non risponde dopo {timeout}s.")
    return False


def setup() -> Tuple[subprocess.Popen, subprocess.Popen, dict]:
    """
    Prepara l'ambiente di test:
    1. Azzera lo stato precedente (file e chiavi residue).
    2. Genera chiavi RSA-2048 e scrive tutti i file in data/.
    3. Avvia SA e AE come sottoprocessi separati.
    Restituisce (sa_proc, ae_proc, ctx) dove ctx contiene la chiave
    pubblica dell'AE per cifrare i voti degli utenti onesti.
    """
    print("\n" + "=" * 70)
    print("  SETUP")
    print("=" * 70)

    # Si creano le directory necessarie e si elimina ogni stato residuo
    # di esecuzioni precedenti per garantire riproducibilità.
    os.makedirs(DATA_DIR,    exist_ok=True)
    os.makedirs(KEYS_DIR,    exist_ok=True)
    os.makedirs(RECEIPTS_DIR, exist_ok=True)

    for fname in ["bulletin_board.json", "voters.json", "ae_state.json", "pins.json"]:
        p = os.path.join(DATA_DIR, fname)
        if os.path.exists(p):
            os.remove(p)
    for f in os.listdir(KEYS_DIR):
        if f == ".gitkeep":
            continue
        os.remove(os.path.join(KEYS_DIR, f))
    # Si eliminano anche le ricevute JSON dei voti precedenti.
    for f in os.listdir(RECEIPTS_DIR):
        fp = os.path.join(RECEIPTS_DIR, f)
        if f.endswith(".json"):
            os.remove(fp)

    # Si generano tre coppie RSA-2048: firma SA, cifratura AE e firma AE.
    sa_sign_priv,  sa_sign_pub  = generate_rsa_keypair()
    ae_enc_priv,   ae_enc_pub   = generate_rsa_keypair()
    ae_sign_priv,  ae_sign_pub  = generate_rsa_keypair()

    save_keypair(sa_sign_priv, sa_sign_pub,  "sa_sign")
    save_keypair(ae_enc_priv,  ae_enc_pub,   "ae_encrypt")
    save_keypair(ae_sign_priv, ae_sign_pub,  "ae_sign")

    # L'elezione apre immediatamente e chiude tra 24 ore.
    opening = datetime.now(UTC).isoformat()
    closing = (datetime.now(UTC) + timedelta(hours=24)).isoformat()

    # Si compone il blocco di inizializzazione con i parametri pubblici
    # dell'elezione e le chiavi pubbliche dei componenti, poi lo si firma.
    init_data = {
        "election_id":      "dos_resilience_test",
        "candidates":       CANDIDATES,
        "opening_time":     opening,
        "closing_time":     closing,
        "sa_sign_public":   serialize_public_key(sa_sign_pub),
        "ae_encrypt_public": serialize_public_key(ae_enc_pub),
        "ae_sign_public":   serialize_public_key(ae_sign_pub),
    }
    init_json      = json.dumps(init_data, sort_keys=True).encode("utf-8")
    init_signature = sign(ae_sign_priv, init_json)

    bb = [{
        "type":      "init",
        "timestamp": datetime.now(UTC).isoformat(),
        "data":      init_data,
        "signature": init_signature.hex(),
    }]
    with open(os.path.join(DATA_DIR, "bulletin_board.json"), "w", encoding="utf-8") as f:
        json.dump(bb, f, indent=2)

    # Si calcolano le impronte SHA-256 delle chiavi AE e si salvano in pins.json
    # per simulare il canale di distribuzione trusted (certificate pinning).
    pins = {
        "ae_encrypt_public": compute_fingerprint(init_data["ae_encrypt_public"]),
        "ae_sign_public":    compute_fingerprint(init_data["ae_sign_public"]),
    }
    with open(os.path.join(DATA_DIR, "pins.json"), "w", encoding="utf-8") as f:
        json.dump(pins, f, indent=2)

    # La chiave privata di cifratura AE viene salvata cifrata con AES-GCM
    # usando la firma del blocco init come IKM (vincolo crittografico WP3 §3.3).
    save_encrypted_private_key(ae_enc_priv, "ae_encrypt", init_signature)

    # Le password vengono salvate come hash Argon2, mai in chiaro.
    voters_data = []
    for u in HONEST_USERS:
        voters_data.append({
            "id":       u["id"],
            "email":    u["email"],
            "username": u["username"],
            "password": hash_password(u["password"]),
        })
    with open(os.path.join(DATA_DIR, "voters.json"), "w", encoding="utf-8") as f:
        json.dump(voters_data, f, indent=2)

    # Si inizializza lo stato privato dell'AE con la lista dei token usati vuota.
    with open(os.path.join(DATA_DIR, "ae_state.json"), "w", encoding="utf-8") as f:
        json.dump({"used_tokens": []}, f, indent=2)

    print("  Chiavi generate e file di configurazione scritti.")

    # Si avvia il SA come sottoprocesso con output soppresso e si attende
    # che Flask risponda su /status prima di procedere.
    sa_proc = subprocess.Popen(
        [sys.executable, os.path.join(SRC_DIR, "sa.py")],
        cwd=PROJECT_ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    print(f"  SA avviato (PID {sa_proc.pid}), attendo...", end=" ", flush=True)
    assert _wait_server(SA_URL, "SA"), "SA non risponde."
    print("OK")

    # Si avvia l'AE come sottoprocesso con output soppresso e si attende
    # che Flask risponda su /status prima di procedere.
    ae_proc = subprocess.Popen(
        [sys.executable, os.path.join(SRC_DIR, "ae.py")],
        cwd=PROJECT_ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    print(f"  AE avviata (PID {ae_proc.pid}), attendo...", end=" ", flush=True)
    assert _wait_server(AE_URL, "AE"), "AE non risponde."
    print("OK")

    # Si restituisce la chiave pubblica AE deserializzata per l'uso diretto
    # nelle funzioni di voto, evitando di ricaricarla più volte dal disco.
    return sa_proc, ae_proc, {"ae_encrypt_public": deserialize_public_key(init_data["ae_encrypt_public"])}


def teardown(sa_proc: subprocess.Popen, ae_proc: subprocess.Popen) -> None:
    """Invia il segnale di shutdown a SA e AE e termina i processi."""
    print("\n" + "=" * 70)
    print("  TEARDOWN")
    print("=" * 70)
    for url, proc, name in [(SA_URL, sa_proc, "SA"), (AE_URL, ae_proc, "AE")]:
        # Si tenta prima lo shutdown HTTP controllato; se non risponde,
        # si termina il processo con wait() e infine con kill().
        try:
            requests.post(f"{url}/shutdown", timeout=1, verify=(ae_verify() if "5002" in url else sa_verify()))
        except Exception:
            pass
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
        print(f"  {name} terminato.")


# ---------------------------------------------------------------------------
# Operazioni degli utenti onesti
# ---------------------------------------------------------------------------

def authenticate_user(user: dict) -> Optional[Tuple[str, str]]:
    """
    Autentica un utente presso il SA inviando username e password.
    Restituisce (token_json, firma_hex) se l'autenticazione ha successo,
    None altrimenti.
    """
    try:
        r = requests.post(
            f"{SA_URL}/authenticate",
            json={"username": user["username"], "password": user["password"]},
            timeout=10,
            verify=sa_verify(),
        )
        if r.status_code == 200:
            data = r.json()
            return data["token"], data["signature"]
        return None
    except Exception:
        return None


def vote_user(user: dict, token: str, token_sig: str,
              ae_pub_key, candidate_idx: int) -> Tuple[bool, float, int]:
    """
    Esegue il flusso di voto completo per un utente onesto con retry automatico.

    La difficoltà PoW può aumentare tra il momento in cui viene letta e il
    momento in cui il voto arriva all'AE (il flood valido nel frattempo aggiunge
    richieste alla finestra di osservazione). In caso di risposta 400 per
    PoW invalida il voto viene ricalcolato con la difficoltà aggiornata,
    fino a MAX_POW_RETRIES tentativi.

    Restituisce (successo, tempo_totale_ms, tentativi_effettuati).
    """
    MAX_POW_RETRIES = 5
    try:
        seed         = os.urandom(32)
        vote_byte    = candidate_idx.to_bytes(1, "big")
        enc_vote     = encrypt(ae_pub_key, vote_byte, seed=seed)
        enc_seed     = encrypt(ae_pub_key, seed)
        enc_vote_hex = enc_vote.hex()
        t0           = time.perf_counter()

        for attempt in range(1, MAX_POW_RETRIES + 1):
            difficulty = get_pow_difficulty()
            pow_nonce  = solve_pow(enc_vote, difficulty)

            r = requests.post(
                f"{AE_URL}/vote",
                json={
                    "enc_vote":        enc_vote_hex,
                    "enc_seed":        enc_seed.hex(),
                    "token":           token,
                    "token_signature": token_sig,
                    "pow_nonce":       pow_nonce,
                },
                timeout=60,
                verify=ae_verify(),
            )

            if r.status_code == 200:
                elapsed_ms = (time.perf_counter() - t0) * 1000
                receipt_path = os.path.join(RECEIPTS_DIR, f"{user['username']}.json")
                with open(receipt_path, "w", encoding="utf-8") as f:
                    json.dump(r.json(), f, indent=2)
                return True, elapsed_ms, attempt

            # PoW non più valida (difficoltà cambiata durante il calcolo):
            # riprova con la difficoltà aggiornata.
            if r.status_code == 400:
                try:
                    err = r.json().get("error", "")
                except Exception:
                    err = ""
                if "Proof of Work" in err or "PoW" in err:
                    continue

            # Qualsiasi altro errore non è risolvibile con un retry.
            elapsed_ms = (time.perf_counter() - t0) * 1000
            try:
                err_body = r.json()
            except Exception:
                err_body = r.text
            print(f"    [VOTO FALLITO] {user['username']}: HTTP {r.status_code} — {err_body}")
            return False, elapsed_ms, attempt

        # Esauriti i tentativi.
        elapsed_ms = (time.perf_counter() - t0) * 1000
        print(f"    [VOTO FALLITO] {user['username']}: PoW invalida dopo {MAX_POW_RETRIES} tentativi")
        return False, elapsed_ms, MAX_POW_RETRIES

    except Exception as e:
        print(f"    [ECCEZIONE VOTO] {user['username']}: {e}")
        return False, 0.0, 0


# ---------------------------------------------------------------------------
# Flood dell'attaccante — due vettori distinti
# ---------------------------------------------------------------------------

class InvalidFlood:
    """
    Thread SPAZZATURA: nonce fisso (PoW invalida).
    Rifiutato subito con HTTP 400, NON alza la difficoltà.
    Simula il vettore volumetrico puro, economico per l'attaccante.
    """

    def __init__(self, n_threads: int):
        self.n_threads = n_threads
        self.running   = False
        self._threads: List[threading.Thread] = []
        self.sent      = 0
        self.rejected  = 0
        self._lock     = threading.Lock()

    def _worker(self) -> None:
        while self.running:
            payload = {
                "enc_vote":        os.urandom(256).hex(),
                "enc_seed":        os.urandom(256).hex(),
                "token":           '{"nonce":"dead","expires_at":"2100-01-01T00:00:00+00:00"}',
                "token_signature": os.urandom(256).hex(),
                "pow_nonce":       "0000000000000000",  # nonce fisso, PoW invalida
            }
            try:
                r = requests.post(f"{AE_URL}/vote", json=payload, timeout=3, verify=ae_verify())
                with self._lock:
                    self.sent += 1
                    if r.status_code == 400:
                        self.rejected += 1
            except Exception:
                with self._lock:
                    self.sent += 1

    def start(self) -> None:
        self.running = True
        for _ in range(self.n_threads):
            t = threading.Thread(target=self._worker, daemon=True)
            t.start()
            self._threads.append(t)

    def stop(self) -> None:
        self.running = False
        for t in self._threads:
            t.join(timeout=5)


class ValidFlood:
    """
    Thread VALIDI: risolvono davvero la PoW corrente prima di ogni richiesta.
    Vengono rifiutati con HTTP 401 (firma token invalida) ma il contatore
    adattivo li registra, alzando la difficoltà.
    Simula il vettore sofisticato (botnet con risorse computazionali reali).
    """

    def __init__(self, n_threads: int):
        self.n_threads    = n_threads
        self.running      = False
        self._threads: List[threading.Thread] = []
        self.sent         = 0
        self.rejected_401 = 0   # PoW ok, token falso → atteso
        self.rejected_400 = 0   # PoW non più valida (race condition)
        self._lock        = threading.Lock()

    def _worker(self) -> None:
        while self.running:
            try:
                difficulty   = get_pow_difficulty()
                enc_vote_hex = os.urandom(32).hex()
                pow_nonce    = solve_pow(bytes.fromhex(enc_vote_hex), difficulty)
                payload = {
                    "enc_vote":        enc_vote_hex,
                    "enc_seed":        os.urandom(256).hex(),
                    "token":           '{"nonce":"dead","expires_at":"2100-01-01T00:00:00+00:00"}',
                    "token_signature": os.urandom(256).hex(),  # firma falsa → rifiutato a step 2
                    "pow_nonce":       pow_nonce,
                }
                r = requests.post(f"{AE_URL}/vote", json=payload, timeout=10, verify=ae_verify())
                with self._lock:
                    self.sent += 1
                    if r.status_code == 401:
                        self.rejected_401 += 1
                    elif r.status_code == 400:
                        self.rejected_400 += 1
            except Exception:
                with self._lock:
                    self.sent += 1

    def start(self) -> None:
        self.running = True
        for _ in range(self.n_threads):
            t = threading.Thread(target=self._worker, daemon=True)
            t.start()
            self._threads.append(t)

    def stop(self) -> None:
        self.running = False
        for t in self._threads:
            t.join(timeout=10)


# ---------------------------------------------------------------------------
# Test principale
# ---------------------------------------------------------------------------

def main() -> None:
    os.chdir(PROJECT_ROOT)
    sa_proc, ae_proc, ctx = setup()
    ae_pub = ctx["ae_encrypt_public"]

    try:
        # ==================================================================
        # FASE 1 — Autenticazione utenti onesti (pre-attacco)
        # ==================================================================
        print("\n" + "=" * 70)
        print("  FASE 1 — Autenticazione utenti onesti (pre-attacco)")
        print("=" * 70)

        tokens: Dict[str, Tuple[str, str]] = {}
        for user in HONEST_USERS:
            result = authenticate_user(user)
            if result:
                tokens[user["username"]] = result
                print(f"  [OK]   {user['username']} autenticato.")
            else:
                print(f"  [FAIL] {user['username']} autenticazione fallita.")

        auth_success = len(tokens)
        print(f"\n  Autenticati: {auth_success}/{len(HONEST_USERS)}")
        assert auth_success == len(HONEST_USERS), \
            "Non tutti gli utenti onesti si sono autenticati."

        # ==================================================================
        # FASE 2 — Attacco MISTO simultaneo + votazione onesti
        #
        # Entrambi i flood partono insieme:
        #   - InvalidFlood: spazzatura, rifiutata subito, non alza difficoltà
        #   - ValidFlood:   PoW risolta, conta nel rate, alza la difficoltà
        #
        # Gli utenti onesti votano MENTRE entrambi i flood sono attivi,
        # simulando lo scenario reale in cui l'attaccante usa entrambi
        # i vettori contemporaneamente.
        # ==================================================================
        print("\n" + "=" * 70)
        print(f"  FASE 2 — Attacco MISTO simultaneo + votazione onesti")
        print(f"           ({FLOOD_INVALID_THREADS} thread spazzatura  +  "
              f"{FLOOD_VALID_THREADS} thread con PoW valida)")
        print("=" * 70)

        diff_before = get_pow_difficulty()
        print(f"\n  Difficoltà PoW prima dell'attacco: {diff_before} bit")

        # Avvio simultaneo dei due flood.
        invalid_flood = InvalidFlood(FLOOD_INVALID_THREADS)
        valid_flood   = ValidFlood(FLOOD_VALID_THREADS)
        invalid_flood.start()
        valid_flood.start()
        print(f"  Flood spazzatura avviato ({FLOOD_INVALID_THREADS} thread).")
        print(f"  Flood valido avviato     ({FLOOD_VALID_THREADS} thread, risolve la PoW).")

        # Attesa iniziale per dare al flood valido il tempo di accumulare
        # richieste nella finestra prima che gli utenti onesti inizino a votare.
        time.sleep(4)

        # Voto degli utenti onesti in parallelo mentre entrambi i flood
        # sono ancora attivi.
        print(f"\n  Votazione utenti onesti (attacco misto ancora attivo)...")
        vote_results: Dict[str, Tuple[bool, float, int]] = {}
        vote_threads = []

        def do_vote(user: dict) -> None:
            tok, sig = tokens[user["username"]]
            ok, ms, attempts = vote_user(user, tok, sig, ae_pub, candidate_idx=0)
            vote_results[user["username"]] = (ok, ms, attempts)

        for user in HONEST_USERS:
            t = threading.Thread(target=do_vote, args=(user,))
            vote_threads.append(t)
            t.start()
        for t in vote_threads:
            t.join(timeout=120)

        # Ferma entrambi i flood.
        invalid_flood.stop()
        valid_flood.stop()

        # Legge la difficoltà DOPO il flood: a questo punto tutte le richieste
        # valide sono già state registrate nella finestra di osservazione.
        diff_during = get_pow_difficulty()

        print(f"\n  Flood fermati. Statistiche attacco:")
        print(f"  Difficoltà PoW durante/dopo l'attacco misto: {diff_during} bit")
        print(f"    [SPAZZATURA] Richieste inviate: {invalid_flood.sent}  |  "
              f"Rifiutate 400: {invalid_flood.rejected}"
              + (f"  ({invalid_flood.rejected/invalid_flood.sent*100:.1f}%)"
                 if invalid_flood.sent else ""))
        print(f"    [VALIDO]     Richieste inviate: {valid_flood.sent}  |  "
              f"Rifiutate 401: {valid_flood.rejected_401}  |  "
              f"Rifiutate 400 (race): {valid_flood.rejected_400}")

        # Risultati dei voti onesti.
        print(f"\n  Risultati votazione utenti onesti:")
        votes_ok = 0
        times_ms: List[float] = []
        for username, (ok, ms, attempts) in vote_results.items():
            retry_note = f", {attempts} tentativ{'o' if attempts == 1 else 'i'}"
            print(f"    {'[OK]  ' if ok else '[FAIL]'} {username}  "
                  f"({ms:.0f} ms{retry_note})")
            if ok:
                votes_ok += 1
                times_ms.append(ms)

        if times_ms:
            print(f"\n  Tempo medio voto onesto sotto attacco misto: "
                  f"{sum(times_ms)/len(times_ms):.0f} ms  "
                  f"(max: {max(times_ms):.0f} ms)")
            if any(att > 1 for _, _, att in vote_results.values()):
                retried = [(u, att) for u, (_, _, att) in vote_results.items() if att > 1]
                print(f"  Retry automatici per difficoltà cambiata: "
                      f"{', '.join(f'{u}({a})' for u, a in retried)}")

        # ==================================================================
        # FASE 3 — Recovery
        # ==================================================================
        print("\n" + "=" * 70)
        print(f"  FASE 3 — Recovery (attesa {RECOVERY_WAIT_SEC:.0f}s)")
        print("=" * 70)
        print(f"  Attendo scadenza finestra di osservazione...", end=" ", flush=True)
        time.sleep(RECOVERY_WAIT_SEC)
        print("OK")

        diff_after = get_pow_difficulty()
        print(f"  Difficoltà PoW dopo recovery: {diff_after} bit  "
              f"(attesa: {POW_MIN_DIFFICULTY} bit)")

        # ==================================================================
        # RIEPILOGO
        # ==================================================================
        print("\n" + "=" * 70)
        print("  RIEPILOGO")
        print("=" * 70)

        p1             = auth_success == len(HONEST_USERS)
        p2_pow         = diff_during > diff_before          # flood valido ha alzato la difficoltà
        p2_votes       = votes_ok == len(HONEST_USERS)      # tutti gli onesti hanno votato
        p2_inv_blocked = (invalid_flood.sent > 0 and
                          invalid_flood.rejected / invalid_flood.sent >= 0.95)  # 95%+ spazzatura bloccata
        p2_val_blocked = (valid_flood.sent > 0 and
                          (valid_flood.rejected_401 + valid_flood.rejected_400) /
                          valid_flood.sent >= 0.80)  # 80%+ ha risolto la PoW (401 + race 400)
        p3             = diff_after == POW_MIN_DIFFICULTY

        def mark(c): return "[PASS]" if c else "[FAIL]"

        print(f"\n  {mark(p1)}  Fase 1 — autenticazione onesti "
              f"({auth_success}/{len(HONEST_USERS)})")
        print(f"  {mark(p2_pow)}  Fase 2 — difficoltà aumentata durante attacco misto "
              f"({diff_before} → {diff_during} bit)")
        print(f"  {mark(p2_votes)}  Fase 2 — utenti onesti votano con attacco attivo "
              f"({votes_ok}/{len(HONEST_USERS)})")
        print(f"  {mark(p2_inv_blocked)}  Fase 2 — spazzatura bloccata (400) "
              f"({invalid_flood.rejected}/{invalid_flood.sent}  ≥95% atteso)")
        print(f"  {mark(p2_val_blocked)}  Fase 2 — flood valido ha risolto la PoW (401+400race) "
              f"({valid_flood.rejected_401 + valid_flood.rejected_400}/{valid_flood.sent}  ≥80% atteso)")
        print(f"  {mark(p3)}  Fase 3 — difficoltà tornata al minimo "
              f"({diff_after} bit)")

        all_pass = p1 and p2_pow and p2_votes and p2_inv_blocked and p2_val_blocked and p3

        print("\n" + "=" * 70)
        if all_pass:
            print("\n  [SUCCESS] Il sistema ha resistito all'attacco misto simultaneo:")
            print("    - Il flood valido ha alzato la difficoltà come atteso.")
            print("    - Tutta la spazzatura è stata bloccata a basso costo (400).")
            print("    - Il flood valido è stato bloccato al controllo token (401).")
            print("    - Tutti gli utenti onesti hanno votato nonostante l'attacco.")
            print("    - La difficoltà è tornata al minimo dopo il cessare dell'attacco.")
            if times_ms:
                print(f"\n  Nota: tempo medio di voto {sum(times_ms)/len(times_ms):.0f} ms "
                      f"(più alto del normale per via della PoW adattiva aumentata).")
        else:
            print("\n  [ATTENZIONE] Uno o più controlli non superati. Dettagli sopra.")
        print("=" * 70)

        save_report(
            test_id="dos_resilience",
            test_name="Resilienza DoS — Attacco Misto Simultaneo (WP2 Fase 3 / WP3 §2.4)",
            outcome="PASS" if all_pass else "FAIL",
            details={
                "flood_invalid_threads": FLOOD_INVALID_THREADS,
                "flood_valid_threads":   FLOOD_VALID_THREADS,
                "recovery_wait_sec":     RECOVERY_WAIT_SEC,
                "flood_invalid": {
                    "sent":         invalid_flood.sent,
                    "rejected_400": invalid_flood.rejected,
                    "rejection_rate_pct": round(
                        invalid_flood.rejected / invalid_flood.sent * 100, 1
                    ) if invalid_flood.sent else 0,
                },
                "flood_valid": {
                    "sent":         valid_flood.sent,
                    "rejected_401": valid_flood.rejected_401,
                    "rejected_400_race": valid_flood.rejected_400,
                },
                "pow_difficulty": {
                    "before_attack_bit":  diff_before,
                    "during_attack_bit":  diff_during,
                    "after_recovery_bit": diff_after,
                },
                "honest_users": {
                    "total":            len(HONEST_USERS),
                    "authenticated":    auth_success,
                    "voted_ok":         votes_ok,
                    "vote_times_ms":    {u: round(ms, 1)
                                         for u, (ok, ms, _) in vote_results.items()},
                    "avg_vote_time_ms": round(sum(times_ms) / len(times_ms), 1)
                                        if times_ms else None,
                    "retry_counts":     {u: att
                                         for u, (_, _, att) in vote_results.items()},
                },
                "checks": {
                    "p1_all_authenticated":             p1,
                    "p2_pow_increased":                 p2_pow,
                    "p2_all_honest_voted":              p2_votes,
                    "p2_invalid_blocked_95pct":         p2_inv_blocked,
                    "p2_valid_pow_resolved_80pct":      p2_val_blocked,
                    "p3_difficulty_recovered":          p3,
                },
            },
        )

    finally:
        teardown(sa_proc, ae_proc)


if __name__ == "__main__":
    os.chdir(PROJECT_ROOT)
    try:
        main()
    except Exception as e:
        print(f"\n[ERRORE] {e}")
    finally:
        input("\nPremi Invio per chiudere...")

"""
Test di resilienza al DoS durante la votazione (WP2 Fase 3 / WP3 §2.4).

Verifica che il sistema mantenga la funzionalità per gli utenti onesti
anche durante un attacco volumetrico concorrente contro l'AE, e che la
PoW adattiva penalizzi l'attaccante senza bloccare i legittimi votanti.

Struttura del test
------------------
  Setup         Inizializza l'elezione e avvia SA e AE in processi separati.

  Fase 1        Autenticazione utenti onesti presso il SA (pre-attacco).
                Verifica che tutti ottengano un token valido.

  Fase 2        Avvio dell'attacco DoS concorrente (flood con PoW invalida)
                + votazione degli utenti onesti in contemporanea.
                Misura la difficoltà PoW durante il carico e i tempi di
                risposta dei votanti legittimi.

  Fase 3        Attesa recovery (> POW_WINDOW_SECONDS) e verifica che la
                difficoltà torni al minimo.

  Teardown      Chiusura ordinata di SA e AE, ripristino dello stato iniziale.

Risultato atteso
----------------
  - Tutti gli utenti onesti riescono a votare anche sotto attacco.
  - La difficoltà PoW aumenta durante il flood.
  - Le richieste dell'attaccante vengono rifiutate (HTTP 400).
  - La difficoltà torna al minimo dopo il cessare del traffico anomalo.
"""

import os
import sys
import json
import time
import hashlib
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
from crypto.rsa_pss  import sign, verify
from crypto.rsa_oaep import encrypt
from crypto.password import hash_password
from cryptography.hazmat.primitives import serialization

# ---------------------------------------------------------------------------
# Costanti
# ---------------------------------------------------------------------------
SA_URL             = "http://localhost:5001"
AE_URL             = "http://localhost:5002"
DATA_DIR           = os.path.join(PROJECT_ROOT, "data")
KEYS_DIR           = os.path.join(DATA_DIR, "keys")
RECEIPTS_DIR       = os.path.join(DATA_DIR, "receipts")

POW_MIN_DIFFICULTY = 4       # Difficoltà minima attesa a sistema a riposo
POW_WINDOW_SECONDS = 10.0    # Finestra di osservazione del traffico nell'AE
RECOVERY_WAIT_SEC  = 13.0    # Attesa > POW_WINDOW_SECONDS per garantire il reset
SERVER_STARTUP_SEC = 6       # Secondi di attesa avvio Flask

# Utenti onesti usati nel test: autenticati prima dell'attacco, votano durante.
HONEST_USERS = [
    {"id": "v001", "email": "mario.rossi@studenti.unisa.it",
     "username": "mario.rossi",  "password": "password123"},
    {"id": "v002", "email": "luigi.bianchi@unisa.it",
     "username": "luigi.bianchi", "password": "password456"},
    {"id": "v003", "email": "anna.verdi@studenti.unisa.it",
     "username": "anna.verdi",    "password": "password789"},
    {"id": "v004", "email": "carla.neri@studenti.unisa.it",
     "username": "carla.neri",    "password": "passwordabc"},
    {"id": "v005", "email": "marco.blu@unisa.it",
     "username": "marco.blu",     "password": "passworddef"},
]
CANDIDATES = ["Lista A", "Lista B", "Lista C"]

# Parametri del flood: numero totale di richieste invalide e thread concorrenti.
FLOOD_REQUESTS = 80
FLOOD_THREADS  = 30


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
    """
    Calcola un nonce valido per la PoW richiesta.
    Si cerca un nonce tale che SHA-256(enc_vote || nonce) abbia
    i primi 'difficulty' bit a zero.
    """
    nonce = 0
    while True:
        nb = nonce.to_bytes(8, "big")
        h  = hashlib.sha256(enc_vote_bytes + nb).digest()
        ok = True
        # Si verificano prima i byte interi a zero, poi i bit rimanenti.
        for i in range(difficulty // 8):
            if h[i] != 0:
                ok = False
                break
        if ok and difficulty % 8:
            mask = (0xFF << (8 - difficulty % 8)) & 0xFF
            if h[difficulty // 8] & mask:
                ok = False
        if ok:
            return nb.hex()
        nonce += 1


def get_pow_difficulty() -> int:
    """Interroga l'AE per ottenere la difficoltà PoW adattiva corrente."""
    r = requests.get(f"{AE_URL}/status", timeout=3)
    return int(r.json().get("pow_difficulty", POW_MIN_DIFFICULTY))


# ---------------------------------------------------------------------------
# Setup / Teardown
# ---------------------------------------------------------------------------

def _wait_server(url: str, name: str, timeout: int = SERVER_STARTUP_SEC) -> bool:
    """Attende che il server risponda sull'endpoint /status entro il timeout."""
    for _ in range(timeout * 2):
        try:
            if requests.get(f"{url}/status", timeout=0.5).status_code == 200:
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
            requests.post(f"{url}/shutdown", timeout=1)
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
        )
        if r.status_code == 200:
            data = r.json()
            return data["token"], data["signature"]
        return None
    except Exception:
        return None


def vote_user(user: dict, token: str, token_sig: str,
              ae_pub_key, candidate_idx: int) -> Tuple[bool, float]:
    """
    Esegue il flusso di voto completo per un utente onesto con retry automatico.

    La difficoltà PoW può aumentare tra il momento in cui viene letta e il
    momento in cui il voto arriva all'AE (il flood nel frattempo aggiunge
    richieste alla finestra di osservazione). In caso di risposta 400 per
    PoW invalida il voto viene ricalcolato con la difficoltà aggiornata,
    fino a MAX_POW_RETRIES tentativi.
    """
    MAX_POW_RETRIES = 5
    try:
        seed         = os.urandom(32)
        vote_byte    = candidate_idx.to_bytes(1, "big")
        enc_vote     = encrypt(ae_pub_key, vote_byte, seed=seed)
        enc_seed     = encrypt(ae_pub_key, seed)
        enc_vote_hex = enc_vote.hex()

        t0 = time.perf_counter()

        for attempt in range(MAX_POW_RETRIES):
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
            )

            if r.status_code == 200:
                elapsed_ms = (time.perf_counter() - t0) * 1000
                receipt_path = os.path.join(RECEIPTS_DIR, f"{user['username']}.json")
                with open(receipt_path, "w", encoding="utf-8") as f:
                    json.dump(r.json(), f, indent=2)
                return True, elapsed_ms

            # Se la PoW non è più valida (difficoltà cambiata durante il calcolo)
            # si riprova immediatamente con la difficoltà aggiornata.
            if r.status_code == 400:
                try:
                    err = r.json().get("error", "")
                except Exception:
                    err = ""
                if "Proof of Work" in err or "PoW" in err:
                    continue  # retry con difficoltà aggiornata

            # Qualsiasi altro errore non è risolvibile con un retry
            elapsed_ms = (time.perf_counter() - t0) * 1000
            try:
                err_body = r.json()
            except Exception:
                err_body = r.text
            print(f"    [VOTO FALLITO] {user['username']}: HTTP {r.status_code} — {err_body}")
            return False, elapsed_ms

        # Esauriti i tentativi
        elapsed_ms = (time.perf_counter() - t0) * 1000
        print(f"    [VOTO FALLITO] {user['username']}: PoW invalida dopo {MAX_POW_RETRIES} tentativi")
        return False, elapsed_ms

    except Exception as e:
        print(f"    [ECCEZIONE VOTO] {user['username']}: {e}")
        return False, 0.0


# ---------------------------------------------------------------------------
# Flood dell'attaccante
# ---------------------------------------------------------------------------

class FloodController:
    """
    Gestisce il flood in background tramite thread daemon.
    Ogni thread invia continuamente richieste con PoW invalida all'AE,
    simulando una botnet che tenta di saturare il sistema.
    Il flood può essere fermato in qualsiasi momento con stop().
    """

    def __init__(self, n_threads: int):
        self.n_threads  = n_threads
        self.running    = False
        self._threads:  List[threading.Thread] = []
        self.sent       = 0      # Richieste totali inviate
        self.rejected   = 0      # Richieste rifiutate con HTTP 400 (PoW invalida)
        self._lock      = threading.Lock()

    def _worker(self) -> None:
        """Funzione eseguita da ogni thread del flood: invia richieste invalide in loop."""
        while self.running:
            # Il payload contiene dati casuali senza senso crittografico:
            # il nonce PoW fisso a zero non soddisferà mai i bit a zero richiesti.
            payload = {
                "enc_vote":        os.urandom(256).hex(),
                "enc_seed":        os.urandom(256).hex(),
                "token":           '{"nonce":"dead","expires_at":"2100-01-01T00:00:00+00:00"}',
                "token_signature": os.urandom(256).hex(),
                "pow_nonce":       "0000000000000000",  # PoW invalida
            }
            try:
                r = requests.post(f"{AE_URL}/vote", json=payload, timeout=3)
                with self._lock:
                    self.sent += 1
                    # Si conta ogni risposta 400 come richiesta bloccata dalla PoW.
                    if r.status_code == 400:
                        self.rejected += 1
            except Exception:
                with self._lock:
                    self.sent += 1

    def start(self) -> None:
        """Avvia i thread del flood in modalità daemon."""
        self.running = True
        for _ in range(self.n_threads):
            t = threading.Thread(target=self._worker, daemon=True)
            t.start()
            self._threads.append(t)

    def stop(self) -> None:
        """Ferma i thread del flood e attende la loro terminazione."""
        self.running = False
        for t in self._threads:
            t.join(timeout=5)


# ---------------------------------------------------------------------------
# Test principale
# ---------------------------------------------------------------------------

def main() -> None:
    os.chdir(PROJECT_ROOT)

    # Si esegue il setup: init elezione, avvio SA e AE.
    sa_proc, ae_proc, ctx = setup()
    ae_pub = ctx["ae_encrypt_public"]

    try:
        # ==================================================================
        # FASE 1 — Autenticazione utenti onesti (pre-attacco)
        # ==================================================================
        # Si autenticano tutti gli utenti onesti prima dell'attacco,
        # così da ottenere token validi che useranno durante il flood.
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
        # Il test si interrompe se anche un solo utente non si è autenticato.
        assert auth_success == len(HONEST_USERS), \
            "Non tutti gli utenti onesti si sono autenticati. Controlla SA e voters.json."

        # ==================================================================
        # FASE 2 — Attacco DoS concorrente + votazione onesti
        # ==================================================================
        # Si misurano la difficoltà PoW prima e durante l'attacco, e si
        # verifica che gli utenti onesti riescano a votare nonostante il flood.
        print("\n" + "=" * 70)
        print(f"  FASE 2 — Attacco DoS ({FLOOD_THREADS} thread) + votazione onesti")
        print("=" * 70)

        # Si registra la difficoltà di base prima dell'attacco.
        diff_before = get_pow_difficulty()
        print(f"\n  Difficoltà PoW prima dell'attacco: {diff_before} bit")

        # Si avvia il flood in background.
        flood = FloodController(FLOOD_THREADS)
        flood.start()
        print(f"  Flood avviato ({FLOOD_THREADS} thread con PoW invalida).")

        # Si attende che il flood saturi la finestra di osservazione dell'AE
        # e la difficoltà si stabilizzi prima di avviare la votazione.
        # Senza questa attesa la difficoltà può ancora salire mentre gli utenti
        # onesti stanno già calcolando la PoW, invalidando il nonce appena trovato.
        time.sleep(3)

        # Si misura la difficoltà durante l'attacco: deve essere maggiore
        # di quella di base (POW_MIN_DIFFICULTY).
        diff_during = get_pow_difficulty()
        print(f"  Difficoltà PoW durante l'attacco: {diff_during} bit")

        # Si avviano in parallelo i thread di voto degli utenti onesti
        # mentre il flood è ancora attivo, simulando l'uso reale del sistema
        # durante un attacco DoS.
        print(f"\n  Votazione degli utenti onesti (in parallelo con il flood)...")
        vote_results: Dict[str, Tuple[bool, float]] = {}
        vote_threads = []

        def do_vote(user: dict) -> None:
            """Wrapper per eseguire il voto di un utente in un thread separato."""
            token, sig = tokens[user["username"]]
            ok, ms = vote_user(user, token, sig, ae_pub, candidate_idx=0)
            vote_results[user["username"]] = (ok, ms)

        for user in HONEST_USERS:
            t = threading.Thread(target=do_vote, args=(user,))
            vote_threads.append(t)
            t.start()

        # Si attende che tutti i thread di voto abbiano completato.
        for t in vote_threads:
            t.join(timeout=120)

        # Si ferma il flood dopo che tutti gli utenti onesti hanno votato.
        flood.stop()
        print(f"\n  Flood fermato. Statistiche attacco:")
        print(f"    Richieste inviate:   {flood.sent}")
        print(f"    Rifiutate (400):     {flood.rejected}  "
              f"({flood.rejected/flood.sent*100:.1f}% del totale)" if flood.sent else "")

        # Si raccolgono i risultati dei voti degli utenti onesti.
        print(f"\n  Risultati votazione utenti onesti:")
        votes_ok  = 0
        times_ms  = []
        for username, (ok, ms) in vote_results.items():
            status = "OK  " if ok else "FAIL"
            print(f"    [{status}] {username}  ({ms:.0f} ms)")
            if ok:
                votes_ok += 1
                times_ms.append(ms)

        if times_ms:
            avg_ms = sum(times_ms) / len(times_ms)
            print(f"\n  Tempo medio voto onesto sotto attacco: {avg_ms:.0f} ms")

        # ==================================================================
        # FASE 3 — Recovery
        # ==================================================================
        # Si attende che la finestra di osservazione dell'AE scada
        # (RECOVERY_WAIT_SEC > POW_WINDOW_SECONDS) e si verifica che la
        # difficoltà ritorni al valore minimo di default.
        print("\n" + "=" * 70)
        print(f"  FASE 3 — Recovery (attesa {RECOVERY_WAIT_SEC:.0f}s)")
        print("=" * 70)
        print(f"  Attendo scadenza finestra...", end=" ", flush=True)
        time.sleep(RECOVERY_WAIT_SEC)
        print("OK")

        diff_after = get_pow_difficulty()
        print(f"  Difficoltà PoW dopo recovery: {diff_after} bit")

        # ==================================================================
        # RIEPILOGO
        # ==================================================================
        print("\n" + "=" * 70)
        print("  RIEPILOGO")
        print("=" * 70)

        # Si valutano cinque condizioni di successo distinte.
        p1      = auth_success == len(HONEST_USERS)    # Tutti autenticati
        p2_pow  = diff_during > diff_before             # Difficoltà aumentata sotto attacco
        p2_vote = votes_ok == len(HONEST_USERS)         # Tutti i voti onesti accettati
        p2_rej  = flood.sent > 0 and (flood.rejected / flood.sent) >= 0.85  # 85%+ rifiutate
        p3      = diff_after == POW_MIN_DIFFICULTY      # Difficoltà tornata al minimo

        def mark(cond): return "[PASS]" if cond else "[FAIL]"

        print(f"\n  {mark(p1)}  Fase 1 — tutti gli utenti onesti autenticati "
              f"({auth_success}/{len(HONEST_USERS)})")
        print(f"  {mark(p2_pow)}  Fase 2 — difficoltà PoW aumentata sotto attacco "
              f"({diff_before} → {diff_during} bit)")
        print(f"  {mark(p2_vote)} Fase 2 — tutti gli utenti onesti hanno votato "
              f"({votes_ok}/{len(HONEST_USERS)})")
        print(f"  {mark(p2_rej)}  Fase 2 — attacco bloccato dalla PoW invalida "
              f"({flood.rejected}/{flood.sent} rifiutate)")
        print(f"  {mark(p3)}  Fase 3 — difficoltà tornata al minimo dopo recovery "
              f"({diff_after} bit)")

        all_pass = p1 and p2_pow and p2_vote and p2_rej and p3
        print("\n" + ("=" * 70))
        if all_pass:
            print("\n  [SUCCESS] Il sistema ha resistito all'attacco DoS mantenendo")
            print("  la funzionalità per gli utenti onesti e ripristinando")
            print("  la difficoltà minima al cessare del traffico anomalo.")
            print(f"\n  Nota: il tempo medio di voto è aumentato a {round(sum(times_ms)/len(times_ms), 0):.0f} ms")
            print("  (contro i ~100-200 ms a sistema a riposo) perché la PoW adattiva")
            print("  penalizza anche gli utenti onesti, ma non li blocca.")
        else:
            print("\n  [ATTENZIONE] Uno o più controlli non sono stati superati.")
            print("  Consulta i dettagli sopra per identificare il problema.")
        print("=" * 70)

        save_report(
            test_id="dos_resilience",
            test_name="Resilienza DoS durante la votazione (WP2 Fase 3 / WP3 §2.4)",
            outcome="PASS" if all_pass else "FAIL",
            details={
                "flood_threads": FLOOD_THREADS,
                "flood_requests_sent": flood.sent,
                "flood_rejected_400": flood.rejected,
                "flood_rejection_rate_pct": round(flood.rejected / flood.sent * 100, 1) if flood.sent else 0,
                "pow_difficulty": {
                    "before_attack_bit": diff_before,
                    "during_attack_bit": diff_during,
                    "after_recovery_bit": diff_after,
                },
                "honest_users": {
                    "total": len(HONEST_USERS),
                    "authenticated": auth_success,
                    "voted_ok": votes_ok,
                    "vote_times_ms": {u: round(ms, 1) for u, (ok, ms) in vote_results.items()},
                    "avg_vote_time_ms": round(sum(times_ms) / len(times_ms), 1) if times_ms else None,
                },
                "checks": {
                    "p1_all_authenticated":     p1,
                    "p2_pow_increased":         p2_pow,
                    "p2_all_honest_voted":      p2_vote,
                    "p2_attack_blocked_85pct":  p2_rej,
                    "p3_difficulty_recovered":  p3,
                },
            },
        )

    finally:
        # Il teardown viene eseguito sempre, anche in caso di errore nel test.
        teardown(sa_proc, ae_proc)


if __name__ == "__main__":
    os.chdir(PROJECT_ROOT)
    try:
        main()
    except Exception as e:
        print(f"\n[ERRORE] {e}")
    finally:
        input("\nPremi Invio per chiudere...")

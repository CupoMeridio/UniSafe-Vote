"""
Test di verifica della PoW adattiva dell'AE (mitigazione DoS).

Questo test verifica che la difficoltà della Proof of Work aumenti
automaticamente SOLO sotto attacco volumetrico con PoW valida (botnet che
risolve davvero la PoW), e NON aumenti quando l'attaccante manda nonce
casuali (attacco spazzatura). La distinzione è fondamentale: un attaccante
spazzatura viene rifiutato immediatamente con 400 senza impatto sugli
elettori legittimi; solo chi risolve la PoW a raffica (e quindi possiede
risorse computazionali reali) merita una difficoltà più alta.

Il test verifica anche la recovery: dopo lo scadere della finestra di
osservazione la difficoltà torna al minimo.

Struttura del test:
    Setup      -  Inizializza l'elezione e avvia l'AE.
    Fase 1  -  Baseline: misura la difficoltà a sistema a riposo.
    Fase 2a -  Flood spazzatura: invia richieste con nonce casuale
               e verifica che la difficoltà NON aumenti.
    Fase 2b -  Flood valido: invia richieste con PoW correttamente
               risolta e verifica che la difficoltà aumenti.
    Fase 3  -  Difficoltà sotto carico (dopo flood valido).
    Fase 4  -  Recovery: attende lo scadere della finestra e verifica
               il ritorno alla difficoltà minima.
    Teardown -  Chiusura ordinata dell'AE.

Parametri AE di riferimento (src/ae.py):
    POW_MIN_DIFFICULTY  = 4    bit
    POW_MAX_DIFFICULTY  = 24   bit
    POW_WINDOW_SECONDS  = 10.0 s
    POW_RATE_THRESHOLD  = 5    richieste/finestra (con PoW valida)
"""

import os
import sys
import json
import time
import hashlib
import struct
import subprocess
import threading
import requests
from collections import Counter
from datetime import datetime, timedelta, UTC
from typing import List

# ---------------------------------------------------------------------------
# Path setup — il test gira da qualsiasi directory
# ---------------------------------------------------------------------------
PROJECT_ROOT  = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SRC_DIR       = os.path.join(PROJECT_ROOT, "src")
DATA_DIR      = os.path.join(PROJECT_ROOT, "data")
KEYS_DIR      = os.path.join(DATA_DIR, "keys")
TESTS_SEC_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SRC_DIR)
sys.path.insert(0, TESTS_SEC_DIR)

from test_reporter import save_report

from crypto.keys import (generate_rsa_keypair, save_keypair, serialize_public_key,
                          deserialize_public_key, save_encrypted_private_key)
from crypto.rsa_pss import sign
from crypto.password import hash_password
from cryptography.hazmat.primitives import serialization

# ---------------------------------------------------------------------------
# Configurazione
# ---------------------------------------------------------------------------
import sys as _sys
_sys.path.insert(0, os.path.join(PROJECT_ROOT, "tests"))
from tls_config import AE_URL, ae_verify, ensure_tls_certs

POW_MIN_DIFFICULTY  = 4
POW_RATE_THRESHOLD  = 5
POW_WINDOW_SECONDS  = 10.0

# Flood spazzatura: nonce casuali, nessuna PoW risolta
FLOOD_INVALID_REQUESTS = 60
FLOOD_INVALID_THREADS  = 20

# Flood valido: ogni richiesta risolve davvero la PoW corrente
# Deve superare la soglia per far salire la difficoltà in modo visibile
FLOOD_VALID_REQUESTS   = 30   # >> POW_RATE_THRESHOLD → difficoltà attesa = 4 + (30-5)//5 = 9 bit
FLOOD_VALID_THREADS    = 6

RECOVERY_WAIT_SEC   = 12.0
SERVER_STARTUP_SEC  = 15

VOTERS = [
    {"id": "v001", "email": "v.postiglione7@studenti.unisa.it",
     "username": "vitto.posti",  "password": "password123"},
    {"id": "v002", "email": "mattia.sanzari@unisa.it",
     "username": "matty.sanz",   "password": "password456"},
    {"id": "v003", "email": "c.deluca92@studenti.unisa.it",
     "username": "carlo.deluca", "password": "pass_cDL92"},
]
CANDIDATES = ["Lista A", "Lista B", "Lista C"]

ae_process = None


# ---------------------------------------------------------------------------
# Setup / Teardown
# ---------------------------------------------------------------------------

def _compute_fingerprint(pem_str: str) -> str:
    pubkey = deserialize_public_key(pem_str)
    der = pubkey.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return "sha256:" + hashlib.sha256(der).hexdigest()


def _wait_server(url: str, name: str, timeout: int = SERVER_STARTUP_SEC) -> bool:
    for _ in range(timeout * 2):
        try:
            if requests.get(f"{url}/status", timeout=0.5, verify=ae_verify()).status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(0.5)
    print(f"  [ERRORE] {name} non risponde dopo {timeout}s.")
    return False


def setup():
    """Inizializza l'elezione e avvia solo l'AE."""
    global ae_process

    print("\n[SETUP] Inizializzazione elezione...")

    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(KEYS_DIR, exist_ok=True)

    ensure_tls_certs()

    for fname in ["bulletin_board.json", "voters.json", "ae_state.json", "pins.json"]:
        p = os.path.join(DATA_DIR, fname)
        if os.path.exists(p):
            os.remove(p)
    for f in os.listdir(KEYS_DIR):
        if f == ".gitkeep":
            continue
        os.remove(os.path.join(KEYS_DIR, f))

    sa_sign_priv,  sa_sign_pub  = generate_rsa_keypair()
    ae_enc_priv,   ae_enc_pub   = generate_rsa_keypair()
    ae_sign_priv,  ae_sign_pub  = generate_rsa_keypair()

    save_keypair(sa_sign_priv, sa_sign_pub,  "sa_sign")
    save_keypair(ae_enc_priv,  ae_enc_pub,   "ae_encrypt")
    save_keypair(ae_sign_priv, ae_sign_pub,  "ae_sign")

    opening = datetime.now(UTC).isoformat()
    closing = (datetime.now(UTC) + timedelta(hours=24)).isoformat()

    init_data = {
        "election_id":       "pow_adaptive_test",
        "candidates":        CANDIDATES,
        "opening_time":      opening,
        "closing_time":      closing,
        "sa_sign_public":    serialize_public_key(sa_sign_pub),
        "ae_encrypt_public": serialize_public_key(ae_enc_pub),
        "ae_sign_public":    serialize_public_key(ae_sign_pub),
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

    pins = {
        "ae_encrypt_public": _compute_fingerprint(init_data["ae_encrypt_public"]),
        "ae_sign_public":    _compute_fingerprint(init_data["ae_sign_public"]),
    }
    with open(os.path.join(DATA_DIR, "pins.json"), "w", encoding="utf-8") as f:
        json.dump(pins, f, indent=2)

    save_encrypted_private_key(ae_enc_priv, "ae_encrypt", init_signature)

    voters_data = []
    for v in VOTERS:
        vc = v.copy()
        vc["password"] = hash_password(vc["password"])
        voters_data.append(vc)
    with open(os.path.join(DATA_DIR, "voters.json"), "w", encoding="utf-8") as f:
        json.dump(voters_data, f, indent=2)

    with open(os.path.join(DATA_DIR, "ae_state.json"), "w", encoding="utf-8") as f:
        json.dump({"used_tokens": []}, f, indent=2)

    ae_process = subprocess.Popen(
        [sys.executable, os.path.join(SRC_DIR, "ae.py")],
        cwd=PROJECT_ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    print(f"[SETUP] AE avviata (PID {ae_process.pid}), attendo...", end=" ", flush=True)
    assert _wait_server(AE_URL, "AE"), "AE non risponde."
    print("OK")


def teardown():
    """Chiude l'AE e pulisce i file di stato."""
    global ae_process
    print("\n[TEARDOWN] Chiusura AE...")
    try:
        requests.post(f"{AE_URL}/shutdown", timeout=1, verify=ae_verify())
    except Exception:
        pass
    if ae_process:
        try:
            ae_process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            ae_process.kill()
    print("[TEARDOWN] AE terminata.")
    # Pulizia dei file di stato lasciati dal test.
    for fname in ["bulletin_board.json", "voters.json", "ae_state.json", "pins.json"]:
        p = os.path.join(DATA_DIR, fname)
        if os.path.exists(p):
            os.remove(p)
    for f in os.listdir(KEYS_DIR):
        if f != ".gitkeep":
            os.remove(os.path.join(KEYS_DIR, f))
    print("[TEARDOWN] File di stato rimossi.")


# ---------------------------------------------------------------------------
# Utilità
# ---------------------------------------------------------------------------

def get_pow_status() -> dict:
    """Restituisce l'intero payload JSON di /status."""
    resp = requests.get(f"{AE_URL}/status", timeout=3, verify=ae_verify())
    resp.raise_for_status()
    return resp.json()


def get_pow_difficulty() -> int:
    return int(get_pow_status()["pow_difficulty"])


def solve_pow(enc_vote_hex: str, difficulty: int) -> str:
    """
    Risolve la Proof of Work: cerca un nonce a 64-bit tale che
    SHA-256(enc_vote || nonce) abbia i primi 'difficulty' bit a zero.

    Restituisce il nonce come stringa esadecimale (16 caratteri).
    """
    enc_vote_bytes = bytes.fromhex(enc_vote_hex)
    required_bytes = difficulty // 8
    required_bits  = difficulty % 8
    mask = (0xFF << (8 - required_bits)) & 0xFF if required_bits else 0

    for nonce_int in range(2 ** 64):
        nonce_bytes = struct.pack(">Q", nonce_int)
        digest = hashlib.sha256(enc_vote_bytes + nonce_bytes).digest()

        ok = all(digest[i] == 0 for i in range(required_bytes))
        if ok and (required_bits == 0 or (digest[required_bytes] & mask) == 0):
            return nonce_bytes.hex()

    raise RuntimeError("Nonce non trovato (difficoltà troppo alta?)")


def send_invalid_request(_: int) -> dict:
    """
    Invia una richiesta con PoW NON risolta (nonce casuale / spazzatura).
    Simula un attaccante DoS che non spende CPU per risolvere la PoW.
    L'AE deve rifiutarla con 400 senza incrementare il contatore adattivo.
    """
    payload = {
        "enc_vote":        os.urandom(256).hex(),
        "enc_seed":        os.urandom(256).hex(),
        "token":           '{"nonce":"deadbeef","expires_at":"2100-01-01T00:00:00+00:00"}',
        "token_signature": os.urandom(256).hex(),
        "pow_nonce":       "0000000000000000",  # nonce fisso, non risolve nulla
    }
    try:
        resp = requests.post(f"{AE_URL}/vote", json=payload, timeout=5, verify=ae_verify())
        body = resp.json() if resp.content else {}
        return {"status_code": resp.status_code, "body": body}
    except Exception as e:
        return {"status_code": 0, "body": {"error": str(e)}}


def send_valid_pow_request(req_id: int) -> dict:
    """
    Invia una richiesta con PoW CORRETTAMENTE risolta.
    Simula un attaccante sofisticato (botnet) che risolve davvero la PoW
    per superare il primo controllo dell'AE.
    La richiesta verrà comunque rifiutata (token invalido) ma il contatore
    adattivo DEVE essere incrementato perché la PoW era valida.
    """
    # Ottieni la difficoltà corrente prima di risolvere
    difficulty = get_pow_difficulty()

    enc_vote_hex = os.urandom(32).hex()   # payload fittizio ma coerente
    t_solve_start = time.monotonic()
    pow_nonce    = solve_pow(enc_vote_hex, difficulty)
    t_solve_end  = time.monotonic()

    payload = {
        "enc_vote":        enc_vote_hex,
        "enc_seed":        os.urandom(256).hex(),
        "token":           '{"nonce":"deadbeef","expires_at":"2100-01-01T00:00:00+00:00"}',
        "token_signature": os.urandom(256).hex(),   # firma invalida → rifiutato al passo 2
        "pow_nonce":       pow_nonce,
    }
    try:
        t_req_start = time.monotonic()
        resp = requests.post(f"{AE_URL}/vote", json=payload, timeout=10, verify=ae_verify())
        t_req_end   = time.monotonic()
        body = resp.json() if resp.content else {}
        return {
            "status_code":    resp.status_code,
            "body":           body,
            "difficulty_used": difficulty,
            "solve_ms":       round((t_solve_end - t_solve_start) * 1000, 1),
            "request_ms":     round((t_req_end   - t_req_start)  * 1000, 1),
        }
    except Exception as e:
        return {
            "status_code":    0,
            "body":           {"error": str(e)},
            "difficulty_used": difficulty,
            "solve_ms":       0,
            "request_ms":     0,
        }


def flood(n_requests: int, n_threads: int, sender_fn) -> List[dict]:
    """Esegue un flood usando la funzione sender_fn per ogni richiesta."""
    results: List[dict] = []
    lock = threading.Lock()

    def worker(req_id: int) -> None:
        result = sender_fn(req_id)
        with lock:
            results.append(result)

    threads = []
    for i in range(n_requests):
        t = threading.Thread(target=worker, args=(i,), daemon=True)
        threads.append(t)
        if len([th for th in threads if th.is_alive()]) >= n_threads:
            time.sleep(0.01)
        t.start()

    for t in threads:
        t.join(timeout=30)

    return results


# ---------------------------------------------------------------------------
# Test principale
# ---------------------------------------------------------------------------

def main() -> None:
    global ae_process
    print("=" * 70)
    print("  TEST POW ADATTIVA — MITIGAZIONE DoS SELETTIVA (WP2 Fase 3 / WP3 §2.4)")
    print("=" * 70)
    print()
    print("  Principio: la difficoltà aumenta SOLO per richieste con PoW valida.")
    print("  Un flood di nonce casuali (spazzatura) NON deve alzare la difficoltà.")
    try:
        setup()

        # ------------------------------------------------------------------ #
        # FASE 1 — Baseline                                                   #
        # ------------------------------------------------------------------ #
        print("\n" + "-" * 70)
        print("FASE 1 — Baseline (sistema a riposo)")
        print("-" * 70)
        print(f"  Attendo {RECOVERY_WAIT_SEC:.0f}s per azzerare la finestra di osservazione...",
              end=" ", flush=True)
        time.sleep(RECOVERY_WAIT_SEC)
        print("OK")

        baseline_status = get_pow_status()
        baseline_difficulty = int(baseline_status["pow_difficulty"])
        print(f"  Risposta /status (raw): {json.dumps(baseline_status)}")
        print(f"  Difficoltà PoW baseline: {baseline_difficulty} bit  "
              f"(attesa: {POW_MIN_DIFFICULTY} bit)")

        # ------------------------------------------------------------------ #
        # FASE 2a — Flood spazzatura (PoW invalida)                           #
        # ------------------------------------------------------------------ #
        print("\n" + "-" * 70)
        print(f"FASE 2a — Flood SPAZZATURA ({FLOOD_INVALID_REQUESTS} richieste con nonce casuale)")
        print("-" * 70)
        print("  Proprietà attesa: la difficoltà NON deve aumentare.")
        print("  Invio richieste con nonce non risolto...", end=" ", flush=True)

        t0 = time.monotonic()
        results_invalid = flood(FLOOD_INVALID_REQUESTS, FLOOD_INVALID_THREADS, send_invalid_request)
        t1 = time.monotonic()
        print("completato")

        status_invalid = Counter(r["status_code"] for r in results_invalid)
        print(f"\n  Durata flood:   {t1 - t0:.2f}s")
        print(f"  Totale:         {len(results_invalid)} richieste")
        print(f"  Distribuzione HTTP:")
        for code, cnt in sorted(status_invalid.items()):
            print(f"    HTTP {code}: {cnt:3d}  ({cnt/len(results_invalid)*100:.1f}%)")

        after_invalid_status = get_pow_status()
        after_invalid_difficulty = int(after_invalid_status["pow_difficulty"])
        print(f"\n  Risposta /status dopo flood spazzatura: {json.dumps(after_invalid_status)}")
        print(f"  Difficoltà dopo flood spazzatura: {after_invalid_difficulty} bit")

        phase2a_pass = after_invalid_difficulty == POW_MIN_DIFFICULTY
        if phase2a_pass:
            print(f"  [PASS] La difficoltà è rimasta al minimo ({POW_MIN_DIFFICULTY} bit): "
                  f"le richieste spazzatura non impattano gli elettori legittimi.")
        else:
            print(f"  [FAIL] La difficoltà è aumentata a {after_invalid_difficulty} bit "
                  f"nonostante il flood fosse di pura spazzatura.")

        # Pausa per azzerare la finestra prima del flood valido
        print(f"\n  Attendo {RECOVERY_WAIT_SEC:.0f}s per azzerare la finestra...",
              end=" ", flush=True)
        time.sleep(RECOVERY_WAIT_SEC)
        print("OK")

        # ------------------------------------------------------------------ #
        # FASE 2b — Flood valido (PoW correttamente risolta)                  #
        # ------------------------------------------------------------------ #
        print("\n" + "-" * 70)
        print(f"FASE 2b — Flood VALIDO ({FLOOD_VALID_REQUESTS} richieste con PoW risolta)")
        print("-" * 70)
        print("  Proprietà attesa: la difficoltà DEVE aumentare.")
        print("  Risolvo la PoW per ogni richiesta (può richiedere qualche secondo)...",
              end=" ", flush=True)

        t2 = time.monotonic()
        results_valid = flood(FLOOD_VALID_REQUESTS, FLOOD_VALID_THREADS, send_valid_pow_request)
        t3 = time.monotonic()
        print("completato")

        status_valid = Counter(r["status_code"] for r in results_valid)
        difficulties_used = [r.get("difficulty_used", POW_MIN_DIFFICULTY) for r in results_valid]
        solve_times   = [r["solve_ms"]   for r in results_valid if r["solve_ms"]   > 0]
        request_times = [r["request_ms"] for r in results_valid if r["request_ms"] > 0]
        print(f"\n  Durata flood:   {t3 - t2:.2f}s")
        print(f"  Totale:         {len(results_valid)} richieste")
        print(f"  Distribuzione HTTP:")
        for code, cnt in sorted(status_valid.items()):
            label = "PoW ok, token invalido (atteso)" if code == 401 else \
                    "PoW invalida (inatteso)"         if code == 400 else "altro"
            print(f"    HTTP {code}: {cnt:3d}  ({cnt/len(results_valid)*100:.1f}%)  — {label}")
        print(f"  Difficoltà usate per risolvere la PoW: {sorted(set(difficulties_used))}")
        if solve_times:
            print(f"  Tempo medio risoluzione PoW: {sum(solve_times)/len(solve_times):.1f} ms  "
                  f"(min {min(solve_times):.1f} ms, max {max(solve_times):.1f} ms)")
        if request_times:
            print(f"  Tempo medio risposta AE:     {sum(request_times)/len(request_times):.1f} ms  "
                  f"(min {min(request_times):.1f} ms, max {max(request_times):.1f} ms)")

        # Campione di risposte per evidenza
        samples = results_valid[:3]
        print(f"\n  Campione risposte (prime {len(samples)}):")
        for s in samples:
            print(f"    HTTP {s['status_code']}: {json.dumps(s['body'])}")

        # ------------------------------------------------------------------ #
        # FASE 3 — Difficoltà sotto carico                                    #
        # ------------------------------------------------------------------ #
        print("\n" + "-" * 70)
        print("FASE 3 — Difficoltà sotto carico (dopo flood valido)")
        print("-" * 70)

        attack_status = get_pow_status()
        attack_difficulty = int(attack_status["pow_difficulty"])
        print(f"  Risposta /status (raw): {json.dumps(attack_status)}")
        print(f"  Difficoltà PoW durante/dopo flood valido: {attack_difficulty} bit")

        expected_extra = (FLOOD_VALID_REQUESTS - POW_RATE_THRESHOLD) // POW_RATE_THRESHOLD
        expected_difficulty = min(POW_MIN_DIFFICULTY + expected_extra, 24)
        print(f"  Difficoltà attesa (formula AE): {expected_difficulty} bit  "
              f"[min={POW_MIN_DIFFICULTY} + extra={expected_extra} "
              f"= ({FLOOD_VALID_REQUESTS}-{POW_RATE_THRESHOLD})//{POW_RATE_THRESHOLD}, cap=24]")
        print(f"  Delta rispetto alla baseline: "
              f"{baseline_difficulty} → {attack_difficulty} bit  "
              f"(+{attack_difficulty - baseline_difficulty})")

        phase3_pass = attack_difficulty > POW_MIN_DIFFICULTY
        if phase3_pass:
            print(f"  [PASS] La difficoltà è aumentata: {baseline_difficulty} → {attack_difficulty} bit")
        else:
            print(f"  [FAIL] La difficoltà non è aumentata nonostante il flood valido.")

        # ------------------------------------------------------------------ #
        # FASE 4 — Recovery                                                   #
        # ------------------------------------------------------------------ #
        print("\n" + "-" * 70)
        print(f"FASE 4 — Recovery (attesa {RECOVERY_WAIT_SEC:.0f}s per scadenza finestra)")
        print("-" * 70)
        print(f"  Attendo {RECOVERY_WAIT_SEC:.0f}s...", end=" ", flush=True)
        time.sleep(RECOVERY_WAIT_SEC)
        print("OK")

        recovery_status = get_pow_status()
        recovery_difficulty = int(recovery_status["pow_difficulty"])
        print(f"  Risposta /status (raw): {json.dumps(recovery_status)}")
        print(f"  Difficoltà PoW dopo recovery: {recovery_difficulty} bit  "
              f"(attesa: {POW_MIN_DIFFICULTY} bit)")

        phase4_pass = recovery_difficulty == POW_MIN_DIFFICULTY
        if phase4_pass:
            print(f"  [PASS] La difficoltà è tornata al minimo ({POW_MIN_DIFFICULTY} bit).")
        else:
            print(f"  [FAIL] La difficoltà non è tornata al minimo atteso ({POW_MIN_DIFFICULTY} bit).")

        # ------------------------------------------------------------------ #
        # Riepilogo                                                           #
        # ------------------------------------------------------------------ #
        print("\n" + "=" * 70)
        print("RIEPILOGO")
        print("=" * 70)
        print(f"  Baseline:                           {baseline_difficulty} bit")
        print(f"  Dopo flood SPAZZATURA (no PoW):     {after_invalid_difficulty} bit  "
              f"({'invariata ✓' if phase2a_pass else 'aumentata ✗'})")
        print(f"  Dopo flood VALIDO (PoW risolta):    {attack_difficulty} bit  "
              f"({'aumentata ✓' if phase3_pass else 'invariata ✗'})")
        print(f"  Dopo recovery:                      {recovery_difficulty} bit  "
              f"({'tornata al minimo ✓' if phase4_pass else 'non recuperata ✗'})")
        print(f"  Flood spazzatura rifiutate (400):   "
              f"{status_invalid.get(400,0)}/{len(results_invalid)}")
        print(f"  Flood valido superano PoW (401):    "
              f"{status_valid.get(401,0)}/{len(results_valid)}")

        all_pass = phase2a_pass and phase3_pass and phase4_pass
        if all_pass:
            print("\n  [SUCCESS] PoW adattiva selettiva funziona correttamente:")
            print("    - Il flood spazzatura non alza la difficoltà (elettori protetti).")
            print("    - Il flood valido alza la difficoltà (botnet rallentata).")
            print("    - La difficoltà torna al minimo al cessare del traffico anomalo.")
        else:
            if not phase2a_pass:
                print("\n  [FAIL] Il flood spazzatura ha alzato la difficoltà.")
                print("    Verificare che request_timestamps.append sia DOPO verify_pow in ae.py.")
            if not phase3_pass:
                print("\n  [FAIL] Il flood valido non ha alzato la difficoltà.")
                print(f"    Verificare che FLOOD_VALID_REQUESTS ({FLOOD_VALID_REQUESTS}) "
                      f"> POW_RATE_THRESHOLD ({POW_RATE_THRESHOLD}).")
            if not phase4_pass:
                print("\n  [FAIL] La difficoltà non è tornata al minimo.")
                print("    Verificare che RECOVERY_WAIT_SEC > POW_WINDOW_SECONDS del server.")

        # ------------------------------------------------------------------ #
        # Analisi dell'efficacia della PoW adattiva                          #
        # ------------------------------------------------------------------ #
        print("\n" + "=" * 70)
        print("ANALISI — EFFICACIA DELLA PoW ADATTIVA")
        print("=" * 70)
        print("""
  ATTACCO CON NONCE VALIDO (botnet che risolve la PoW)
  -----------------------------------------------------
  Un attaccante sofisticato che dispone di risorse computazionali può
  risolvere la PoW e inviare richieste strutturalmente valide fino alla
  verifica del token SA (operazione RSA-PSS, ben più costosa di SHA-256).
  In questo scenario la PoW adattiva è efficace:

    - Ogni richiesta valida viene conteggiata nella finestra di osservazione.
    - Al superamento della soglia la difficoltà cresce di 1 bit per ogni
      blocco aggiuntivo di richieste (crescita esponenziale del costo CPU).
    - Il costo di risoluzione raddoppia ad ogni bit: a difficoltà 9 bit
      occorrono in media ~256 volte più tentativi rispetto a difficoltà 4 bit.
    - L'attaccante deve investire risorse reali per sostenere il flood,
      rendendo l'attacco economicamente costoso.

  ATTACCO CON NONCE NON VALIDO (flood di spazzatura)
  ---------------------------------------------------
  Un attaccante che invia nonce casuali senza risolvere la PoW viene
  rifiutato immediatamente al primo controllo (verify_pow → HTTP 400),
  prima di qualsiasi operazione costosa lato server. Il costo per l'AE
  è minimo: un singolo SHA-256 e un return 400.

  Poiché queste richieste non superano la verifica PoW, NON vengono
  conteggiate nella finestra adattiva e NON alzano la difficoltà.
  Gli elettori legittimi non subiscono alcun impatto.

  La PoW adattiva NON rallenta questo tipo di attaccante: lui continua
  a inviare spazzatura allo stesso ritmo indipendentemente dalla difficoltà,
  poiché non risolve mai nulla. La difesa qui è semplicemente il rifiuto
  immediato e a basso costo.

  LIMITAZIONE — RATE LIMITING PER IP
  ------------------------------------
  La contromisura più efficace contro il flood di spazzatura sarebbe un
  rate limiting per indirizzo IP: dopo N richieste rifiutate dallo stesso
  IP in una finestra temporale, l'AE bloccherebbe ulteriori richieste.

  Tuttavia, in questo sistema di voto elettronico il rate limiting per IP
  è incompatibile con il modello di privacy adottato:

    - Il sistema separa deliberatamente SA e AE: il SA sa chi vota (identità)
      ma non cosa vota; l'AE sa cosa vota (scheda cifrata) ma non chi è
      l'elettore. Nessuna delle due entità possiede entrambe le informazioni.
    - Se l'AE tracciasse gli indirizzi IP, potrebbe correlare IP → identità
      (specialmente in una rete universitaria dove ogni utente ha IP fisso),
      violando la separazione SA/AE e compromettendo l'anonimato del voto.
    - Un IP è spesso sufficiente per risalire all'identità in un contesto
      istituzionale, anche in assenza di nome o username espliciti.

  La PoW adattiva è quindi la scelta progettuale motivata da questo vincolo:
  è l'unico meccanismo di mitigazione DoS che non richiede all'AE di
  osservare alcuna informazione sull'identità del mittente, preservando
  la proprietà di anonimato del sistema.
""")
        print("=" * 70)

        outcome = "PASS" if all_pass else (
            "PARTIAL" if (phase3_pass or phase4_pass or phase2a_pass) else "FAIL"
        )
        save_report(
            test_id="pow_adaptive",
            test_name="PoW Adattiva Selettiva — Spazzatura vs Flood Valido (WP2 Fase 3 / WP3 §2.4)",
            outcome=outcome,
            details={
                "flood_invalid_requests": FLOOD_INVALID_REQUESTS,
                "flood_valid_requests":   FLOOD_VALID_REQUESTS,
                "flood_valid_threads":    FLOOD_VALID_THREADS,
                "recovery_wait_sec":      RECOVERY_WAIT_SEC,
                "phases": {
                    "baseline_difficulty_bit":       baseline_difficulty,
                    "after_invalid_flood_bit":       after_invalid_difficulty,
                    "attack_difficulty_bit":         attack_difficulty,
                    "recovery_difficulty_bit":       recovery_difficulty,
                    "expected_attack_difficulty_bit": expected_difficulty,
                },
                "flood_invalid": {
                    "total_requests":     len(results_invalid),
                    "status_distribution": {str(k): v for k, v in sorted(status_invalid.items())},
                },
                "flood_valid": {
                    "total_requests":     len(results_valid),
                    "status_distribution": {str(k): v for k, v in sorted(status_valid.items())},
                    "difficulties_used":  sorted(set(difficulties_used)),
                    "solve_time_ms": {
                        "avg": round(sum(solve_times)/len(solve_times), 1) if solve_times else 0,
                        "min": min(solve_times) if solve_times else 0,
                        "max": max(solve_times) if solve_times else 0,
                    },
                    "request_time_ms": {
                        "avg": round(sum(request_times)/len(request_times), 1) if request_times else 0,
                        "min": min(request_times) if request_times else 0,
                        "max": max(request_times) if request_times else 0,
                    },
                },
                "checks": {
                    "phase2a_invalid_flood_no_increase": phase2a_pass,
                    "phase3_valid_flood_increases":      phase3_pass,
                    "phase4_difficulty_recovered":       phase4_pass,
                },
                "ae_status_baseline":      baseline_status,
                "ae_status_after_invalid": after_invalid_status,
                "ae_status_attack":        attack_status,
                "ae_status_recovery":      recovery_status,
            },
        )

    finally:
        teardown()


if __name__ == "__main__":
    os.chdir(PROJECT_ROOT)
    try:
        main()
    except Exception as e:
        print(f"\n[ERRORE] {e}")
    finally:
        input("\nPremi Invio per chiudere...")

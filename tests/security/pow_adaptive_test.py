"""
Test di verifica della PoW adattiva dell'AE (mitigazione DoS).

Questo test verifica che la difficoltà della Proof of Work aumenti
automaticamente sotto attacco volumetrico e torni al minimo al cessare
del traffico anomalo, in accordo con quanto descritto in WP2 (Fase 3 -
Proof of Work Adattiva Globale) e WP3 (§2.4 - Avversario Esterno Attivo).

Struttura del test:
    Setup    -    Inizializza l'elezione e avvia l'AE.
    Fase 1 - Baseline:    misura la difficoltà a sistema a riposo.
    Fase 2 - Attacco:     invia un flood di richieste con PoW invalida
                          per saturare la finestra di osservazione dell'AE.
    Fase 3 - Sotto carico: misura la difficoltà durante il flood.
    Fase 4 - Recovery:    attende lo scadere della finestra (POW_WINDOW_SECONDS)
                          e misura la difficoltà dopo il ritorno alla normalità.
    Teardown -    Chiusura ordinata dell'AE.

Parametri AE di riferimento (src/ae.py):
    POW_MIN_DIFFICULTY  = 4    bit
    POW_MAX_DIFFICULTY  = 24   bit
    POW_WINDOW_SECONDS  = 10.0 s
    POW_RATE_THRESHOLD  = 5    richieste/finestra
"""

import os
import sys
import json
import time
import hashlib
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
AE_URL              = "http://localhost:5002"
POW_MIN_DIFFICULTY  = 4
POW_RATE_THRESHOLD  = 5
POW_WINDOW_SECONDS  = 10.0

FLOOD_REQUESTS      = 60
FLOOD_THREADS       = 20
RECOVERY_WAIT_SEC   = 12.0

SERVER_STARTUP_SEC  = 6

VOTERS = [
    {"id": "v001", "email": "mario.rossi@studenti.unisa.it",
     "username": "mario.rossi",   "password": "password123"},
    {"id": "v002", "email": "luigi.bianchi@unisa.it",
     "username": "luigi.bianchi", "password": "password456"},
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
            if requests.get(f"{url}/status", timeout=0.5).status_code == 200:
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

    for fname in ["bulletin_board.json", "voters.json", "ae_state.json", "pins.json"]:
        p = os.path.join(DATA_DIR, fname)
        if os.path.exists(p):
            os.remove(p)
    for f in os.listdir(KEYS_DIR):
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
    """Chiude l'AE."""
    global ae_process
    print("\n[TEARDOWN] Chiusura AE...")
    try:
        requests.post(f"{AE_URL}/shutdown", timeout=1)
    except Exception:
        pass
    if ae_process:
        try:
            ae_process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            ae_process.kill()
    print("[TEARDOWN] AE terminata.")


# ---------------------------------------------------------------------------
# Utilità
# ---------------------------------------------------------------------------

def get_pow_status() -> dict:
    """Restituisce l'intero payload JSON di /status per mostrare evidenza raw."""
    resp = requests.get(f"{AE_URL}/status", timeout=3)
    resp.raise_for_status()
    return resp.json()


def get_pow_difficulty() -> int:
    return int(get_pow_status()["pow_difficulty"])


def send_invalid_request(_: int) -> dict:
    """
    Invia una singola richiesta di attacco con PoW invalida.
    Restituisce un dizionario con status_code e body della risposta.
    """
    payload = {
        "enc_vote":        os.urandom(256).hex(),
        "enc_seed":        os.urandom(256).hex(),
        "token":           '{"nonce":"deadbeef","expires_at":"2100-01-01T00:00:00+00:00"}',
        "token_signature": os.urandom(256).hex(),
        "pow_nonce":       "0000000000000000",
    }
    try:
        resp = requests.post(f"{AE_URL}/vote", json=payload, timeout=5)
        body = resp.json() if resp.content else {}
        return {"status_code": resp.status_code, "body": body}
    except Exception as e:
        return {"status_code": 0, "body": {"error": str(e)}}


def flood(n_requests: int, n_threads: int) -> List[dict]:
    results: List[dict] = []
    lock = threading.Lock()

    def worker(req_id: int) -> None:
        result = send_invalid_request(req_id)
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
        t.join(timeout=10)

    return results


# ---------------------------------------------------------------------------
# Test principale
# ---------------------------------------------------------------------------

def main() -> None:
    global ae_process
    try:
        setup()

        print("=" * 70)
        print("  TEST POW ADATTIVA — MITIGAZIONE DoS (WP2 Fase 3 / WP3 §2.4)")
        print("=" * 70)

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

        if baseline_difficulty != POW_MIN_DIFFICULTY:
            print(f"  [WARN] Difficoltà attesa a riposo: {POW_MIN_DIFFICULTY} bit, "
                  f"server riporta: {baseline_difficulty} bit.")

        # ------------------------------------------------------------------ #
        # FASE 2 — Flood                                                      #
        # ------------------------------------------------------------------ #
        print("\n" + "-" * 70)
        print(f"FASE 2 — Flood ({FLOOD_REQUESTS} richieste, {FLOOD_THREADS} thread)")
        print("-" * 70)
        print("  Invio richieste con PoW invalida...", end=" ", flush=True)

        t_flood_start = time.monotonic()
        results = flood(FLOOD_REQUESTS, FLOOD_THREADS)
        t_flood_end = time.monotonic()
        print("completato")

        # Conta e distribuisce i codici di stato
        status_counts = Counter(r["status_code"] for r in results)
        rejected_400 = status_counts.get(400, 0)

        print(f"\n  Durata flood:            {t_flood_end - t_flood_start:.2f}s")
        print(f"  Richieste totali:        {len(results)}")
        print(f"  Distribuzione codici HTTP ricevuti:")
        for code, cnt in sorted(status_counts.items()):
            label = "✓ rifiutata (PoW invalida)" if code == 400 else "altro"
            print(f"    HTTP {code}: {cnt:3d} richieste  ({cnt/len(results)*100:.1f}%)  — {label}")

        # Mostra un campione di risposte JSON per dimostrare il motivo del rifiuto
        samples_400 = [r for r in results if r["status_code"] == 400][:3]
        samples_other = [r for r in results if r["status_code"] != 400][:3]
        if samples_400:
            print(f"\n  Campione risposte HTTP 400 (prime {len(samples_400)}):")
            for s in samples_400:
                print(f"    {json.dumps(s['body'])}")
        if samples_other:
            print(f"\n  Campione risposte NON-400:")
            for s in samples_other:
                print(f"    HTTP {s['status_code']}: {json.dumps(s['body'])}")

        # ------------------------------------------------------------------ #
        # FASE 3 — Difficoltà sotto carico                                    #
        # ------------------------------------------------------------------ #
        print("\n" + "-" * 70)
        print("FASE 3 — Difficoltà sotto carico")
        print("-" * 70)

        attack_status = get_pow_status()
        attack_difficulty = int(attack_status["pow_difficulty"])
        print(f"  Risposta /status (raw): {json.dumps(attack_status)}")
        print(f"  Difficoltà PoW durante/dopo il flood: {attack_difficulty} bit")

        expected_extra = (FLOOD_REQUESTS - POW_RATE_THRESHOLD) // POW_RATE_THRESHOLD
        expected_difficulty = min(POW_MIN_DIFFICULTY + expected_extra, 24)
        print(f"  Difficoltà attesa (formula AE):       {expected_difficulty} bit  "
              f"[min={POW_MIN_DIFFICULTY} + extra={expected_extra}, cap=24]")
        print(f"  Delta rispetto alla baseline:         "
              f"{baseline_difficulty} → {attack_difficulty} bit  "
              f"(+{attack_difficulty - baseline_difficulty})")

        if attack_difficulty > POW_MIN_DIFFICULTY:
            print(f"  [PASS] La difficoltà è aumentata: {baseline_difficulty} → {attack_difficulty} bit")
        else:
            print(f"  [FAIL] La difficoltà non è aumentata come atteso.")

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

        if recovery_difficulty == POW_MIN_DIFFICULTY:
            print(f"  [PASS] La difficoltà è tornata al minimo ({POW_MIN_DIFFICULTY} bit).")
        else:
            print(f"  [FAIL] La difficoltà non è tornata al minimo atteso ({POW_MIN_DIFFICULTY} bit).")

        # ------------------------------------------------------------------ #
        # Riepilogo                                                           #
        # ------------------------------------------------------------------ #
        print("\n" + "=" * 70)
        print("RIEPILOGO")
        print("=" * 70)
        print(f"  Baseline:       {baseline_difficulty} bit")
        print(f"  Sotto attacco:  {attack_difficulty} bit")
        print(f"  Dopo recovery:  {recovery_difficulty} bit")
        print(f"  Rifiutate 400:  {rejected_400}/{len(results)} ({rejected_400/len(results)*100:.1f}%)")

        phase3_pass = attack_difficulty > POW_MIN_DIFFICULTY
        phase4_pass = recovery_difficulty == POW_MIN_DIFFICULTY

        if phase3_pass and phase4_pass:
            print("\n  [SUCCESS] PoW adattiva funziona correttamente:")
            print("    - La difficoltà aumenta sotto attacco volumetrico.")
            print("    - La difficoltà torna al minimo al cessare del traffico anomalo.")
        elif phase3_pass and not phase4_pass:
            print("\n  [PARZIALE] La difficoltà è aumentata ma non è tornata al minimo.")
            print("    Verifica che RECOVERY_WAIT_SEC > POW_WINDOW_SECONDS del server.")
        elif not phase3_pass and phase4_pass:
            print("\n  [PARZIALE] La difficoltà non è aumentata durante il flood.")
            print("    Verifica che FLOOD_REQUESTS > POW_RATE_THRESHOLD del server.")
        else:
            print("\n  [FAIL] Il comportamento adattivo non è stato rilevato.")

        print("=" * 70)

        outcome = "PASS" if (phase3_pass and phase4_pass) else ("PARTIAL" if (phase3_pass or phase4_pass) else "FAIL")
        save_report(
            test_id="pow_adaptive",
            test_name="PoW Adattiva — Aumento e Recovery della Difficoltà (WP2 Fase 3 / WP3 §2.4)",
            outcome=outcome,
            details={
                "flood_requests": FLOOD_REQUESTS,
                "flood_threads": FLOOD_THREADS,
                "recovery_wait_sec": RECOVERY_WAIT_SEC,
                "phases": {
                    "baseline_difficulty_bit":  baseline_difficulty,
                    "attack_difficulty_bit":    attack_difficulty,
                    "recovery_difficulty_bit":  recovery_difficulty,
                    "expected_difficulty_bit":  expected_difficulty,
                },
                "flood": {
                    "total_requests":   len(results),
                    "rejected_400":     rejected_400,
                    "rejection_rate_pct": round(rejected_400 / len(results) * 100, 1),
                    "status_distribution": {str(k): v for k, v in sorted(status_counts.items())},
                },
                "checks": {
                    "phase3_difficulty_increased": phase3_pass,
                    "phase4_difficulty_recovered": phase4_pass,
                },
                "ae_status_baseline":  baseline_status,
                "ae_status_attack":    attack_status,
                "ae_status_recovery":  recovery_status,
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

"""
Script di test per Volumetric Spamming & Naive DoS (Bypass della Proof of Work)
Simula una botnet che invia 500 richieste concorrenti con PoW invalida all'AE.
"""

import os
import sys
import json
import random
import time
import subprocess
import concurrent.futures
import requests
from collections import defaultdict
from datetime import datetime, timedelta, UTC

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
import hashlib

# Numero totale di richieste di attacco da inviare e thread concorrenti.
AE_URL = "http://localhost:5002/vote"
NUM_REQUESTS = 500
NUM_THREADS = 50

# Secondi di attesa affinché il server Flask sia pronto dopo l'avvio.
SERVER_STARTUP_SEC = 6

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
    """Calcola l'impronta SHA-256 DER della chiave pubblica per il certificate pinning."""
    pubkey = deserialize_public_key(pem_str)
    der = pubkey.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return "sha256:" + hashlib.sha256(der).hexdigest()


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


def setup():
    """Inizializza l'elezione e avvia solo l'AE (il SA non è necessario per questo test)."""
    global ae_process

    print("\n[SETUP] Inizializzazione elezione...")

    # Si creano le directory necessarie e si elimina ogni stato residuo
    # di esecuzioni precedenti per garantire riproducibilità.
    os.makedirs(DATA_DIR,  exist_ok=True)
    os.makedirs(KEYS_DIR,  exist_ok=True)

    for fname in ["bulletin_board.json", "voters.json", "ae_state.json", "pins.json"]:
        p = os.path.join(DATA_DIR, fname)
        if os.path.exists(p):
            os.remove(p)
    for f in os.listdir(KEYS_DIR):
        os.remove(os.path.join(KEYS_DIR, f))

    # Si generano tre coppie RSA-2048 distinte per SA, cifratura AE e firma AE.
    sa_sign_priv,  sa_sign_pub  = generate_rsa_keypair()
    ae_enc_priv,   ae_enc_pub   = generate_rsa_keypair()
    ae_sign_priv,  ae_sign_pub  = generate_rsa_keypair()

    save_keypair(sa_sign_priv, sa_sign_pub,  "sa_sign")
    save_keypair(ae_enc_priv,  ae_enc_pub,   "ae_encrypt")
    save_keypair(ae_sign_priv, ae_sign_pub,  "ae_sign")

    # L'elezione è aperta immediatamente e chiude tra 24 ore,
    # così i voti di test non vengono rifiutati per finestra temporale scaduta.
    opening = datetime.now(UTC).isoformat()
    closing = (datetime.now(UTC) + timedelta(hours=24)).isoformat()

    # Si compone il blocco di inizializzazione con i parametri pubblici
    # dell'elezione e lo si firma con la chiave di firma dell'AE.
    init_data = {
        "election_id":       "dos_attack_test",
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

    # Si calcolano le impronte delle chiavi pubbliche AE e si salvano in pins.json
    # per simulare il canale di distribuzione trusted (certificate pinning).
    pins = {
        "ae_encrypt_public": _compute_fingerprint(init_data["ae_encrypt_public"]),
        "ae_sign_public":    _compute_fingerprint(init_data["ae_sign_public"]),
    }
    with open(os.path.join(DATA_DIR, "pins.json"), "w", encoding="utf-8") as f:
        json.dump(pins, f, indent=2)

    # La chiave privata di cifratura viene salvata cifrata con AES-GCM,
    # usando la firma del blocco init come IKM (vincolo crittografico WP3 §3.3).
    save_encrypted_private_key(ae_enc_priv, "ae_encrypt", init_signature)

    # Le password vengono salvate come hash Argon2, mai in chiaro.
    voters_data = []
    for v in VOTERS:
        vc = v.copy()
        vc["password"] = hash_password(vc["password"])
        voters_data.append(vc)
    with open(os.path.join(DATA_DIR, "voters.json"), "w", encoding="utf-8") as f:
        json.dump(voters_data, f, indent=2)

    # Si inizializza lo stato privato dell'AE (lista token usati vuota).
    with open(os.path.join(DATA_DIR, "ae_state.json"), "w", encoding="utf-8") as f:
        json.dump({"used_tokens": []}, f, indent=2)

    # Si avvia l'AE come sottoprocesso separato con output soppresso,
    # e si attende che Flask risponda prima di procedere con il test.
    ae_process = subprocess.Popen(
        [sys.executable, os.path.join(SRC_DIR, "ae.py")],
        cwd=PROJECT_ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    print(f"[SETUP] AE avviata (PID {ae_process.pid}), attendo...", end=" ", flush=True)
    assert _wait_server("http://localhost:5002", "AE"), "AE non risponde."
    print("OK")


def teardown():
    """Invia il segnale di shutdown all'AE e termina il processo."""
    global ae_process
    print("\n[TEARDOWN] Chiusura AE...")
    # Si tenta prima lo shutdown controllato via HTTP; se fallisce, si termina
    # il processo con terminate() e, come ultima risorsa, con kill().
    try:
        requests.post("http://localhost:5002/shutdown", timeout=1)
    except Exception:
        pass
    if ae_process:
        try:
            ae_process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            ae_process.kill()
    print("[TEARDOWN] AE terminata.")


# ---------------------------------------------------------------------------
# Logica di test
# ---------------------------------------------------------------------------

def generate_random_hex(length: int) -> str:
    """Genera una stringa esadecimale casuale di lunghezza specificata."""
    return os.urandom(length).hex()


def attack_request(request_id: int) -> dict:
    """
    Esegue una singola richiesta di attacco con payload spazzatura e PoW invalida.
    Il nonce della PoW è fisso a zero, quindi sicuramente non soddisferà
    i bit iniziali a zero richiesti dall'AE.
    """
    # Il payload contiene dati completamente casuali e non validi:
    # la firma del token è falsa e la PoW è deliberatamente sbagliata.
    payload = {
        "enc_vote": generate_random_hex(256),
        "enc_seed": generate_random_hex(256),
        "token": json.dumps({"nonce": generate_random_hex(16), "expires_at": "2100-01-01T00:00:00+00:00"}),
        "token_signature": generate_random_hex(256),
        "pow_nonce": "0000000000000000"  # PoW deliberatamente sbagliata
    }

    start_time = time.time()
    try:
        response = requests.post(AE_URL, json=payload, timeout=5)
        elapsed = time.time() - start_time
        return {
            "id": request_id,
            "status_code": response.status_code,
            "response": response.json() if response.content else None,
            "elapsed_ms": elapsed * 1000
        }
    except Exception as e:
        elapsed = time.time() - start_time
        return {
            "id": request_id,
            "status_code": None,
            "error": str(e),
            "elapsed_ms": elapsed * 1000
        }


def main():
    global ae_process
    try:
        # Si esegue il setup completo prima di avviare il test.
        setup()

        print("=" * 80)
        print("TEST ATTACCO VOLUMETRICO / NAIVE DOS")
        print("(Bypass della Proof of Work)")
        print("=" * 80)

        print(f"\nConfigurazione:")
        print(f"  - Numero di richieste totali: {NUM_REQUESTS}")
        print(f"  - Thread concorrenti: {NUM_THREADS}")
        print(f"  - Endpoint target: {AE_URL}")

        # Si verifica che l'AE sia raggiungibile prima di avviare l'attacco.
        try:
            test_response = requests.get("http://localhost:5002/status", timeout=2)
            if test_response.status_code == 200:
                print("\n[OK] AE è raggiungibile e in esecuzione!")
            else:
                print("\n[WARN] AE non sembra rispondere correttamente")
        except Exception as e:
            print(f"\n[ERROR] impossibile connettersi all'AE: {e}")
            sys.exit(1)

        # Si lanciano NUM_REQUESTS richieste in parallelo usando un pool di thread.
        # concurrent.futures.ThreadPoolExecutor gestisce automaticamente la coda
        # delle richieste con al più NUM_THREADS thread attivi contemporaneamente.
        print(f"\nAvvio dell'attacco con {NUM_THREADS} thread...")
        print("-" * 80)
        start_time_total = time.time()
        results = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=NUM_THREADS) as executor:
            futures = [executor.submit(attack_request, i) for i in range(NUM_REQUESTS)]
            for i, future in enumerate(concurrent.futures.as_completed(futures)):
                result = future.result()
                results.append(result)
                # Si stampa un indicatore di avanzamento ogni 50 richieste completate.
                if (i + 1) % 50 == 0:
                    print(f"  Richieste inviate: {i + 1}/{NUM_REQUESTS} ({((i + 1) / NUM_REQUESTS) * 100:.0f}%)")

        total_time = time.time() - start_time_total

        # Si aggregano i codici di stato HTTP ricevuti per valutare l'esito del test.
        print("\nAnalisi dei risultati:")
        print("-" * 80)
        status_counts = defaultdict(int)
        total_requests = len(results)
        total_elapsed_ms = 0

        for result in results:
            if result.get("status_code"):
                status_counts[result["status_code"]] += 1
            else:
                status_counts["ERROR"] += 1
            total_elapsed_ms += result.get("elapsed_ms", 0)

        for status, count in sorted(status_counts.items()):
            print(f"  - {status}: {count} risposte ({(count / total_requests) * 100:.1f}%)")

        avg_elapsed_ms = total_elapsed_ms / total_requests
        print(f"\n  Tempo totale: {total_time:.2f} secondi")
        print(f"  Tempo medio per richiesta: {avg_elapsed_ms:.2f} ms")

        # Il test è considerato superato se almeno il 90% delle richieste
        # è stato rifiutato con HTTP 400 per PoW invalida, dimostrando che
        # l'AE blocca il traffico malevolo prima di eseguire operazioni costose.
        print("\nConclusione:")
        print("-" * 80)
        passed = 400 in status_counts and status_counts[400] >= NUM_REQUESTS * 0.9
        if passed:
            print("[SUCCESS] SISTEMA PROTETTO!")
            print("  La maggior parte delle richieste sono state rifiutate istantaneamente")
            print("  con codice 400 Bad Request (Proof of Work invalida).")
            print("  Questo dimostra che l'AE scarta le richieste senza PoW valida")
            print("  PRIMA di eseguire operazioni crittografiche pesanti!")
        else:
            print("[WARN] Attenzione: il risultato non è quello atteso.")

        print("\n" + "=" * 80)

        save_report(
            test_id="dos_attack",
            test_name="Attacco DoS / Flood con PoW invalida (Volumetric Spamming)",
            outcome="PASS" if passed else "FAIL",
            details={
                "total_requests": total_requests,
                "threads": NUM_THREADS,
                "total_time_s": round(total_time, 3),
                "avg_response_ms": round(avg_elapsed_ms, 2),
                "status_distribution": {str(k): v for k, v in sorted(status_counts.items())},
                "rejected_400": status_counts.get(400, 0),
                "rejection_rate_pct": round(status_counts.get(400, 0) / total_requests * 100, 1),
                "threshold_pct": 90,
            },
        )

    finally:
        # Il teardown viene eseguito sempre, anche in caso di errore nel test.
        teardown()

if __name__ == "__main__":
    os.chdir(PROJECT_ROOT)
    try:
        main()
    except Exception as e:
        print(f"\n[ERRORE] {e}")
    finally:
        input("\nPremi Invio per chiudere...")
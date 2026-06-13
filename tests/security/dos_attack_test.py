
"""
Script di test per Volumetric Spamming & Naive DoS (Bypass della Proof of Work)
Simula una botnet che invia 500 richieste concorrenti con PoW invalida all'AE.
"""

import os
import sys
import json
import random
import time
import concurrent.futures
import requests
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Configurazione
AE_URL = "http://localhost:5002/vote"
NUM_REQUESTS = 500
NUM_THREADS = 50


def generate_random_hex(length: int) -> str:
    """Genera una stringa esadecimale casuale."""
    return os.urandom(length).hex()


def attack_request(request_id: int) -> dict:
    """
    Esegue una singola richiesta di attacco con payload spazzatura e PoW invalida.
    """
    # Crea payload con dati casuali (spazzatura)
    payload = {
        "enc_vote": generate_random_hex(256),
        "enc_seed": generate_random_hex(256),
        "token": json.dumps({"nonce": generate_random_hex(16), "expires_at": "2100-01-01T00:00:00+00:00"}),
        "token_signature": generate_random_hex(256),
        "pow_nonce": "0000000000000000"  # PoW deliberatamente sbagliata!
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
    print("=" * 80)
    print("TEST ATTACCO VOLUMETRICO / NAIVE DOS")
    print("(Bypass della Proof of Work)")
    print("=" * 80)

    print(f"\nConfigurazione:")
    print(f"  - Numero di richieste totali: {NUM_REQUESTS}")
    print(f"  - Thread concorrenti: {NUM_THREADS}")
    print(f"  - Endpoint target: {AE_URL}")

    # Verifica che l'AE sia raggiungibile
    try:
        test_response = requests.get("http://localhost:5002/status", timeout=2)
        if test_response.status_code == 200:
            print("\n[OK] AE è raggiungibile e in esecuzione!")
        else:
            print("\n[WARN] AE non sembra rispondere correttamente")
    except Exception as e:
        print(f"\n[ERROR] impossibile connettersi all'AE: {e}")
        print("  Assicurati che l'AE sia in esecuzione (py ae.py)")
        sys.exit(1)

    # Esegui l'attacco massivo!
    print(f"\nAvvio dell'attacco con {NUM_THREADS} thread...")
    print("-" * 80)
    start_time_total = time.time()
    results = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=NUM_THREADS) as executor:
        futures = [executor.submit(attack_request, i) for i in range(NUM_REQUESTS)]
        for i, future in enumerate(concurrent.futures.as_completed(futures)):
            result = future.result()
            results.append(result)
            # Stampa un piccolo indicatore di progresso
            if (i + 1) % 50 == 0:
                print(f"  Richieste inviate: {i + 1}/{NUM_REQUESTS} ({((i + 1) / NUM_REQUESTS) * 100:.0f}%)")

    total_time = time.time() - start_time_total

    # Analizza i risultati
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

    # Verifica se l'attacco è stato bloccato dalla PoW!
    print("\nConclusione:")
    print("-" * 80)
    if 400 in status_counts and status_counts[400] >= NUM_REQUESTS * 0.9:
        print("[SUCCESS] SISTEMA PROTETTO!")
        print("  La maggior parte delle richieste sono state rifiutate istantaneamente")
        print("  con codice 400 Bad Request (Proof of Work invalida).")
        print("  Questo dimostra che l'AE scarta le richieste senza PoW valida")
        print("  PRIMA di eseguire operazioni crittografiche pesanti!")
    else:
        print("[WARN] Attenzione: il risultato non è quello atteso.")

    print("\n" + "=" * 80)


if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    main()


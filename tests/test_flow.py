"""
Test del flusso completo di un'elezione (end-to-end).

Percorre l'intero ciclo di vita con i server reali SA e AE:
  1. inizializzazione dell'elezione di test (modulo condiviso tests/common.py);
  2. autenticazione presso il SA e verifica dei pin trusted delle chiavi AE;
  3. cifratura del voto, Proof of Work, invio all'AE e ricevuta firmata;
  4. riconciliazione, consegna delle quote degli scrutatori e scrutinio;
  5. verifica individuale della ricevuta con il client reale;
  6. verifica universale con l'Observer.
"""

import contextlib
import io
import json
import os
import subprocess
import sys
import time

import requests

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(TESTS_DIR, ".."))
SRC_DIR = os.path.join(PROJECT_ROOT, "src")
sys.path.insert(0, SRC_DIR)
sys.path.insert(0, TESTS_DIR)
sys.path.insert(0, os.path.join(TESTS_DIR, "security"))

from tls_config import SA_URL, AE_URL, sa_verify, ae_verify, ensure_tls_certs, admin_headers
from common import (create_test_election, close_payload, clean_election_state, pow_fields,
                    compute_public_key_fingerprint, DATA_DIR, BULLETIN_BOARD_PATH)
from test_reporter import save_report
from crypto.keys import deserialize_public_key
from crypto.rsa_oaep import encrypt

VOTER = {"id": "v001", "email": "v.postiglione7@studenti.unisa.it",
         "username": "vitto.posti", "password": "password123"}
RECEIPTS_DIR = os.path.join(DATA_DIR, "receipts")


def wait_server(url: str, verify) -> bool:
    for _ in range(30):
        try:
            if requests.get(f"{url}/status", timeout=0.5, verify=verify).status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def main():
    print("=" * 70)
    print("  TEST FLUSSO COMPLETO DELL'ELEZIONE (END-TO-END)")
    print("=" * 70)
    steps = {}
    sa_proc = ae_proc = None
    try:
        # 1 -----------------------------------------------------------------
        print("\n[1] Inizializzazione dell'elezione di test e avvio dei server...")
        ensure_tls_certs()
        init_data = create_test_election("test_flusso_completo", [VOTER])
        sa_proc = subprocess.Popen([sys.executable, os.path.join(SRC_DIR, "sa.py")], cwd=PROJECT_ROOT,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ae_proc = subprocess.Popen([sys.executable, os.path.join(SRC_DIR, "ae.py")], cwd=PROJECT_ROOT,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        steps["servers_started"] = wait_server(SA_URL, sa_verify()) and wait_server(AE_URL, ae_verify())
        assert steps["servers_started"], "Timeout nell'avvio dei server"
        print("    SA e AE pronti.")

        # 2 -----------------------------------------------------------------
        print(f"\n[2] Autenticazione di {VOTER['username']} e verifica dei pin AE...")
        r = requests.post(f"{SA_URL}/authenticate",
                          json={"username": VOTER["username"], "password": VOTER["password"]},
                          timeout=10, verify=sa_verify())
        r.raise_for_status()
        token, token_signature = r.json()["token"], r.json()["signature"]
        with open(os.path.join(DATA_DIR, "pins.json"), "r", encoding="utf-8") as f:
            pins = json.load(f)
        steps["pins_ok"] = (
            pins["ae_encrypt_public"].removeprefix("sha256:") == compute_public_key_fingerprint(init_data["ae_encrypt_public"])
            and pins["ae_sign_public"].removeprefix("sha256:") == compute_public_key_fingerprint(init_data["ae_sign_public"])
        )
        print(f"    Token ottenuto; pin trusted AE {'verificati' if steps['pins_ok'] else 'NON corrispondenti'}.")

        # 3 -----------------------------------------------------------------
        print("\n[3] Voto per Lista A: cifratura, Proof of Work, invio all'AE...")
        ae_encrypt_public = deserialize_public_key(init_data["ae_encrypt_public"])
        seed = os.urandom(32)
        enc_vote = encrypt(ae_encrypt_public, (0).to_bytes(1, "big"), seed=seed).hex()
        enc_seed = encrypt(ae_encrypt_public, seed).hex()
        r = requests.post(f"{AE_URL}/vote", json={
            "enc_vote": enc_vote, "enc_seed": enc_seed, "token": token,
            "token_signature": token_signature, **pow_fields(enc_vote),
        }, timeout=10, verify=ae_verify())
        r.raise_for_status()
        receipt = r.json()
        os.makedirs(RECEIPTS_DIR, exist_ok=True)
        with open(os.path.join(RECEIPTS_DIR, f"{VOTER['username']}.json"), "w", encoding="utf-8") as f:
            json.dump(receipt, f, indent=2)
        steps["vote_accepted"] = True
        print(f"    Voto accettato, leaf_index {receipt['leaf_index']}, ricevuta salvata.")

        # 4 -----------------------------------------------------------------
        print("\n[4] Riconciliazione, consegna delle quote degli scrutatori e scrutinio...")
        requests.post(f"{SA_URL}/reconcile", headers=admin_headers(), timeout=10, verify=sa_verify()).raise_for_status()
        r = requests.post(f"{AE_URL}/close", headers=admin_headers(), json=close_payload(),
                          timeout=60, verify=ae_verify())
        r.raise_for_status()
        result = r.json()["result"]
        steps["tally_ok"] = result.get("Lista A") == 1
        print(f"    Scrutinio: {result}")

        # 5 -----------------------------------------------------------------
        print("\n[5] Verifica individuale della ricevuta (client reale)...")
        from client import Client
        client = Client()
        client.username = VOTER["username"]
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            steps["receipt_verified"] = bool(client.verify_vote())
        print(f"    Ricevuta {'verificata' if steps['receipt_verified'] else 'NON verificata'}.")

        # 6 -----------------------------------------------------------------
        print("\n[6] Verifica universale (Observer)...")
        obs = subprocess.run([sys.executable, os.path.join(SRC_DIR, "observer.py")], cwd=PROJECT_ROOT,
                             input="\n", capture_output=True, text=True, encoding="utf-8", errors="replace")
        for line in obs.stdout.splitlines():
            if line.strip() and line.strip()[0].isdigit():
                print(f"    {line.strip()}")
        steps["observer_ok"] = "TUTTE LE VERIFICHE PUBBLICHE SONO RIUSCITE" in obs.stdout

    except Exception as e:
        print(f"\n[ERRORE] {e}")
        steps["error"] = str(e)
    finally:
        print("\nSpegnimento dei server e pulizia...")
        for url, proc, verify in [(SA_URL, sa_proc, sa_verify()), (AE_URL, ae_proc, ae_verify())]:
            try:
                requests.post(f"{url}/shutdown", headers=admin_headers(), timeout=2, verify=verify)
            except Exception:
                pass
            if proc:
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
        clean_election_state()
        if os.path.isdir(RECEIPTS_DIR):
            for f in os.listdir(RECEIPTS_DIR):
                if f.endswith(".json"):
                    os.remove(os.path.join(RECEIPTS_DIR, f))

    checks = ["servers_started", "pins_ok", "vote_accepted", "tally_ok", "receipt_verified", "observer_ok"]
    passed = all(steps.get(c) for c in checks)
    print("\n" + "=" * 70)
    for c in checks:
        print(f"  {'[PASS]' if steps.get(c) else '[FAIL]'} {c}")
    print(f"\n  {'TEST OK: flusso completo riuscito.' if passed else 'TEST FALLITO.'}")
    print("=" * 70)
    save_report(test_id="full_flow", test_name="Flusso completo dell'elezione (end-to-end)",
                outcome="PASS" if passed else "FAIL", details=steps)
    return passed


if __name__ == "__main__":
    os.chdir(PROJECT_ROOT)
    ok = False
    try:
        ok = main()
    finally:
        try:
            input("\nPremi Invio per chiudere...")
        except EOFError:
            pass
    sys.exit(0 if ok else 1)

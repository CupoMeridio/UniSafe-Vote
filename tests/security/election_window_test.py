"""
Test della finestra temporale dell'elezione.

Il blocco init (firmato dall'AE) fissa l'apertura e la chiusura delle urne. Un
token valido e una Proof of Work corretta non bastano per votare fuori da
quella finestra: l'AE confronta l'orario di ogni voto con i parametri
pubblicati, e il SA chiude le registrazioni a elezione conclusa.

  Scenario A — Urne non ancora aperte (apertura tra un'ora):
               l'elettore ottiene il token, ma il voto è rifiutato (HTTP 403).
  Scenario B — Urne chiuse da un'ora (finestra già scaduta):
               il voto è rifiutato (HTTP 403) e il SA non accetta nuove
               registrazioni (HTTP 403).
  Scenario C — Urne aperte: lo stesso elettore vota regolarmente (HTTP 200).

Ogni scenario usa una nuova elezione di test con la propria finestra temporale.
"""

import os
import sys
from datetime import datetime

import requests

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TESTS_SEC_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "src"))
sys.path.insert(0, TESTS_SEC_DIR)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "tests"))

from test_reporter import save_report
from tls_config import SA_URL, AE_URL, sa_verify, ae_verify, ensure_tls_certs
from common import create_test_election, clean_election_state, start_servers, stop_servers, pow_fields
from crypto.keys import deserialize_public_key
from crypto.rsa_oaep import encrypt

VOTER = {"id": "v001", "email": "v.postiglione7@studenti.unisa.it",
         "username": "vitto.posti", "password": "password123"}


def fmt(iso: str) -> str:
    return datetime.fromisoformat(iso).astimezone().strftime("%d/%m %H:%M:%S")


def try_to_vote(init_data: dict) -> tuple:
    """Autentica l'elettore e tenta di votare; restituisce (HTTP auth, HTTP voto, messaggio)."""
    r = requests.post(f"{SA_URL}/authenticate", json={"username": VOTER["username"], "password": VOTER["password"]},
                      timeout=15, verify=sa_verify())
    if r.status_code != 200:
        return r.status_code, None, r.json().get("error")
    pk = deserialize_public_key(init_data["ae_encrypt_public"])
    seed = os.urandom(32)
    enc_vote = encrypt(pk, (1).to_bytes(1, "big"), seed=seed).hex()
    v = requests.post(f"{AE_URL}/vote", json={
        "enc_vote": enc_vote, "enc_seed": encrypt(pk, seed).hex(), "token": r.json()["token"],
        "token_signature": r.json()["signature"], **pow_fields(enc_vote)}, timeout=30, verify=ae_verify())
    return r.status_code, v.status_code, v.json().get("error") or f"accettato, leaf_index {v.json().get('leaf_index')}"


def run_scenario(label: str, opens_in_minutes: float, duration_hours: float, test_registration: bool) -> dict:
    print("\n" + "-" * 80)
    print(label)
    print("-" * 80)
    init_data = create_test_election("election_window_test", [VOTER],
                                     opens_in_minutes=opens_in_minutes, duration_hours=duration_hours)
    print(f"  Ora attuale:          {datetime.now().strftime('%d/%m %H:%M:%S')}")
    print(f"  Apertura (blocco init): {fmt(init_data['opening_time'])}")
    print(f"  Chiusura (blocco init): {fmt(init_data['closing_time'])}")
    procs = start_servers()
    try:
        auth_code, vote_code, msg = try_to_vote(init_data)
        print(f"  Autenticazione → HTTP {auth_code}   Voto → HTTP {vote_code}  {msg}")
        result = {"auth_http_status": auth_code, "vote_http_status": vote_code, "message": msg}
        if test_registration:
            r = requests.post(f"{SA_URL}/register", json={"email": "nuovo.elettore@studenti.unisa.it",
                                                          "username": "nuovo.elettore", "password": "Nuovo!2026"},
                              timeout=15, verify=sa_verify())
            print(f"  Nuova registrazione → HTTP {r.status_code}  {r.json().get('error') or r.json().get('message')}")
            result["registration_http_status"] = r.status_code
        return result
    finally:
        stop_servers(procs)


def main():
    print("=" * 80)
    print("  TEST FINESTRA TEMPORALE DELL'ELEZIONE")
    print("=" * 80)
    ensure_tls_certs()
    results = {}
    try:
        a = run_scenario("SCENARIO A — Urne non ancora aperte (apertura tra 60 minuti)",
                         opens_in_minutes=60, duration_hours=24, test_registration=False)
        pa = a["auth_http_status"] == 200 and a["vote_http_status"] == 403
        print(f"  {'[PASS]' if pa else '[FAIL]'} Voto rifiutato prima dell'apertura")
        results["scenario_a_not_open_yet"] = {**a, "passed": pa}

        b = run_scenario("SCENARIO B — Urne chiuse (aperte 2 ore fa, chiuse 1 ora fa)",
                         opens_in_minutes=-120, duration_hours=1, test_registration=True)
        pb = b["vote_http_status"] == 403 and b["registration_http_status"] == 403
        print(f"  {'[PASS]' if pb else '[FAIL]'} Voto e registrazione rifiutati dopo la chiusura")
        results["scenario_b_closed"] = {**b, "passed": pb}

        c = run_scenario("SCENARIO C — Urne aperte (aperte ora, chiusura tra 24 ore)",
                         opens_in_minutes=0, duration_hours=24, test_registration=False)
        pc = c["vote_http_status"] == 200
        print(f"  {'[PASS]' if pc else '[FAIL]'} Voto accettato dentro la finestra")
        results["scenario_c_open"] = {**c, "passed": pc}

        passed = pa and pb and pc
        print("\n" + "=" * 80)
        print("RIEPILOGO")
        print("=" * 80)
        print(f"  A — prima dell'apertura: voto rifiutato (403)               {'PASS' if pa else 'FAIL'}")
        print(f"  B — dopo la chiusura: voto e registrazione rifiutati (403)  {'PASS' if pb else 'FAIL'}")
        print(f"  C — dentro la finestra: voto accettato (200)                {'PASS' if pc else 'FAIL'}")
        print("=" * 80)
        save_report(test_id="election_window", test_name="Finestra temporale dell'elezione",
                    outcome="PASS" if passed else "FAIL", details=results)
    finally:
        clean_election_state()


if __name__ == "__main__":
    os.chdir(PROJECT_ROOT)
    try:
        main()
    except Exception as e:
        print(f"\n[ERRORE] {e}")
    finally:
        input("\nPremi Invio per chiudere...")

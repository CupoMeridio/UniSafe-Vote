"""
Test della registrazione degli elettori (modalità "solo liste").

In questa modalità l'elezione parte senza elettori: chi vuole votare si
registra presso il SA con un indirizzo istituzionale, poi si autentica e vota.
Il test percorre il flusso e mette alla prova i controlli del SA:

  Fase 1 — Registrazioni non ammesse: dominio non istituzionale, dominio che
           imita quello dell'ateneo, campi mancanti (HTTP 400).
  Fase 2 — Registrazione valida (HTTP 201) e tentativi di duplicato: stesso
           username, stessa email scritta con maiuscole diverse (HTTP 409).
  Fase 3 — Protezione delle credenziali: in voters.json la password è salvata
           solo come hash PBKDF2 con salt, mai in chiaro.
  Fase 4 — L'elettore appena registrato si autentica, ottiene il token e vota.
"""

import json
import os
import sys

import requests

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TESTS_SEC_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "src"))
sys.path.insert(0, TESTS_SEC_DIR)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "tests"))

from test_reporter import save_report
from tls_config import SA_URL, AE_URL, sa_verify, ae_verify, ensure_tls_certs
from common import (create_test_election, clean_election_state, start_servers, stop_servers,
                    pow_fields, DATA_DIR)
from crypto.keys import deserialize_public_key
from crypto.rsa_oaep import encrypt

NEW_VOTER = {"email": "giulia.rossi@studenti.unisa.it", "username": "giulia.rossi", "password": "Rossi!2026"}


def register(email, username, password):
    r = requests.post(f"{SA_URL}/register", json={"email": email, "username": username, "password": password},
                      timeout=15, verify=sa_verify())
    return r.status_code, r.json().get("error") or r.json().get("message")


def main():
    print("=" * 80)
    print("  TEST REGISTRAZIONE DEGLI ELETTORI (MODALITÀ 'SOLO LISTE')")
    print("=" * 80)
    results = {}
    procs = {}
    try:
        print("\n[SETUP] Elezione senza elettori pre-registrati, avvio di SA e AE...")
        ensure_tls_certs()
        init_data = create_test_election("registration_test", voters=[])
        procs = start_servers()
        print("        SA e AE pronti. Elettori registrati: 0")

        # FASE 1 ------------------------------------------------------------
        print("\n" + "-" * 80)
        print("FASE 1 — Registrazioni non ammesse")
        print("-" * 80)
        rejected = [
            ("dominio non istituzionale", "giulia.rossi@gmail.com", "giulia.g", "pw"),
            ("dominio che imita l'ateneo", "giulia.rossi@fakeunisa.it", "giulia.f", "pw"),
            ("username mancante", "giulia.r@studenti.unisa.it", "", "pw"),
        ]
        phase1 = []
        for label, email, user, pwd in rejected:
            code, msg = register(email, user, pwd)
            ok = code == 400
            phase1.append({"case": label, "email": email, "http_status": code, "ok": ok})
            print(f"  {label:<28} {email:<32} → HTTP {code}  {msg}  {'✓' if ok else '✗'}")
        results["phase1_invalid_registrations"] = phase1
        p1 = all(c["ok"] for c in phase1)
        print(f"  {'[PASS]' if p1 else '[FAIL]'} Fase 1")

        # FASE 2 ------------------------------------------------------------
        print("\n" + "-" * 80)
        print("FASE 2 — Registrazione valida e tentativi di duplicato")
        print("-" * 80)
        code_ok, msg_ok = register(**NEW_VOTER)
        print(f"  Registrazione di {NEW_VOTER['username']} ({NEW_VOTER['email']}) → HTTP {code_ok}  {msg_ok}")
        code_user, msg_user = register("altra.email@studenti.unisa.it", NEW_VOTER["username"], "pw2")
        print(f"  Stesso username, email diversa              → HTTP {code_user}  {msg_user}")
        upper_email = NEW_VOTER["email"].upper()
        code_mail, msg_mail = register(upper_email, "giulia.bis", "pw3")
        print(f"  Stessa email in maiuscolo ({upper_email[:20]}...) → HTTP {code_mail}  {msg_mail}")
        p2 = code_ok == 201 and code_user == 409 and code_mail == 409
        results["phase2_registration"] = {"valid": code_ok, "duplicate_username": code_user,
                                          "duplicate_email_case": code_mail, "passed": p2}
        print(f"  {'[PASS]' if p2 else '[FAIL]'} Fase 2")

        # FASE 3 ------------------------------------------------------------
        print("\n" + "-" * 80)
        print("FASE 3 — Come è salvata la password in voters.json")
        print("-" * 80)
        with open(os.path.join(DATA_DIR, "voters.json"), "r", encoding="utf-8") as f:
            stored = json.load(f)
        print(f"  Elettori registrati: {len(stored)}")
        entry = next((v for v in stored if v["username"] == NEW_VOTER["username"]), {})
        stored_pw = entry.get("password", "")
        parts = stored_pw.split("$")
        print(f"  Campo password: {stored_pw[:60]}...")
        if len(parts) == 4:
            print(f"    algoritmo {parts[0]}, iterazioni {parts[1]}, salt {parts[2][:16]}..., hash {parts[3][:16]}...")
        plain_absent = NEW_VOTER["password"] not in json.dumps(stored)
        p3 = len(stored) == 1 and len(parts) == 4 and parts[0] == "pbkdf2_sha256" and plain_absent
        print(f"  Password in chiaro presente nel file? {not plain_absent}")
        results["phase3_password_storage"] = {"voters_stored": len(stored), "format": parts[0] if parts else None,
                                              "iterations": parts[1] if len(parts) == 4 else None,
                                              "plaintext_absent": plain_absent, "passed": p3}
        print(f"  {'[PASS]' if p3 else '[FAIL]'} Fase 3")

        # FASE 4 ------------------------------------------------------------
        print("\n" + "-" * 80)
        print("FASE 4 — L'elettore registrato si autentica e vota")
        print("-" * 80)
        r = requests.post(f"{SA_URL}/authenticate",
                          json={"username": NEW_VOTER["username"], "password": NEW_VOTER["password"]},
                          timeout=15, verify=sa_verify())
        print(f"  Autenticazione → HTTP {r.status_code}")
        vote_status = None
        if r.status_code == 200:
            token, signature = r.json()["token"], r.json()["signature"]
            pk = deserialize_public_key(init_data["ae_encrypt_public"])
            seed = os.urandom(32)
            enc_vote = encrypt(pk, (0).to_bytes(1, "big"), seed=seed).hex()
            vote = requests.post(f"{AE_URL}/vote", json={
                "enc_vote": enc_vote, "enc_seed": encrypt(pk, seed).hex(), "token": token,
                "token_signature": signature, **pow_fields(enc_vote)}, timeout=30, verify=ae_verify())
            vote_status = vote.status_code
            print(f"  Voto per {init_data['candidates'][0]} → HTTP {vote_status}"
                  f"{'  (ricevuta firmata, leaf_index ' + str(vote.json().get('leaf_index')) + ')' if vote_status == 200 else ''}")
        p4 = r.status_code == 200 and vote_status == 200
        results["phase4_auth_and_vote"] = {"auth_http_status": r.status_code, "vote_http_status": vote_status,
                                           "passed": p4}
        print(f"  {'[PASS]' if p4 else '[FAIL]'} Fase 4")

        passed = p1 and p2 and p3 and p4
        print("\n" + "=" * 80)
        print("RIEPILOGO")
        print("=" * 80)
        print(f"  Fase 1 — registrazioni non ammesse rifiutate:     {'PASS' if p1 else 'FAIL'}")
        print(f"  Fase 2 — registrazione valida, duplicati rifiutati: {'PASS' if p2 else 'FAIL'}")
        print(f"  Fase 3 — password salvata solo come hash PBKDF2:   {'PASS' if p3 else 'FAIL'}")
        print(f"  Fase 4 — l'elettore registrato vota:               {'PASS' if p4 else 'FAIL'}")
        print("\n  Nota: il SA controlla il dominio dell'indirizzo, non il possesso della")
        print("  casella (limite dichiarato del PoC).")
        print("=" * 80)
        save_report(test_id="registration", test_name="Registrazione degli elettori (modalità solo liste)",
                    outcome="PASS" if passed else "FAIL", details=results)
    finally:
        print("\n[TEARDOWN] Spegnimento dei server e pulizia...")
        stop_servers(procs)
        clean_election_state()


if __name__ == "__main__":
    os.chdir(PROJECT_ROOT)
    try:
        main()
    except Exception as e:
        print(f"\n[ERRORE] {e}")
    finally:
        input("\nPremi Invio per chiudere...")

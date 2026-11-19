"""
Test del pinning del certificato TLS: server AE impostore.

Il client si fida solo del certificato dell'AE distribuito con l'elezione
(data/tls/ae_cert.pem), usato come unica autorità di certificazione per le
connessioni HTTPS verso l'AE. Un attaccante che riesce a mettersi al posto
dell'AE (stesso indirizzo e porta, certificato con lo stesso nome e gli stessi
SAN, ma con una propria chiave) non deve ricevere nulla dal client.

  Fase 1 — L'attaccante genera un certificato self-signed identico nei campi
           visibili (CN "UniSafe-Vote AE", SAN localhost / 127.0.0.1) e avvia
           un server AE falso sulla porta 5002 (l'AE vera non è avviata).
  Fase 2 — Il server falso funziona: chi si fida del suo certificato vi si
           connette normalmente.
  Fase 3 — Il client reale rifiuta la connessione: la verifica TLS fallisce,
           il client non ottiene la challenge PoW e non può inviare schede.
  Fase 4 — Il server falso non ha ricevuto alcuna richiesta dal client.

Non usa i server reali: il server falso gira nel processo del test.
"""

import os
import shutil
import ssl
import sys
import tempfile
import threading

import requests

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SRC_DIR = os.path.join(PROJECT_ROOT, "src")
TESTS_SEC_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SRC_DIR)
sys.path.insert(0, TESTS_SEC_DIR)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "tests"))

from flask import Flask, jsonify
from werkzeug.serving import make_server
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from test_reporter import save_report
from tls_config import ensure_tls_certs
from common import create_test_election, clean_election_state, DATA_DIR
from generate_tls_certs import generate_self_signed_cert

REAL_AE_CERT = os.path.join(DATA_DIR, "tls", "ae_cert.pem")


def cert_summary(path: str) -> dict:
    with open(path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    return {
        "subject": cert.subject.rfc4514_string(),
        "san": [str(n.value) for n in san],
        "sha256": cert.fingerprint(hashes.SHA256()).hex(),
    }


def main():
    print("=" * 80)
    print("  TEST PINNING DEL CERTIFICATO TLS — SERVER AE IMPOSTORE")
    print("=" * 80)
    ensure_tls_certs()
    temp_dir = tempfile.mkdtemp(prefix="unisafe_vote_fake_ae_")
    server = None
    received = []
    results = {}
    try:
        # Elezione di test: il client legge Bulletin Board e pin all'avvio.
        create_test_election("tls_pinning_test", voters=[])

        # FASE 1 ------------------------------------------------------------
        print("\n" + "-" * 80)
        print("FASE 1 — L'attaccante prepara un AE falso con un certificato 'gemello'")
        print("-" * 80)
        fake_cert = os.path.join(temp_dir, "fake_ae_cert.pem")
        fake_key = os.path.join(temp_dir, "fake_ae_key.pem")
        generate_self_signed_cert("UniSafe-Vote AE", fake_cert, fake_key)
        real, fake = cert_summary(REAL_AE_CERT), cert_summary(fake_cert)
        print(f"  Certificato AE legittimo:  {real['subject']}  SAN {real['san']}")
        print(f"                             SHA-256 {real['sha256'][:48]}...")
        print(f"  Certificato dell'impostore: {fake['subject']}  SAN {fake['san']}")
        print(f"                             SHA-256 {fake['sha256'][:48]}...")
        print(f"  Nome e SAN identici: {real['subject'] == fake['subject'] and real['san'] == fake['san']}  "
              f"— chiave e impronta diverse: {real['sha256'] != fake['sha256']}")

        app = Flask("fake_ae")

        @app.route("/<path:anything>", methods=["GET", "POST"])
        def capture(anything):
            received.append(anything)  # registra ogni richiesta che riesce ad arrivare
            return jsonify({"challenge": "00" * 49, "difficulty": 0, "urn_open": True,
                            "pow_difficulty": 0, "votes_received": 0}), 200

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(fake_cert, fake_key)
        server = make_server("127.0.0.1", 5002, app, ssl_context=ctx, threaded=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        print("  Server AE falso in ascolto su https://localhost:5002")

        # FASE 2 ------------------------------------------------------------
        print("\n" + "-" * 80)
        print("FASE 2 — Il server falso risponde a chi si fida del suo certificato")
        print("-" * 80)
        r = requests.get("https://localhost:5002/status", timeout=10, verify=fake_cert)
        print(f"  GET /status con il certificato dell'impostore come CA → HTTP {r.status_code}")
        p2 = r.status_code == 200
        received.clear()
        results["fake_server_reachable"] = p2

        # FASE 3 ------------------------------------------------------------
        print("\n" + "-" * 80)
        print("FASE 3 — Il client reale si connette all'AE (pinning su data/tls/ae_cert.pem)")
        print("-" * 80)
        os.chdir(PROJECT_ROOT)
        from client import Client, AE_URL
        client = Client()
        print(f"  Certificato usato dal client per l'AE: {client._ae_verify()}")
        tls_error = None
        try:
            requests.get(f"{AE_URL}/status", timeout=10, verify=client._ae_verify())
        except requests.exceptions.SSLError as e:
            tls_error = type(e).__name__
            reason = str(e)
            print(f"  Connessione rifiutata: {tls_error}")
            print(f"    {reason[reason.find('certificate verify failed'):][:90] if 'certificate verify failed' in reason else reason[:90]}")
        challenge, difficulty = client.get_pow_challenge()
        print(f"  Client.get_pow_challenge() → challenge {challenge!r}: il client non ottiene la challenge "
              f"e non può preparare alcuna scheda")
        p3 = tls_error is not None and challenge is None
        results["client_rejected_connection"] = tls_error is not None
        results["client_got_no_challenge"] = challenge is None

        # FASE 4 ------------------------------------------------------------
        print("\n" + "-" * 80)
        print("FASE 4 — Cosa ha ricevuto il server falso dal client")
        print("-" * 80)
        print(f"  Richieste arrivate all'applicazione dell'impostore: {len(received)}")
        p4 = len(received) == 0
        results["requests_received_by_impostor"] = len(received)

        passed = p2 and p3 and p4
        print("\n" + "=" * 80)
        print("RIEPILOGO")
        print("=" * 80)
        print(f"  Fase 2 — il server falso è raggiungibile e funzionante:    {'PASS' if p2 else 'FAIL'}")
        print(f"  Fase 3 — il client rifiuta il certificato dell'impostore:  {'PASS' if p3 else 'FAIL'}")
        print(f"  Fase 4 — nessuna richiesta del client arriva all'impostore: {'PASS' if p4 else 'FAIL'}")
        print("=" * 80)
        save_report(test_id="tls_pinning", test_name="Pinning del certificato TLS (server AE impostore)",
                    outcome="PASS" if passed else "FAIL",
                    details={"legit_cert": real, "impostor_cert": fake, **results})
    finally:
        if server:
            server.shutdown()
        shutil.rmtree(temp_dir, ignore_errors=True)
        clean_election_state()


if __name__ == "__main__":
    os.chdir(PROJECT_ROOT)
    try:
        main()
    except Exception as e:
        print(f"\n[ERRORE] {e}")
    finally:
        input("\nPremi Invio per chiudere...")

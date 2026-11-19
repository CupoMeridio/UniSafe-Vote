"""
Test della PKI dell'elezione dal lato del client: identità del server AE.

Il client si connette all'AE solo se:
  - la catena del certificato arriva alla CA dell'elezione;
  - il certificato non è revocato (CRL firmata dalla CA);
  - la chiave pubblica del server corrisponde al pin SPKI distribuito ai client.

Il test mette in scena una sequenza di impostori che si spacciano per l'AE,
ciascuno fermato da un controllo diverso, e il caso della chiave rubata gestito
con revoca e riemissione:

  Scenario 1 — AE legittimo (certificato emesso dalla CA su CSR): connessione accettata.
  Scenario 2 — Impostore con certificato self-signed "gemello" (stesso nome e
               SAN): rifiutato dalla verifica della catena.
  Scenario 3 — Impostore con certificato emesso da un'altra CA: rifiutato.
  Scenario 4 — Impostore con certificato emesso dalla CA dell'elezione (CA
               compromessa o emissione errata): la catena è valida, lo ferma il
               pin SPKI. Senza pin il client gli consegnerebbe il token.
  Scenario 5 — Chiave privata dell'AE rubata: l'impostore presenta il
               certificato vero con la chiave vera, quindi catena e pin sono
               validi. La CA revoca il certificato, l'AE riceve una nuova chiave
               e un nuovo certificato e i pin vengono aggiornati: l'impostore è
               rifiutato, l'AE con il nuovo certificato è accettato.

Il test usa una PKI temporanea generata con lo stesso codice dell'elezione
(src/pki.py) e le stesse sessioni HTTPS del client (src/tls_context.py), così
da poter revocare e riemettere certificati senza toccare la PKI reale. I server
falsi girano nel processo del test.
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

from flask import Flask, jsonify
from werkzeug.serving import make_server

from test_reporter import save_report
import pki
import tls_context
from generate_tls_certs import generate_self_signed_cert


def start_fake_ae(label: str, cert: str, key: str, port: int, hits: dict):
    """Server che si spaccia per l'AE: registra ogni richiesta che riesce a ricevere."""
    app = Flask(f"fake_{port}")

    @app.route("/<path:anything>", methods=["GET", "POST"])
    def capture(anything):
        hits[label] = hits.get(label, 0) + 1
        return jsonify({"challenge": "00" * 49, "difficulty": 0, "urn_open": True}), 200

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    server = make_server("127.0.0.1", port, app, ssl_context=ctx, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def connect(port: int, tls_dir: str, **options) -> tuple:
    """Il client chiede una challenge all'AE con la propria sessione; restituisce (esito, dettaglio)."""
    session = tls_context.client_session("ae", tls_dir, **options)
    try:
        r = session.get(f"https://127.0.0.1:{port}/pow_challenge", timeout=10)
        return "accettata", f"HTTP {r.status_code}"
    except requests.exceptions.SSLError as e:
        msg = str(e)
        for marker, reason in (("pin SPKI", "pin SPKI non corrispondente"),
                               ("revoked", "certificato revocato (CRL)"),
                               ("self-signed", "certificato self-signed non emesso dalla CA"),
                               ("unable to get local issuer", "certificato emesso da una CA non riconosciuta"),
                               ("unknown ca", "CA non riconosciuta")):
            if marker in msg:
                return "rifiutata", reason
        return "rifiutata", msg[:80]


def main():
    print("=" * 84)
    print("  TEST PKI LATO CLIENT — IMPOSTORI DELL'AE, PINNING SPKI E REVOCA")
    print("=" * 84)
    work = tempfile.mkdtemp(prefix="unisafe_vote_pki_test_")
    pki_dir = os.path.join(work, "pki")
    other_dir = os.path.join(work, "other_ca")
    servers, hits, results, scenarios = [], {}, {}, []

    def record(n, label, outcome, detail, expected):
        ok = outcome == expected
        scenarios.append({"scenario": n, "label": label, "outcome": outcome, "detail": detail,
                          "expected": expected, "ok": ok})
        print(f"  → connessione {outcome} ({detail})  atteso: {expected}  {'✓' if ok else '✗'}")
        return ok

    try:
        print("\n[SETUP] PKI dell'elezione (CA, CSR, certificati, CRL vuota, pin SPKI)...")
        pki.init_pki(pki_dir)
        print("  " + pki.status(pki_dir).replace("\n", "\n  "))
        print(f"  Pin SPKI dell'AE distribuito ai client: {tls_context.load_pin('ae', pki_dir)[:32]}...")

        # 1 ------------------------------------------------------------------
        print("\n" + "-" * 84)
        print("SCENARIO 1 — AE legittimo")
        servers.append(start_fake_ae("ae_legittimo", pki.cert_path("ae", pki_dir), pki.key_path("ae", pki_dir), 5611, hits))
        s1 = record(1, "AE legittimo", *connect(5611, pki_dir), expected="accettata")

        # 2 ------------------------------------------------------------------
        print("\n" + "-" * 84)
        print("SCENARIO 2 — Impostore con certificato self-signed 'gemello'")
        fake_cert, fake_key = os.path.join(work, "self_cert.pem"), os.path.join(work, "self_key.pem")
        generate_self_signed_cert("UniSafe-Vote AE", fake_cert, fake_key)
        print("  Stesso nome (CN=UniSafe-Vote AE) e stessi SAN del certificato legittimo, ma self-signed.")
        servers.append(start_fake_ae("self_signed", fake_cert, fake_key, 5612, hits))
        s2 = record(2, "self-signed", *connect(5612, pki_dir), expected="rifiutata")

        # 3 ------------------------------------------------------------------
        print("\n" + "-" * 84)
        print("SCENARIO 3 — Impostore con certificato emesso da un'altra CA")
        pki.init_pki(other_dir)
        print(f"  Certificato 'UniSafe-Vote AE' firmato da una CA diversa (stesso nome della CA vera).")
        servers.append(start_fake_ae("altra_ca", pki.cert_path("ae", other_dir), pki.key_path("ae", other_dir), 5613, hits))
        s3 = record(3, "altra CA", *connect(5613, pki_dir), expected="rifiutata")

        # 4 ------------------------------------------------------------------
        print("\n" + "-" * 84)
        print("SCENARIO 4 — Impostore con certificato emesso dalla CA vera (CA compromessa)")
        pki.issue_entity("ae_impostore", "UniSafe-Vote AE", "server", pki_dir)
        print("  La CA emette un certificato valido per 'UniSafe-Vote AE' a una chiave dell'impostore.")
        servers.append(start_fake_ae("ca_compromessa", pki.cert_path("ae_impostore", pki_dir),
                                     pki.key_path("ae_impostore", pki_dir), 5614, hits))
        print("  Client senza pin SPKI (solo catena e CRL):")
        no_pin = connect(5614, pki_dir, check_pin=False)
        s4a = record(4, "CA compromessa, senza pin", *no_pin, expected="accettata")
        print("    il client avrebbe inviato all'impostore la richiesta (e poi il token di voto).")
        hits_before = hits.get("ca_compromessa", 0)
        print("  Client reale (catena, CRL e pin SPKI):")
        s4b = record(4, "CA compromessa, con pin", *connect(5614, pki_dir), expected="rifiutata")
        s4c = hits.get("ca_compromessa", 0) == hits_before
        print(f"  Richieste del client reale arrivate all'impostore: {hits.get('ca_compromessa', 0) - hits_before}")

        # 5 ------------------------------------------------------------------
        print("\n" + "-" * 84)
        print("SCENARIO 5 — Chiave privata dell'AE rubata: revoca e riemissione")
        stolen_cert, stolen_key = os.path.join(work, "stolen_cert.pem"), os.path.join(work, "stolen_key.pem")
        shutil.copy(pki.cert_path("ae", pki_dir), stolen_cert)
        shutil.copy(pki.key_path("ae", pki_dir), stolen_key)
        servers.append(start_fake_ae("chiave_rubata", stolen_cert, stolen_key, 5615, hits))
        print("  L'impostore presenta il certificato VERO dell'AE con la chiave VERA (rubata).")
        s5a = record(5, "chiave rubata, prima della revoca", *connect(5615, pki_dir), expected="accettata")
        print("    catena e pin sono validi: senza revoca l'attacco riesce.")
        serial = pki.revoke("ae", pki_dir)
        print(f"  La CA revoca il certificato dell'AE (seriale {serial[:16]}...) e ripubblica la CRL.")
        pki.issue_entity("ae", "UniSafe-Vote AE", "server", pki_dir)
        pki.write_tls_pins(pki_dir)
        print(f"  L'AE genera una nuova chiave e una nuova CSR; la CA emette il nuovo certificato;")
        print(f"  il nuovo pin SPKI ({tls_context.load_pin('ae', pki_dir)[:16]}...) viene distribuito ai client.")
        s5b = record(5, "chiave rubata, dopo la revoca", *connect(5615, pki_dir), expected="rifiutata")
        print("  Stessa verifica con il solo controllo di revoca (pin disattivato):")
        s5c = record(5, "chiave rubata, solo CRL", *connect(5615, pki_dir, check_pin=False), expected="rifiutata")
        servers.append(start_fake_ae("ae_nuovo", pki.cert_path("ae", pki_dir), pki.key_path("ae", pki_dir), 5616, hits))
        print("  AE con il nuovo certificato:")
        s5d = record(5, "AE con nuovo certificato", *connect(5616, pki_dir), expected="accettata")

        passed = all([s1, s2, s3, s4a, s4b, s4c, s5a, s5b, s5c, s5d])
        print("\n" + "=" * 84)
        print("RIEPILOGO")
        print("=" * 84)
        print(f"  1 — AE legittimo accettato:                                 {'PASS' if s1 else 'FAIL'}")
        print(f"  2 — self-signed rifiutato dalla catena:                     {'PASS' if s2 else 'FAIL'}")
        print(f"  3 — certificato di un'altra CA rifiutato:                   {'PASS' if s3 else 'FAIL'}")
        print(f"  4 — CA compromessa: fermata solo dal pin SPKI:              {'PASS' if (s4a and s4b and s4c) else 'FAIL'}")
        print(f"  5 — chiave rubata: revoca e riemissione la neutralizzano:   {'PASS' if (s5a and s5b and s5c and s5d) else 'FAIL'}")
        print("=" * 84)
        save_report(test_id="tls_pki_client", test_name="PKI lato client: impostori dell'AE, pinning SPKI e revoca",
                    outcome="PASS" if passed else "FAIL",
                    details={"scenarios": scenarios, "requests_reaching_servers": hits})
    finally:
        for s in servers:
            s.shutdown()
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    os.chdir(PROJECT_ROOT)
    try:
        main()
    except Exception as e:
        print(f"\n[ERRORE] {e}")
    finally:
        input("\nPremi Invio per chiudere...")

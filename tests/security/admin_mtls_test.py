"""
Test del TLS mutuo per le operazioni amministrative.

Chiudere le urne (/close), pubblicare la riconciliazione (/reconcile) e spegnere
i server (/shutdown) è consentito solo al pannello amministrativo, che si
autentica presentando un certificato client emesso dalla CA dell'elezione con
uso "clientAuth". Il certificato è facoltativo nell'handshake (gli elettori non
ne hanno), ma se presentato viene verificato con la CA e con la CRL.

Il test usa i server reali e tenta l'accesso amministrativo in cinque modi:

  1. senza certificato client                    → HTTP 403, urne ancora aperte
  2. con un certificato emesso da un'altra CA    → connessione TLS rifiutata
  3. con un certificato del pannello revocato    → connessione TLS rifiutata (CRL)
  4. con il certificato del server SA            → rifiutato: non è un certificato client
  5. con il certificato del pannello valido      → riconciliazione e chiusura riuscite

Il certificato revocato è emesso dalla CA dell'elezione solo per il test e
revocato prima dell'avvio dei server, che leggono la CRL all'avvio.
"""

import os
import shutil
import sys
import tempfile

import requests

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SRC_DIR = os.path.join(PROJECT_ROOT, "src")
TESTS_SEC_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SRC_DIR)
sys.path.insert(0, TESTS_SEC_DIR)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "tests"))

from test_reporter import save_report
from tls_config import SA_URL, AE_URL, sa_verify, ae_verify, ensure_tls_certs, admin_cert
from common import create_test_election, clean_election_state, start_servers, stop_servers, close_payload
import pki

TLS_DIR = os.path.join(PROJECT_ROOT, "data", "tls")
VOTERS = [{"id": "v001", "email": "v.postiglione7@studenti.unisa.it",
           "username": "vitto.posti", "password": "password123"}]


def admin_call(url: str, endpoint: str, client_cert, payload=None) -> tuple:
    """Esegue una chiamata amministrativa; restituisce (esito breve, dettaglio)."""
    try:
        r = requests.post(f"{url}/{endpoint}", cert=client_cert, json=payload, timeout=30,
                          verify=sa_verify() if url == SA_URL else ae_verify())
        return f"HTTP {r.status_code}", r.json().get("error") or r.json().get("status", "")
    except requests.exceptions.SSLError as e:
        msg = str(e)
        reason = ("certificato revocato" if "revoked" in msg else
                  "CA sconosciuta" if "unknown ca" in msg else
                  "uso del certificato non ammesso" if "unsupported certificate" in msg else
                  "handshake TLS rifiutato dal server")
        return "TLS rifiutato", reason
    except requests.exceptions.ConnectionError as e:
        return "TLS rifiutato", "connessione chiusa dal server durante l'handshake"


def urns_open() -> bool:
    return requests.get(f"{AE_URL}/status", timeout=10, verify=ae_verify()).json()["urn_open"]


def main():
    print("=" * 84)
    print("  TEST TLS MUTUO PER LE OPERAZIONI AMMINISTRATIVE")
    print("=" * 84)
    work = tempfile.mkdtemp(prefix="unisafe_vote_mtls_")
    procs = {}
    checks = []

    def check(label, outcome, detail, expected_prefix):
        ok = outcome.startswith(expected_prefix)
        checks.append({"check": label, "outcome": outcome, "detail": detail, "ok": ok})
        print(f"  {label:<46} → {outcome:<14} {detail}  {'✓' if ok else '✗'}")
        return ok

    try:
        print("\n[SETUP] PKI, certificati di prova, elezione e server...")
        ensure_tls_certs()
        # Certificato del pannello revocato: stesso nome del pannello, emesso dalla CA vera
        pki.issue_entity("admin_test_revocato", pki.ADMIN_CN, "client", TLS_DIR)
        serial = pki.revoke("admin_test_revocato", TLS_DIR)
        print(f"  Certificato del pannello di prova emesso e revocato (seriale {serial[:16]}...)")
        # Certificato del pannello emesso da un'altra CA
        other = os.path.join(work, "other_ca")
        pki.init_pki(other)
        print("  Certificato del pannello emesso da un'altra CA generato")
        create_test_election("admin_mtls_test", VOTERS)
        procs = start_servers()
        print("  SA e AE avviati (hanno caricato CA e CRL)")

        revoked = (pki.cert_path("admin_test_revocato", TLS_DIR), pki.key_path("admin_test_revocato", TLS_DIR))
        other_ca = (pki.cert_path("admin", other), pki.key_path("admin", other))
        server_as_client = (pki.cert_path("sa", TLS_DIR), pki.key_path("sa", TLS_DIR))

        print("\n" + "-" * 84)
        print("TENTATIVI DI CHIUDERE LE URNE (AE /close) E RICONCILIARE (SA /reconcile)")
        print("-" * 84)
        c1 = check("1. senza certificato client: /close", *admin_call(AE_URL, "close", None, close_payload()), "HTTP 403")
        c1b = check("1. senza certificato client: /reconcile", *admin_call(SA_URL, "reconcile", None), "HTTP 403")
        c2 = check("2. certificato di un'altra CA: /close", *admin_call(AE_URL, "close", other_ca, close_payload()), "TLS rifiutato")
        c3 = check("3. certificato revocato: /close", *admin_call(AE_URL, "close", revoked, close_payload()), "TLS rifiutato")
        c4 = check("4. certificato del server SA: /close", *admin_call(AE_URL, "close", server_as_client, close_payload()), "TLS rifiutato")
        still_open = urns_open()
        print(f"\n  Urne ancora aperte dopo i tentativi non autorizzati: {still_open}")

        print("\n" + "-" * 84)
        print("PANNELLO CON IL CERTIFICATO VALIDO")
        print("-" * 84)
        c5a = check("5. certificato del pannello: /reconcile", *admin_call(SA_URL, "reconcile", admin_cert()), "HTTP 200")
        c5b = check("5. certificato del pannello: /close", *admin_call(AE_URL, "close", admin_cert(), close_payload()), "HTTP 200")
        closed = not urns_open()
        print(f"\n  Urne chiuse e scrutinio eseguito: {closed}")

        passed = all([c1, c1b, c2, c3, c4, still_open, c5a, c5b, closed])
        print("\n" + "=" * 84)
        print("RIEPILOGO")
        print("=" * 84)
        print(f"  Senza certificato client: 403 e urne aperte:          {'PASS' if (c1 and c1b and still_open) else 'FAIL'}")
        print(f"  Certificato di un'altra CA rifiutato nell'handshake:  {'PASS' if c2 else 'FAIL'}")
        print(f"  Certificato revocato rifiutato tramite CRL:           {'PASS' if c3 else 'FAIL'}")
        print(f"  Certificato di un server non accettato come client:   {'PASS' if c4 else 'FAIL'}")
        print(f"  Pannello con certificato valido: operazioni riuscite: {'PASS' if (c5a and c5b and closed) else 'FAIL'}")
        print("=" * 84)
        save_report(test_id="admin_mtls", test_name="TLS mutuo per le operazioni amministrative",
                    outcome="PASS" if passed else "FAIL",
                    details={"checks": checks, "urns_open_after_unauthorized": still_open,
                             "closed_by_admin": closed})
    finally:
        print("\n[TEARDOWN] Spegnimento dei server e pulizia...")
        stop_servers(procs)
        clean_election_state()
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    os.chdir(PROJECT_ROOT)
    try:
        main()
    except Exception as e:
        print(f"\n[ERRORE] {e}")
    finally:
        input("\nPremi Invio per chiudere...")

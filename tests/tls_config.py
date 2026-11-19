"""
Configurazione TLS condivisa per i test.

Fornisce gli URL HTTPS dei server, il parametro `verify` (la CA dell'elezione)
e il certificato client del pannello per le operazioni amministrative, usando
la PKI generata da src/pki.py.

I test che attaccano direttamente le API usano requests con la sola verifica
della catena fino alla CA; i test che riguardano il comportamento del client
reale (pinning, revoca) usano le sessioni di src/tls_context.py, le stesse del
client.
"""

import os
import subprocess
import sys

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_TLS_DIR = os.path.join(_PROJECT_ROOT, "data", "tls")
_SRC_DIR = os.path.join(_PROJECT_ROOT, "src")
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

SA_URL = "https://localhost:5001"
AE_URL = "https://localhost:5002"

_CA_CERT = os.path.join(_TLS_DIR, "ca_cert.pem")


def sa_verify() -> "str | bool":
    """Parametro verify per requests verso il SA: la CA dell'elezione."""
    return _CA_CERT if os.path.exists(_CA_CERT) else True


def ae_verify() -> "str | bool":
    """Parametro verify per requests verso l'AE: la CA dell'elezione."""
    return _CA_CERT if os.path.exists(_CA_CERT) else True


def admin_cert() -> tuple:
    """
    Certificato client del pannello (parametro `cert` di requests) per le
    operazioni amministrative (/close, /reconcile, /shutdown). Il server lo
    verifica nell'handshake TLS: senza, risponde 403.
    """
    return (os.path.join(_TLS_DIR, "admin_cert.pem"), os.path.join(_TLS_DIR, "admin_key.pem"))


def ensure_tls_certs() -> None:
    """
    Genera la PKI (CA, certificati, CRL, pin) se manca o se CA, certificati o
    CRL sono scaduti. Chiamare nel setup() di ogni test che avvia SA o AE.
    """
    import pki
    if pki.pki_ready():
        return
    print("  [TLS] PKI assente o scaduta, generazione in corso...", end=" ", flush=True)
    script = os.path.join(_SRC_DIR, "generate_tls_certs.py")
    result = subprocess.run([sys.executable, script], cwd=_PROJECT_ROOT, capture_output=True)
    if result.returncode == 0:
        print("OK")
    else:
        print("ERRORE")
        print(result.stderr.decode(errors="replace"))
        raise RuntimeError("Impossibile generare la PKI dell'elezione")

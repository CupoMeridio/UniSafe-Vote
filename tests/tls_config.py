"""
Configurazione TLS condivisa per i test.

Fornisce gli URL HTTPS e il parametro `verify` corretto per ogni server,
usando i certificati self-signed generati da generate_tls_certs.py.
"""

import os
import subprocess
import sys

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SA_URL = "https://localhost:5001"
AE_URL = "https://localhost:5002"

_SA_CERT = os.path.join(_PROJECT_ROOT, "data", "tls", "sa_cert.pem")
_AE_CERT = os.path.join(_PROJECT_ROOT, "data", "tls", "ae_cert.pem")


def sa_verify() -> "str | bool":
    """Restituisce il parametro verify per requests verso il SA."""
    return _SA_CERT if os.path.exists(_SA_CERT) else True


def ae_verify() -> "str | bool":
    """Restituisce il parametro verify per requests verso l'AE."""
    return _AE_CERT if os.path.exists(_AE_CERT) else True


def ensure_tls_certs() -> None:
    """
    Genera i certificati TLS self-signed se non esistono o se sono stati
    eliminati (es. dopo un reset). Chiamare nel setup() di ogni test che
    avvia SA o AE come sottoprocesso, prima di lanciare i server.
    """
    tls_dir = os.path.join(_PROJECT_ROOT, "data", "tls")
    sa_cert = os.path.join(tls_dir, "sa_cert.pem")
    ae_cert = os.path.join(tls_dir, "ae_cert.pem")

    sa_key = os.path.join(tls_dir, "sa_key.pem")
    ae_key = os.path.join(tls_dir, "ae_key.pem")

    if all(os.path.exists(p) for p in [sa_cert, sa_key, ae_cert, ae_key]):
        return  # già presenti, niente da fare

    print("  [TLS] Certificati non trovati, generazione in corso...", end=" ", flush=True)
    script = os.path.join(_PROJECT_ROOT, "src", "generate_tls_certs.py")
    result = subprocess.run(
        [sys.executable, script],
        cwd=_PROJECT_ROOT,
        capture_output=True,
    )
    if result.returncode == 0:
        print("OK")
    else:
        print("ERRORE")
        print(result.stderr.decode(errors="replace"))
        raise RuntimeError("Impossibile generare i certificati TLS self-signed")

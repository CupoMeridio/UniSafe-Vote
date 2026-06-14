"""
Configurazione TLS condivisa per i test.

Fornisce gli URL HTTPS e il parametro `verify` corretto per ogni server,
usando i certificati self-signed generati da generate_tls_certs.py.
Se i certificati non esistono (es. prima dell'init), degrada a HTTP
in modo trasparente, così i test continuano a funzionare.
"""

import os

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

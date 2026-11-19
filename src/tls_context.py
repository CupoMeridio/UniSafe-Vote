"""
Configurazione TLS condivisa da server, client, pannello e test.

Tutte le connessioni HTTPS passano dal modulo ssl della libreria standard; il
materiale (CA, certificati, CRL, pin) è prodotto da pki.py con cryptography.
Qui si costruiscono i contesti TLS in un solo punto, così che tutti i
componenti applichino le stesse verifiche.

Lato client, per ogni connessione verso SA o AE si verifica che:
1. la catena del certificato del server arrivi alla CA dell'elezione (e solo a
   quella: le CA pubbliche del sistema non sono considerate);
2. il nome del server corrisponda al certificato (localhost / 127.0.0.1);
3. il certificato non compaia nella CRL pubblicata dalla CA;
4. la chiave pubblica del server corrisponda all'impronta SPKI distribuita in
   tls_pins.json (pinning). Questo controllo protegge anche se la CA venisse
   compromessa: un certificato emesso dalla CA a un impostore ha comunque una
   chiave diversa da quella attesa.

Lato server il certificato client è FACOLTATIVO: gli elettori si connettono
senza, il pannello amministrativo presenta il certificato emesso dalla CA con
uso "clientAuth". Se presentato, viene verificato già nell'handshake (catena e
CRL); gli endpoint amministrativi controllano poi che sia quello del pannello.
"""

import hashlib
import json
import os
import ssl
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TLS_DIR = os.path.join(PROJECT_ROOT, "data", "tls")
ADMIN_CN = "UniSafe-Vote Admin"


def _p(tls_dir: str, name: str) -> str:
    return os.path.join(tls_dir, name)


def tls_available(tls_dir: str = DEFAULT_TLS_DIR) -> bool:
    return all(os.path.exists(_p(tls_dir, f)) for f in ("ca_cert.pem", "crl.pem", "tls_pins.json"))


def load_pin(server: str, tls_dir: str = DEFAULT_TLS_DIR) -> Optional[str]:
    """Impronta SPKI attesa per il server ("sa" o "ae"), senza prefisso."""
    try:
        with open(_p(tls_dir, "tls_pins.json"), "r", encoding="utf-8") as f:
            return json.load(f)[server].removeprefix("sha256:")
    except (FileNotFoundError, KeyError):
        return None


# ---------------------------------------------------------------------------
# Lato server
# ---------------------------------------------------------------------------

def server_ssl_context(server: str, tls_dir: str = DEFAULT_TLS_DIR) -> ssl.SSLContext:
    """Contesto TLS del server: proprio certificato, certificato client facoltativo verificato con CA e CRL."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(_p(tls_dir, f"{server}_cert.pem"), _p(tls_dir, f"{server}_key.pem"))
    ctx.verify_mode = ssl.CERT_OPTIONAL
    ctx.load_verify_locations(_p(tls_dir, "ca_cert.pem"))
    ctx.load_verify_locations(_p(tls_dir, "crl.pem"))
    ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
    return ctx


def admin_client_cert_ok(client_cert_pem: Optional[str]) -> bool:
    """
    True se la connessione ha presentato il certificato del pannello.

    Catena e revoca sono già state verificate nell'handshake TLS; qui si
    controlla che sia un certificato client (clientAuth) emesso al pannello,
    e non, ad esempio, il certificato di un server.
    """
    if not client_cert_pem:
        return False
    try:
        cert = x509.load_pem_x509_certificate(client_cert_pem.encode("ascii"))
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except (ValueError, x509.ExtensionNotFound, IndexError):
        return False
    return ExtendedKeyUsageOID.CLIENT_AUTH in eku and cn == ADMIN_CN


# ---------------------------------------------------------------------------
# Lato client
# ---------------------------------------------------------------------------

def _spki_of_der(der: bytes) -> str:
    cert = x509.load_der_x509_certificate(der)
    return hashlib.sha256(cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()


def client_ssl_context(server: str, tls_dir: str = DEFAULT_TLS_DIR, admin: bool = False,
                       check_pin: bool = True, check_crl: bool = True) -> ssl.SSLContext:
    """
    Contesto TLS per connettersi a SA o AE.

    Args:
        server: "sa" o "ae" (determina il pin SPKI atteso).
        admin: se True presenta il certificato client del pannello.
        check_pin / check_crl: disattivabili SOLO nei test, per mostrare che
            cosa accadrebbe senza quel controllo.
    """
    ctx = ssl.create_default_context(cafile=_p(tls_dir, "ca_cert.pem"))  # solo la CA dell'elezione
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if check_crl:
        ctx.load_verify_locations(_p(tls_dir, "crl.pem"))
        ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
    if admin:
        ctx.load_cert_chain(_p(tls_dir, "admin_cert.pem"), _p(tls_dir, "admin_key.pem"))
    expected = load_pin(server, tls_dir) if check_pin else None
    if check_pin and not expected:
        raise RuntimeError(f"Pin SPKI per '{server}' non disponibile in tls_pins.json")

    class PinnedSSLSocket(ssl.SSLSocket):
        """Socket TLS che, completato l'handshake, confronta la chiave del server con il pin."""

        def do_handshake(self, *args, **kwargs):
            super().do_handshake(*args, **kwargs)
            if expected:
                presented = _spki_of_der(self.getpeercert(binary_form=True))
                if presented != expected:
                    raise ssl.SSLCertVerificationError(
                        f"pin SPKI non corrispondente: chiave del server {presented[:16]}..., "
                        f"attesa {expected[:16]}...")

    ctx.sslsocket_class = PinnedSSLSocket
    return ctx


class _ContextAdapter(HTTPAdapter):
    """Adattatore che fa usare a requests un contesto TLS costruito da noi."""

    def __init__(self, ssl_context: ssl.SSLContext, **kwargs):
        self._ssl_context = ssl_context
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs["ssl_context"] = self._ssl_context
        return super().init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        kwargs["ssl_context"] = self._ssl_context
        return super().proxy_manager_for(*args, **kwargs)


def client_session(server: str, tls_dir: str = DEFAULT_TLS_DIR, admin: bool = False,
                   check_pin: bool = True, check_crl: bool = True) -> requests.Session:
    """Sessione requests verso SA o AE con catena, nome, CRL e pin SPKI verificati."""
    session = requests.Session()
    # verify punta alla sola CA dell'elezione: requests non aggiunge le CA pubbliche
    session.verify = _p(tls_dir, "ca_cert.pem")
    session.mount("https://", _ContextAdapter(
        client_ssl_context(server, tls_dir, admin=admin, check_pin=check_pin, check_crl=check_crl)))
    return session

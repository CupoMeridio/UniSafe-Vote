"""
Infrastruttura a chiave pubblica (PKI) dell'elezione: Certification Authority locale.

Operazioni fondamentali di una CA implementate:
1. Creazione della CA radice: certificato self-signed con BasicConstraints
   CA:TRUE e KeyUsage limitato a firmare certificati e CRL. La chiave privata
   della CA resta in data/tls/ca/, cartella che SA e AE non leggono mai
   (nel PoC "offline" significa: usata solo da questo modulo).
2. Richiesta di certificato (CSR): ogni ente genera da sé la propria coppia di
   chiavi e invia alla CA solo identità e chiave pubblica, firmando la richiesta
   con la propria chiave privata (prova di possesso). La chiave privata non
   passa mai dalla CA.
3. Emissione: la CA verifica la firma della CSR e firma un certificato con le
   estensioni del profilo richiesto: CA:FALSE, uso della chiave, uso esteso
   (serverAuth per SA e AE, clientAuth per il pannello amministrativo), SAN
   per i server, validità breve.
4. Revoca e pubblicazione della CRL: la CA mantiene un registro dei certificati
   emessi; revocare un certificato significa aggiungerne il numero di serie alla
   Certificate Revocation List, firmata dalla CA e con una data di prossimo
   aggiornamento.

Materiale prodotto in data/tls/:
  ca_cert.pem            certificato della CA radice (distribuito ai client)
  crl.pem                lista dei certificati revocati, firmata dalla CA
  sa_cert.pem/_key.pem   certificato e chiave TLS del SA (serverAuth)
  ae_cert.pem/_key.pem   certificato e chiave TLS dell'AE (serverAuth)
  admin_cert.pem/_key.pem certificato client del pannello (clientAuth)
  tls_pins.json          impronte SHA-256 delle chiavi pubbliche (SPKI) di SA e AE
  ca/ca_key.pem          chiave privata della CA (non letta dai server)
  ca/registry.json       registro dei certificati emessi e revocati

Uso da riga di comando (dalla radice del progetto):
  python src/pki.py init             crea CA, certificati, CRL e pin
  python src/pki.py revoke <nome>    revoca il certificato <nome> e ripubblica la CRL
  python src/pki.py status           mostra certificati emessi, revoche e validità
"""

import datetime as dt
import hashlib
import ipaddress
import json
import os
import shutil
import sys
from typing import Dict, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TLS_DIR = os.path.join(PROJECT_ROOT, "data", "tls")

CA_NAME = "UniSafe-Vote Root CA"
ADMIN_CN = "UniSafe-Vote Admin"
CA_VALIDITY_DAYS = 365
LEAF_VALIDITY_DAYS = 30
CRL_VALIDITY_DAYS = 30

# Profili degli enti certificati: nome file -> (Common Name, tipo)
ENTITIES = {
    "sa": ("UniSafe-Vote SA", "server"),
    "ae": ("UniSafe-Vote AE", "server"),
    "admin": (ADMIN_CN, "client"),
}


# ---------------------------------------------------------------------------
# Utilità
# ---------------------------------------------------------------------------

def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _paths(tls_dir: str) -> Dict[str, str]:
    return {
        "ca_cert": os.path.join(tls_dir, "ca_cert.pem"),
        "crl": os.path.join(tls_dir, "crl.pem"),
        "pins": os.path.join(tls_dir, "tls_pins.json"),
        "ca_dir": os.path.join(tls_dir, "ca"),
        "ca_key": os.path.join(tls_dir, "ca", "ca_key.pem"),
        "registry": os.path.join(tls_dir, "ca", "registry.json"),
    }


def cert_path(name: str, tls_dir: str = DEFAULT_TLS_DIR) -> str:
    return os.path.join(tls_dir, f"{name}_cert.pem")


def key_path(name: str, tls_dir: str = DEFAULT_TLS_DIR) -> str:
    return os.path.join(tls_dir, f"{name}_key.pem")


def _write(path: str, data: bytes) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def _new_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _key_pem(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def spki_sha256(cert: x509.Certificate) -> str:
    """Impronta SHA-256 della chiave pubblica del certificato (SubjectPublicKeyInfo, DER)."""
    der = cert.public_key().public_bytes(serialization.Encoding.DER,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def load_cert(path: str) -> x509.Certificate:
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def _load_ca(tls_dir: str) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
    p = _paths(tls_dir)
    with open(p["ca_key"], "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    return ca_key, load_cert(p["ca_cert"])


def _load_registry(tls_dir: str) -> Dict:
    p = _paths(tls_dir)
    if not os.path.exists(p["registry"]):
        return {"issued": {}, "revoked": []}
    with open(p["registry"], "r", encoding="utf-8") as f:
        return json.load(f)


def _save_registry(tls_dir: str, registry: Dict) -> None:
    _write(_paths(tls_dir)["registry"], json.dumps(registry, indent=2).encode("utf-8"))


# ---------------------------------------------------------------------------
# 1. Creazione della CA radice
# ---------------------------------------------------------------------------

def create_ca(tls_dir: str = DEFAULT_TLS_DIR, common_name: str = CA_NAME) -> x509.Certificate:
    """Genera la chiave della CA e il certificato radice self-signed."""
    ca_key = _new_key()
    name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "UniSafe-Vote"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    now = _now()
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=CA_VALIDITY_DAYS))
        # Può firmare solo certificati di enti finali, non altre CA (path_length=0)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
                                     key_encipherment=False, data_encipherment=False,
                                     key_agreement=False, key_cert_sign=True, crl_sign=True,
                                     encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    p = _paths(tls_dir)
    _write(p["ca_key"], _key_pem(ca_key))
    _write(p["ca_cert"], ca_cert.public_bytes(serialization.Encoding.PEM))
    _save_registry(tls_dir, {"issued": {}, "revoked": []})
    return ca_cert


# ---------------------------------------------------------------------------
# 2. Richiesta di certificato (lato ente)
# ---------------------------------------------------------------------------

def create_key_and_csr(common_name: str) -> Tuple[rsa.RSAPrivateKey, x509.CertificateSigningRequest]:
    """
    Operazione svolta dall'ente (SA, AE, pannello): genera la propria coppia di
    chiavi e una CSR firmata con la chiave privata. Alla CA arriva solo la CSR.
    """
    key = _new_key()
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "UniSafe-Vote"),
                                    x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
           .sign(key, hashes.SHA256()))
    return key, csr


# ---------------------------------------------------------------------------
# 3. Emissione (lato CA)
# ---------------------------------------------------------------------------

def issue_certificate(csr: x509.CertificateSigningRequest, profile: str, record_name: str,
                      tls_dir: str = DEFAULT_TLS_DIR) -> x509.Certificate:
    """
    La CA verifica la CSR e firma un certificato con le estensioni del profilo.

    Args:
        profile: "server" (TLS server, con SAN localhost/127.0.0.1) o "client".
        record_name: nome con cui il certificato è registrato (serve per la revoca).
    """
    if not csr.is_signature_valid:
        raise ValueError("CSR non valida: la firma non prova il possesso della chiave privata")
    ca_key, ca_cert = _load_ca(tls_dir)
    now = _now()
    eku = ExtendedKeyUsageOID.SERVER_AUTH if profile == "server" else ExtendedKeyUsageOID.CLIENT_AUTH
    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject).issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=LEAF_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                     key_encipherment=True, data_encipherment=False,
                                     key_agreement=False, key_cert_sign=False, crl_sign=False,
                                     encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
    )
    if profile == "server":
        builder = builder.add_extension(x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        ]), critical=False)
    cert = builder.sign(ca_key, hashes.SHA256())

    registry = _load_registry(tls_dir)
    registry["issued"][record_name] = {
        "serial": format(cert.serial_number, "x"),
        "subject": cert.subject.rfc4514_string(),
        "profile": profile,
        "not_after": cert.not_valid_after_utc.isoformat(),
    }
    _save_registry(tls_dir, registry)
    return cert


def issue_entity(name: str, common_name: str, profile: str, tls_dir: str = DEFAULT_TLS_DIR) -> x509.Certificate:
    """Flusso completo per un ente: chiave + CSR (lato ente), emissione (lato CA), salvataggio."""
    key, csr = create_key_and_csr(common_name)
    cert = issue_certificate(csr, profile, name, tls_dir)
    _write(key_path(name, tls_dir), _key_pem(key))
    _write(cert_path(name, tls_dir), cert.public_bytes(serialization.Encoding.PEM))
    return cert


# ---------------------------------------------------------------------------
# 4. Revoca e pubblicazione della CRL
# ---------------------------------------------------------------------------

def publish_crl(tls_dir: str = DEFAULT_TLS_DIR) -> x509.CertificateRevocationList:
    """
    Firma e pubblica la CRL con tutti i certificati revocati del registro.

    Con il controllo di revoca attivo, una CRL mancante o scaduta fa rifiutare
    TUTTE le connessioni: la CRL viene quindi pubblicata (anche vuota) già alla
    creazione della CA, con validità pari a quella dei certificati emessi.
    """
    ca_key, ca_cert = _load_ca(tls_dir)
    registry = _load_registry(tls_dir)
    now = _now()
    builder = (x509.CertificateRevocationListBuilder()
               .issuer_name(ca_cert.subject)
               .last_update(now - dt.timedelta(minutes=5))
               .next_update(now + dt.timedelta(days=CRL_VALIDITY_DAYS)))
    for entry in registry["revoked"]:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(int(entry["serial"], 16))
            .revocation_date(dt.datetime.fromisoformat(entry["revoked_at"]))
            .build())
    crl = builder.sign(ca_key, hashes.SHA256())
    _write(_paths(tls_dir)["crl"], crl.public_bytes(serialization.Encoding.PEM))
    return crl


def revoke(name: str, tls_dir: str = DEFAULT_TLS_DIR) -> str:
    """Revoca il certificato registrato come <name> e ripubblica la CRL. Restituisce il seriale."""
    registry = _load_registry(tls_dir)
    if name not in registry["issued"]:
        raise KeyError(f"Nessun certificato emesso con nome '{name}'")
    serial = registry["issued"][name]["serial"]
    if not any(r["serial"] == serial for r in registry["revoked"]):
        registry["revoked"].append({"name": name, "serial": serial, "revoked_at": _now().isoformat()})
        _save_registry(tls_dir, registry)
    publish_crl(tls_dir)
    return serial


# ---------------------------------------------------------------------------
# Inizializzazione completa e pin
# ---------------------------------------------------------------------------

def write_tls_pins(tls_dir: str = DEFAULT_TLS_DIR) -> Dict[str, str]:
    """
    Impronte SPKI dei server, distribuite ai client su canale separato (come
    pins.json per le chiavi applicative). Il client le confronta con la chiave
    presentata nell'handshake, oltre a verificare la catena fino alla CA.
    """
    pins = {name: "sha256:" + spki_sha256(load_cert(cert_path(name, tls_dir)))
            for name, (_, profile) in ENTITIES.items() if profile == "server"}
    _write(_paths(tls_dir)["pins"], json.dumps(pins, indent=2).encode("utf-8"))
    return pins


def init_pki(tls_dir: str = DEFAULT_TLS_DIR) -> None:
    """Crea da zero CA, certificati di SA/AE/pannello, CRL vuota e pin SPKI."""
    if os.path.isdir(tls_dir):
        for entry in os.listdir(tls_dir):
            path = os.path.join(tls_dir, entry)
            shutil.rmtree(path) if os.path.isdir(path) else os.remove(path)
    create_ca(tls_dir)
    for name, (cn, profile) in ENTITIES.items():
        issue_entity(name, cn, profile, tls_dir)
    publish_crl(tls_dir)
    write_tls_pins(tls_dir)


def pki_ready(tls_dir: str = DEFAULT_TLS_DIR) -> bool:
    """True se tutto il materiale esiste e CA, certificati e CRL sono ancora validi."""
    p = _paths(tls_dir)
    required = [p["ca_cert"], p["crl"], p["pins"], p["ca_key"]] + \
               [f(n, tls_dir) for n in ENTITIES for f in (cert_path, key_path)]
    if not all(os.path.exists(x) for x in required):
        return False
    now = _now()
    certs = [load_cert(p["ca_cert"])] + [load_cert(cert_path(n, tls_dir)) for n in ENTITIES]
    if any(c.not_valid_after_utc <= now for c in certs):
        return False
    with open(p["crl"], "rb") as f:
        crl = x509.load_pem_x509_crl(f.read())
    return crl.next_update_utc is not None and crl.next_update_utc > now


def status(tls_dir: str = DEFAULT_TLS_DIR) -> str:
    registry = _load_registry(tls_dir)
    revoked = {r["serial"] for r in registry["revoked"]}
    lines = [f"CA: {load_cert(_paths(tls_dir)['ca_cert']).subject.rfc4514_string()}"]
    for name, info in registry["issued"].items():
        state = "REVOCATO" if info["serial"] in revoked else "valido"
        lines.append(f"  {name:<20} {info['profile']:<7} seriale {info['serial'][:16]}...  "
                     f"scade {info['not_after'][:10]}  {state}")
    return "\n".join(lines)


if __name__ == "__main__":
    command = sys.argv[1] if len(sys.argv) > 1 else "init"
    if command == "init":
        init_pki()
        print("PKI creata in data/tls/: CA, certificati di SA, AE e pannello, CRL e pin SPKI.")
        print(status())
    elif command == "revoke" and len(sys.argv) == 3:
        serial = revoke(sys.argv[2])
        print(f"Certificato '{sys.argv[2]}' revocato (seriale {serial}). CRL ripubblicata.")
        print("I server rileggono la CRL al riavvio; i client a ogni nuova connessione.")
    elif command == "status":
        print(status())
    else:
        print(__doc__)
        sys.exit(1)

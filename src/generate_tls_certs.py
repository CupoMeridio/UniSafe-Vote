"""
Generazione del materiale TLS dell'elezione tramite la PKI (src/pki.py).

Lo script crea la Certification Authority dell'elezione e, tramite richieste di
certificato (CSR), i certificati di SA e AE (uso server) e del pannello
amministrativo (uso client), oltre alla CRL e alle impronte SPKI dei server.
Tutto il materiale è salvato in data/tls/ (la chiave della CA in data/tls/ca/).

La funzione generate_self_signed_cert() resta disponibile per i test, che la
usano per simulare un server impostore con un certificato self-signed.
"""

import os
import sys
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

TLS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "tls")


def generate_self_signed_cert(common_name: str, cert_path: str, key_path: str) -> None:
    """
    Genera una chiave RSA-2048 e un certificato X.509 self-signed,
    salvandoli in formato PEM.

    Args:
        common_name: CN del certificato (es. "SA" o "AE")
        cert_path: percorso dove salvare il certificato PEM
        key_path: percorso dove salvare la chiave privata PEM
    """
    # 1. Genera la chiave privata RSA-2048
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # 2. Costruisci il soggetto/issuer (self-signed → stessi)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "UniSafe-Vote"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    # 3. Costruisci il certificato
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
        .add_extension(
            # SAN con localhost e 127.0.0.1 — obbligatorio per i browser moderni
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(__import__("ipaddress").IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    # 4. Salva certificato e chiave in PEM
    os.makedirs(os.path.dirname(cert_path), exist_ok=True)

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    print(f"  [TLS] Certificato generato: {cert_path}")
    print(f"  [TLS] Chiave privata:        {key_path}")


def main() -> None:
    import pki

    print("\n=== GENERAZIONE PKI DELL'ELEZIONE (CA, CERTIFICATI, CRL) ===\n")
    pki.init_pki()
    print("Materiale salvato in data/tls/:")
    print("  ca_cert.pem              certificato della CA radice (fiducia dei client)")
    print("  sa_cert.pem / ae_cert.pem certificati dei server, emessi dalla CA su CSR")
    print("  admin_cert.pem           certificato client del pannello amministrativo")
    print("  crl.pem                  lista dei certificati revocati (vuota)")
    print("  tls_pins.json            impronte SPKI delle chiavi di SA e AE")
    print("  ca/                      chiave privata e registro della CA (non letti dai server)\n")
    print(pki.status())
    print("\nSA: https://localhost:5001")
    print("AE: https://localhost:5002\n")


if __name__ == "__main__":
    # Esegui sempre dalla root del progetto
    os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    main()

"""
Generazione dei certificati TLS self-signed per SA e AE.

Questo script genera due coppie certificato/chiave RSA-2048 self-signed
per abilitare HTTPS su SA (porta 5001) e AE (porta 5002).

I certificati vengono salvati in data/tls/:
  - sa_cert.pem  / sa_key.pem
  - ae_cert.pem  / ae_key.pem

In un sistema reale i certificati sarebbero rilasciati da una CA riconosciuta.
Qui usiamo certificati self-signed a scopo didattico/locale.
"""

import os
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
    print("\n=== GENERAZIONE CERTIFICATI TLS SELF-SIGNED ===\n")

    os.makedirs(TLS_DIR, exist_ok=True)

    generate_self_signed_cert(
        common_name="UniSafe-Vote SA",
        cert_path=os.path.join(TLS_DIR, "sa_cert.pem"),
        key_path=os.path.join(TLS_DIR, "sa_key.pem"),
    )

    generate_self_signed_cert(
        common_name="UniSafe-Vote AE",
        cert_path=os.path.join(TLS_DIR, "ae_cert.pem"),
        key_path=os.path.join(TLS_DIR, "ae_key.pem"),
    )

    print("\nCertificati salvati in data/tls/")
    print("SA: https://localhost:5001")
    print("AE: https://localhost:5002\n")


if __name__ == "__main__":
    # Esegui sempre dalla root del progetto
    os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    main()

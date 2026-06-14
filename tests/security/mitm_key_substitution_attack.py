"""
Test di attacco MitM — Sostituzione Chiave Pubblica (Key Substitution Attack).

Verifica che il certificate pinning del client rilevi correttamente
la sostituzione delle chiavi pubbliche dell'AE nel Bulletin Board.
"""

import os
import sys
import json
import hashlib

# ---------------------------------------------------------------------------
# Path setup — il test gira da qualsiasi directory
# ---------------------------------------------------------------------------
PROJECT_ROOT  = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SRC_DIR       = os.path.join(PROJECT_ROOT, "src")
DATA_DIR      = os.path.join(PROJECT_ROOT, "data")
KEYS_DIR      = os.path.join(DATA_DIR, "keys")
TESTS_SEC_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SRC_DIR)
sys.path.insert(0, TESTS_SEC_DIR)

from test_reporter import save_report
from crypto.keys import (generate_rsa_keypair, save_keypair, serialize_public_key,
                          deserialize_public_key, save_encrypted_private_key)
from crypto.rsa_pss import sign
from crypto.password import hash_password
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta, UTC


# ---------------------------------------------------------------------------
# compute_public_key_fingerprint inline (evita import da client)
# ---------------------------------------------------------------------------

def compute_public_key_fingerprint(pem_str: str) -> str:
    """Calcola l'impronta SHA-256 DER di una chiave pubblica RSA."""
    # Si converte la chiave PEM in formato DER e se ne calcola l'hash SHA-256,
    # ottenendo l'impronta usata per il certificate pinning (WP3 §3.4).
    pubkey = deserialize_public_key(pem_str)
    pubkey_bytes = pubkey.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(pubkey_bytes).hexdigest()


# ---------------------------------------------------------------------------
# Logica di inizializzazione inline (path assoluti, nessun import con cwd sbagliato)
# ---------------------------------------------------------------------------

VOTERS = [
    {"id": "v001", "email": "mario.rossi@studenti.unisa.it",
     "username": "mario.rossi",   "password": "password123"},
    {"id": "v002", "email": "luigi.bianchi@unisa.it",
     "username": "luigi.bianchi", "password": "password456"},
]
CANDIDATES = ["Lista A", "Lista B", "Lista C"]

BULLETIN_BOARD_PATH = os.path.join(DATA_DIR, "bulletin_board.json")


def init_election():
    """
    Inizializza l'elezione: genera chiavi, scrive tutti i file di configurazione.
    Usa path assoluti — funziona da qualsiasi directory corrente.
    """
    # Si creano le directory e si elimina ogni stato residuo
    # di esecuzioni precedenti per garantire riproducibilità.
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(KEYS_DIR, exist_ok=True)

    for fname in ["bulletin_board.json", "voters.json", "ae_state.json", "pins.json"]:
        p = os.path.join(DATA_DIR, fname)
        if os.path.exists(p):
            os.remove(p)
    for f in os.listdir(KEYS_DIR):
        os.remove(os.path.join(KEYS_DIR, f))

    # Si generano tre coppie RSA-2048: firma SA, cifratura AE e firma AE.
    sa_sign_priv,  sa_sign_pub  = generate_rsa_keypair()
    ae_enc_priv,   ae_enc_pub   = generate_rsa_keypair()
    ae_sign_priv,  ae_sign_pub  = generate_rsa_keypair()

    save_keypair(sa_sign_priv, sa_sign_pub,  "sa_sign")
    save_keypair(ae_enc_priv,  ae_enc_pub,   "ae_encrypt")
    save_keypair(ae_sign_priv, ae_sign_pub,  "ae_sign")

    # L'elezione apre immediatamente e chiude tra 24 ore.
    opening = datetime.now(UTC).isoformat()
    closing = (datetime.now(UTC) + timedelta(hours=24)).isoformat()

    # Si compone il blocco di inizializzazione con i parametri pubblici
    # dell'elezione e le chiavi pubbliche dei componenti, poi lo si firma.
    init_data = {
        "election_id":       "elezione_test_double_voting",
        "candidates":        CANDIDATES,
        "opening_time":      opening,
        "closing_time":      closing,
        "sa_sign_public":    serialize_public_key(sa_sign_pub),
        "ae_encrypt_public": serialize_public_key(ae_enc_pub),
        "ae_sign_public":    serialize_public_key(ae_sign_pub),
    }
    init_json      = json.dumps(init_data, sort_keys=True).encode("utf-8")
    init_signature = sign(ae_sign_priv, init_json)

    bb = [{
        "type":      "init",
        "timestamp": datetime.now(UTC).isoformat(),
        "data":      init_data,
        "signature": init_signature.hex(),
    }]
    with open(BULLETIN_BOARD_PATH, "w", encoding="utf-8") as f:
        json.dump(bb, f, indent=2, ensure_ascii=False)

    # Si calcolano le impronte SHA-256 delle chiavi pubbliche AE e si salvano
    # in pins.json, simulando il canale di distribuzione trusted separato
    # dal Bulletin Board (certificate pinning, WP3 §3.4).
    pins = {
        "ae_encrypt_public": "sha256:" + compute_public_key_fingerprint(init_data["ae_encrypt_public"]),
        "ae_sign_public":    "sha256:" + compute_public_key_fingerprint(init_data["ae_sign_public"]),
    }
    with open(os.path.join(DATA_DIR, "pins.json"), "w", encoding="utf-8") as f:
        json.dump(pins, f, indent=2, ensure_ascii=False)

    # La chiave privata di cifratura AE viene salvata cifrata con AES-GCM
    # usando la firma del blocco init come IKM (WP3 §3.3).
    save_encrypted_private_key(ae_enc_priv, "ae_encrypt", init_signature)

    # Le password vengono salvate come hash Argon2, mai in chiaro.
    voters_data = []
    for v in VOTERS:
        vc = v.copy()
        vc["password"] = hash_password(vc["password"])
        voters_data.append(vc)
    with open(os.path.join(DATA_DIR, "voters.json"), "w", encoding="utf-8") as f:
        json.dump(voters_data, f, indent=2, ensure_ascii=False)

    # Si inizializza lo stato privato dell'AE con la lista dei token usati vuota.
    with open(os.path.join(DATA_DIR, "ae_state.json"), "w", encoding="utf-8") as f:
        json.dump({"used_tokens": []}, f, indent=2, ensure_ascii=False)

    print("Elezioni inizializzate con successo!")


# ---------------------------------------------------------------------------
# Import Client dopo sys.path.insert — funziona da qualsiasi directory
# ---------------------------------------------------------------------------
# Si importa Client da src/client.py dopo aver aggiunto SRC_DIR al path.
# L'import avviene qui (e non in cima al file) perché dipende da sys.path.insert.
from client import Client, SecurityError


def main():
    os.chdir(PROJECT_ROOT)

    print("=" * 80)
    print("  TEST ATTACCO MitM — SOSTITUZIONE CHIAVE PUBBLICA")
    print("  (Certificate Pinning contro Key Substitution Attack)")
    print("=" * 80)

    # ------------------------------------------------------------------ #
    # PASSO 1 — Inizializzazione elezione con chiavi legittime            #
    # ------------------------------------------------------------------ #
    print("\n" + "-" * 80)
    print("PASSO 1 — Inizializzazione elezione con chiavi legittime")
    print("-" * 80)
    init_election()

    # Si legge il Bulletin Board appena creato per mostrare le chiavi reali.
    with open(BULLETIN_BOARD_PATH, "r", encoding="utf-8") as f:
        original_bb = json.load(f)

    legit_enc_pem  = original_bb[0]["data"]["ae_encrypt_public"]
    legit_sign_pem = original_bb[0]["data"]["ae_sign_public"]

    legit_enc_fp  = compute_public_key_fingerprint(legit_enc_pem)
    legit_sign_fp = compute_public_key_fingerprint(legit_sign_pem)

    print(f"\n  Chiave pubblica AE (cifratura) sul Bulletin Board:")
    print(f"    {legit_enc_pem.splitlines()[1][:64]}...")
    print(f"  Impronta SHA-256:  {legit_enc_fp}")

    print(f"\n  Chiave pubblica AE (firma) sul Bulletin Board:")
    print(f"    {legit_sign_pem.splitlines()[1][:64]}...")
    print(f"  Impronta SHA-256:  {legit_sign_fp}")

    # ------------------------------------------------------------------ #
    # PASSO 2 — Caricamento pin trusted dal canale sicuro (pins.json)     #
    # ------------------------------------------------------------------ #
    print("\n" + "-" * 80)
    print("PASSO 2 — Pin trusted caricati dal canale sicuro (pins.json)")
    print("-" * 80)

    client = Client()
    pin_enc  = client.trusted_pins["ae_encrypt_public"]
    pin_sign = client.trusted_pins["ae_sign_public"]

    print(f"\n  Pin trusted AE (cifratura):  {pin_enc}")
    print(f"  Pin trusted AE (firma):      {pin_sign}")

    # Verifica che i pin corrispondano alle impronte delle chiavi legittime.
    match_enc  = pin_enc.removeprefix("sha256:") == legit_enc_fp
    match_sign = pin_sign.removeprefix("sha256:") == legit_sign_fp
    print(f"\n  Corrispondenza pin ↔ chiave legittima (cifratura): {'✓ sì' if match_enc  else '✗ no'}")
    print(f"  Corrispondenza pin ↔ chiave legittima (firma):     {'✓ sì' if match_sign else '✗ no'}")

    # ------------------------------------------------------------------ #
    # PASSO 3 — L'attaccante genera chiavi RSA contraffatte               #
    # ------------------------------------------------------------------ #
    print("\n" + "-" * 80)
    print("PASSO 3 — L'attaccante genera chiavi RSA contraffatte")
    print("-" * 80)

    fake_enc_priv,  fake_enc_pub  = generate_rsa_keypair()
    fake_sign_priv, fake_sign_pub = generate_rsa_keypair()
    fake_enc_pem  = serialize_public_key(fake_enc_pub)
    fake_sign_pem = serialize_public_key(fake_sign_pub)

    fake_enc_fp  = compute_public_key_fingerprint(fake_enc_pem)
    fake_sign_fp = compute_public_key_fingerprint(fake_sign_pem)

    print(f"\n  Chiave CONTRAFFATTA AE (cifratura):")
    print(f"    {fake_enc_pem.splitlines()[1][:64]}...")
    print(f"  Impronta SHA-256:  {fake_enc_fp}")

    print(f"\n  Chiave CONTRAFFATTA AE (firma):")
    print(f"    {fake_sign_pem.splitlines()[1][:64]}...")
    print(f"  Impronta SHA-256:  {fake_sign_fp}")

    print(f"\n  Confronto impronte (cifratura):")
    print(f"    Legittima:    {legit_enc_fp}")
    print(f"    Contraffatta: {fake_enc_fp}")
    print(f"    Uguali? {'sì' if legit_enc_fp == fake_enc_fp else 'no — sono chiavi diverse, come atteso'}")

    # ------------------------------------------------------------------ #
    # PASSO 4 — L'attaccante inietta le chiavi false nel Bulletin Board   #
    # ------------------------------------------------------------------ #
    print("\n" + "-" * 80)
    print("PASSO 4 — L'attaccante inietta le chiavi false nel Bulletin Board")
    print("-" * 80)

    with open(BULLETIN_BOARD_PATH, "r", encoding="utf-8") as f:
        tampered_bb = json.load(f)

    tampered_bb[0]["data"]["ae_encrypt_public"] = fake_enc_pem
    tampered_bb[0]["data"]["ae_sign_public"]    = fake_sign_pem

    with open(BULLETIN_BOARD_PATH, "w", encoding="utf-8") as f:
        json.dump(tampered_bb, f, indent=2, ensure_ascii=False)

    # Si mostra il diff: la chiave nel BB ora è quella contraffatta.
    with open(BULLETIN_BOARD_PATH, "r", encoding="utf-8") as f:
        bb_after = json.load(f)

    fp_after_enc  = compute_public_key_fingerprint(bb_after[0]["data"]["ae_encrypt_public"])
    fp_after_sign = compute_public_key_fingerprint(bb_after[0]["data"]["ae_sign_public"])

    print(f"\n  Bulletin Board PRIMA della manomissione:")
    print(f"    ae_encrypt_public SHA-256: {legit_enc_fp}")
    print(f"    ae_sign_public    SHA-256: {legit_sign_fp}")
    print(f"\n  Bulletin Board DOPO la manomissione:")
    print(f"    ae_encrypt_public SHA-256: {fp_after_enc}")
    print(f"    ae_sign_public    SHA-256: {fp_after_sign}")
    print(f"\n  Le chiavi nel BB coincidono ancora con i pin trusted?")
    print(f"    ae_encrypt_public: {'✓ sì' if pin_enc.removeprefix('sha256:') == fp_after_enc  else '✗ no — BB manomesso!'}")
    print(f"    ae_sign_public:    {'✓ sì' if pin_sign.removeprefix('sha256:') == fp_after_sign else '✗ no — BB manomesso!'}")

    # ------------------------------------------------------------------ #
    # PASSO 5 — Il client tenta di caricare il BB manomesso               #
    # ------------------------------------------------------------------ #
    print("\n" + "-" * 80)
    print("PASSO 5 — Il client tenta di caricare il BB manomesso")
    print("-" * 80)
    print("\n  Il client confronta le impronte delle chiavi ricevute dal BB")
    print("  con i pin trusted caricati dal canale sicuro (pins.json).")
    print("  Se non corrispondono, deve bloccarsi con SecurityError.\n")

    error_message = None
    detected = False
    try:
        client.load_bulletin_board()
        print("  [FALLIMENTO] Il client ha accettato le chiavi contraffatte!")
    except SecurityError as e:
        error_message = str(e)
        detected = True
        print(f"  [PASS] SecurityError sollevato correttamente!")
        print(f"  Messaggio: {error_message}")

    # ------------------------------------------------------------------ #
    # PASSO 6 — Ripristino                                                #
    # ------------------------------------------------------------------ #
    print("\n" + "-" * 80)
    print("PASSO 6 — Ripristino stato pulito")
    print("-" * 80)
    init_election()
    print("  Bulletin Board ripristinato con chiavi legittime.")

    # ------------------------------------------------------------------ #
    # Riepilogo                                                           #
    # ------------------------------------------------------------------ #
    print("\n" + "=" * 80)
    print("RIEPILOGO")
    print("=" * 80)
    print(f"  Chiave legittima (cifratura):    {legit_enc_fp[:48]}...")
    print(f"  Chiave contraffatta (cifratura): {fake_enc_fp[:48]}...")
    print(f"  Pin trusted (cifratura):         {pin_enc[7:55]}...")
    print(f"\n  Il client ha rilevato la manomissione: {'✓ SÌ' if detected else '✗ NO'}")
    if error_message:
        print(f"  Errore restituito: {error_message}")

    if detected:
        print("\n  [SUCCESS] Certificate Pinning ha bloccato l'attacco MitM.")
        print("  Le chiavi contraffatte non corrispondono ai pin trusted:")
        print("  il client si è rifiutato di procedere prima di usarle.")
    else:
        print("\n  [FAIL] Il client ha accettato chiavi contraffatte!")
    print("=" * 80)

    save_report(
        test_id="mitm_key_substitution",
        test_name="Attacco MitM / Sostituzione Chiave Pubblica (Certificate Pinning)",
        outcome="PASS" if detected else "FAIL",
        details={
            "legitimate_keys": {
                "ae_encrypt_public_fp": legit_enc_fp,
                "ae_sign_public_fp":    legit_sign_fp,
            },
            "fake_keys": {
                "ae_encrypt_public_fp": fake_enc_fp,
                "ae_sign_public_fp":    fake_sign_fp,
            },
            "trusted_pins": {
                "ae_encrypt_public": pin_enc,
                "ae_sign_public":    pin_sign,
            },
            "tampering_detected": detected,
            "security_error_message": error_message,
            "protection_mechanism": "Certificate Pinning (SHA-256 DER fingerprint)",
        },
    )


if __name__ == "__main__":
    os.chdir(PROJECT_ROOT)
    try:
        main()
    except Exception as e:
        print(f"\n[ERRORE] {e}")
    finally:
        input("\nPremi Invio per chiudere...")

"""
Script di test per attacco dizionario / analisi di frequenza
(Ciphertext Equality & Dictionary Attack) per dimostrare
la sicurezza di RSA-OAEP nel sistema UniSafe-Vote.
"""

import os
import json
import sys
import hashlib
from typing import Dict
from datetime import datetime, timedelta, UTC

# ---------------------------------------------------------------------------
# Path setup — il test gira da qualsiasi directory
# ---------------------------------------------------------------------------
# Si risale di tre livelli (tests/security/ -> tests/ -> root) per ottenere
# la directory radice del progetto, così tutti i path successivi sono assoluti.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SRC_DIR      = os.path.join(PROJECT_ROOT, "src")
DATA_DIR     = os.path.join(PROJECT_ROOT, "data")
KEYS_DIR     = os.path.join(DATA_DIR, "keys")
TESTS_SEC_DIR = os.path.dirname(os.path.abspath(__file__))
# Si aggiunge src/ al path di ricerca dei moduli per importare i moduli
# crittografici del progetto (crypto.keys, crypto.rsa_oaep, ecc.)
sys.path.insert(0, SRC_DIR)
sys.path.insert(0, TESTS_SEC_DIR)

from test_reporter import save_report
from crypto.keys import (generate_rsa_keypair, save_keypair, serialize_public_key,
                          deserialize_public_key, save_encrypted_private_key)
from crypto.rsa_pss import sign
from crypto.rsa_oaep import encrypt
from crypto.password import hash_password
from cryptography.hazmat.primitives import serialization


# ---------------------------------------------------------------------------
# compute_public_key_fingerprint inline (evita import da client)
# ---------------------------------------------------------------------------

def compute_public_key_fingerprint(pem_str: str) -> str:
    """Calcola l'impronta SHA-256 DER di una chiave pubblica RSA."""
    # Si deserializza la chiave PEM e si converte nel formato DER (binario),
    # quindi si calcola l'hash SHA-256 del DER come impronta univoca della chiave.
    pubkey = deserialize_public_key(pem_str)
    pubkey_bytes = pubkey.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(pubkey_bytes).hexdigest()


# ---------------------------------------------------------------------------
# Setup dati (senza avvio server — test puramente crittografico offline)
# ---------------------------------------------------------------------------

VOTERS = [
    {"id": "v001", "email": "mario.rossi@studenti.unisa.it",
     "username": "mario.rossi",   "password": "password123"},
    {"id": "v002", "email": "luigi.bianchi@unisa.it",
     "username": "luigi.bianchi", "password": "password456"},
]
CANDIDATES = ["Lista A", "Lista B", "Lista C"]


def setup_data():
    """Genera chiavi e scrive bulletin_board.json e pins.json. Nessun server avviato."""
    print("\n[SETUP] Generazione chiavi e dati di elezione...")

    # Si creano le directory necessarie se non esistono.
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(KEYS_DIR, exist_ok=True)

    # Si eliminano i file residui di eventuali esecuzioni precedenti per
    # garantire uno stato pulito e riproducibile.
    for fname in ["bulletin_board.json", "voters.json", "ae_state.json", "pins.json"]:
        p = os.path.join(DATA_DIR, fname)
        if os.path.exists(p):
            os.remove(p)
    for f in os.listdir(KEYS_DIR):
        os.remove(os.path.join(KEYS_DIR, f))

    # Si generano tre coppie di chiavi RSA-2048 distinte per funzione:
    # firma del SA, cifratura dell'AE e firma dell'AE.
    sa_sign_priv,  sa_sign_pub  = generate_rsa_keypair()
    ae_enc_priv,   ae_enc_pub   = generate_rsa_keypair()
    ae_sign_priv,  ae_sign_pub  = generate_rsa_keypair()

    save_keypair(sa_sign_priv, sa_sign_pub,  "sa_sign")
    save_keypair(ae_enc_priv,  ae_enc_pub,   "ae_encrypt")
    save_keypair(ae_sign_priv, ae_sign_pub,  "ae_sign")

    # Si definisce la finestra temporale dell'elezione: apertura immediata,
    # chiusura tra 24 ore, in modo che i voti di test siano sempre validi.
    opening = datetime.now(UTC).isoformat()
    closing = (datetime.now(UTC) + timedelta(hours=24)).isoformat()

    # Si costruisce il blocco di inizializzazione del Bulletin Board con tutti
    # i parametri pubblici dell'elezione e le chiavi pubbliche dei componenti.
    init_data = {
        "election_id":       "dictionary_attack_test",
        "candidates":        CANDIDATES,
        "opening_time":      opening,
        "closing_time":      closing,
        "sa_sign_public":    serialize_public_key(sa_sign_pub),
        "ae_encrypt_public": serialize_public_key(ae_enc_pub),
        "ae_sign_public":    serialize_public_key(ae_sign_pub),
    }
    # Il blocco init viene firmato dall'AE con la propria chiave di firma,
    # esattamente come avviene nel sistema reale durante l'inizializzazione.
    init_json      = json.dumps(init_data, sort_keys=True).encode("utf-8")
    init_signature = sign(ae_sign_priv, init_json)

    bb = [{
        "type":      "init",
        "timestamp": datetime.now(UTC).isoformat(),
        "data":      init_data,
        "signature": init_signature.hex(),
    }]
    with open(os.path.join(DATA_DIR, "bulletin_board.json"), "w", encoding="utf-8") as f:
        json.dump(bb, f, indent=2)

    # Si calcolano le impronte SHA-256 delle chiavi pubbliche dell'AE e si
    # salvano in pins.json, simulando il canale di distribuzione trusted
    # separato dal Bulletin Board (certificate pinning, WP3 §3.4).
    pins = {
        "ae_encrypt_public": "sha256:" + compute_public_key_fingerprint(init_data["ae_encrypt_public"]),
        "ae_sign_public":    "sha256:" + compute_public_key_fingerprint(init_data["ae_sign_public"]),
    }
    with open(os.path.join(DATA_DIR, "pins.json"), "w", encoding="utf-8") as f:
        json.dump(pins, f, indent=2)

    # La chiave privata di cifratura dell'AE viene salvata cifrata con AES-GCM,
    # usando la firma del blocco init come IKM.
    save_encrypted_private_key(ae_enc_priv, "ae_encrypt", init_signature)

    # Le password degli elettori vengono memorizzate come hash Argon2,
    # mai in chiaro, come nel sistema reale.
    voters_data = []
    for v in VOTERS:
        vc = v.copy()
        vc["password"] = hash_password(vc["password"])
        voters_data.append(vc)
    with open(os.path.join(DATA_DIR, "voters.json"), "w", encoding="utf-8") as f:
        json.dump(voters_data, f, indent=2)

    # Si inizializza lo stato privato dell'AE con la lista dei token usati vuota.
    with open(os.path.join(DATA_DIR, "ae_state.json"), "w", encoding="utf-8") as f:
        json.dump({"used_tokens": []}, f, indent=2)

    print("[SETUP] Dati di elezione pronti (nessun server avviato).")


# ---------------------------------------------------------------------------
# Logica di test (invariata)
# ---------------------------------------------------------------------------

def validate_pins(bulletin_board: Dict):
    """Verifica che le chiavi AE del Bulletin Board corrispondano ai pin trusted."""
    with open(os.path.join(DATA_DIR, "pins.json"), "r", encoding="utf-8") as f:
        pins = json.load(f)

    init_data = bulletin_board[0]["data"]

    # Si normalizza il pin rimuovendo il prefisso "sha256:" se presente,
    # per confrontare solo il valore esadecimale dell'impronta.
    def normalize_pin(pin_value):
        return pin_value[7:] if pin_value.startswith("sha256:") else pin_value

    assert normalize_pin(pins["ae_encrypt_public"]) == compute_public_key_fingerprint(init_data["ae_encrypt_public"])
    assert normalize_pin(pins["ae_sign_public"]) == compute_public_key_fingerprint(init_data["ae_sign_public"])
    print("   Pin trusted AE verificati con successo!")


def load_bulletin_board() -> Dict:
    """Carica il Bulletin Board pubblico."""
    with open(os.path.join(DATA_DIR, "bulletin_board.json"), "r", encoding="utf-8") as f:
        return json.load(f)


def get_ae_public_key(bulletin_board: Dict):
    """Carica la chiave pubblica dell'AE dal Bulletin Board."""
    init_data = bulletin_board[0]["data"]
    return deserialize_public_key(init_data["ae_encrypt_public"])


def get_target_ciphertext(bulletin_board: Dict):
    """Prende un ciphertext di voto dal Bulletin Board (se presente)."""
    for block in bulletin_board:
        if block["type"] == "vote":
            return block["data"]["enc_vote"]
    return None


def main():
    # Si inizializza l'ambiente di test generando chiavi e file di configurazione.
    setup_data()

    print("=" * 80)
    print("TEST ATTACCO DIZIONARIO / ANALISI DI FREQUENZA")
    print("(Ciphertext Equality & Dictionary Attack)")
    print("=" * 80)

    # 1. Si carica il Bulletin Board e si verifica il certificate pinning:
    #    le chiavi pubbliche dell'AE devono corrispondere ai pin trusted.
    print("\n1. Caricamento chiave pubblica e dati...")
    bb = load_bulletin_board()
    validate_pins(bb)
    ae_pubkey = get_ae_public_key(bb)
    candidates = bb[0]["data"]["candidates"]

    # 2. Si costruisce il dizionario dei possibili voti: per ogni candidato
    #    si associa l'indice (1 byte) alla stringa descrittiva.
    #    Questo è esattamente il dizionario che un attaccante conoscerebbe,
    #    dato che i candidati sono pubblici sul Bulletin Board.
    print("\n2. Definizione dizionario di voti possibili:")
    MappaVoti = {}
    for i, candidate in enumerate(candidates):
        vote_bytes = i.to_bytes(1, byteorder="big")
        MappaVoti[vote_bytes] = candidate
        print(f"   {vote_bytes.hex()} -> {candidate}")
    print(f"   {b'\\x03'.hex()} -> Scheda Bianca/Nulla")
    MappaVoti[b"\x03"] = "Scheda Bianca/Nulla"

    # 3. Si seleziona il ciphertext bersaglio dell'attacco: se nel Bulletin Board
    #    è già presente un voto reale, si usa quello; altrimenti si crea un voto
    #    fittizio cifrato con un seed casuale (sconosciuto all'attaccante).
    target_hex = get_target_ciphertext(bb)
    if target_hex is None:
        print("\n3. Creazione voto fittizio come target...")
        seed = os.urandom(32)
        target_vote_bytes = (0).to_bytes(1, byteorder="big")  # Voto per Lista A
        # Si cifra il voto con RSA-OAEP usando un seed casuale noto solo al mittente.
        target_ciphertext = encrypt(ae_pubkey, target_vote_bytes, seed=seed)
        target_hex = target_ciphertext.hex()
        print(f"   Target vote: {target_vote_bytes.hex()} ({MappaVoti[target_vote_bytes]})")
        print(f"   Target ciphertext: {target_hex[:60]}...")
    else:
        print(f"\n3. Target ciphertext preso dal Bulletin Board: {target_hex[:60]}...")
    target_bytes = bytes.fromhex(target_hex)

    # 4. Si esegue l'attacco dizionario: per ogni possibile voto si cifra il
    #    messaggio più volte con seed casuali diversi e si confronta il risultato
    #    con il ciphertext bersaglio. L'attaccante spera che due cifrature
    #    dello stesso messaggio producano lo stesso ciphertext (cosa impossibile
    #    con RSA-OAEP perché ogni cifratura usa un seed casuale indipendente).
    print("\n4. Inizio attacco dizionario (crittografia di ogni opzione nota)...")
    print("-" * 80)
    attack_success = False

    for vote_plain, candidate in MappaVoti.items():
        for attempt in range(3):
            # Ogni tentativo usa un seed diverso, come farebbe un attaccante
            # che non conosce il seed usato dall'elettore originale.
            attack_seed = os.urandom(32)
            attack_ciphertext = encrypt(ae_pubkey, vote_plain, seed=attack_seed)
            attack_hex = attack_ciphertext.hex()

            print(f"   Tentativo: voto={vote_plain.hex()} ({candidate}), seed={attack_seed.hex()[:16]}...")
            print(f"      Ciphertext generato: {attack_hex[:60]}...")
            print(f"      Corrisponde al target? {attack_ciphertext == target_bytes}")

            if attack_ciphertext == target_bytes:
                attack_success = True
                print(f"  [SUCCESSO ATTACCO?] Voto identificato: {candidate}!")
                break
        print()

    # 5. Si valuta l'esito dell'attacco e si spiega perché RSA-OAEP
    #    rende questo tipo di attacco computazionalmente impossibile.
    print("\n5. Risultato e spiegazione matematica:")
    print("-" * 80)
    if attack_success:
        print("  Attacco riuscito! (Ma questo NON dovrebbe accadere in realtà)")
    else:
        print("  ATTACCO FALLITO! (Come previsto dalla sicurezza di RSA-OAEP)")

    print("\nPerché l'attacco fallisce:")
    print("  RSA-OAEP è uno schema di cifratura PROBABILISTICO (IND-CPA sicuro).")
    print("  Ogni operazione di cifratura utilizza un SEED CASUALE (32 byte, generato")
    print("  con un CSPRNG), che produce un ciphertext totalmente diverso anche per")
    print("  lo stesso messaggio in chiaro.")
    print("\nUn attaccante che intercetta solo il ciphertext (senza conoscere il seed)")
    print("non può ricostruirlo semplicemente cifrando le opzioni note, perché non")
    print("conosce il seed casuale usato dall'elettore originale.")
    print("\nLa verifica universale è resa possibile solo perché, A SCRUTINIO CONCLUSO,")
    print("l'AE pubblica (scheda cifrata, voto in chiaro, seed): a quel punto chiunque")
    print("può ricifrare con lo stesso seed e verificare la corrispondenza!")

    print("\n" + "=" * 80)

    # Salvataggio report
    save_report(
        test_id="dictionary_attack",
        test_name="Attacco Dizionario / Analisi di Frequenza (Ciphertext Equality)",
        outcome="FAIL" if attack_success else "PASS",
        details={
            "schema": "RSA-OAEP",
            "candidates": candidates,
            "attempts_per_candidate": 3,
            "attack_succeeded": attack_success,
            "conclusion": (
                "RSA-OAEP è probabilistico (IND-CPA): ogni cifratura usa un seed "
                "casuale indipendente, rendendo l'attacco dizionario impossibile."
            ),
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

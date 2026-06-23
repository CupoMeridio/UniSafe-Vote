"""
Test unitario per il Vincolo Crittografico sulla Chiave Privata di Decifratura dell'AE.
Dimostra in modo concreto e visivo il funzionamento del meccanismo di escrow:
stampa i moduli delle chiavi, le chiavi AES derivate, le firme IKM, e il contenuto
del file cifrato prima e dopo la transizione.
"""

import os
import sys
import shutil
import tempfile
import hashlib
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes as _hashes
from cryptography.hazmat.backends import default_backend

# Risolve dinamicamente la root del progetto
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SRC_DIR = os.path.join(PROJECT_ROOT, "src")
TESTS_SEC_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SRC_DIR)
sys.path.insert(0, TESTS_SEC_DIR)

from test_reporter import save_report
from crypto.keys import (
    generate_rsa_keypair,
    save_encrypted_private_key,
    load_and_decrypt_private_key
)


def derive_aes_key_preview(ikm: bytes) -> str:
    """Deriva e restituisce una stringa hex dei primi 8 byte della chiave AES derived"""
    hkdf = HKDF(
        algorithm=_hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ae_encrypt_private_key_escrow",
        backend=default_backend()
    )
    aes_key = hkdf.derive(ikm)
    return aes_key[:8].hex() + "..."


def get_key_fingerprint(key) -> str:
    """Restituisce l'hash SHA-256 del modulo n della chiave per un confronto visivo"""
    n_val = key.private_numbers().public_numbers.n
    n_bytes = n_val.to_bytes((n_val.bit_length() + 7) // 8, byteorder='big')
    return hashlib.sha256(n_bytes).hexdigest()[:16] + "..."


def print_file_hex_preview(filepath: str):
    """Legge il file cifrato e ne stampa le dimensioni, nonce e un'anteprima hex"""
    with open(filepath, "rb") as f:
        blob = f.read()
    nonce = blob[:12]
    ciphertext = blob[12:]
    print(f"    - Path del file:  {filepath}")
    print(f"    - Dimensione:     {len(blob)} byte")
    print(f"    - Nonce (GCM):    {nonce.hex()}")
    print(f"    - Ciphertext preview: {ciphertext[:16].hex()}...")


def main():
    print("=" * 90)
    print("TEST CONCRETO: VINCOLO CRITTOGRAFICO CHIAVE PRIVATA AE (ESCROW)")
    print("=" * 90)

    # Setup cartella temporanea per le chiavi del test
    temp_dir = tempfile.mkdtemp(prefix="unisafe_vote_test_keys_")
    key_name = "ae_encrypt_test"
    encrypted_file_path = os.path.join(temp_dir, f"{key_name}_private.enc")

    # Inizializzazione degli esiti del test
    step_1_failed_decryption_wrong_ikm = False
    step_2_successful_decryption_init_ikm = False
    step_3_transition_successful = False
    step_4_old_ikm_fails = False
    step_5_new_ikm_succeeds = False

    try:
        # 1. Generazione delle chiavi di test dell'AE
        print("\n[1] GENERAZIONE CHIAVI AE DI TEST")
        print("-" * 90)
        private_key, public_key = generate_rsa_keypair()
        key_fp = get_key_fingerprint(private_key)
        print(f"  [OK] Coppia di chiavi RSA generata.")
        print(f"       Fingerprint modulo n chiave privata: {key_fp}")

        # Simula le firme usate come Input Key Material (IKM)
        init_signature = b"mock_signature_of_init_block_representing_election_start"
        merkle_root_signature = b"mock_signature_of_final_merkle_root_at_polls_close"
        wrong_signature = b"some_unrelated_or_malicious_signature_value"

        print(f"\n  Firme IKM di simulazione:")
        print(f"    - Init Signature (Fase raccolta):  {hashlib.sha256(init_signature).hexdigest()[:16]}...")
        print(f"    - Merkle Root Signature (Chiusura): {hashlib.sha256(merkle_root_signature).hexdigest()[:16]}...")
        print(f"    - Wrong Signature (Attacco):        {hashlib.sha256(wrong_signature).hexdigest()[:16]}...")

        # Mostra le chiavi simmetriche AES derivate tramite KDF
        print(f"\n  Chiavi simmetriche AES derivate (HKDF-SHA256):")
        print(f"    - K_init (da Init Signature):       {derive_aes_key_preview(init_signature)}")
        print(f"    - K_root (da Merkle Root Sig):      {derive_aes_key_preview(merkle_root_signature)}")
        print(f"    - K_wrong (da Wrong Signature):     {derive_aes_key_preview(wrong_signature)}")

        # 2. Cifratura iniziale con la firma dell'Init Block (Fase di raccolta)
        print("\n[2] CIFRATURA DELLA CHIAVE PRIVATA CON L'IKM DI INIZIALIZZAZIONE (Firma Init)")
        print("-" * 90)
        save_encrypted_private_key(private_key, key_name, init_signature, base_path=temp_dir)
        print("  [OK] Chiave privata cifrata e salvata su disco.")
        print("  Stato del file cifrato su disco:")
        print_file_hex_preview(encrypted_file_path)

        # 3. Verifica del comportamento sotto attacco / decifratura prematura errata
        print("\n[3] TENTATIVO DI ATTACCO: DECIFRATURA CON CHIAVE AES NON AUTORIZZATA")
        print("-" * 90)
        print("  Attaccante tenta di decifrare il file usando 'Wrong Signature' (K_wrong)...")
        try:
            load_and_decrypt_private_key(key_name, wrong_signature, base_path=temp_dir)
            print("  [ERRORE] La chiave è stata decifrata! Vulnerabilità rilevata.")
        except InvalidTag as e:
            step_1_failed_decryption_wrong_ikm = True
            print("  [OK] Decifratura fallita come previsto.")
            print(f"       Eccezione catturata: {type(e).__name__} (AES-GCM Authentication Tag fallito!)")
        except Exception as e:
            step_1_failed_decryption_wrong_ikm = True
            print(f"  [OK] Decifratura fallita come previsto con eccezione: {type(e).__name__} - {e}")

        # 4. Verifica di decifratura con l'IKM di inizializzazione legittimo
        print("\n[4] VERIFICA DECIFRATURA CON IKM LEGITTIMO DI INIZIALIZZAZIONE (Fase di voto)")
        print("-" * 90)
        print("  L'AE sblocca la chiave privata usando la 'Init Signature' (K_init) per la transizione...")
        try:
            decrypted_key = load_and_decrypt_private_key(key_name, init_signature, base_path=temp_dir)
            dec_fp = get_key_fingerprint(decrypted_key)
            print(f"  Fingerprint modulo n chiave originale: {key_fp}")
            print(f"  Fingerprint modulo n chiave decifrata:  {dec_fp}")
            if dec_fp == key_fp:
                step_2_successful_decryption_init_ikm = True
                print("  [OK] Decifratura riuscita! I moduli coincidono perfettamente.")
            else:
                print("  [ERRORE] Chiave decifrata ma non corrispondente.")
        except Exception as e:
            print(f"  [ERRORE] Decifratura fallita con eccezione: {e}")

        # 5. Simulazione della transizione (Chiusura delle Urne)
        print("\n[5] SIMULAZIONE TRANSIZIONE: RI-CIFRATURA CON FIRMA MERKLE ROOT FINALE")
        print("-" * 90)
        print("  L'AE chiude le urne. Viene calcolata la Merkle Root finale e firmata.")
        print("  Esecuzione del codice di transizione di /close...")
        
        try:
            # Tenta prima con il nuovo IKM (merkle_root_signature)
            try:
                decrypted_key = load_and_decrypt_private_key(key_name, merkle_root_signature, base_path=temp_dir)
                print("  Chiave già transita.")
            except Exception:
                print("    - Tentativo iniziale con K_root fallito (previsto, la chiave è ancora cifrata con K_init).")
                print("    - Caricamento chiave privata con K_init...")
                decrypted_key = load_and_decrypt_private_key(key_name, init_signature, base_path=temp_dir)
                print("    - Scrittura del nuovo file cifrato con K_root...")
                # Ri-cifra con la firma della Merkle Root definitiva
                save_encrypted_private_key(decrypted_key, key_name, merkle_root_signature, base_path=temp_dir)
                step_3_transition_successful = True
                print("  [OK] Transizione completata. Chiave ri-cifrata.")
        except Exception as e:
            print(f"  [ERRORE] Transizione fallita con eccezione: {e}")

        # Mostra il nuovo stato del file cifrato
        print("\n  Stato del file cifrato su disco DOPO la transizione:")
        print_file_hex_preview(encrypted_file_path)

        # 6. Verifica post-transizione
        print("\n[6] VERIFICA POST-TRANSIZIONE: ACCESSIBILITÀ DELLA CHIAVE")
        print("-" * 90)
        
        # Verifichiamo che la vecchia firma init non funzioni più (file sovrascritto)
        print("  Tentativo di decifratura con la vecchia 'Init Signature' (K_init)...")
        try:
            load_and_decrypt_private_key(key_name, init_signature, base_path=temp_dir)
            print("  [ERRORE] La vecchia firma init sblocca ancora la chiave! Sovrascrittura fallita.")
        except Exception as e:
            step_4_old_ikm_fails = True
            print("  [OK] La vecchia firma dell'inizializzazione non funziona più.")
            print(f"       Eccezione catturata: {type(e).__name__} (Accesso Negato/Tag Invalido)")

        # Verifichiamo che la firma della Merkle Root finale sblocchi la chiave
        print("  Tentativo di decifratura con la nuova 'Merkle Root Signature' (K_root)...")
        try:
            decrypted_key_final = load_and_decrypt_private_key(key_name, merkle_root_signature, base_path=temp_dir)
            final_dec_fp = get_key_fingerprint(decrypted_key_final)
            print(f"  Fingerprint modulo n chiave originale: {key_fp}")
            print(f"  Fingerprint modulo n chiave decifrata:  {final_dec_fp}")
            if final_dec_fp == key_fp:
                step_5_new_ikm_succeeds = True
                print("  [OK] La firma della Merkle Root sblocca la chiave privata con successo.")
            else:
                print("  [ERRORE] Chiave finale decifrata ma non corrispondente.")
        except Exception as e:
            print(f"  [ERRORE] Decifratura finale fallita con eccezione: {e}")

    finally:
        # Pulizia cartella temporanea
        shutil.rmtree(temp_dir, ignore_errors=True)

    # Esito globale del test
    test_passed = (
        step_1_failed_decryption_wrong_ikm and
        step_2_successful_decryption_init_ikm and
        step_3_transition_successful and
        step_4_old_ikm_fails and
        step_5_new_ikm_succeeds
    )
    outcome = "PASS" if test_passed else "FAIL"

    print("\n" + "=" * 90)
    print(f"TEST COMPLETATO CON ESITO: {outcome}")
    print("=" * 90)

    save_report(
        test_id="key_escrow",
        test_name="Vincolo Crittografico Chiave Privata AE (Escrow)",
        outcome=outcome,
        details={
            "step_1_failed_decryption_wrong_ikm": step_1_failed_decryption_wrong_ikm,
            "step_2_successful_decryption_init_ikm": step_2_successful_decryption_init_ikm,
            "step_3_transition_successful": step_3_transition_successful,
            "step_4_old_ikm_fails": step_4_old_ikm_fails,
            "step_5_new_ikm_succeeds": step_5_new_ikm_succeeds,
            "conclusion": (
                "La chiave privata dell'AE viene correttamente legata allo stato dell'elezione: "
                "inizialmente sbloccabile solo con la firma dell'inizializzazione, e successivamente "
                "transita in modo irreversibile per essere sbloccabile solo con la firma della Merkle Root finale."
            )
        }
    )


if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    try:
        main()
    finally:
        input("\nPremi Invio per chiudere...")

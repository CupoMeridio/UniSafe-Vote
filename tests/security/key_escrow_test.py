"""
Test dell'escrow a soglia della chiave privata di decifratura dell'AE
(Shamir Secret Sharing 2-su-3).

Schema verificato:
- la chiave privata RSA dell'AE è cifrata con AES-256-GCM sotto una chiave
  AES casuale (con l'ID dell'elezione come dato associato);
- la chiave AES è divisa in 3 quote, una per scrutatore; ne servono 2 per
  ricostruirla e la chiave AES non viene mai salvata;
- gli impegni (SHA-256) sulle quote sono pubblicati nel blocco init firmato.

L'avversario considerato ha accesso al file cifrato e a tutto il Bulletin Board
(pubblico) e vuole decifrare le schede prima dello scrutinio, eventualmente
con la complicità di uno scrutatore.

Il test dimostra in modo concreto e visivo che:
  [3] nessuna informazione pubblica e nessuna singola quota sblocca la chiave;
  [4] qualunque coppia di scrutatori la ricostruisce, e così tutti e tre;
  [5] una quota manomessa viene rifiutata (impegno non corrispondente) e,
      anche se usata, fa fallire l'autenticazione AES-GCM;
  [6] il file cifrato manomesso o usato per un'altra elezione non si decifra.
"""

import hashlib
import json
import os
import shutil
import sys
import tempfile
from itertools import combinations

from cryptography.exceptions import InvalidTag

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SRC_DIR = os.path.join(PROJECT_ROOT, "src")
TESTS_SEC_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SRC_DIR)
sys.path.insert(0, TESTS_SEC_DIR)

from test_reporter import save_report
from crypto.keys import (generate_rsa_keypair, escrow_private_key, escrow_public_info,
                         recover_private_key, share_commitment)

ELECTION_ID = "key_escrow_test"
TRUSTEES, THRESHOLD = 3, 2


def key_fingerprint(key) -> str:
    """Hash SHA-256 del modulo n, per confrontare visivamente le chiavi."""
    n = key.private_numbers().public_numbers.n
    return hashlib.sha256(n.to_bytes((n.bit_length() + 7) // 8, "big")).hexdigest()[:16] + "..."


def try_recover(shares, election_id, base_path):
    """Tenta la ricostruzione; restituisce (chiave o None, nome dell'eccezione o None)."""
    try:
        return recover_private_key(shares, election_id, base_path=base_path), None
    except (InvalidTag, ValueError) as e:
        return None, type(e).__name__


def main():
    print("=" * 90)
    print("TEST ESCROW A SOGLIA DELLA CHIAVE PRIVATA AE (SHAMIR 2-SU-3)")
    print("=" * 90)

    temp_dir = tempfile.mkdtemp(prefix="unisafe_vote_escrow_")
    results = {}
    try:
        # [1] ---------------------------------------------------------------
        print("\n[1] GENERAZIONE CHIAVE PRIVATA DI DECIFRATURA DELL'AE")
        print("-" * 90)
        private_key, _ = generate_rsa_keypair()
        original_fp = key_fingerprint(private_key)
        print(f"  Fingerprint modulo n della chiave originale: {original_fp}")

        # [2] ---------------------------------------------------------------
        print("\n[2] ESCROW: CIFRATURA CON CHIAVE AES CASUALE E DIVISIONE IN QUOTE")
        print("-" * 90)
        shares = escrow_private_key(private_key, ELECTION_ID, trustees=TRUSTEES,
                                    threshold=THRESHOLD, base_path=temp_dir)
        public_info = escrow_public_info(shares)
        enc_path = os.path.join(temp_dir, "ae_encrypt_private.enc")
        with open(enc_path, "rb") as f:
            blob = f.read()
        print(f"  File cifrato: {len(blob)} byte, nonce GCM {blob[:12].hex()}, "
              f"ciphertext {blob[12:28].hex()}...")
        print(f"  La chiave AES non è salvata da nessuna parte: esiste solo divisa in quote.")
        for share in shares:
            print(f"  Quota scrutatore {share['trustee']}: x={share['x']}  y={share['y'][:40]}...")
        print(f"\n  Parametri pubblicati nel blocco init: schema {public_info['scheme']}, "
              f"soglia {public_info['threshold']} su {public_info['trustees']}")
        for c in public_info["share_commitments"]:
            print(f"    impegno {c[:48]}...")
        del private_key

        # [3] ---------------------------------------------------------------
        print("\n[3] TENTATIVI NON AUTORIZZATI: INFORMAZIONI PUBBLICHE E QUOTA SINGOLA")
        print("-" * 90)
        print("  L'attaccante dispone del file cifrato e dell'intero Bulletin Board, ma nessun dato")
        print("  pubblico entra nella chiave AES (casuale): l'unica via è ottenere le quote degli scrutatori.")
        single_results = {}
        for share in shares:
            key, err = try_recover([share], ELECTION_ID, temp_dir)
            single_results[share["trustee"]] = err
            print(f"  Solo la quota dello scrutatore {share['trustee']}: "
                  f"{'[ERRORE] chiave sbloccata!' if key else f'bloccato ({err})'}")
        step3 = all(single_results.values())
        results["single_share_blocked"] = step3

        # [4] ---------------------------------------------------------------
        print("\n[4] RICOSTRUZIONE CON LA SOGLIA (QUALUNQUE COPPIA) E CON TUTTE LE QUOTE")
        print("-" * 90)
        combo_results = {}
        for combo in list(combinations(shares, THRESHOLD)) + [tuple(shares)]:
            ids = "+".join(str(s["trustee"]) for s in combo)
            key, err = try_recover(list(combo), ELECTION_ID, temp_dir)
            ok = key is not None and key_fingerprint(key) == original_fp
            combo_results[ids] = ok
            print(f"  Scrutatori {ids:<6}: "
                  f"{'chiave ricostruita, fingerprint ' + key_fingerprint(key) if key else 'fallito (' + str(err) + ')'}"
                  f"{'  ✓' if ok else '  ✗'}")
        step4 = all(combo_results.values())
        results["threshold_combinations"] = combo_results

        # [5] ---------------------------------------------------------------
        print("\n[5] QUOTA MANOMESSA")
        print("-" * 90)
        tampered = dict(shares[1])
        tampered["y"] = format(int(tampered["y"], 16) + 1, "x")
        commitment_ok = share_commitment(tampered) in public_info["share_commitments"]
        print(f"  Quota dello scrutatore 2 alterata (y+1).")
        verdict = "[ERRORE]" if commitment_ok else "rifiutata dall'AE prima della ricostruzione"
        print(f"  Impegno della quota alterata presente nel blocco init? {commitment_ok}  → {verdict}")
        key, err = try_recover([shares[0], tampered], ELECTION_ID, temp_dir)
        print(f"  Anche usandola, ricostruzione con quota 1 + quota 2 alterata: "
              f"{'[ERRORE] chiave sbloccata!' if key else f'bloccata ({err})'}")
        step5 = not commitment_ok and key is None
        results["tampered_share"] = {"commitment_matches": commitment_ok, "recovery_error": err}

        # [6] ---------------------------------------------------------------
        print("\n[6] FILE CIFRATO MANOMESSO E RIUSO PER UN'ALTRA ELEZIONE")
        print("-" * 90)
        valid_pair = shares[:THRESHOLD]
        key_other, err_other = try_recover(valid_pair, "un_altra_elezione", temp_dir)
        print(f"  Quote valide ma ID elezione diverso (AAD): "
              f"{'[ERRORE] chiave sbloccata!' if key_other else f'bloccato ({err_other})'}")
        corrupted = bytearray(blob)
        corrupted[-1] ^= 0x01
        with open(enc_path, "wb") as f:
            f.write(bytes(corrupted))
        key_corrupt, err_corrupt = try_recover(valid_pair, ELECTION_ID, temp_dir)
        print(f"  File cifrato con 1 bit alterato: "
              f"{'[ERRORE] chiave sbloccata!' if key_corrupt else f'bloccato ({err_corrupt})'}")
        step6 = key_other is None and key_corrupt is None
        results["wrong_election_blocked"] = key_other is None
        results["corrupted_file_blocked"] = key_corrupt is None

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    passed = step3 and step4 and step5 and step6
    print("\n" + "=" * 90)
    print("RIEPILOGO")
    print("=" * 90)
    print(f"  [3] Informazioni pubbliche e quota singola non bastano: {'PASS' if step3 else 'FAIL'}")
    print(f"  [4] Qualunque coppia di scrutatori ricostruisce la chiave: {'PASS' if step4 else 'FAIL'}")
    print(f"  [5] Quota manomessa rifiutata:                           {'PASS' if step5 else 'FAIL'}")
    print(f"  [6] File manomesso / altra elezione rifiutati:           {'PASS' if step6 else 'FAIL'}")
    print("=" * 90)

    save_report(
        test_id="key_escrow",
        test_name="Escrow a soglia della chiave privata AE (Shamir 2-su-3)",
        outcome="PASS" if passed else "FAIL",
        details={
            "scheme": "Shamir Secret Sharing su GF(2^521-1) + AES-256-GCM (AAD = election_id)",
            "trustees": TRUSTEES,
            "threshold": THRESHOLD,
            **results,
            "conclusion": (
                "La chiave di decifratura dell'AE può essere ricostruita solo con almeno "
                f"{THRESHOLD} quote su {TRUSTEES} di scrutatori distinti: né l'AE da sola né "
                "chi legge il Bulletin Board possono decifrare le schede prima dello scrutinio."
            ),
        },
    )


if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    try:
        main()
    finally:
        input("\nPremi Invio per chiudere...")

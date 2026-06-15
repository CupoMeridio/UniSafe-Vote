
"""
Test per Ledger Tampering & Retroactive Vote Modification
Dimostra che la manomissione del Bulletin Board è impossibile da nascondere grazie all'albero di Merkle.
"""

import os
import json
import hashlib
import sys

# Risale alla root del progetto e aggiunge src/ al path,
# così Python trova crypto.merkle in src/crypto/merkle.py.
PROJECT_ROOT  = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SRC_DIR       = os.path.join(PROJECT_ROOT, "src")
TESTS_SEC_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SRC_DIR)
sys.path.insert(0, TESTS_SEC_DIR)

from test_reporter import save_report
from crypto.merkle import MerkleTree, verify_proof


def create_dummy_vote(index: int, candidate: int = 0) -> dict:
    """Crea un record di voto dummy per il test"""
    return {
        "index": index,
        "encrypted_vote": f"dummy_encrypted_vote_for_candidate_{candidate}_index_{index}".encode("utf-8").hex(),
        "encrypted_seed": f"dummy_encrypted_seed_index_{index}".encode("utf-8").hex()
    }


def get_leaf_hash(vote_record: dict) -> bytes:
    """Calcola l'hash SHA-256 di un record di voto (come nel sistema vero)"""
    record_bytes = json.dumps(vote_record, sort_keys=True).encode("utf-8")
    return hashlib.sha256(record_bytes).digest()


def main():
    print("=" * 90)
    print("TEST LEDGER TAMPERING & RETROACTIVE VOTE MODIFICATION")
    print("(Append-only Merkle Tree Integrity Check)")
    print("=" * 90)

    # Passo 1: Inizializza l'albero di Merkle con 8 foglie
    print("\n[1] CREAZIONE ALBERO DI MERKLE ORIGINALE")
    print("-" * 90)
    original_votes = []
    mt = MerkleTree()

    for i in range(8):
        vote = create_dummy_vote(index=i, candidate=i % 3)  # 0, 1, 2 ripetuti
        original_votes.append(vote)
        record_bytes = json.dumps(vote, sort_keys=True).encode("utf-8")
        mt.add_leaf(record_bytes)
        print(f"  [Foglia {i}] Aggiunto voto per candidato {i % 3}")

    original_root = mt.get_root()
    print(f"\n  [RADICE ORIGINALE] Merkle Root: {original_root}")
    print(f"  (Salvata sul Bulletin Board e visibile pubblicamente)")

    # Salva anche una proof per la foglia 3, per dimostrare la verifica individuale
    leaf_to_modify_index = 3
    original_leaf = original_votes[leaf_to_modify_index]
    original_leaf_record_bytes = json.dumps(original_leaf, sort_keys=True).encode("utf-8")
    original_leaf_hash = hashlib.sha256(original_leaf_record_bytes).digest()
    original_proof = mt.get_proof(leaf_to_modify_index)

    print(f"\n[2] PREPARAZIONE ATTACCO")
    print("-" * 90)
    print(f"  Obiettivo: Modificare retroattivamente il voto alla foglia {leaf_to_modify_index}")
    print(f"  Voto originale: Candidato {leaf_to_modify_index % 3}")
    print(f"  Voto modificato: Candidato {(leaf_to_modify_index % 3) + 1} (nuova preferenza)")

    # Passo 3: Modifica la foglia (simula attacco di admin corrotto)
    modified_votes = original_votes.copy()
    modified_vote = create_dummy_vote(index=leaf_to_modify_index, candidate=(leaf_to_modify_index % 3) + 1)
    modified_votes[leaf_to_modify_index] = modified_vote

    print("\n[3] ESECUZIONE TAMPERING")
    print("-" * 90)
    print(f"  [Foglia {leaf_to_modify_index}] Dati modificati!")
    old_hex = original_leaf['encrypted_vote']
    new_hex = modified_vote['encrypted_vote']
    # Trova il primo byte diverso per mostrare dove avviene la modifica
    diff_pos = next((i for i in range(min(len(old_hex), len(new_hex))) if old_hex[i] != new_hex[i]), None)
    print(f"    - Vecchio encrypted_vote: {old_hex}")
    print(f"    - Nuovo encrypted_vote:   {new_hex}")
    if diff_pos is not None:
        print(f"    → Prima differenza al carattere {diff_pos}: '{old_hex[diff_pos]}' → '{new_hex[diff_pos]}'")
    else:
        print(f"    → I due valori sono identici (nessuna differenza rilevata)")

    # Passo 4: Ricostruisci l'albero di Merkle con i dati modificati
    print("\n[4] RICOSTRUZIONE ALBERO DOPO TAMPERING")
    print("-" * 90)
    mt_modified = MerkleTree()
    for vote in modified_votes:
        record_bytes = json.dumps(vote, sort_keys=True).encode("utf-8")
        mt_modified.add_leaf(record_bytes)

    modified_root = mt_modified.get_root()
    modified_leaf_record_bytes = json.dumps(modified_vote, sort_keys=True).encode("utf-8")
    modified_leaf_hash = hashlib.sha256(modified_leaf_record_bytes).digest()
    modified_proof = mt_modified.get_proof(leaf_to_modify_index)

    # Passo 5: Confronta le radici
    print("\n[5] VERIFICA INTEGRITÀ")
    print("-" * 90)
    print(f"  Merkle Root ORIGINALE: {original_root}")
    print(f"  Merkle Root MODIFICATA: {modified_root}")
    print(f"\n  Le radici corrispondono? {original_root == modified_root}")

    print("\n[6] IMPATTO SULLA SICUREZZA")
    print("-" * 90)

    # Verifica individuale per l'utente della foglia 3: la vecchia ricevuta non funziona più!
    print("  [Verifica Individuale (utente della foglia 3)]")
    print(f"    - Voto ORIGINALE + ricevuta ORIGINALE")
    print(f"      * Verifica con radice ORIGINALE: {verify_proof(original_leaf_hash, original_proof, original_root)}")
    print(f"      * Verifica con radice MODIFICATA: {verify_proof(original_leaf_hash, original_proof, modified_root)}")
    print("\n    - Voto MODIFICATO + ricevuta MODIFICATA")
    print(f"      * Verifica con radice ORIGINALE: {verify_proof(modified_leaf_hash, modified_proof, original_root)}")
    print(f"      * Verifica con radice MODIFICATA: {verify_proof(modified_leaf_hash, modified_proof, modified_root)}")

    print("\n  [Conclusioni]")
    print("  1. Qualsiasi modifica ai dati sul Bulletin Board altera la Merkle Root")
    print("  2. La Merkle Root originale è pubblicamente conosciuta (sul Bulletin Board firmata)")
    print("  3. Tutte le ricevute degli utenti diventano invalide se si usa la radice modificata")
    print("  4. L'Observer (Verifica Universale) rileva immediatamente la discrepanza")
    print("  5. La manomissione è impossibile da nascondere!")

    print("\n" + "=" * 90)
    print("TEST COMPLETATO CON SUCCESSO!")
    print("=" * 90)

    roots_match       = original_root == modified_root
    orig_valid_orig   = verify_proof(original_leaf_hash,  original_proof,  original_root)
    orig_valid_mod    = verify_proof(original_leaf_hash,  original_proof,  modified_root)
    mod_valid_orig    = verify_proof(modified_leaf_hash,  modified_proof,  original_root)
    mod_valid_mod     = verify_proof(modified_leaf_hash,  modified_proof,  modified_root)

    save_report(
        test_id="ledger_tampering",
        test_name="Manomissione del Bulletin Board (Ledger Tampering / Merkle Tree)",
        outcome="PASS" if (not roots_match and orig_valid_orig and not orig_valid_mod) else "FAIL",
        details={
            "leaves_count": 8,
            "tampered_leaf_index": leaf_to_modify_index,
            "original_root": original_root,
            "modified_root": modified_root,
            "roots_match": roots_match,
            "verification": {
                "original_leaf_original_proof_vs_original_root": orig_valid_orig,
                "original_leaf_original_proof_vs_modified_root": orig_valid_mod,
                "modified_leaf_modified_proof_vs_original_root": mod_valid_orig,
                "modified_leaf_modified_proof_vs_modified_root": mod_valid_mod,
            },
            "conclusion": (
                "Qualsiasi modifica ai dati del Bulletin Board altera la Merkle Root: "
                "la manomissione è rilevabile da chiunque conosca la root originale."
            ),
        },
    )


if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    try:
        main()
    finally:
        input("\nPremi Invio per chiudere...")


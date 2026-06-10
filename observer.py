
"""
Verifica Universale - Strumento per controllare l'integrità dell'elezione.

Questo programma permette a chiunque di verificare che l'elezione
si sia svolta correttamente, analizzando il Bulletin Board.

Le verifiche effettuate sono:
1. Verifica della firma del blocco di inizializzazione
2. Verifica della firma del blocco con la Merkle Root
3. Verifica della firma del blocco con i risultati dello scrutinio
4. Ricostruzione del Merkle Tree e verifica che corrisponda alla Root pubblicata
5. Verifica della correttezza dei voti decifrati e del conteggio aggregato
6. Verifica delle Merkle Proof per ogni singolo voto

Tutto questo è possibile grazie al fatto che il Bulletin Board è un
registro append-only, pubblico e firmato digitalmente.
"""

import os
import json
import hashlib
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto.keys import deserialize_public_key
from crypto.rsa_oaep import encrypt, decrypt
from crypto.rsa_pss import verify
from crypto.merkle import MerkleTree, verify_proof
from cryptography.hazmat.primitives import serialization


def main():
    print("=== VERIFICA UNIVERSALE ===")

    bulletin_board_path = "data/bulletin_board.json"
    if not os.path.exists(bulletin_board_path):
        print("Bulletin Board non trovato!")
        return

    with open(bulletin_board_path, "r", encoding="utf-8") as f:
        bb = json.load(f)

    if len(bb) < 3:  # init + votes (at least one) + merkle_root + scrutinio
        print("Scrutinio non ancora eseguito!")
        return

    # Ottieni i dati iniziali
    init_block = bb[0]
    init_data = init_block["data"]
    ae_sign_public = deserialize_public_key(init_data["ae_sign_public"])
    candidates = init_data["candidates"]

    all_passed = True

    # 1. Verifica firma del blocco init
    print("\n1. Verifica firma blocco init... ", end="")
    init_data_json = json.dumps(init_data, sort_keys=True).encode('utf-8')
    init_signature = bytes.fromhex(init_block["signature"])
    if verify(ae_sign_public, init_data_json, init_signature):
        print("OK")
    else:
        print("FAIL")
        all_passed = False

    # 2. Ottieni blocco merkle_root e verifica firma
    merkle_root_block = None
    for block in bb:
        if block["type"] == "merkle_root":
            merkle_root_block = block
            break

    if not merkle_root_block:
        print("\n2. Verifica firma blocco merkle_root... FAIL (blocco non trovato)")
        all_passed = False
    else:
        print("\n2. Verifica firma blocco merkle_root... ", end="")
        root_data_json = json.dumps(merkle_root_block["data"], sort_keys=True).encode('utf-8')
        root_signature = bytes.fromhex(merkle_root_block["signature"])
        if verify(ae_sign_public, root_data_json, root_signature):
            print("OK")
        else:
            print("FAIL")
            all_passed = False

    merkle_root = merkle_root_block["data"]["merkle_root"] if merkle_root_block else None

    # 3. Ottieni blocco scrutinio e verifica firma
    scrutinio_block = None
    for block in bb:
        if block["type"] == "scrutinio":
            scrutinio_block = block
            break

    if not scrutinio_block:
        print("\n3. Verifica firma blocco scrutinio... FAIL (blocco non trovato)")
        all_passed = False
    else:
        print("\n3. Verifica firma blocco scrutinio... ", end="")
        scrutinio_data_json = json.dumps(scrutinio_block["data"], sort_keys=True).encode('utf-8')
        scrutinio_signature = bytes.fromhex(scrutinio_block["signature"])
        if verify(ae_sign_public, scrutinio_data_json, scrutinio_signature):
            print("OK")
        else:
            print("FAIL")
            all_passed = False

    scrutinio_data = scrutinio_block["data"] if scrutinio_block else None

    if scrutinio_data and merkle_root:
        # 4. Ricostruisci Merkle Tree da tutti i voti e verifica la root
        print("\n4. Ricostruzione Merkle Tree e verifica root... ", end="")
        reconstructed_tree = MerkleTree()
        vote_blocks = [block for block in bb if block["type"] == "vote"]

        for vote_block in vote_blocks:
            record_bytes = json.dumps(vote_block["data"], sort_keys=True).encode('utf-8')
            reconstructed_tree.add_leaf(record_bytes)

        if reconstructed_tree.get_root() == merkle_root:
            print("OK")
        else:
            print("FAIL")
            all_passed = False

        # 5. Verifica ogni voto nel blocco scrutinio
        print("\n5. Verifica voti e conteggio aggregato... ", end="")
        ae_encrypt_private_pem = scrutinio_data["ae_encrypt_private"]
        ae_encrypt_private = serialization.load_pem_private_key(
            ae_encrypt_private_pem.encode('utf-8'),
            password=None
        )

        verified_counts = {c: 0 for c in candidates}
        votes_ok = True

        for verified_vote in scrutinio_data["voti_verificati"]:
            enc_vote_hex = verified_vote["enc_vote"]
            seed_hex = verified_vote["seed"]
            candidate = verified_vote["voto_chiaro"]

            # Ricostruisci il plaintext (voto + seed)
            seed_bytes = bytes.fromhex(seed_hex)
            vote_index = candidates.index(candidate)
            vote_byte = vote_index.to_bytes(1, byteorder='big')
            plaintext_reconstructed = vote_byte + seed_bytes

            # Verifica che decifrando il voto corrisponda al plaintext ricostruito
            enc_vote_bytes = bytes.fromhex(enc_vote_hex)
            decrypted = decrypt(ae_encrypt_private, enc_vote_bytes)

            if decrypted == plaintext_reconstructed and candidate in candidates:
                verified_counts[candidate] += 1
            else:
                votes_ok = False

        # Verifica che il conteggio aggregato corrisponda
        if votes_ok and verified_counts == scrutinio_data["risultato_aggregato"]:
            print("OK")
            print(f"   Conteggio verificato: {verified_counts}")
        else:
            print("FAIL")
            all_passed = False

    # 6. Verifica Merkle Proof per ogni voto (usando l'albero ricostruito)
    print("\n6. Verifica Merkle Proof per ogni voto... ", end="")
    if merkle_root and vote_blocks:
        proofs_ok = True
        for i, vote_block in enumerate(vote_blocks):
            # Genera proof dall'albero ricostruito
            record_bytes = json.dumps(vote_block["data"], sort_keys=True).encode('utf-8')
            leaf_hash = hashlib.sha256(record_bytes).digest()
            proof = reconstructed_tree.get_proof(i)

            if not verify_proof(leaf_hash, proof, merkle_root):
                proofs_ok = False
                break

        if proofs_ok:
            print("OK")
        else:
            print("FAIL")
            all_passed = False
    else:
        print("Saltato (nessun voto)")

    print("\n=== RISULTATO FINALE ===")
    if all_passed:
        print("TUTTE LE VERIFICHE SONO RIUSCITE! L'elezione è valida.")
    else:
        print("ALCUNE VERIFICHE HANNO FALLITO! L'elezione potrebbe essere stata manipolata.")


if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    main()



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
from typing import List, Dict
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto.keys import deserialize_public_key
from crypto.rsa_pss import verify
from crypto.rsa_oaep import encrypt
from crypto.merkle import MerkleTree, verify_proof


def main() -> None:
    print("=== VERIFICA UNIVERSALE ===")

    bulletin_board_path = "data/bulletin_board.json"
    if not os.path.exists(bulletin_board_path):
        print("Bulletin Board non trovato!")
        return

    with open(bulletin_board_path, "r", encoding="utf-8") as f:
        bb = json.load(f)

    scrutinio_presente = any(block.get("type") == "scrutinio" for block in bb)
    merkle_root_presente = any(block.get("type") == "merkle_root" for block in bb)

    if not scrutinio_presente or not merkle_root_presente:
        print("Verifica universale finale non disponibile: mancano ancora Merkle Root e/o scrutinio.")
        print("Prima chiudi le urne e avvia lo scrutinio (opzione 5 nel pannello).")
        try:
            input("\nPremi Invio per chiudere...")
        except (EOFError, KeyboardInterrupt):
            pass
        return

    if len(bb) < 3:  # init + votes (at least one) + merkle_root + scrutinio
        print("Scrutinio non ancora eseguito!")
        return

    # Ottieni i dati iniziali
    init_block = bb[0]
    init_data = init_block["data"]
    ae_sign_public = deserialize_public_key(init_data["ae_sign_public"])
    ae_encrypt_public = deserialize_public_key(init_data["ae_encrypt_public"])
    sa_sign_public = deserialize_public_key(init_data["sa_sign_public"])
    candidates = init_data["candidates"]
    NULL_LABEL = "Scheda nulla"

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

        # 5. Verifica dati pubblici del blocco scrutinio tramite RICIFRATURA.
        #    Grazie all'OAEP con seed iniettabile, l'observer ricifra
        #    Enc_OAEP(voto, seed) e confronta con la scheda registrata: se il
        #    risultato coincide, l'AE non ha alterato né inventato la decifratura.
        print("\n5. Verifica voti scrutinati (ricifratura) e conteggio aggregato... ", end="")
        scrutinated_votes = scrutinio_data.get("voti_verificati", [])
        scrutinated_enc_votes = [vote.get("enc_vote") for vote in scrutinated_votes]
        vote_block_enc_votes = [block["data"]["enc_vote"] for block in vote_blocks]

        scrutinated_set = set(scrutinated_enc_votes)
        vote_block_set = set(vote_block_enc_votes)
        public_votes_ok = (
            scrutinated_set == vote_block_set
            and len(scrutinated_enc_votes) == len(scrutinated_set)
            and len(vote_block_enc_votes) == len(vote_block_set)
        )

        # Mappa enc_vote -> enc_seed dai blocchi voto, per recuperare il seed pubblicato
        valid_labels = set(candidates) | {NULL_LABEL}
        verified_counts = {c: 0 for c in candidates}
        verified_counts[NULL_LABEL] = 0

        for verified_vote in scrutinated_votes:
            enc_vote_hex = verified_vote.get("enc_vote")
            seed_hex = verified_vote.get("seed")
            candidate = verified_vote.get("voto_chiaro")

            if not enc_vote_hex or not seed_hex or not candidate:
                public_votes_ok = False
                continue

            if enc_vote_hex not in vote_block_set:
                public_votes_ok = False
                continue

            if candidate not in valid_labels:
                public_votes_ok = False
                continue

            try:
                seed_bytes = bytes.fromhex(seed_hex)
            except ValueError:
                public_votes_ok = False
                continue

            if len(seed_bytes) != 32:
                public_votes_ok = False
                continue

            # Ricifratura deterministica per le schede valide: il voto in chiaro
            # corrisponde a un indice di candidato noto, quindi possiamo ricostruire
            # Enc_OAEP(indice, seed) e confrontarlo con enc_vote pubblicato.
            if candidate != NULL_LABEL:
                vote_index = candidates.index(candidate)
                vote_byte = vote_index.to_bytes(1, byteorder='big')
                recomputed = encrypt(ae_encrypt_public, vote_byte, seed=seed_bytes).hex()
                if recomputed != enc_vote_hex:
                    print(f"\n   Ricifratura non corrispondente per enc_vote: {enc_vote_hex}")
                    public_votes_ok = False
                    continue

            verified_counts[candidate] += 1

        # Verifica che il conteggio aggregato corrisponda
        if public_votes_ok and verified_counts == scrutinio_data["risultato_aggregato"]:
            print("OK")
            print(f"   Conteggio verificato: {verified_counts}")
        else:
            print("FAIL")
            all_passed = False
            if not public_votes_ok:
                print("   Uno o più voti scrutinati non corrispondono ai blocchi voto o alla ricifratura.")
            if verified_counts != scrutinio_data["risultato_aggregato"]:
                print(f"   Conteggio atteso: {scrutinio_data['risultato_aggregato']}")
                print(f"   Conteggio ricostruito: {verified_counts}")

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

    # 7. Verifica riconciliazione
    print("\n7. Verifica riconciliazione token e schede... ", end="")
    rec_sa_block = next((b for b in bb if b["type"] == "reconciliation_sa"), None)
    rec_ae_block = next((b for b in bb if b["type"] == "reconciliation_ae"), None)
    
    if rec_sa_block and rec_ae_block:
        # Verifica firme
        sa_data_json = json.dumps(rec_sa_block["data"], sort_keys=True).encode('utf-8')
        sa_sig = bytes.fromhex(rec_sa_block["signature"])
        ae_data_json = json.dumps(rec_ae_block["data"], sort_keys=True).encode('utf-8')
        ae_sig = bytes.fromhex(rec_ae_block["signature"])
        
        if not verify(sa_sign_public, sa_data_json, sa_sig) or not verify(ae_sign_public, ae_data_json, ae_sig):
            print("FAIL (Firme non valide)")
            all_passed = False
        else:
            total_tokens = rec_sa_block["data"]["total_tokens"]
            total_votes = rec_ae_block["data"]["total_votes"]
            
            if total_votes <= total_tokens:
                print(f"OK ({total_votes} voti su {total_tokens} token emessi)")
            else:
                print(f"FAIL (Voti ricevuti {total_votes} > Token emessi {total_tokens})")
                all_passed = False
    else:
        print("Saltato (Blocchi di riconciliazione mancanti)")


    print("\n=== RISULTATO FINALE ===")
    if all_passed:
        print("TUTTE LE VERIFICHE PUBBLICHE SONO RIUSCITE! L'elezione è coerente con il Bulletin Board.")
    else:
        print("ALCUNE VERIFICHE PUBBLICHE HANNO FALLITO! L'elezione potrebbe essere stata manipolata.")

    try:
        input("\nPremi Invio per chiudere...")
    except (EOFError, KeyboardInterrupt):
        pass


if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    main()


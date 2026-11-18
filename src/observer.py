
"""
Verifica Universale - Strumento per controllare l'integrità dell'elezione.

Questo programma permette a chiunque di verificare che l'elezione
si sia svolta correttamente, analizzando il Bulletin Board.

Le verifiche effettuate sono:
1. Verifica della firma del blocco di inizializzazione
2. Verifica della firma del blocco con la Merkle Root
3. Verifica della firma del blocco con i risultati dello scrutinio
4. Ricostruzione del Merkle Tree e verifica che corrisponda alla Root pubblicata
5. Verifica pubblica della decifratura di OGNI scheda (EM^e mod n == c),
   schede nulle comprese, e del conteggio aggregato
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
from crypto.rsa_oaep import encrypt, verify_raw_decryption, oaep_decode, is_valid_ciphertext, modulus_length
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

        # 5. Verifica dati pubblici del blocco scrutinio tramite DECIFRATURA
        #    VERIFICABILE. Per ogni scheda l'AE pubblica EM = c^d mod n: con la
        #    sola chiave pubblica si controlla che EM^e mod n == c (esiste un
        #    solo EM con questa proprietà) e si decodifica EM ricavando voto e
        #    seed. Il contenuto di ogni scheda, NULLE COMPRESE, viene così
        #    ricostruito in modo indipendente: l'AE non può dichiarare nulla una
        #    scheda valida né attribuirle un candidato diverso.
        print("\n5. Verifica pubblica delle decifrature (EM) e conteggio aggregato... ", end="")
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

        valid_labels = set(candidates) | {NULL_LABEL}
        verified_counts = {c: 0 for c in candidates}
        verified_counts[NULL_LABEL] = 0
        k = modulus_length(ae_encrypt_public)
        problems = []

        for verified_vote in scrutinated_votes:
            enc_vote_hex = verified_vote.get("enc_vote")
            candidate = verified_vote.get("voto_chiaro")
            em_hex = verified_vote.get("em")
            seed_hex = verified_vote.get("seed", "")

            if (not enc_vote_hex or enc_vote_hex not in vote_block_set
                    or candidate not in valid_labels or em_hex is None):
                problems.append(f"voce di scrutinio incompleta o estranea: {str(enc_vote_hex)[:32]}...")
                continue

            try:
                enc_vote_bytes = bytes.fromhex(enc_vote_hex)
                em_bytes = bytes.fromhex(em_hex)
            except ValueError:
                problems.append(f"campi non esadecimali per {enc_vote_hex[:32]}...")
                continue

            # Contenuto ricostruito in modo indipendente dall'AE
            if not em_bytes:
                # Nessun EM: ammesso solo se il ciphertext è malformato
                if is_valid_ciphertext(ae_encrypt_public, enc_vote_bytes):
                    problems.append(f"EM mancante per una scheda ben formata: {enc_vote_hex[:32]}...")
                    continue
                expected, expected_seed = NULL_LABEL, b""
            else:
                if not verify_raw_decryption(ae_encrypt_public, enc_vote_bytes, em_bytes):
                    problems.append(f"EM non corrisponde alla scheda (EM^e mod n != c): {enc_vote_hex[:32]}...")
                    continue
                try:
                    expected_seed, plain = oaep_decode(em_bytes, k)
                except ValueError:
                    expected_seed, plain = b"", b""
                if len(plain) == 1 and 0 <= plain[0] < len(candidates):
                    expected = candidates[plain[0]]
                else:
                    expected = NULL_LABEL

            if candidate != expected:
                problems.append(f"l'AE dichiara '{candidate}' ma la scheda contiene '{expected}': {enc_vote_hex[:32]}...")
                continue
            if seed_hex != expected_seed.hex():
                problems.append(f"seed pubblicato diverso da quello contenuto in EM: {enc_vote_hex[:32]}...")
                continue

            # Ricifratura con il seed pubblicato (la stessa verifica del client)
            if candidate != NULL_LABEL:
                vote_byte = candidates.index(candidate).to_bytes(1, byteorder='big')
                if encrypt(ae_encrypt_public, vote_byte, seed=expected_seed).hex() != enc_vote_hex:
                    problems.append(f"ricifratura non corrispondente: {enc_vote_hex[:32]}...")
                    continue

            verified_counts[candidate] += 1

        if problems:
            public_votes_ok = False

        # Verifica che il conteggio aggregato corrisponda
        if public_votes_ok and verified_counts == scrutinio_data["risultato_aggregato"]:
            print("OK")
            print(f"   Conteggio verificato: {verified_counts}")
        else:
            print("FAIL")
            all_passed = False
            if not public_votes_ok:
                print("   Uno o più voti scrutinati non corrispondono ai blocchi voto o alla decifratura pubblicata.")
                for problem in problems:
                    print(f"   - {problem}")
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
            received_vote_blocks = len(vote_blocks)
            
            if total_votes != received_vote_blocks:
                print(f"FAIL (Voti dichiarati {total_votes} != Blocchi voto {received_vote_blocks})")
                all_passed = False
            elif total_votes <= total_tokens:
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


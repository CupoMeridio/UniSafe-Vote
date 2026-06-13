
"""
Script di test per attacco dizionario / analisi di frequenza
(Ciphertext Equality & Dictionary Attack) per dimostrare
la sicurezza di RSA-OAEP nel sistema UniSafe-Vote.
"""

import os
import json
import sys
from typing import Dict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto.keys import load_public_key, deserialize_public_key
from crypto.rsa_oaep import encrypt


def load_bulletin_board() -> Dict:
    """Carica il Bulletin Board pubblico."""
    with open("data/bulletin_board.json", "r", encoding="utf-8") as f:
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
    print("=" * 80)
    print("TEST ATTACCO DIZIONARIO / ANALISI DI FREQUENZA")
    print("(Ciphertext Equality & Dictionary Attack)")
    print("=" * 80)

    # 1. Carica dati iniziali
    print("\n1. Caricamento chiave pubblica e dati...")
    bb = load_bulletin_board()
    ae_pubkey = get_ae_public_key(bb)
    candidates = bb[0]["data"]["candidates"]

    # 2. Dizionario delle opzioni di voto
    print("\n2. Definizione dizionario di voti possibili:")
    MappaVoti = {}
    for i, candidate in enumerate(candidates):
        vote_bytes = i.to_bytes(1, byteorder="big")
        MappaVoti[vote_bytes] = candidate
        print(f"   {vote_bytes.hex()} -> {candidate}")
    print(f"   {b'\x03'.hex()} -> Scheda Bianca/Nulla")
    MappaVoti[b"\x03"] = "Scheda Bianca/Nulla"

    # 3. Se non c'è un voto già sul BB, creane uno fittizio come target
    target_hex = get_target_ciphertext(bb)
    if target_hex is None:
        print("\n3. Creazione voto fittizio come target...")
        seed = os.urandom(32)
        target_vote_bytes = (0).to_bytes(1, byteorder="big")  # Voto per Lista A
        target_ciphertext = encrypt(ae_pubkey, target_vote_bytes, seed=seed)
        target_hex = target_ciphertext.hex()
        print(f"   Target vote: {target_vote_bytes.hex()} ({MappaVoti[target_vote_bytes]})")
        print(f"   Target ciphertext: {target_hex[:60]}...")
    else:
        print(f"\n3. Target ciphertext preso dal Bulletin Board: {target_hex[:60]}...")
    target_bytes = bytes.fromhex(target_hex)

    # 4. Tenta l'attacco dizionario
    print("\n4. Inizio attacco dizionario (crittografia di ogni opzione nota)...")
    print("-" * 80)
    attack_success = False

    for vote_plain, candidate in MappaVoti.items():
        # Tenta più volte per dimostrare che ogni volta si ottiene un ciphertext diverso!
        for attempt in range(3):
            # Genera un nuovo seed casuale ogni volta (come farebbe un attaccante senza conoscere il seed)
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

    # 5. Spiegazione matematica
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


if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    main()


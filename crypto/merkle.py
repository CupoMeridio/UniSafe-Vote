
"""
Modulo per la gestione del Merkle Tree.

Un Merkle Tree (o albero di hash) è una struttura dati che permette di
verificare l'integrità di grandi insiemi di dati in modo efficiente.
Nel nostro sistema:
- L'AE costruisce un Merkle Tree con tutti i voti ricevuti
- Ogni client riceve una Merkle Proof per dimostrare che il proprio voto
  è stato incluso nel registro
- Dopo la chiusura delle urne, l'AE pubblica la radice finale (Merkle Root)
  sul Bulletin Board

Questo garantisce che nessun voto possa essere modificato o rimosso senza
che ciò venga rilevato.
"""

import hashlib
from typing import List, Dict


class MerkleTree:
    """
    Implementazione di un Merkle Tree append-only.

    L'albero è costruito utilizzando SHA-256 come funzione hash.
    Quando viene aggiunta una nuova foglia, l'intero albero viene ricostruito.
    """

    def __init__(self):
        """
        Inizializza un nuovo Merkle Tree vuoto.
        """
        self.leaves: List[bytes] = []  # Lista degli hash delle foglie
        self.levels: List[List[bytes]] = []  # Lista dei livelli dell'albero

    def _hash(self, data: bytes) -> bytes:
        """
        Funzione di hash interna: calcola SHA-256 di un dato.

        Args:
            data (bytes): Dati da hashare

        Returns:
            bytes: SHA-256 dei dati (32 byte)
        """
        return hashlib.sha256(data).digest()

    def add_leaf(self, data_bytes: bytes) -> int:
        """
        Aggiunge una nuova foglia all'albero.

        Calcola l'hash dei dati, aggiunge la foglia e ricostruisce l'albero.

        Args:
            data_bytes (bytes): Dati da aggiungere come foglia (es. un voto)

        Returns:
            int: Indice della foglia appena aggiunta (inizia da 0)
        """
        # Calcola l'hash della foglia
        leaf_hash = self._hash(data_bytes)
        # Aggiungi la foglia alla lista
        self.leaves.append(leaf_hash)
        # Ricostruisci l'intero albero
        self._rebuild_tree()
        # Restituisci l'indice della nuova foglia
        return len(self.leaves) - 1

    def _rebuild_tree(self):
        """
        Ricostruisce l'intero albero partendo dalle foglie.

        Questo metodo viene chiamato ogni volta che viene aggiunta una nuova foglia.
        L'albero è costruito dal basso verso l'alto:
        - Livello 0: foglie (hash dei dati)
        - Livello 1: hash delle coppie di foglie
        - Livello 2: hash delle coppie del livello 1
        - ...
        - Ultimo livello: la radice (Merkle Root)
        """
        self.levels = []
        # Inizia con le foglie
        current_level = self.leaves.copy()
        self.levels.append(current_level.copy())

        # Costruisci i livelli superiori fino ad arrivare alla radice
        while len(current_level) > 1:
            next_level = []
            # Processa gli elementi a coppie
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                # Se c'è un numero dispari di elementi, l'ultimo si abbina con se stesso
                right = current_level[i + 1] if (i + 1) < len(current_level) else left
                # Concatena e calcola l'hash
                combined = left + right
                next_level.append(self._hash(combined))
            # Passa al livello superiore
            current_level = next_level
            self.levels.append(current_level.copy())

    def get_root(self) -> str:
        """
        Restituisce la radice dell'albero (Merkle Root) in formato esadecimale.

        Returns:
            str: Merkle Root come stringa esadecimale, o stringa vuota se l'albero è vuoto
        """
        if not self.levels:
            return ""
        # La radice è l'unico elemento dell'ultimo livello
        return self.levels[-1][0].hex()

    def get_proof(self, leaf_index: int) -> List[Dict]:
        """
        Genera una Merkle Proof per una foglia specifica.

        Una Merkle Proof è una lista di nodi "fratelli" che permettono di
        verificare che una foglia sia inclusa nell'albero, senza bisogno
        dell'intero albero stesso.

        Args:
            leaf_index (int): Indice della foglia per cui generare la proof

        Returns:
            List[Dict]: Lista di passaggi della proof, ognuno con:
                - "hash": hash del nodo fratello (esadecimale)
                - "position": "left" o "right" (posizione del fratello rispetto al nodo corrente)
        """
        proof = []
        current_level_index = 0
        current_index = leaf_index

        # Risali l'albero fino alla radice
        while current_level_index < len(self.levels) - 1:
            current_level = self.levels[current_level_index]
            # Trova l'indice del fratello (XOR con 1 scambia l'ultimo bit: 0↔1, 2↔3, ecc.)
            sibling_index = current_index ^ 1

            if sibling_index < len(current_level):
                # Determina se il fratello è a sinistra o a destra
                is_left = sibling_index > current_index
                proof.append({
                    "hash": current_level[sibling_index].hex(),
                    "position": "left" if is_left else "right"
                })

            # Passa al nodo genitore nel livello superiore
            current_index = current_index // 2
            current_level_index += 1

        return proof


def verify_proof(leaf_hash: bytes, proof: List[Dict], root_hex: str) -> bool:
    """
    Verifica una Merkle Proof senza bisogno dell'intero albero.

    Questo metodo viene utilizzato:
    - Dal client per verificare che il proprio voto sia incluso nell'albero
    - Dall'Observer per verificare tutti i voti

    Args:
        leaf_hash (bytes): Hash della foglia da verificare
        proof (List[Dict]): Merkle Proof generata da get_proof()
        root_hex (str): Merkle Root pubblica (esadecimale)

    Returns:
        bool: True se la proof è valida, False altrimenti
    """
    # Inizia con l'hash della foglia
    current_hash = leaf_hash

    # Applica tutti i passaggi della proof
    for step in proof:
        sibling_hash = bytes.fromhex(step["hash"])
        # Combina l'hash corrente con quello del fratello, nell'ordine corretto
        if step["position"] == "left":
            combined = sibling_hash + current_hash
        else:
            combined = current_hash + sibling_hash
        # Calcola il nuovo hash per il livello superiore
        current_hash = hashlib.sha256(combined).digest()

    # Verifica che l'hash finale corrisponda alla Merkle Root
    return current_hash.hex() == root_hex


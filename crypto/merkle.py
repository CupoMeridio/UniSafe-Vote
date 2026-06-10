
import hashlib
from typing import List, Dict


class MerkleTree:
    """
    Merkle Tree append-only per l'integrità del registro
    """

    def __init__(self):
        self.leaves: List[bytes] = []
        self.levels: List[List[bytes]] = []

    def _hash(self, data: bytes) -> bytes:
        """
        Calcola SHA-256 di un dato
        """
        return hashlib.sha256(data).digest()

    def add_leaf(self, data_bytes: bytes) -> int:
        """
        Aggiunge una foglia all'albero e restituisce l'indice
        """
        leaf_hash = self._hash(data_bytes)
        self.leaves.append(leaf_hash)
        self._rebuild_tree()
        return len(self.leaves) - 1

    def _rebuild_tree(self):
        """
        Ricostruisce l'albero partendo dalle foglie
        """
        self.levels = []
        current_level = self.leaves.copy()
        self.levels.append(current_level.copy())

        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if (i + 1) < len(current_level) else left
                combined = left + right
                next_level.append(self._hash(combined))
            current_level = next_level
            self.levels.append(current_level.copy())

    def get_root(self) -> str:
        """
        Restituisce la radice dell'albero in formato esadecimale
        """
        if not self.levels:
            return ""
        return self.levels[-1][0].hex()

    def get_proof(self, leaf_index: int) -> List[Dict]:
        """
        Genera la Merkle Proof per una foglia specifica
        """
        proof = []
        current_level_index = 0
        current_index = leaf_index

        while current_level_index < len(self.levels) - 1:
            current_level = self.levels[current_level_index]
            sibling_index = current_index ^ 1  # XOR per ottenere il fratello

            if sibling_index < len(current_level):
                is_left = sibling_index > current_index
                proof.append({
                    "hash": current_level[sibling_index].hex(),
                    "position": "left" if is_left else "right"
                })

            current_index = current_index // 2
            current_level_index += 1

        return proof


def verify_proof(leaf_hash: bytes, proof: List[Dict], root_hex: str) -> bool:
    """
    Verifica una Merkle Proof senza bisogno dell'intero albero
    """
    current_hash = leaf_hash

    for step in proof:
        sibling_hash = bytes.fromhex(step["hash"])
        if step["position"] == "left":
            combined = sibling_hash + current_hash
        else:
            combined = current_hash + sibling_hash
        current_hash = hashlib.sha256(combined).digest()

    return current_hash.hex() == root_hex

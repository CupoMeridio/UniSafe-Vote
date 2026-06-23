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

Implementazione: Forest of Perfect Trees
-----------------------------------------
Invece di ricostruire un unico albero ad ogni inserimento (O(n)),
manteniamo una lista di alberi binari perfetti (dimensioni 1, 2, 4, 8, ...).
Ogni inserimento aggiorna solo O(log n) nodi, come un carry nella somma binaria.

Complessità:
  - add_leaf:  O(log n) ammortizzato  [era O(n)]
  - get_root:  O(log n)               [era O(1) ma dopo O(n) di rebuild]
  - get_proof: O(log² n)              [era O(log n)]
"""

import hashlib
from typing import List, Dict, Literal, Optional, Tuple


# ---------------------------------------------------------------------------
# Struttura interna: un albero perfetto nel forest
# ---------------------------------------------------------------------------

class _PerfectTree:
    """
    Albero binario perfetto con esattamente 2^k foglie.

    Internamente memorizza tutti i livelli dell'albero, dalla radice alle foglie.
    Il livello 0 è la radice, l'ultimo livello contiene le foglie.

    Attributi:
        levels: levels[0] = [root], levels[-1] = foglie
        size:   numero di foglie (sempre una potenza di 2)
    """

    def __init__(self, levels: List[List[bytes]]):
        self.levels = levels          # levels[0] = [root], levels[-1] = foglie
        self.size = len(levels[-1])   # numero di foglie (potenza di 2)

    @property
    def root(self) -> bytes:
        return self.levels[0][0]

    @property
    def height(self) -> int:
        """Altezza dell'albero: 0 per un albero con una sola foglia."""
        return len(self.levels) - 1

    def get_proof_path(self, leaf_index: int) -> List[Dict[Literal["hash", "position"], str]]:
        """
        Restituisce il percorso di proof all'interno di questo albero perfetto.

        Args:
            leaf_index: indice della foglia all'interno di questo albero

        Returns:
            Lista di step della proof (dal basso verso la radice)
        """
        proof = []
        current_index = leaf_index

        # Risali dall'ultimo livello (foglie) al penultimo (figlio della radice)
        for level_idx in range(len(self.levels) - 1, 0, -1):
            level = self.levels[level_idx]
            sibling_index = current_index ^ 1  # XOR: scambia 0↔1, 2↔3, ecc.

            if sibling_index < len(level):
                is_left = sibling_index < current_index
                proof.append({
                    "hash": level[sibling_index].hex(),
                    "position": "left" if is_left else "right"
                })

            current_index //= 2

        return proof


# ---------------------------------------------------------------------------
# Forest of Perfect Trees
# ---------------------------------------------------------------------------

class MerkleTree:
    """
    Implementazione di un Merkle Tree append-only basata sul
    "Forest of Perfect Trees".

    Il forest è una lista di alberi perfetti le cui dimensioni corrispondono
    ai bit a 1 nella rappresentazione binaria del numero totale di foglie.

    Esempio: con 11 foglie (1011₂) il forest contiene:
      - un albero con 8 foglie  (bit 3)
      - un albero con 2 foglie  (bit 1)
      - un albero con 1 foglia  (bit 0)

    Quando si aggiunge una foglia, due alberi della stessa dimensione
    vengono fusi in uno doppio, esattamente come il carry nella somma binaria.
    """

    def __init__(self):
        """Inizializza un nuovo Merkle Tree vuoto."""
        self.leaves: List[bytes] = []         # tutti gli hash delle foglie, in ordine
        self._forest: List[_PerfectTree] = [] # lista di alberi perfetti (dal più piccolo)
        self._leaf_to_tree: List[Tuple[int, int]] = []
        # _leaf_to_tree[i] = (indice nel forest al momento dell'inserimento, indice locale)
        # Nota: il forest cambia nel tempo per le fusioni, quindi memorizziamo
        # le informazioni necessarie alla proof in modo diverso (vedi _proof_metadata).
        self._proof_metadata: List[Tuple[int, int]] = []
        # _proof_metadata[i] = (tree_size al momento dell'inserimento, leaf_index_locale)
        # Questo permette di ricostruire la proof anche dopo le fusioni.

    # ------------------------------------------------------------------
    # Metodi pubblici
    # ------------------------------------------------------------------

    def add_leaf(self, data_bytes: bytes) -> int:
        """
        Aggiunge una nuova foglia all'albero.

        Complessità ammortizzata: O(log n) invece di O(n).

        Args:
            data_bytes: dati da aggiungere come foglia (es. un voto serializzato)

        Returns:
            int: indice globale della foglia appena aggiunta (inizia da 0)
        """
        leaf_hash = self._hash(data_bytes)
        global_index = len(self.leaves)
        self.leaves.append(leaf_hash)

        # Crea un albero perfetto con la singola nuova foglia
        new_tree = _PerfectTree(levels=[[leaf_hash], [leaf_hash]])
        # levels[0] = root (= la foglia stessa), levels[1] = [foglia]
        # Per coerenza con get_proof_path, usiamo:
        # levels[-1] = foglie, levels[0] = root
        # Per un albero di altezza 0 (1 foglia), root = foglia stessa.
        new_tree = _PerfectTree(levels=[[leaf_hash]])
        # Caso speciale: albero di 1 foglia ha un solo livello.

        # Metadato per la proof: dimensione iniziale=1, indice locale=0
        local_index = 0

        # Fusione: finché ci sono due alberi della stessa dimensione, fondili
        # (analogo al carry nella somma binaria)
        while self._forest and self._forest[-1].size == new_tree.size:
            left_tree = self._forest.pop()
            new_tree = self._merge(left_tree, new_tree)
            # L'indice locale della nostra foglia era nell'albero di destra,
            # quindi nel nuovo albero fuso si trova nella metà destra:
            local_index = left_tree.size + local_index

        self._forest.append(new_tree)
        # Salva i metadati per get_proof: dimensione dell'albero in cui
        # la foglia è ora contenuta, e il suo indice locale in quell'albero.
        self._proof_metadata.append((new_tree.size, local_index))

        return global_index

    def get_root(self) -> str:
        """
        Restituisce la Merkle Root in formato esadecimale.

        Combina le radici dei vari alberi del forest in O(log n).

        Returns:
            str: Merkle Root come stringa esadecimale, o stringa vuota se vuoto
        """
        if not self._forest:
            return ""

        # Combina le radici da destra a sinistra (albero più piccolo prima)
        # In questo modo otteniamo una root deterministica e consistente
        # con un albero singolo costruito nello stesso ordine.
        current = self._forest[-1].root
        for tree in reversed(self._forest[:-1]):
            combined = tree.root + current
            current = self._hash(combined)

        return current.hex()

    def get_proof(self, leaf_index: int) -> List[Dict[Literal["hash", "position"], str]]:
        """
        Genera una Merkle Proof per una foglia specifica.

        La proof è composta da due parti:
        1. Il percorso all'interno dell'albero perfetto che contiene la foglia
        2. I passi per combinare la radice di quell'albero con le radici
           degli altri alberi del forest, fino alla Merkle Root globale

        Args:
            leaf_index: indice globale della foglia

        Returns:
            List[Dict]: lista di step della proof, ognuno con:
                - "hash":     hash del nodo fratello (esadecimale)
                - "position": "left" o "right"
        """
        if leaf_index < 0 or leaf_index >= len(self.leaves):
            raise IndexError(f"Indice foglia {leaf_index} fuori range")

        tree_size, local_index = self._proof_metadata[leaf_index]

        # Trova l'albero nel forest che contiene questa foglia.
        # Poiché il forest può essere cambiato dopo l'inserimento (per fusioni
        # successive), dobbiamo trovare l'albero che ora contiene la foglia.
        # La foglia globale leaf_index appartiene all'albero che copre
        # il range [start, start + tree_size).
        containing_tree, tree_start, tree_pos = self._find_tree_for_leaf(leaf_index)

        # Parte 1: proof all'interno dell'albero perfetto
        proof = containing_tree.get_proof_path(tree_pos)

        # Parte 2: proof tra gli alberi del forest per arrivare alla root globale
        # Dobbiamo combinare la root del nostro albero con quelle degli altri,
        # nell'ordine in cui get_root() li combina.
        proof += self._inter_tree_proof(containing_tree)

        return proof

    # ------------------------------------------------------------------
    # Metodi privati
    # ------------------------------------------------------------------

    @staticmethod
    def _hash(data: bytes) -> bytes:
        return hashlib.sha256(data).digest()

    def _merge(self, left: _PerfectTree, right: _PerfectTree) -> _PerfectTree:
        """
        Fonde due alberi perfetti della stessa dimensione in uno doppio.

        Il nuovo albero ha:
        - foglie = foglie di left + foglie di right
        - livelli = livelli combinati dei due alberi + nuova radice
        """
        assert left.size == right.size, "Solo alberi della stessa dimensione possono essere fusi"

        new_root = self._hash(left.root + right.root)
        new_levels: List[List[bytes]] = []

        # Livello 0 (radice del nuovo albero)
        new_levels.append([new_root])

        # Livelli intermedi: affianca i livelli corrispondenti dei due alberi
        left_levels = left.levels  # left.levels[0] = root, left.levels[-1] = foglie
        right_levels = right.levels

        for i in range(len(left_levels)):
            new_levels.append(left_levels[i] + right_levels[i])

        return _PerfectTree(levels=new_levels)

    def _find_tree_for_leaf(self, global_leaf_index: int) -> Tuple[_PerfectTree, int, int]:
        """
        Trova l'albero del forest che contiene la foglia con indice globale dato.

        Returns:
            (albero, indice_globale_della_prima_foglia, indice_locale_nell_albero)
        """
        # Gli alberi nel forest sono ordinati dal più grande al più piccolo
        # (o dal più piccolo al più grande, a seconda dell'implementazione).
        # Il forest copre le foglie in ordine: prima le foglie dell'albero
        # più grande (più a sinistra), poi le successive, ecc.
        # ATTENZIONE: in questa implementazione il forest è ordinato dal più
        # grande al più piccolo (il primo albero è quello con più foglie).
        # Questo segue la rappresentazione binaria: bit più significativo prima.

        # Ricostruiamo i range di ogni albero nel forest
        # Il forest è ordinato come viene costruito dall'algoritmo:
        # in generale, gli alberi nel forest non sono in un ordine fisso,
        # ma in questa implementazione sono in ordine dal più grande al
        # più piccolo (bit più significativi prima).
        # Dobbiamo trovare l'albero che contiene global_leaf_index.

        start = 0
        for tree in self._forest:
            end = start + tree.size
            if start <= global_leaf_index < end:
                return tree, start, global_leaf_index - start
            start = end

        raise ValueError(f"Foglia {global_leaf_index} non trovata nel forest")

    def _inter_tree_proof(self, target_tree: _PerfectTree) -> List[Dict[Literal["hash", "position"], str]]:
        """
        Genera i passi della proof che collegano la radice di target_tree
        alla Merkle Root globale (combinando le radici degli altri alberi).

        Replica la logica di get_root() tenendo traccia dei passi.
        """
        if len(self._forest) == 1:
            # Il forest ha un solo albero: la sua root è già la root globale
            return []

        # get_root() combina da destra a sinistra:
        # current = forest[-1].root
        # current = hash(forest[-2].root + current)
        # current = hash(forest[-3].root + current)
        # ...
        # Dobbiamo trovare a che punto appare target_tree e generare
        # i passi corrispondenti.

        proof_steps = []
        trees = self._forest

        # Trova l'indice di target_tree nel forest
        target_idx = next(i for i, t in enumerate(trees) if t is target_tree)

        # Simula get_root() tenendo traccia dei passi
        # La combinazione avviene da destra (indice alto) a sinistra (indice 0).
        # Il valore "corrente" parte dall'albero più a destra.

        # Costruiamo la proof separando i contributi a destra e a sinistra
        # di target_tree.

        # Contributi a destra di target_tree (alberi con indice > target_idx):
        # vengono combinati prima, producendo un hash che sta a "destra"
        # di target_tree nella combinazione finale.
        right_hash: Optional[bytes] = None
        for i in range(len(trees) - 1, target_idx, -1):
            if right_hash is None:
                right_hash = trees[i].root
            else:
                right_hash = self._hash(trees[i].root + right_hash)

        if right_hash is not None:
            proof_steps.append({
                "hash": right_hash.hex(),
                "position": "right"
            })

        # Contributi a sinistra di target_tree (alberi con indice < target_idx):
        # vengono combinati dopo, ognuno a "sinistra" del valore corrente.
        for i in range(target_idx - 1, -1, -1):
            proof_steps.append({
                "hash": trees[i].root.hex(),
                "position": "left"
            })

        return proof_steps


# ---------------------------------------------------------------------------
# Verifica della proof (invariata rispetto all'implementazione originale)
# ---------------------------------------------------------------------------

def verify_proof(
    leaf_hash: bytes,
    proof: List[Dict[Literal["hash", "position"], str]],
    root_hex: str
) -> bool:
    """
    Verifica una Merkle Proof senza bisogno dell'intero albero.

    Questo metodo viene utilizzato:
    - Dal client per verificare che il proprio voto sia incluso nell'albero
    - Dall'Observer per verificare tutti i voti

    Args:
        leaf_hash: hash della foglia da verificare (bytes)
        proof:     Merkle Proof generata da get_proof()
        root_hex:  Merkle Root pubblica (stringa esadecimale)

    Returns:
        bool: True se la proof è valida, False altrimenti
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
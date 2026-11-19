"""
Catena di hash del Bulletin Board.

Ogni blocco successivo al primo contiene, DENTRO i dati firmati, il campo
prev_hash = SHA-256 della serializzazione canonica del blocco precedente
(tipo, timestamp, dati e firma). Le firme dei singoli blocchi garantiscono
che nessun blocco sia stato alterato; la catena garantisce in più che nessun
blocco sia stato rimosso, inserito o riordinato: qualunque modifica alla
sequenza rompe il collegamento con il blocco successivo.
"""

import hashlib
import json
from typing import Dict, List, Optional


def block_hash(block: Dict) -> str:
    """SHA-256 esadecimale della serializzazione canonica di un blocco."""
    return hashlib.sha256(json.dumps(block, sort_keys=True).encode("utf-8")).hexdigest()


def link_to_previous(bulletin_board: List[Dict], block_data: Dict) -> Dict:
    """Inserisce in block_data il riferimento all'ultimo blocco del registro."""
    if bulletin_board:
        block_data["prev_hash"] = block_hash(bulletin_board[-1])
    return block_data


def find_chain_break(bulletin_board: List[Dict]) -> Optional[int]:
    """
    Restituisce l'indice del primo blocco il cui prev_hash non corrisponde al
    blocco precedente, oppure None se la catena è integra.
    """
    for i in range(1, len(bulletin_board)):
        if bulletin_board[i].get("data", {}).get("prev_hash") != block_hash(bulletin_board[i - 1]):
            return i
    return None

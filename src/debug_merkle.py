
"""Debug script for MerkleTree verify_proof MerkleTree di prova // 
non viene utilizzato effettivamente dal server
"""

import hashlib
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto.merkle import MerkleTree, verify_proof


def test():
    mt = MerkleTree()
    vote0 = {"index":0,"encrypted_vote":"test0","encrypted_seed":"seed0"}
    vote1 = {"index":1,"encrypted_vote":"test1","encrypted_seed":"seed1"}
    data0 = json.dumps(vote0, sort_keys=True).encode("utf-8")
    data1 = json.dumps(vote1, sort_keys=True).encode("utf-8")
    mt.add_leaf(data0)
    mt.add_leaf(data1)
    root = mt.get_root()
    print(f"Root: {root}")

    leaf0_hash = hashlib.sha256(data0).digest()
    proof0 = mt.get_proof(0)
    print(f"Proof for 0: {proof0}")
    print(verify_proof(leaf0_hash, proof0, root))

test()


"""
6. Test script for Man-in-the-Middle Key Substitution Attack
"""

import os
import sys
import json
import hashlib
from typing import Dict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto.keys import generate_rsa_keypair, serialize_public_key
from client import Client, SecurityError, compute_public_key_fingerprint


def main():
    print("=" * 80)
    print("6. TEST: Man-in-the-Middle Key Substitution Attack")
    print("=" * 80)

    print("\n[1] Initialize a new election to set up baseline")
    # First, initialize an election so we have baseline
    from init_election_non_interactive import main as init_election
    init_election()

    print("\n[2] Baseline client setup: load keys and set pinning")
    client = Client()
    client._load_pins_from_bulletin_board()
    print(f"Trusted pin for AE encrypt key: {client.pin_ae_encrypt_fingerprint[:20]}...")
    print(f"Trusted pin for AE sign key: {client.pin_ae_sign_fingerprint[:20]}...")

    print("\n[3] Attacker step 1: generate malicious RSA key pair (fake AE keys)")
    fake_ae_encrypt_priv, fake_ae_encrypt_pub = generate_rsa_keypair()
    fake_ae_sign_priv, fake_ae_sign_pub = generate_rsa_keypair()
    fake_ae_encrypt_pem = serialize_public_key(fake_ae_encrypt_pub)
    fake_ae_sign_pem = serialize_public_key(fake_ae_sign_pub)
    print("Attacker generated fake AE keys!")

    print("\n[4] Simulate MitM intercepting Bulletin Board: replace AE public keys")
    with open("data/bulletin_board.json", "r", encoding="utf-8") as f:
        tampered_bb = json.load(f)

    # Modify the init block with fake keys (key substitution attack!)
    tampered_bb[0]["data"]["ae_encrypt_public"] = fake_ae_encrypt_pem
    tampered_bb[0]["data"]["ae_sign_public"] = fake_ae_sign_pem

    # Save the tampered bulletin board (simulate MitM modifying the data)
    with open("data/bulletin_board.json", "w", encoding="utf-8") as f:
        json.dump(tampered_bb, f, indent=2, ensure_ascii=False)
    print("Tampered Bulletin Board saved (fake AE keys injected)!")

    print("\n[5] Client loads bulletin board (now tampered!)")
    try:
        client.load_bulletin_board()
        print("ERROR: Client accepted tampered keys! That's BAD!")
        sys.exit(1)
    except SecurityError as e:
        print("SUCCESS: Client raised SecurityError!")
        print(f"Error message: {str(e)}")
        print("\nThis means the Certificate Pinning worked!")
        print("The client detected key substitution and stopped before proceeding!")

    print("\n[6] Cleanup: restore original bulletin board (using init_election_non_interactive)")
    init_election()  # re-initialize to clean up

    print("\n" + "=" * 80)
    print("[SUCCESS] MitM Key Substitution Attack test PASSED!")
    print("[SUCCESS] Certificate Pinning successfully blocked the attack!")
    print("=" * 80)


if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    main()

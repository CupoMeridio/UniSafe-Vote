"""
Script per l'analisi delle prestazioni (WP4 - Implementazione e Prestazioni)
Calcola i tempi computazionali, la dimensione dei messaggi e la latenza.
"""

import time
import json
import sys
import os
import hashlib
import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto.keys import generate_rsa_keypair, serialize_public_key
from crypto.rsa_oaep import encrypt, decrypt
from crypto.rsa_pss import sign, verify

# Configurazione
AE_URL = "http://localhost:5002"
SA_URL = "http://localhost:5001"

def measure_size(data_dict):
    """Calcola la dimensione in byte di un payload JSON."""
    return len(json.dumps(data_dict).encode('utf-8'))

def test_crypto_performance():
    print("=" * 60)
    print("1. COSTO COMPUTAZIONALE OPERAZIONI CRITTOGRAFICHE")
    print("=" * 60)
    
    # 1. Generazione chiavi
    start = time.perf_counter()
    priv_key, pub_key = generate_rsa_keypair(key_size=2048)
    gen_time = (time.perf_counter() - start) * 1000
    print(f"Generazione coppia chiavi RSA 2048: {gen_time:.2f} ms")

    # 2. Cifratura RSA-OAEP
    message = b"Voto: 1"
    seed = os.urandom(32)
    start = time.perf_counter()
    ciphertext = encrypt(pub_key, message, seed)
    enc_time = (time.perf_counter() - start) * 1000
    print(f"Cifratura RSA-OAEP (Client): {enc_time:.2f} ms")

    # 3. Decifratura RSA-OAEP
    start = time.perf_counter()
    decrypt(priv_key, ciphertext)
    dec_time = (time.perf_counter() - start) * 1000
    print(f"Decifratura RSA-OAEP (Server AE, Scrutinio): {dec_time:.2f} ms")

    # 4. Firma RSA-PSS
    payload_to_sign = b"Test_Token_Data"
    start = time.perf_counter()
    signature = sign(priv_key, payload_to_sign)
    sign_time = (time.perf_counter() - start) * 1000
    print(f"Firma RSA-PSS (Server SA/AE): {sign_time:.2f} ms")

    # 5. Verifica RSA-PSS
    start = time.perf_counter()
    verify(pub_key, payload_to_sign, signature)
    ver_time = (time.perf_counter() - start) * 1000
    print(f"Verifica Firma RSA-PSS (Client/Observer): {ver_time:.2f} ms")

    # 6. Proof of Work (Difficoltà 4)
    enc_vote_bytes = os.urandom(256)
    nonce = 0
    start = time.perf_counter()
    while True:
        combined = enc_vote_bytes + nonce.to_bytes(8, 'big')
        if hashlib.sha256(combined).digest()[0] == 0:  # Difficoltà semplificata per test
            break
        nonce += 1
    pow_time = (time.perf_counter() - start) * 1000
    print(f"Risoluzione PoW (Difficoltà standard 8-bit, Client): {pow_time:.2f} ms")


def test_payload_sizes():
    print("\n" + "=" * 60)
    print("2. DIMENSIONE DEI MESSAGGI SCAMBIATI (In Rete)")
    print("=" * 60)

    # Simula un token
    token = {
        "election_id": "ele_12345",
        "nonce": os.urandom(16).hex(),
        "issued_at": "2025-01-01T10:00:00+00:00",
        "expires_at": "2025-01-01T10:30:00+00:00"
    }
    signature = os.urandom(256).hex()
    
    auth_response = {"token": json.dumps(token), "signature": signature}
    print(f"Risposta Autenticazione (Token + Firma): {measure_size(auth_response)} byte")

    # Simula un payload di voto
    vote_payload = {
        "enc_vote": os.urandom(256).hex(),
        "enc_seed": os.urandom(256).hex(),
        "token": json.dumps(token),
        "token_signature": signature,
        "pow_nonce": "0000000000000abc"
    }
    print(f"Richiesta Voto (Scheda cifrata + PoW + Token): {measure_size(vote_payload)} byte")

    # Simula una ricevuta
    receipt = {
        "leaf_index": 42,
        "enc_vote": os.urandom(256).hex(),
        "merkle_proof": [
            {"position": "left", "hash": os.urandom(32).hex()},
            {"position": "right", "hash": os.urandom(32).hex()},
            {"position": "left", "hash": os.urandom(32).hex()}
        ],
        "ae_signature": signature
    }
    print(f"Ricevuta di Voto dall'AE: {measure_size(receipt)} byte")


def test_network_latency():
    print("\n" + "=" * 60)
    print("3. LATENZA DELLE OPERAZIONI (Richiede server avviati!)")
    print("=" * 60)
    
    try:
        # Status SA
        start = time.perf_counter()
        requests.get(f"{SA_URL}/status", timeout=2)
        print(f"Ping Server Autenticazione: {(time.perf_counter() - start)*1000:.2f} ms")

        # Status AE
        start = time.perf_counter()
        requests.get(f"{AE_URL}/status", timeout=2)
        print(f"Ping Autorità Elettorale: {(time.perf_counter() - start)*1000:.2f} ms")
        
    except requests.exceptions.RequestException:
        print("Server non raggiungibili per il test di latenza. Avvia sa.py e ae.py.")

if __name__ == "__main__":
    test_crypto_performance()
    test_payload_sizes()
    test_network_latency()
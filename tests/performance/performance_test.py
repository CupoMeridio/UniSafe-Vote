
"""
Script per l'analisi delle prestazioni (WP4 - Implementazione e Prestazioni)
Calcola i tempi computazionali, la dimensione dei messaggi e la latenza.
Include: casi limite, test Merkle Tree, più iterazioni per significatività statistica,
          difficoltà PoW variabili, chiavi RSA 4096 bit.
"""

import time
import json
import sys
import os
import hashlib
import requests
from typing import List, Dict, Any

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "src"))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "tests"))

from crypto.keys import generate_rsa_keypair, serialize_public_key
from crypto.rsa_oaep import encrypt, decrypt
from crypto.rsa_pss import sign, verify
from crypto.merkle import MerkleTree, verify_proof

# Configurazione
SA_URL = "https://localhost:5001"
AE_URL = "https://localhost:5002"
SA_CERT = os.path.join(PROJECT_ROOT, "data", "tls", "sa_cert.pem")
AE_CERT = os.path.join(PROJECT_ROOT, "data", "tls", "ae_cert.pem")
NUM_ITERATIONS = 5  # Numero di iterazioni per calcolare media e deviazione standard


def _verify_for(url: str) -> str | bool:
    if "5001" in url:
        return SA_CERT if os.path.exists(SA_CERT) else True
    if "5002" in url:
        return AE_CERT if os.path.exists(AE_CERT) else True
    return True


def measure_size(data_dict: Dict) -> int:
    """Calcola la dimensione in byte di un payload JSON."""
    return len(json.dumps(data_dict).encode('utf-8'))


def test_crypto_performance():
    print("=" * 70)
    print("COSTO COMPUTAZIONALE OPERAZIONI CRITTOGRAFICHE")
    print("   (Media su {} iterazioni)".format(NUM_ITERATIONS))
    print("=" * 70)

    for key_size in [2048, 4096]:
        print(f"\n--- Chiavi RSA {key_size} bit ---")
        
        # 1. Generazione chiavi
        gen_times = []
        for _ in range(NUM_ITERATIONS):
            start = time.perf_counter()
            priv_key, pub_key = generate_rsa_keypair(key_size=key_size)
            gen_times.append((time.perf_counter() - start) * 1000)
        print(f"Generazione coppia chiavi: {sum(gen_times)/NUM_ITERATIONS:.2f} ms (media)")

        # Prepariamo dati per altri test
        message = b"Voto: 1"  # Simile a indice candidato (1 byte)
        seed = os.urandom(32)
        payload_to_sign = b"Test_Token_Data"

        # 2. Cifratura RSA-OAEP
        enc_times = []
        for _ in range(NUM_ITERATIONS):
            start = time.perf_counter()
            ciphertext = encrypt(pub_key, message, seed)
            enc_times.append((time.perf_counter() - start) * 1000)
        print(f"Cifratura RSA-OAEP (Client): {sum(enc_times)/NUM_ITERATIONS:.2f} ms (media)")

        # 3. Decifratura RSA-OAEP
        dec_times = []
        for _ in range(NUM_ITERATIONS):
            start = time.perf_counter()
            decrypt(priv_key, ciphertext)
            dec_times.append((time.perf_counter() - start) * 1000)
        print(f"Decifratura RSA-OAEP (Server AE, Scrutinio): {sum(dec_times)/NUM_ITERATIONS:.2f} ms (media)")

        # 4. Firma RSA-PSS
        sign_times = []
        for _ in range(NUM_ITERATIONS):
            start = time.perf_counter()
            signature = sign(priv_key, payload_to_sign)
            sign_times.append((time.perf_counter() - start) * 1000)
        print(f"Firma RSA-PSS (Server SA/AE): {sum(sign_times)/NUM_ITERATIONS:.2f} ms (media)")

        # 5. Verifica RSA-PSS
        ver_times = []
        for _ in range(NUM_ITERATIONS):
            start = time.perf_counter()
            verify(pub_key, payload_to_sign, signature)
            ver_times.append((time.perf_counter() - start) * 1000)
        print(f"Verifica Firma RSA-PSS (Client/Observer): {sum(ver_times)/NUM_ITERATIONS:.2f} ms (media)")


def test_pow_performance():
    print("\n" + "=" * 70)
    print("2. PERFORMANCE PROOF OF WORK (PoW)")
    print("   (Difficoltà variabili, media su {} iterazioni)".format(NUM_ITERATIONS))
    print("=" * 70)

    enc_vote_bytes = os.urandom(256)  # Dati simili a enc_vote reale
    
    for difficulty in [4, 8, 12]:  # Min, medio, alto
        print(f"\n--- Difficoltà: {difficulty} bit di zero iniziali ---")
        pow_times = []
        
        for _ in range(NUM_ITERATIONS):
            nonce = 0
            start = time.perf_counter()
            
            while True:
                combined = enc_vote_bytes + nonce.to_bytes(8, 'big')
                hash_result = hashlib.sha256(combined).digest()
                
                # Verifica esatta come nel sistema reale (client.py e ae.py)
                valid = True
                required_zeros = difficulty // 8
                required_bits = difficulty % 8
                
                for i in range(required_zeros):
                    if hash_result[i] != 0:
                        valid = False
                        break
                
                if valid and required_bits > 0:
                    mask = (0xFF << (8 - required_bits)) & 0xFF
                    if (hash_result[required_zeros] & mask) != 0:
                        valid = False
                
                if valid:
                    break
                nonce += 1
            
            pow_times.append((time.perf_counter() - start) * 1000)
        
        avg_pow = sum(pow_times)/NUM_ITERATIONS
        min_pow = min(pow_times)
        max_pow = max(pow_times)
        print(f"Media: {avg_pow:.2f} ms")
        print(f"Range: [{min_pow:.2f} - {max_pow:.2f}] ms")


def test_merkle_performance():
    print("\n" + "=" * 70)
    print("3. PERFORMANCE ALBERO DI MERKLE")
    print("   (Diverse dimensioni, media su {} iterazioni)".format(NUM_ITERATIONS))
    print("=" * 70)

    for num_leaves in [10, 100, 1000]:
        print(f"\n--- {num_leaves} foglie ---")
        
        # Prepariamo foglie (simili a record di voto)
        leaves = []
        for i in range(num_leaves):
            leaves.append(json.dumps({
                "index": i,
                "enc_vote": os.urandom(256).hex(),
                "timestamp": "2025-01-01T00:00:00+00:00"
            }).encode('utf-8'))
        
        # 1. Costruzione albero
        build_times = []
        root = None
        for _ in range(NUM_ITERATIONS):
            start = time.perf_counter()
            mt = MerkleTree()
            for leaf in leaves:
                mt.add_leaf(leaf)
            root = mt.get_root()
            build_times.append((time.perf_counter() - start) * 1000)
        
        # 2. Generazione proof per una foglia (es. la metà)
        proof_times = []
        proof = None
        for _ in range(NUM_ITERATIONS):
            mt = MerkleTree()
            for leaf in leaves:
                mt.add_leaf(leaf)
            start = time.perf_counter()
            proof = mt.get_proof(num_leaves // 2)
            proof_times.append((time.perf_counter() - start) * 1000)
        
        # 3. Verifica proof
        verify_times = []
        leaf_hash = hashlib.sha256(leaves[num_leaves//2]).digest()
        for _ in range(NUM_ITERATIONS):
            start = time.perf_counter()
            verify_proof(leaf_hash, proof, root)
            verify_times.append((time.perf_counter() - start) * 1000)
        
        print(f"Costruzione albero: {sum(build_times)/NUM_ITERATIONS:.2f} ms")
        print(f"Generazione Merkle Proof: {sum(proof_times)/NUM_ITERATIONS:.2f} ms")
        print(f"Verifica Merkle Proof: {sum(verify_times)/NUM_ITERATIONS:.2f} ms")
        print(f"Dimensione Merkle Proof: {measure_size(proof)} byte")


def test_payload_sizes():
    print("\n" + "=" * 70)
    print("4. DIMENSIONE DEI MESSAGGI SCAMBIATI (In Rete)")
    print("=" * 70)

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


def test_network_latency_and_flow():
    print("\n" + "=" * 70)
    print("5. LATENZA E FLUSSO COMPLETO")
    print("   (Richiede server SA e AE AVVIATI!)")
    print("=" * 70)
    
    try:
        # Status SA
        start = time.perf_counter()
        requests.get(f"{SA_URL}/status", timeout=2, verify=_verify_for(SA_URL))
        print(f"Ping Server Autenticazione: {(time.perf_counter() - start)*1000:.2f} ms")

        # Status AE
        start = time.perf_counter()
        requests.get(f"{AE_URL}/status", timeout=2, verify=_verify_for(AE_URL))
        print(f"Ping Autorità Elettorale: {(time.perf_counter() - start)*1000:.2f} ms")
        
        # Se i server sono su, testiamo un flusso completo (se possibile, senza init elezione)
        print("\n--- Tentativo flusso parziale (richiede elezione già inizializzata!) ---")
        try:
            # 1. Autenticazione
            start_auth = time.perf_counter()
            auth_resp = requests.post(f"{SA_URL}/authenticate", json={
                "username": "mario.rossi",
                "password": "password123"
            }, timeout=5, verify=_verify_for(SA_URL))
            auth_time = (time.perf_counter() - start_auth)*1000
            
            if auth_resp.status_code == 200:
                print(f"Autenticazione (SA): {auth_time:.2f} ms")
                print("  (Nota: Se hai già ricevuto un token, la seconda autenticazione potrebbe dare errore)")
            else:
                print(f"Autenticazione fallita (status {auth_resp.status_code})")
                
        except Exception as e:
            print(f"Test flusso non riuscito: {str(e)}")
        
    except requests.exceptions.RequestException:
        print("\nServer non raggiungibili per il test di latenza.")
        print("  Per testare la latenza, avvia 'py sa.py' e 'py ae.py' in terminali separati.")


if __name__ == "__main__":
    try:
        print("\n" + "=" * 70)
        print("ANALISI PRESTAZIONI SISTEMA UNISAFE-VOTE")
        print("=" * 70)
        
        test_crypto_performance()
        test_pow_performance()
        test_merkle_performance()
        test_payload_sizes()
        test_network_latency_and_flow()
        
        print("\n" + "=" * 70)
        print("ANALISI COMPLETATA!")
        print("=" * 70)
    finally:
        input("\nPremi Invio per chiudere...")


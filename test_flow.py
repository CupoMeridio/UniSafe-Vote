import os
import subprocess
import sys
import time
import requests
import json
import hashlib

# Risolve dinamicamente la cartella del progetto corrente
WORKSPACE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, WORKSPACE_DIR)

from crypto.keys import deserialize_public_key
from crypto.rsa_oaep import encrypt

def check_server(url):
    try:
        r = requests.get(url + "/status", timeout=1)
        return r.status_code == 200
    except:
        return False

def solve_pow(enc_vote_hex, difficulty=4):
    enc_vote_bytes = bytes.fromhex(enc_vote_hex)
    nonce = 0
    while True:
        nonce_bytes = nonce.to_bytes(8, byteorder='big')
        combined = enc_vote_bytes + nonce_bytes
        hash_result = hashlib.sha256(combined).digest()
        
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
            return nonce_bytes.hex()
        nonce += 1

def main():
    print("Avvio dei server SA e AE per il test...")
    python_exe = sys.executable
    
    # Avvia i server SA e AE in background
    sa_proc = subprocess.Popen([python_exe, "sa.py"], cwd=WORKSPACE_DIR)
    ae_proc = subprocess.Popen([python_exe, "ae.py"], cwd=WORKSPACE_DIR)
    
    try:
        # Attesa del boot
        print("Attesa che i server rispondano...")
        for _ in range(15):
            if check_server("http://localhost:5001") and check_server("http://localhost:5002"):
                print("Server pronti!")
                break
            time.sleep(1)
        else:
            raise Exception("Timeout nell'avvio dei server")
            
        # 1. Autenticazione elettore
        print("Autenticazione mario.rossi...")
        r = requests.post("http://localhost:5001/authenticate", json={
            "username": "mario.rossi",
            "password": "password123"
        })
        r.raise_for_status()
        auth_data = r.json()
        token = auth_data["token"]
        token_signature = auth_data["signature"]
        print("Autenticato con successo!")
        
        # 2. Preparazione voto
        print("Preparazione del voto per Lista A (indice 0)...")
        with open(os.path.join(WORKSPACE_DIR, "data", "bulletin_board.json"), "r", encoding="utf-8") as f:
            bb = json.load(f)
        ae_encrypt_public_pem = bb[0]["data"]["ae_encrypt_public"]
        ae_encrypt_public = deserialize_public_key(ae_encrypt_public_pem)
        
        seed = os.urandom(16)
        vote_byte = (0).to_bytes(1, byteorder='big')
        plaintext = vote_byte + seed
        enc_vote = encrypt(ae_encrypt_public, plaintext).hex()
        enc_seed = encrypt(ae_encrypt_public, seed).hex()
        
        print("Risoluzione Proof of Work...")
        pow_nonce = solve_pow(enc_vote)
        
        # 3. Invio del voto all'AE
        print("Invio del voto all'AE...")
        r = requests.post("http://localhost:5002/vote", json={
            "enc_vote": enc_vote,
            "enc_seed": enc_seed,
            "token": token,
            "token_signature": token_signature,
            "pow_nonce": pow_nonce
        })
        r.raise_for_status()
        receipt = r.json()
        print(f"Voto accettato! Leaf index: {receipt['leaf_index']}")
        
        # 4. Chiusura elezione e scrutinio
        print("Chiusura dell'elezione...")
        r = requests.post("http://localhost:5002/close")
        r.raise_for_status()
        close_res = r.json()
        print("Scrutinio completato:", close_res["result"])
        
        # 5. Verifica con l'Observer
        print("Avvio dell'observer per la verifica universale...")
        obs_proc = subprocess.Popen([python_exe, "observer.py"], cwd=WORKSPACE_DIR, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = obs_proc.communicate()
        print("--- Output Observer ---")
        print(stdout)
        print("--- Stderr Observer ---")
        print(stderr)
        
        if "TUTTE LE VERIFICHE SONO RIUSCITE!" in stdout:
            print("TEST OK: La verifica dell'observer ha avuto successo!")
        else:
            print("TEST FALLITO: L'observer ha riscontrato problemi!")
            sys.exit(1)
            
    finally:
        print("Spegnimento dei server...")
        try:
            requests.post("http://localhost:5001/shutdown", timeout=2)
        except:
            pass
        try:
            requests.post("http://localhost:5002/shutdown", timeout=2)
        except:
            pass
            
        sa_proc.terminate()
        ae_proc.terminate()
        try:
            sa_proc.wait(timeout=3)
        except:
            sa_proc.kill()
        try:
            ae_proc.wait(timeout=3)
        except:
            ae_proc.kill()
        print("Server spenti.")

if __name__ == "__main__":
    main()

"""
Locust Test File per UniSafe-Vote Performance Testing
- Scenario Ottimale (Baseline): Utenti legittimi che autenticano e votano
- Scenario DoS: Attacco volumetrico con PoW invalida (simulazione DDoS)
"""
import json
import os
import sys
import hashlib
import random
from locust import HttpUser, task, between
from typing import Optional

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "src"))  # Aggiungi src/ al path per importare i moduli

from crypto.keys import deserialize_public_key
from crypto.rsa_oaep import encrypt


def solve_pow(enc_vote_bytes: bytes, difficulty: int = 4) -> str:
    """Risoluzione Proof of Work per test"""
    nonce = 0
    while True:
        nonce_bytes = nonce.to_bytes(8, 'big')
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


class LegitimateUser(HttpUser):
    """Utente legittimo: autentica e vota"""
    wait_time = between(1, 3)
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.username: Optional[str] = None
        self.token: Optional[str] = None
        self.token_signature: Optional[str] = None
        self.has_voted: bool = False
        self.ae_public_key = None
        
        # IP Finto per bypassare il Rate Limiting
        self.fake_ip = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
        self.headers = {"X-Forwarded-For": self.fake_ip}
    
    def on_start(self):
        """Carica la chiave dell'AE e autentica l'utente"""
        
        # 1. Carica la chiave pubblica dell'AE per cifrare i voti
        # Data è ora in src/data/
        bb_path = os.path.join(PROJECT_ROOT, "src", "data", "bulletin_board.json")
        try:
            with open(bb_path, "r", encoding="utf-8") as f:
                bb = json.load(f)
                ae_pub_pem = bb[0]["data"]["ae_encrypt_public"]
                self.ae_public_key = deserialize_public_key(ae_pub_pem)
        except Exception as e:
            print(f"Errore caricamento chiave AE da {bb_path}: {e}")
            
        # 2. Utenti presenti nel voters.json
        test_users = [
            ("mario.rossi", "password123"),
            ("luigi.bianchi", "password456")
        ]
        
        self.username, password = random.choice(test_users)
        
        # Autenticazione sul SA
        auth_response = self.client.post(
            "http://localhost:5001/authenticate",
            json={"username": self.username, "password": password},
            headers=self.headers
        )
        if auth_response.status_code == 200:
            self.token = auth_response.json()["token"]
            self.token_signature = auth_response.json()["signature"]
    
    @task(3)  # 3 voti ogni 1 verifica
    def vote(self):
        if not self.token or self.has_voted or not self.ae_public_key:
            return
        
        # 1. Genera un VOTO VERO e cifralo in RSA-OAEP
        candidate_index = random.randint(0, 2)
        candidate_bytes = str(candidate_index).encode('utf-8')
        
        seed = os.urandom(32)
        enc_vote_bytes = encrypt(self.ae_public_key, candidate_bytes, seed)
        enc_seed_bytes = encrypt(self.ae_public_key, seed, os.urandom(32))
        
        # 2. Calcola la Proof of Work
        pow_nonce = solve_pow(enc_vote_bytes, 4)
        
        vote_payload = {
            "enc_vote": enc_vote_bytes.hex(),
            "enc_seed": enc_seed_bytes.hex(),
            "token": self.token,
            "token_signature": self.token_signature,
            "pow_nonce": pow_nonce
        }
        
        # 3. Invia il voto all'AE
        response = self.client.post(
            "http://localhost:5002/vote",
            json=vote_payload,
            headers=self.headers
        )
        if response.status_code == 200:
            self.has_voted = True
    
    @task(1)  # 1 verifica ogni 3 voti
    def verify_status(self):
        self.client.get(
            "http://localhost:5002/status",
            headers=self.headers
        )


class MaliciousDoSUser(HttpUser):
    """Utente malintenzionato che attacca con PoW invalida (Botnet DDoS)"""
    wait_time = between(0.01, 0.1)
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fake_ip = f"10.0.{random.randint(1, 254)}.{random.randint(1, 254)}"
        self.headers = {"X-Forwarded-For": self.fake_ip}

    @task(100)
    def send_invalid_pow(self):
        # Dati dummy con PoW invalida per testare il blocco 400 Bad Request
        enc_vote_bytes = os.urandom(256)
        vote_payload = {
            "enc_vote": enc_vote_bytes.hex(),
            "enc_seed": os.urandom(256).hex(),
            "token": "dummy_token",
            "token_signature": "dummy_signature",
            "pow_nonce": "0000000000000000"
        }
        self.client.post(
            "http://localhost:5002/vote",
            json=vote_payload,
            headers=self.headers
        )

#!/usr/bin/env python3
import os
import json
import hashlib
import requests
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto.keys import deserialize_public_key
from crypto.rsa_oaep import encrypt
from crypto.rsa_pss import verify
from crypto.merkle import verify_proof

SA_URL = "http://localhost:5001"
AE_URL = "http://localhost:5002"
BULLETIN_BOARD_PATH = "data/bulletin_board.json"


class Client:
    def __init__(self):
        self.username = None
        self.token = None
        self.token_signature = None
        self.receipt = None
        self.load_bulletin_board()

    def load_bulletin_board(self):
        with open(BULLETIN_BOARD_PATH, "r", encoding="utf-8") as f:
            self.bb = json.load(f)
        self.init_data = self.bb[0]["data"]
        self.candidates = self.init_data["candidates"]
        self.ae_encrypt_public = deserialize_public_key(self.init_data["ae_encrypt_public"])
        self.ae_sign_public = deserialize_public_key(self.init_data["ae_sign_public"])

    def solve_pow(self, enc_vote_hex: str, difficulty=4) -> str:
        """
        Risolve la Proof of Work: trova nonce tale che SHA-256(enc_vote || nonce) ha i primi 'difficulty' bit a zero
        """
        enc_vote_bytes = bytes.fromhex(enc_vote_hex)
        nonce = 0
        print("  Risolvendo Proof of Work...", end="", flush=True)

        while True:
            nonce_bytes = nonce.to_bytes(8, byteorder='big')
            combined = enc_vote_bytes + nonce_bytes
            hash_result = hashlib.sha256(combined).digest()

            # Verifica i primi 'difficulty' bit
            required_zeros = difficulty // 8
            required_bits = difficulty % 8
            valid = True

            for i in range(required_zeros):
                if hash_result[i] != 0:
                    valid = False
                    break

            if valid and required_bits > 0:
                mask = (0xFF << (8 - required_bits)) & 0xFF
                if (hash_result[required_zeros] & mask) != 0:
                    valid = False

            if valid:
                print(" ✓")
                return nonce_bytes.hex()

            nonce += 1
            if nonce % 100000 == 0:
                print(".", end="", flush=True)

    def register(self):
        print("\n=== REGISTRAZIONE UTENTE ===")
        print("Puoi registrarti solo con un'email UNISA (@studenti.unisa.it o @unisa.it)\n")
        
        email = input("Inserisci la tua email UNISA: ")
        username = input("Scegli un username: ")
        password = input("Scegli una password: ")

        try:
            response = requests.post(
                f"{SA_URL}/register",
                json={"email": email, "username": username, "password": password}
            )

            if response.status_code == 201:
                print(f"\n{response.json().get('message')}")
                print("Ora puoi autenticarti con le tue credenziali!")
            else:
                print(f"\nErrore: {response.json().get('error')}")

        except requests.exceptions.ConnectionError:
            print("\nImpossibile connettersi al SA. Assicurati che sia in esecuzione.")

    def authenticate(self):
        username = input("Inserisci username: ")
        password = input("Inserisci password: ")

        try:
            response = requests.post(
                f"{SA_URL}/authenticate",
                json={"username": username, "password": password}
            )

            if response.status_code == 200:
                data = response.json()
                self.username = username
                self.token = data["token"]
                self.token_signature = data["signature"]
                print("\nAutenticazione riuscita! Token ricevuto.")
            else:
                print(f"\nErrore: {response.json().get('error')}")

        except requests.exceptions.ConnectionError:
            print("\nImpossibile connettersi al SA. Assicurati che sia in esecuzione.")

    def vote(self):
        if not self.token:
            print("\n❌ Devi prima autenticarti!")
            return

        print("\nLista candidate:")
        for i, candidate in enumerate(self.candidates):
            print(f"{i + 1}. {candidate}")

        choice = input("\nSeleziona il numero della lista: ")
        try:
            choice_index = int(choice) - 1
            if choice_index < 0 or choice_index >= len(self.candidates):
                print("\n❌ Scelta non valida!")
                return
        except ValueError:
            print("\n❌ Inserisci un numero valido!")
            return

        # 1. Genera seed casuale e prepara il plaintext
        seed = os.urandom(16)
        vote_byte = choice_index.to_bytes(1, byteorder='big')
        plaintext_vote_seed = vote_byte + seed

        # 2. Cifra enc_vote e enc_seed
        enc_vote_bytes = encrypt(self.ae_encrypt_public, plaintext_vote_seed)
        enc_seed_bytes = encrypt(self.ae_encrypt_public, seed)
        enc_vote_hex = enc_vote_bytes.hex()
        enc_seed_hex = enc_seed_bytes.hex()

        # 3. Risolvi PoW
        pow_nonce_hex = self.solve_pow(enc_vote_hex)

        # 4. Invia voto all'AE
        try:
            response = requests.post(
                f"{AE_URL}/vote",
                json={
                    "enc_vote": enc_vote_hex,
                    "enc_seed": enc_seed_hex,
                    "token": self.token,
                    "token_signature": self.token_signature,
                    "pow_nonce": pow_nonce_hex
                }
            )

            if response.status_code == 200:
                receipt_data = response.json()
                self.receipt = receipt_data

                # Salva ricevuta
                receipt_path = f"data/receipts/{self.username}.json"
                with open(receipt_path, "w", encoding="utf-8") as f:
                    json.dump(receipt_data, f, indent=2, ensure_ascii=False)

                print(f"\n✅ Voto espresso con successo! Ricevuta salvata in {receipt_path}")
            else:
                print(f"\n❌ Errore: {response.json().get('error')}")

        except requests.exceptions.ConnectionError:
            print("\n❌ Impossibile connettersi all'AE. Assicurati che sia in esecuzione.")

    def show_receipt(self):
        if self.username:
            receipt_path = f"data/receipts/{self.username}.json"
            if os.path.exists(receipt_path):
                with open(receipt_path, "r", encoding="utf-8") as f:
                    receipt = json.load(f)
                print("\n=== RICEVUTA VOTO ===")
                print(json.dumps(receipt, indent=2, ensure_ascii=False))
            else:
                print("\n❌ Nessuna ricevuta trovata per questo utente.")
        else:
            print("\n❌ Devi prima autenticarti!")

    def verify_vote(self):
        if self.username:
            receipt_path = f"data/receipts/{self.username}.json"
            if not os.path.exists(receipt_path):
                print("\n❌ Nessuna ricevuta trovata per questo utente.")
                return

            with open(receipt_path, "r", encoding="utf-8") as f:
                receipt = json.load(f)

            # Ricarica Bulletin Board per ottenere la root finale
            self.load_bulletin_board()

            # 1. Ottieni Merkle root finale
            merkle_root = None
            for block in self.bb:
                if block['type'] == 'merkle_root':
                    merkle_root = block['data']['merkle_root']
                    break

            if not merkle_root:
                print("\n❌ Urne non ancora chiuse e scrutinio non eseguito.")
                return

            # 2. Verifica firma della ricevuta
            receipt_data_to_verify = {
                "leaf_index": receipt['leaf_index'],
                "enc_vote": receipt['enc_vote'],
                "merkle_proof": receipt['merkle_proof']
            }
            receipt_json = json.dumps(receipt_data_to_verify, sort_keys=True).encode('utf-8')
            receipt_signature = bytes.fromhex(receipt['ae_signature'])

            if not verify(self.ae_sign_public, receipt_json, receipt_signature):
                print("\n❌ Verifica firma ricevuta fallita!")
                return

            # 3. Ottieni il record della scheda dal Bulletin Board per calcolare la foglia
            vote_record = None
            for block in self.bb:
                if block['type'] == 'vote' and block['data']['enc_vote'] == receipt['enc_vote']:
                    vote_record = block['data']
                    break

            if not vote_record:
                print("\n❌ Scheda non trovata nel Bulletin Board!")
                return

            # 4. Calcola hash della foglia e verifica Merkle Proof
            record_bytes = json.dumps(vote_record, sort_keys=True).encode('utf-8')
            leaf_hash = hashlib.sha256(record_bytes).digest()
            proof = receipt['merkle_proof']

            if verify_proof(leaf_hash, proof, merkle_root):
                print("\n✅ Verifica riuscita! Il tuo voto è stato incluso correttamente.")
            else:
                print("\n❌ Verifica Merkle Proof fallita!")

        else:
            print("\n❌ Devi prima autenticarti!")

    def menu(self):
        while True:
            print("\n=== SISTEMA DI VOTO ELETTRONICO ===")
            print("1. Registrati (solo email UNISA)")
            print("2. Autenticati presso il SA")
            print("3. Esprimi il tuo voto")
            print("4. Visualizza ricevuta")
            print("5. Verifica inclusione del tuo voto")
            print("0. Esci")

            choice = input("\nSeleziona un'opzione: ")

            if choice == '1':
                self.register()
            elif choice == '2':
                self.authenticate()
            elif choice == '3':
                self.vote()
            elif choice == '4':
                self.show_receipt()
            elif choice == '5':
                self.verify_vote()
            elif choice == '0':
                print("\nArrivederci!")
                break
            else:
                print("\nOpzione non valida!")


if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    client = Client()
    client.menu()

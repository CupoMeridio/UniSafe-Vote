
"""
Client dell'elettore - Interfaccia a riga di comando.

Questo programma permette agli elettori di:
1. Registrarsi con un'email UNISA valida
2. Autenticarsi presso il Sistema di Autenticazione (SA)
3. Esprimere un voto cifrato
4. Salvare e visualizzare la ricevuta di voto
5. Verificare che il proprio voto sia stato incluso nello scrutinio

Il voto è cifrato con la chiave pubblica dell'Autorità Elettorale (AE)
e viene inviato insieme a:
- Un token di autenticazione firmato dal SA
- Una Proof of Work per prevenire spam
- Un seed casuale per verificare l'integrità
"""

import os
import json
import hashlib
import requests
import sys
from typing import Optional, List, Dict, Any
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cryptography.hazmat.primitives import serialization
from crypto.keys import deserialize_public_key
from crypto.rsa_oaep import encrypt
from crypto.rsa_pss import verify
from crypto.merkle import verify_proof


import hashlib
SA_URL: str = "http://localhost:5001"  # URL del Sistema di Autenticazione
AE_URL: str = "http://localhost:5002"  # URL dell'Autorità Elettorale
BULLETIN_BOARD_PATH: str = "data/bulletin_board.json"


class SecurityError(Exception):
    """Raised when key substitution or other security violation occurs"""
    pass


def compute_public_key_fingerprint(pem_str: str) -> str:
    """Compute SHA-256 fingerprint of RSA public key in PEM format"""
    from crypto.keys import deserialize_public_key
    pubkey = deserialize_public_key(pem_str)
    pubkey_bytes = pubkey.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(pubkey_bytes).hexdigest()


class Client:
    """Classe che gestisce le operazioni dell'elettore."""

    def __init__(self):
        self.username: Optional[str] = None  # Username dell'elettore autenticato
        self.token: Optional[str] = None  # Token di autenticazione (se ottenuto)
        self.token_signature: Optional[str] = None  # Firma del token
        self.receipt: Optional[Dict] = None  # Ricevuta di voto (se ricevuta)
        self.bb: List[Dict] = []  # Bulletin Board caricato da file
        self.init_data: Dict = {}  # Dati di inizializzazione
        self.candidates: List[str] = []  # Lista candidati
        self.ae_encrypt_public: Optional[RSAPublicKey] = None  # Chiave pubblica di cifratura AE
        self.ae_sign_public: Optional[RSAPublicKey] = None  # Chiave pubblica di firma AE
        self.pin_ae_encrypt_fingerprint: Optional[str] = None
        self.pin_ae_sign_fingerprint: Optional[str] = None

    def _load_pins_from_bulletin_board(self):
        """Load trusted fingerprints of AE keys from the initial bulletin board.
        In a real system these would be hardcoded or distributed via a secure channel.
        """
        # In a real system these pins would be hardcoded or distributed via a secure channel
        # For this simulation we load them after initializing an election, but in real life they are pre-shared
        self.load_bulletin_board()
        self.pin_ae_encrypt_fingerprint = compute_public_key_fingerprint(self.init_data["ae_encrypt_public"])
        self.pin_ae_sign_fingerprint = compute_public_key_fingerprint(self.init_data["ae_sign_public"])

    def load_bulletin_board(self) -> None:
        """
        Carica il Bulletin Board da file locale per ottenere:
        - La lista dei candidati
        - La chiave pubblica di cifratura dell'AE
        - La chiave pubblica di firma dell'AE
        Also verifies key fingerprints via certificate pinning
        """
        with open(BULLETIN_BOARD_PATH, "r", encoding="utf-8") as f:
            self.bb = json.load(f)
        self.init_data = self.bb[0]["data"]  # Dati di inizializzazione
        self.candidates = self.init_data["candidates"]  # Lista candidati

        # Certificate Pinning: Verify fingerprints of AE public keys
        ae_encrypt_pem = self.init_data["ae_encrypt_public"]
        ae_sign_pem = self.init_data["ae_sign_public"]

        # Compute fingerprints of received keys
        received_encrypt_fingerprint = compute_public_key_fingerprint(ae_encrypt_pem)
        received_sign_fingerprint = compute_public_key_fingerprint(ae_sign_pem)

        # If pins are not yet set, set them (only once, during first initialization)
        if self.pin_ae_encrypt_fingerprint is None or self.pin_ae_sign_fingerprint is None:
            self.pin_ae_encrypt_fingerprint = received_encrypt_fingerprint
            self.pin_ae_sign_fingerprint = received_sign_fingerprint
        else:
            if received_encrypt_fingerprint != self.pin_ae_encrypt_fingerprint:
                raise SecurityError(
                    "Impronta della chiave pubblica di cifratura AE non corrispondente! Possibile attacco MitM!"
                )
            if received_sign_fingerprint != self.pin_ae_sign_fingerprint:
                raise SecurityError(
                    "Impronta della chiave pubblica di firma AE non corrispondente! Possibile attacco MitM!"
                )

        # Now load the keys normally
        self.ae_encrypt_public = deserialize_public_key(ae_encrypt_pem)
        self.ae_sign_public = deserialize_public_key(ae_sign_pem)

    def get_pow_difficulty(self) -> int:
        """
        Interroga l'AE per ottenere la difficoltà di Proof of Work corrente.

        La difficoltà è adattiva e globale: l'AE la aumenta automaticamente
        sotto carico anomalo (mitigazione DoS). Se l'AE non è raggiungibile o
        non espone il dato, si usa la difficoltà minima di default.

        Returns:
            int: Numero di bit a zero richiesti dalla PoW.
        """
        try:
            response = requests.get(f"{AE_URL}/status", timeout=5)
            if response.status_code == 200:
                return int(response.json().get("pow_difficulty", 4))
        except requests.exceptions.RequestException:
            pass
        return 4

    def solve_pow(self, enc_vote_hex: str, difficulty: int = 4) -> str:
        """
        Risolve la Proof of Work (PoW) per poter inviare un voto.

        La PoW serve a dimostrare che l'elettore ha investito risorse computazionali,
        prevenendo attacchi di spam automatico.

        L'obiettivo è trovare un nonce tale che SHA-256(enc_vote || nonce)
        inizi con 'difficulty' bit a zero.

        Args:
            enc_vote_hex (str): Voto cifrato in esadecimale
            difficulty (int, optional): Numero di bit a zero richiesti. Default 4.

        Returns:
            str: Nonce valido in formato esadecimale
        """
        enc_vote_bytes = bytes.fromhex(enc_vote_hex)
        nonce = 0
        print("  Risolvendo Proof of Work...", end="", flush=True)

        while True:
            # Converti il nonce in 8 byte big-endian
            nonce_bytes = nonce.to_bytes(8, byteorder='big')
            combined = enc_vote_bytes + nonce_bytes
            hash_result = hashlib.sha256(combined).digest()

            # Verifica se l'hash soddisfa la difficoltà richiesta
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
                print(" OK")
                return nonce_bytes.hex()

            # Incrementa il nonce per il prossimo tentativo
            nonce += 1
            # Mostra un puntino ogni 100,000 tentativi per indicare progresso
            if nonce % 100000 == 0:
                print(".", end="", flush=True)

    def register(self) -> None:
        """
        Gestisce la registrazione di un nuovo elettore.

        Richiede un'email UNISA valida, un username e una password.
        Invia i dati al SA che verifica il dominio e salva l'utente.
        """
        print("\n=== REGISTRAZIONE UTENTE ===")
        print("DISCLAIMER: questa procedura è simulativa. In un sistema reale,")
        print("la registrazione richiederebbe una verifica dell'identità, ad esempio")
        print("tramite codice inviato via email o altra procedura istituzionale.")
        print("\nPuoi registrarti solo con un'email UNISA (@studenti.unisa.it o @unisa.it)\n")

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

    def authenticate(self) -> None:
        """
        Gestisce l'autenticazione presso il SA.

        Richiede username e password e, se validi, ottiene un token firmato
        che verrà utilizzato per l'autenticazione presso l'AE.
        """
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

    def vote(self) -> None:
        """
        Gestisce l'espressione del voto.

        Passaggi:
        1. Verifica che l'utente sia autenticato
        2. Mostra la lista dei candidati
        3. Ottiene la scelta dell'utente
        4. Genera un seed casuale
        5. Cifra voto e seed
        6. Risolve la Proof of Work
        7. Invia il voto all'AE
        8. Salva la ricevuta ricevuta
        """
        if not self.token:
            print("\nDevi prima autenticarti!")
            return

        # Mostra la lista dei candidati
        print("\nLista candidati:")
        for i, candidate in enumerate(self.candidates):
            print(f"{i + 1}. {candidate}")

        # Ottieni la scelta dell'utente
        choice = input("\nSeleziona il numero della lista: ")
        try:
            choice_index = int(choice) - 1
            if choice_index < 0 or choice_index >= len(self.candidates):
                print("\nScelta non valida!")
                return
        except ValueError:
            print("\nInserisci un numero valido!")
            return

        # 1. Genera un seed casuale (32 byte = lunghezza del seed OAEP con SHA-256)
        #    Il seed è la randomness di padding usata internamente da RSA-OAEP.
        seed = os.urandom(32)
        # Il voto è il solo indice della lista selezionata (1 byte).
        vote_byte = choice_index.to_bytes(1, byteorder='big')

        # 2. Cifra il voto con RSA-OAEP usando ESPLICITAMENTE il seed come
        #    randomness di padding: la cifratura è così deterministica e
        #    riproducibile da chiunque conosca (voto, seed, pk_AE), abilitando
        #    la verifica universale a scrutinio concluso.
        enc_vote_bytes = encrypt(self.ae_encrypt_public, vote_byte, seed=seed)
        # Il seed viene cifrato separatamente con pk_AE (seed OAEP casuale
        # interno) così che solo l'AE possa recuperarlo a urne chiuse e
        # pubblicarlo per la verifica universale.
        enc_seed_bytes = encrypt(self.ae_encrypt_public, seed)
        enc_vote_hex = enc_vote_bytes.hex()
        enc_seed_hex = enc_seed_bytes.hex()

        # 3. Risolve la Proof of Work alla difficoltà adattiva corrente dell'AE
        difficulty = self.get_pow_difficulty()
        pow_nonce_hex = self.solve_pow(enc_vote_hex, difficulty)

        # 4. Invia il voto all'Autorità Elettorale
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

                # Salva la ricevuta su file
                receipt_path = f"data/receipts/{self.username}.json"
                # Crea la cartella se non esiste
                os.makedirs(os.path.dirname(receipt_path), exist_ok=True)
                with open(receipt_path, "w", encoding="utf-8") as f:
                    json.dump(receipt_data, f, indent=2, ensure_ascii=False)

                print(f"\nVoto espresso con successo! Ricevuta salvata in {receipt_path}")
            else:
                print(f"\nErrore: {response.json().get('error')}")

        except requests.exceptions.ConnectionError:
            print("\nImpossibile connettersi all'AE. Assicurati che sia in esecuzione.")

    def show_receipt(self) -> None:
        """
        Mostra la ricevuta di voto salvata per l'utente corrente.
        """
        if self.username:
            receipt_path = f"data/receipts/{self.username}.json"
            if os.path.exists(receipt_path):
                with open(receipt_path, "r", encoding="utf-8") as f:
                    receipt = json.load(f)
                print("\n=== RICEVUTA VOTO ===")
                print(json.dumps(receipt, indent=2, ensure_ascii=False))
            else:
                print("\nNessuna ricevuta trovata per questo utente.")
        else:
            print("\nDevi prima autenticarti!")

    def verify_vote(self) -> None:
        """
        Verifica che il voto dell'utente sia stato incluso nello scrutinio.

        Effettua tre controlli (WP2 Fase 5 - Verifica individuale):
        1. Verifica che la firma della ricevuta sia valida
        2. Verifica che il voto sia incluso nel Merkle Tree tramite la Proof
        3. Verifica che la scheda sia stata utilizzata nello scrutinio,
           individuando la propria enc_vote tra i voti verificati pubblicati
        """
        if self.username:
            receipt_path = f"data/receipts/{self.username}.json"
            if not os.path.exists(receipt_path):
                print("\nNessuna ricevuta trovata per questo utente.")
                return

            # Carica la ricevuta
            with open(receipt_path, "r", encoding="utf-8") as f:
                receipt = json.load(f)

            # Ricarica il Bulletin Board per ottenere la Merkle Root finale
            self.load_bulletin_board()

            # 1. Ottieni la Merkle Root finale dal Bulletin Board
            merkle_root = None
            for block in self.bb:
                if block['type'] == 'merkle_root':
                    merkle_root = block['data']['merkle_root']
                    break

            if not merkle_root:
                print("\nUrne non ancora chiuse e scrutinio non eseguito.")
                return

            # 2. Verifica la firma della ricevuta con la chiave pubblica dell'AE
            receipt_data_to_verify = {
                "leaf_index": receipt['leaf_index'],
                "enc_vote": receipt['enc_vote'],
                "merkle_proof": receipt['merkle_proof']
            }
            receipt_json = json.dumps(receipt_data_to_verify, sort_keys=True).encode('utf-8')
            receipt_signature = bytes.fromhex(receipt['ae_signature'])

            if not verify(self.ae_sign_public, receipt_json, receipt_signature):
                print("\nVerifica firma ricevuta fallita!")
                return

            # 3. Ottieni il record del voto dal Bulletin Board per calcolare la foglia
            vote_record = None
            for block in self.bb:
                if block['type'] == 'vote' and block['data']['enc_vote'] == receipt['enc_vote']:
                    vote_record = block['data']
                    break

            if not vote_record:
                print("\nScheda non trovata nel Bulletin Board!")
                return

            # 4. Calcola l'hash della foglia e verifica la Merkle Proof
            record_bytes = json.dumps(vote_record, sort_keys=True).encode('utf-8')
            leaf_hash = hashlib.sha256(record_bytes).digest()
            proof = receipt['merkle_proof']

            if not verify_proof(leaf_hash, proof, merkle_root):
                print("\nVerifica Merkle Proof fallita!")
                return

            # 5. Verifica che la scheda sia stata utilizzata nello scrutinio:
            #    la propria enc_vote deve comparire tra i voti verificati
            #    pubblicati nel blocco scrutinio (WP2 Fase 5).
            scrutinio_data = None
            for block in self.bb:
                if block['type'] == 'scrutinio':
                    scrutinio_data = block['data']
                    break

            if not scrutinio_data:
                print("\nVoto incluso nel Merkle Tree, ma scrutinio non ancora pubblicato.")
                return

            scrutinated = scrutinio_data.get("voti_verificati", [])
            matching = next(
                (v for v in scrutinated if v.get("enc_vote") == receipt['enc_vote']),
                None
            )

            if matching:
                print("\nVerifica riuscita! Il tuo voto è stato incluso e conteggiato nello scrutinio.")
                print(f"   Voto in chiaro pubblicato per la tua scheda: {matching.get('voto_chiaro')}")
            else:
                print("\nLa tua scheda è nel Merkle Tree ma non risulta tra i voti scrutinati!")

        else:
            print("\nDevi prima autenticarti!")

    def menu(self) -> None:
        """
        Mostra il menu principale dell'applicazione e gestisce l'interazione con l'utente.
        """
        while True:
            print("\n=== SISTEMA DI VOTO ELETTRONICO ===")
            if self.username:
                print(f"Utente autenticato: {self.username}")
            else:
                print("Utente autenticato: nessuno")
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


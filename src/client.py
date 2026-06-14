
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
from datetime import datetime, UTC
from typing import Optional, List, Dict
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cryptography.hazmat.primitives import serialization
from crypto.keys import deserialize_public_key
from crypto.rsa_oaep import encrypt
from crypto.rsa_pss import verify
from crypto.merkle import verify_proof
SA_URL: str = "http://localhost:5001"  # URL del Sistema di Autenticazione
AE_URL: str = "http://localhost:5002"  # URL dell'Autorità Elettorale
BULLETIN_BOARD_PATH: str = "data/bulletin_board.json"
PINS_PATH: str = "data/pins.json"


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
        self.trusted_pins: Dict[str, str] = {}

        self.load_bulletin_board()

    def load_pins(self) -> Dict[str, str]:
        """
        Carica le impronte trusted delle chiavi pubbliche AE.

        Questo file rappresenta un canale separato rispetto al Bulletin Board.
        In un sistema reale, questi pin sarebbero distribuiti agli elettori
        tramite un canale istituzionale sicuro (es. portale web con TLS,
        comunicazione ufficiale o documento firmato).
        """
        if not os.path.exists(PINS_PATH):
            raise SecurityError(
                "File data/pins.json non trovato. Inizializza prima l'elezione e assicurati "
                "che il file dei pin trusted sia presente sul client."
            )

        with open(PINS_PATH, "r", encoding="utf-8") as f:
            pins = json.load(f)

        if not isinstance(pins, dict):
            raise SecurityError("data/pins.json non valido: il file deve contenere un oggetto JSON.")

        required = ["ae_encrypt_public", "ae_sign_public"]
        missing = [key for key in required if key not in pins]
        if missing:
            raise SecurityError(f"data/pins.json incompleto: mancano i pin {', '.join(missing)}.")

        return {
            "ae_encrypt_public": pins["ae_encrypt_public"],
            "ae_sign_public": pins["ae_sign_public"]
        }

    def _pin_matches(self, received: str, trusted: str) -> bool:
        """Verifica un fingerprint ricevuto contro un pin trusted."""
        trusted_value = trusted[7:] if trusted.startswith("sha256:") else trusted
        return received == trusted_value

    def load_bulletin_board(self) -> None:
        """
        Carica il Bulletin Board da file locale e verifica le chiavi AE tramite pinning.

        Le chiavi pubbliche vengono usate solo se le loro impronte coincidono con
        quelle presenti in data/pins.json, file separato dal Bulletin Board.
        """
        self.trusted_pins = self.load_pins()

        with open(BULLETIN_BOARD_PATH, "r", encoding="utf-8") as f:
            self.bb = json.load(f)
        self.init_data = self.bb[0]["data"]  # Dati di inizializzazione
        self.candidates = self.init_data["candidates"]  # Lista candidati

        # Certificate Pinning: verifica le impronte delle chiavi AE contro il
        # canale trusted separato (data/pins.json), non contro il BB stesso.
        ae_encrypt_pem = self.init_data["ae_encrypt_public"]
        ae_sign_pem = self.init_data["ae_sign_public"]

        received_encrypt_fingerprint = compute_public_key_fingerprint(ae_encrypt_pem)
        received_sign_fingerprint = compute_public_key_fingerprint(ae_sign_pem)

        if not self._pin_matches(received_encrypt_fingerprint, self.trusted_pins["ae_encrypt_public"]):
            raise SecurityError(
                "Impronta della chiave pubblica di cifratura AE non corrispondente! "
                "Possibile attacco MitM o sostituzione del Bulletin Board."
            )
        if not self._pin_matches(received_sign_fingerprint, self.trusted_pins["ae_sign_public"]):
            raise SecurityError(
                "Impronta della chiave pubblica di firma AE non corrispondente! "
                "Possibile attacco MitM o sostituzione del Bulletin Board."
            )

        # Ora le chiavi sono state validate contro il canale trusted separato.
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

    def has_voted(self) -> bool:
        """Check if user has already voted (has a saved receipt)."""
        if not self.username:
            return False
        receipt_path = f"data/receipts/{self.username}.json"
        return os.path.exists(receipt_path)

    def is_urn_open(self) -> bool:
        """Check if urns are open by contacting AE or reading BB."""
        # First try AE status endpoint for real-time info
        try:
            r = requests.get(f"{AE_URL}/status", timeout=2)
            if r.status_code == 200:
                return r.json().get("urn_open", True)
        except requests.exceptions.RequestException:
            pass
        # Fallback to BB (check if there's a 'merkle_root' block, which means urn closed)
        for block in self.bb:
            if block['type'] == 'merkle_root':
                return False
        return True

    def is_token_expired(self) -> bool:
        """Check if stored token (if any) is expired."""
        if not self.token:
            return False
        try:
            token_obj = json.loads(self.token)
            expires_at = datetime.fromisoformat(token_obj['expires_at'])
            now = datetime.now(UTC)
            return now > expires_at
        except (json.JSONDecodeError, KeyError, ValueError):
            return True

    def can_vote(self) -> bool:
        """Check if user can perform voting (WRITE operation):
        - Authenticated
        - Urn is open
        - Has NOT already voted
        - Token NOT expired
        """
        if not self.username:
            return False
        if not self.is_urn_open():
            return False
        if self.has_voted():
            return False
        if self.is_token_expired():
            return False
        return True

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
        if not self.can_vote():
            # Show specific reason why can't vote
            if not self.username:
                print("\nDevi prima autenticarti!")
            elif self.has_voted():
                print("\nHai già espresso il tuo voto! Non puoi votare di nuovo.")
            elif not self.is_urn_open():
                print("\nUrne chiuse! Non puoi più votare.")
            elif self.is_token_expired():
                print("\nIl tuo token è scaduto! Non puoi più votare.")
            return

        # Ricarica i parametri pubblici dal Bulletin Board prima del voto, così
        # da usare la configurazione corrente dell'elezione.
        self.load_bulletin_board()

        if not self.candidates:
            print("\nNessuna lista di voto configurata nel Bulletin Board. Impossibile votare.")
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
        Verifica che il voto dell'utente sia stato incluso e non modificato nello scrutinio.

        Effettua cinque controlli completi (WP2/3 Fase 5 - Verifica individuale):
        1. Verifica che la firma della ricevuta sia valida
        2. Verifica che il voto sia incluso nel Merkle Tree tramite la Proof
        3. Individua il voto nel blocco 'scrutinio'
        4. CRITTOGRAFICO: Riesegue RSA-OAEP (con seed pubblicato) per confrontare con enc_vote originale
        5. Mostra il risultato finale
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
                "merkle_proof": receipt['merkle_proof'],
                "timestamp": receipt['timestamp']
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

            # 5. Ottieni blocco 'scrutinio'
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

            if not matching:
                print("\nLa tua scheda è nel Merkle Tree ma non risulta tra i voti scrutinati!")
                return

            # 6. CRITTOGRAFICO: Riesegui RSA-OAEP usando seed pubblicato e voto in chiaro
            print("\n--- VERIFICA CRITTOGRAFICA (WP2 Fase 5) ---")
            print(f"Voto in chiaro pubblicato: {matching.get('voto_chiaro')}")
            print(f"Seed pubblicato: {matching.get('seed')[:30]}...")

            # Converti voto chiaro e seed in bytes
            voto_chiaro_str = matching.get('voto_chiaro')
            if voto_chiaro_str == "Scheda nulla":
                print("\nNota: Questa è una scheda nulla, non verifichiamo la corrispondenza crittografica (non abbiamo un indice di candidato valido).")
                # Ma gli altri controlli sono già passati (Firma ricevuta, Merkle Proof, incluso nel scrutinio)
            else:
                voto_chiaro_index = int(candidates.index(voto_chiaro_str))  # indice (es: 0,1,2)
                voto_chiaro_bytes = voto_chiaro_index.to_bytes(1, byteorder='big')
                seed_pubblicato_bytes = bytes.fromhex(matching.get('seed'))

            # Only perform cryptographic verification for valid votes, not null ballots
            if voto_chiaro_str != "Scheda nulla":
                # Riesegui encrypt() esattamente come è stato fatto originariamente,
                # usando AES public key e seed_pubblicato come randomness
                enc_vote_verify_bytes = encrypt(self.ae_encrypt_public, voto_chiaro_bytes, seed=seed_pubblicato_bytes)
                enc_vote_verify_hex = enc_vote_verify_bytes.hex()

                print(f"\nEnc_vote ricevuta (client): {receipt['enc_vote'][:50]}...")
                print(f"Enc_vote ricostruito:    {enc_vote_verify_hex[:50]}...")

                if enc_vote_verify_hex != receipt['enc_vote']:
                    print("\nERRORE CRITTOGRAFICO: I ciphertext NON corrispondono!")
                    print("L'AE potrebbe aver modificato il tuo voto durante lo scrutinio!")
                    return

            # Tutti i controlli passati!
            print("\n✅ Tutte le verifiche sono riuscite!")
            print("   1. Firma ricevuta valida")
            print("   2. Merkle Proof valida (voto incluso nel tree)")
            print("   3. Voto presente nel blocco 'scrutinio'")
            if voto_chiaro_str != "Scheda nulla":
                print("   4. CRITTOGRAFICO: Ciphertext ricostruito corrisponde a quello originale")
            print("\nVoto correttamente conteggiato e non manipolato!")
            print(f"   Voto in chiaro pubblicato: {matching.get('voto_chiaro')}")

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
                # Show status information
                if self.can_vote():
                    print("Stato: Modalità completa - Puoi esprimere il voto!")
                else:
                    print("Stato: Modalità sola lettura - Non puoi votare, ma puoi verificare il tuo voto.")
                if self.has_voted():
                    print("   - Hai già espresso il voto.")
                if self.is_token_expired():
                    print("   - Token scaduto.")
                if not self.is_urn_open():
                    print("   - Urne chiuse.")
            else:
                print("Utente autenticato: nessuno")

            print("\nMenu:")
            print("1. Registrati (solo email UNISA)")
            print("2. Autenticati presso il SA")
            if self.can_vote():
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
                if self.can_vote():
                    self.vote()
                else:
                    print("\nOperazione non permessa in modalità sola lettura!")
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
    os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    try:
        client = Client()
        client.menu()
    except SecurityError as e:
        print(f"\nErrore di sicurezza: {e}")
        print("Il client non può continuare senza pin trusted validi.")
        input("\nPremi Invio per uscire...")


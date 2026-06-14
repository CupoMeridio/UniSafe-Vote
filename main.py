
"""
UNISAFE-VOTE - Sistema di Voto Elettronico Sicuro

Questo file è il punto di ingresso principale del sistema e fornisce un menu interattivo per gestire l'intero ciclo di vita di un'elezione.

Componenti principali del sistema:
- Sistema di Autenticazione (SA): Gestisce la registrazione e l'autenticazione degli elettori
- Autorità Elettorale (AE): Riceve i voti, gestisce il Bulletin Board e calcola i risultati
- Client Votante: Interfaccia per gli elettori per esprimere il proprio voto
- Observer: Strumento per la verifica universale dell'integrità dell'elezione

Il menu principale coordina l'avvio di questi componenti e permette all'amministratore di:
- Inizializzare un'elezione
- Avviare e monitorare i server SA e AE
- Aprire il client votante
- Chiudere le urne e avviare lo scrutinio
- Eseguire la verifica universale
"""

import os
import json
import subprocess
import sys
import time
from typing import Optional
import requests
import platform

SA_PROCESS: Optional[subprocess.Popen] = None  # Riferimento al processo del server SA (Sistema di Autenticazione)
AE_PROCESS: Optional[subprocess.Popen] = None  # Riferimento al processo del server AE (Autorità Elettorale)
SA_URL = "http://localhost:5001"  # URL di base per connettersi al server SA
AE_URL = "http://localhost:5002"  # URL di base per connettersi al server AE
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))  # Percorso assoluto della cartella del progetto

ANSI_RESET = "\033[0m"
ANSI_BRIGHT = "\033[1m"
ANSI_DIM = "\033[90m"


def colored(text: str, color_code: str) -> str:
    """Restituisce il testo colorato solo se il terminale supporta ANSI."""
    return f"{color_code}{text}{ANSI_RESET}"

def launch_in_new_terminal(script_name: str) -> Optional[subprocess.Popen]:
    """
    Avvia uno script Python in una nuova finestra di terminale.
    Supporta Windows, macOS e Linux.
    """
    python_exe = sys.executable
    script_path = os.path.join(PROJECT_DIR, script_name)
    current_os = platform.system()

    if current_os == "Windows":
        # Su Windows, usiamo CREATE_NEW_CONSOLE per aprire un vero prompt separato
        # e conservare il riferimento al processo Popen.
        return subprocess.Popen(
            [python_exe, script_path],
            creationflags=subprocess.CREATE_NEW_CONSOLE,
            cwd=PROJECT_DIR
        )
    elif current_os == "Darwin":  # macOS
        # Su macOS usiamo AppleScript per dire a Terminal di eseguire lo script.
        # osascript terminerà subito, ma la finestra del Terminale rimarrà aperta.
        cmd = f'tell application "Terminal" to do script "{python_exe} \\"{script_path}\\""'
        subprocess.Popen(["osascript", "-e", cmd])
        return None
    else:  # Linux / Unix
        # Cerchiamo un emulatore di terminale comune installato
        terminals = ["x-terminal-emulator", "gnome-terminal", "konsole", "xfce4-terminal", "xterm"]
        for term in terminals:
            try:
                if term == "gnome-terminal":
                    subprocess.Popen([term, "--", python_exe, script_path], cwd=PROJECT_DIR)
                else:
                    subprocess.Popen([term, "-e", f"{python_exe} {script_path}"], cwd=PROJECT_DIR)
                return None
            except FileNotFoundError:
                continue
        print(f"Errore: Nessun emulatore di terminale trovato. Esegui 'python {script_name}' manualmente.")
        return None

# Utilità utilizzata per stampare un titolo con un banner
def print_header(title: str) -> None:
    print("\n" + "="*70)
    print(f"  {title}".center(70))
    print("="*70)

# Utilità utilizzata per stampare un testo esplicativo
def print_explanation(text: str) -> None:
    print(f"\n{text}")
    print("-" * 70)


def clear_screen() -> None:
    """
    Pulisce lo schermo del terminale in modo cross-platform.
    Evita l'accumulo di output quando il menu viene ridisegnato.
    """
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')


def check_server_running(url: str) -> bool:
    """
    Verifica se un server è in esecuzione controllando l'endpoint `/status`.
    
    Args:
        url (str): URL del server da verificare
        
    Returns:
        bool: True se il server risponde con status 200, False altrimenti
    """
    try:
        response = requests.get(url + '/status', timeout=0.5)
        return response.status_code == 200
    except:
        return False


def wait_for_server(url: str, server_name: str, timeout: int = 15) -> bool:
    """
    Attende che un server si avvii, mostrando un indicatore di caricamento.
    
    Args:
        url (str): URL del server da monitorare
        server_name (str): Nome identificativo del server (per il messaggio)
        timeout (int, optional): Numero massimo di tentativi prima del timeout. Defaults to 15.
        
    Returns:
        bool: True se il server risponde prima dello scadere del timeout, False altrimenti
    """
    print(f"Attendo che {server_name} si avvii...", end="", flush=True)
    for i in range(timeout):
        if check_server_running(url):
            print(" [PRONTO]")
            return True
        print(".", end="", flush=True)
        time.sleep(1)
    print(" [TIMEOUT]")
    return False


def is_election_initialized() -> bool:
    """
    Verifica se l'elezione è stata inizializzata controllando i file di configurazione.
    """
    bulletin_board_path = os.path.join(PROJECT_DIR, "data", "bulletin_board.json")
    voters_path = os.path.join(PROJECT_DIR, "data", "voters.json")
    return os.path.exists(bulletin_board_path) and os.path.exists(voters_path)


def has_election_configuration() -> bool:
    """
    Verifica se esiste almeno una configurazione da poter resettare.
    """
    bulletin_board_path = os.path.join(PROJECT_DIR, "data", "bulletin_board.json")
    voters_path = os.path.join(PROJECT_DIR, "data", "voters.json")
    keys_dir = os.path.join(PROJECT_DIR, "data", "keys")
    receipts_dir = os.path.join(PROJECT_DIR, "data", "receipts")
    ae_state_path = os.path.join(PROJECT_DIR, "data", "ae_state.json")
    pins_path = os.path.join(PROJECT_DIR, "data", "pins.json")

    return (
        os.path.exists(bulletin_board_path)
        or os.path.exists(voters_path)
        or os.path.isdir(keys_dir)
        or os.path.isdir(receipts_dir)
        or os.path.exists(ae_state_path)
        or os.path.exists(pins_path)
    )


def has_scrutinio() -> bool:
    """
    Verifica se nel Bulletin Board è presente il blocco finale di scrutinio.
    """
    bulletin_board_path = os.path.join(PROJECT_DIR, "data", "bulletin_board.json")
    if not os.path.exists(bulletin_board_path):
        return False

    try:
        with open(bulletin_board_path, "r", encoding="utf-8") as f:
            bb = json.load(f)
        return any(block.get("type") == "scrutinio" for block in bb)
    except Exception:
        return False


def has_merkle_root() -> bool:
    """
    Verifica se nel Bulletin Board è presente la Merkle Root finale.
    """
    bulletin_board_path = os.path.join(PROJECT_DIR, "data", "bulletin_board.json")
    if not os.path.exists(bulletin_board_path):
        return False

    try:
        with open(bulletin_board_path, "r", encoding="utf-8") as f:
            bb = json.load(f)
        return any(block.get("type") == "merkle_root" for block in bb)
    except Exception:
        return False


def get_urn_state(election_initialized: bool, ae_active: bool, ae_status: dict, scrutinio_presente: bool, merkle_root_presente: bool) -> str:
    """
    Restituisce lo stato leggibile delle urne.
    """
    if not election_initialized or not ae_active:
        return "non disponibili"

    if scrutinio_presente:
        return "chiuse"

    if merkle_root_presente:
        return "chiuse"

    urn_open = bool(ae_status.get("urn_open", False))
    return "aperte" if urn_open else "chiuse"


def get_ae_status() -> dict:
    """
    Recupera lo stato corrente dell'AE, se il server è raggiungibile.
    """
    try:
        response = requests.get(AE_URL + "/status", timeout=0.5)
        if response.status_code == 200:
            return response.json()
    except Exception:
        pass
    return {}


def menu_option(number: str, label: str, available: bool, suffix: str = "") -> str:
    """
    Stampa una voce di menu evidenziando quelle non disponibili.
    """
    text = f"  {number}. {label}"
    if suffix:
        text += f" [{suffix}]"
    if not available:
        return colored(f"{text} (non disponibile)", ANSI_DIM)
    return colored(text, ANSI_BRIGHT)


def section_title(text: str) -> str:
    """
    Evidenzia una sezione del menu principale.
    """
    return colored(text, ANSI_BRIGHT)


def start_sa() -> None:
    """
    Avvia il Sistema di Autenticazione (SA) su un nuovo terminale.
    
    Questa funzione esegue sa.py per avviare il server Flask di SA sulla porta 5001.
    """
    global SA_PROCESS
    if not is_election_initialized():
        print("Elezione non inizializzata. Avviare prima l'opzione 1 per inizializzare l'elezione.")
        return

    if check_server_running(SA_URL):
        print("SA già in esecuzione!")
        return
    
    print_header("AVVIO SISTEMA DI AUTENTICAZIONE (SA)")
    print_explanation("""
Il Sistema di Autenticazione (SA) ha il compito di:
1. Verificare le credenziali degli elettori
2. Generare e firmare token di autenticazione
3. Impedire voti multipli dallo stesso elettore

Il server verrà avviato in un nuovo terminale.
    """)
    
    # Avvio del server SA in una nuova finestra
    SA_PROCESS = launch_in_new_terminal("src/sa.py")
    
    if wait_for_server(SA_URL, "SA"):
        print("SA avviato con successo!")


def start_ae() -> None:
    """
    Avvia l'Autorità Elettorale (AE) su un nuovo terminale.
    
    Questa funzione esegue ae.py per avviare il server Flask di AE sulla porta 5002.
    """
    global AE_PROCESS
    if not is_election_initialized():
        print("Elezione non inizializzata. Avviare prima l'opzione 1 per inizializzare l'elezione.")
        return

    if check_server_running(AE_URL):
        print("AE già in esecuzione!")
        return
    
    print_header("AVVIO AUTORITÀ ELETTORALE (AE)")
    print_explanation("""
L'Autorità Elettorale (AE) ha il compito di:
1. Ricevere i voti cifrati dagli elettori
2. Verificare la Proof of Work (anti-spam)
3. Memorizzare i voti nel Bulletin Board
4. Calcolare il Merkle Tree
5. Eseguire lo scrutinio quando le urne sono chiuse

Il server verrà avviato in un nuovo terminale.
    """)
    
    # Avvio del server AE in una nuova finestra
    AE_PROCESS = launch_in_new_terminal("src/ae.py")
    
    if wait_for_server(AE_URL, "AE"):
        print("AE avviato con successo!")


def init_election() -> None:
    """
    Inizializza una nuova elezione.
    
    Questa funzione è un wrapper che esegue `init_election.py`, che:
    - Crea tutte le coppie di chiavi RSA necessarie
    - Genera il Bulletin Board con i parametri dell'elezione
    - Carica i dati iniziali
    - Chiede all'amministratore se preferisce una lista preconfigurata di elettori o di crearne uno personalizzato
    
    Esegue lo script `init_election.py` che completa l'inizializzazione archiviando i dati in `data/`.
    """
    print_header("INIZIALIZZAZIONE ELEZIONE")
    print_explanation("""
Questa operazione:
1. Genera 3 coppie di chiavi RSA-2048:
   - Coppia per firma del SA
   - Coppia per cifratura/decifratura dell'AE
   - Coppia per firma dell'AE
2. Crea il Bulletin Board (registro pubblico append-only)
3. Definisce i candidati e i parametri dell'elezione
4. Genera le impronte trusted AE in data/pins.json
5. Permette di SCEGLIERE tra:
   - Sistema preconfigurato (liste stock + utenti già registrati)
   - Solo liste di voto (registrazione utenti abilitata)
    """)
    input("Premi Invio per continuare...")
    subprocess.run([sys.executable, "src/init_election.py"], cwd=PROJECT_DIR)


def reset_election() -> None:
    """
    Rimuove la configurazione attuale dell'elezione.

    Questa funzione elimina i file di configurazione dell'elezione e le chiavi
    per permettere di inizializzare una nuova elezione con chiavi diverse.
    """
    bulletin_board_path = os.path.join(PROJECT_DIR, "data", "bulletin_board.json")
    voters_path = os.path.join(PROJECT_DIR, "data", "voters.json")
    keys_dir = os.path.join(PROJECT_DIR, "data", "keys")
    receipts_dir = os.path.join(PROJECT_DIR, "data", "receipts")
    ae_state_path = os.path.join(PROJECT_DIR, "data", "ae_state.json")
    pins_path = os.path.join(PROJECT_DIR, "data", "pins.json")

    if not has_election_configuration():
        print("Nessuna configurazione di elezione trovata da rimuovere.")
        return

    print_header("RESET CONFIGURAZIONE ELEZIONE")
    print_explanation("""
Questa operazione elimina i file di configurazione dell'elezione, le chiavi RSA,
lo stato privato dell'Autorità Elettorale, i pin trusted AE e le ricevute JSON
dei voti delle elezioni passate.
Dopo il reset sarà possibile creare una nuova elezione con chiavi completamente nuove.
    """)
    confirm = input("Confermi la rimozione della configurazione dell'elezione? (s/n): ").strip().lower()
    if confirm != 's':
        print("Reset annullato.")
        return

    if os.path.exists(bulletin_board_path):
        os.remove(bulletin_board_path)
    if os.path.exists(voters_path):
        os.remove(voters_path)
    if os.path.exists(ae_state_path):
        os.remove(ae_state_path)
    if os.path.exists(pins_path):
        os.remove(pins_path)
    if os.path.isdir(keys_dir):
        for filename in os.listdir(keys_dir):
            file_path = os.path.join(keys_dir, filename)
            if os.path.isfile(file_path):
                os.remove(file_path)

    if os.path.isdir(receipts_dir):
        for filename in os.listdir(receipts_dir):
            file_path = os.path.join(receipts_dir, filename)
            if os.path.isfile(file_path) and filename.lower().endswith(".json"):
                os.remove(file_path)

    print("Configurazione elezione rimossa. È ora possibile inizializzare una nuova elezione.")


def open_client() -> None:
    """
    Apri il client votante in un nuovo terminale.
    """
    print_header("CLIENT VOTANTE")
    print_explanation("""
Il client votante permette di:
1. Autenticarsi con username e password
2. Selezionare un candidato
3. Cifrare il voto
4. Calcolare una Proof of Work
5. Inviare il voto all'AE
6. Ricevere una ricevuta digitale

Verrà aperto un nuovo terminale per il client.
    """)
    input("Premi Invio per aprire il client...")
    launch_in_new_terminal("src/client.py")


def close_election() -> None:
    """
    Chiude le urne e avvia lo scrutinio.
    
    Questa funzione invia una richiesta POST all'AE (in esecuzione in ae.py) per chiudere le urne e avviare lo scrutinio.
    
    L'AE (in ae.py) esegue il seguente processo:
    1. Pubblica il Merkle Root finale sul Bulletin Board
    2. Carica la chiave privata di decifratura
    3. Decifra tutti i voti
    4. Verifica i seed per garantire l'integrità
    5. Calcola il risultato aggregato
    6. Pubblica tutto sul Bulletin Board
    
    Returns:
        None
    """
    if not is_election_initialized():
        print_header("CHIUSURA URNE E SCRUTINIO")
        print_explanation("""
Nessuna elezione è stata inizializzata.

La chiusura delle urne e lo scrutinio richiedono un Bulletin Board pubblico
con parametri di elezione, chiavi pubblicate e un'Autorità Elettorale avviata.

Per procedere, inizializza prima una elezione dalla sezione PREPARAZIONE.
        """)
        return

    if not check_server_running(AE_URL):
        print("AE non in esecuzione!")
        return
    
    print_header("CHIUSURA URNE E SCRUTINIO")
    print_explanation("""
Quando le urne vengono chiuse:
1. L'AE pubblica il Merkle Root finale
2. Carica la chiave privata di decifratura
3. Decifra tutti i voti
4. Verifica i seed per garantire l'integrità
5. Calcola il risultato aggregato
6. Pubblica tutto sul Bulletin Board
    """)
    input("Premi Invio per chiudere le urne...")
    
    try:
        # Chiamata al SA per pubblicare i token emessi (Riconciliazione)
        if check_server_running(SA_URL):
            requests.post(SA_URL + '/reconcile', timeout=10)

        # Invio di una richiesta POST all'endpoint /close dell'AE per chiudere le urne
        response = requests.post(AE_URL + '/close', timeout=10)
 
        # Se il server risponde con codice 200, la chiusura e lo scrutinio sono andati a buon fine
        if response.status_code == 200:
            # Estrazione del contenuto JSON della risposta
            result = response.json()
            print("\nScrutinio completato!")
            print("\nRISULTATO ELEZIONE:")
 
            # Stampa del risultato per ogni candidato presente nel JSON di risposta
            for candidate, votes in result['result'].items():
                print(f"   {candidate}: {votes} voti")
        else:
            # In caso di errore, stampa del messaggio di errore restituito dal server
            print(f"Errore: {response.json().get('error')}")
    except Exception as e:
        # Gestione degli errori della richiesta
        print(f"Impossibile chiudere le urne: {str(e)}")
 
 
def run_observer() -> None:
    """
    Esegue la verifica universale dell'elezione.
    """
    if not is_election_initialized():
        print_header("VERIFICA UNIVERSALE (OBSERVER)")
        print_explanation("""
Nessuna elezione è stata inizializzata.

La verifica universale richiede un Bulletin Board pubblico con:
1. parametri di elezione e chiavi pubblicate;
2. eventuali schede cifrate;
3. Merkle Root finale;
4. blocco scrutinio.

Per eseguire l'Observer, inizializza prima una elezione dalla sezione PREPARAZIONE.
        """)
        return

    scrutinio_presente = has_scrutinio()

    if not scrutinio_presente:
        print_header("VERIFICA UNIVERSALE (OBSERVER)")
        print_explanation("""
La verifica universale finale non è ancora disponibile.

Sono presenti schede cifrate, ma manca ancora il blocco scrutinio.
Per eseguire la verifica completa bisogna prima chiudere le urne e avviare lo
scrutinio dalla sezione RISULTATI (opzione 5).
        """)
        return

    print_header("VERIFICA UNIVERSALE (OBSERVER)")
    print_explanation("""
L'Observer permette di verificare:
1. L'integrità del Bulletin Board
2. La correttezza dello scrutinio
3. Che tutti i voti siano stati conteggiati
 
Verrà aperto un nuovo terminale per eseguire la verifica.
    """)
    input("Premi Invio per eseguire la verifica...")
    launch_in_new_terminal("src/observer.py")


def run_security_tests() -> None:
    """
    Sottomenu per l'esecuzione dei test di sicurezza.

    Ogni test è autocontenuto: inizializza la propria elezione di test,
    avvia i server necessari, esegue le verifiche e fa teardown alla fine.
    Il test viene eseguito in un nuovo terminale visibile all'utente, così
    è possibile seguire le fasi intermedie e i risultati in tempo reale.
    """

    # Descrizioni dei test mostrate all'utente prima dell'esecuzione.
    # La chiave è il numero mostrato nel menu; i test offline vengono prima,
    # seguiti dai test che richiedono server, con numerazione continua.
    TESTS = {
        "1": {
            "name": "Attacco Dizionario / Analisi di Frequenza",
            "file": "tests/security/dictionary_attack_test.py",
            "description": """
Verifica che RSA-OAEP sia sicuro contro attacchi di tipo dizionario.

Un attaccante conosce tutti i possibili valori di voto (sono pubblici
sul Bulletin Board) e tenta di cifrare ciascuno con seed diversi per
trovare una corrispondenza con un ciphertext intercettato.

Il test dimostra che RSA-OAEP è uno schema PROBABILISTICO (IND-CPA):
ogni cifratura usa un seed casuale diverso, quindi lo stesso voto
produce ciphertext completamente differenti ad ogni esecuzione.
L'attacco dizionario è computazionalmente impossibile.

Non richiede server avviati — è un test crittografico offline.
            """,
        },
        "2": {
            "name": "Attacco MitM / Sostituzione Chiave Pubblica",
            "file": "tests/security/mitm_key_substitution_attack.py",
            "description": """
Simula un attacco Man-in-the-Middle in cui l'attaccante sostituisce le
chiavi pubbliche dell'AE nel Bulletin Board con chiavi contraffatte.

Con le chiavi false, l'attaccante potrebbe decifrare i voti degli
elettori. Il test verifica che il certificate pinning del client rilevi
la sostituzione: le impronte delle chiavi ricevute non corrispondono
ai pin trusted in data/pins.json, quindi il client solleva un errore
di sicurezza e blocca l'operazione prima di usare le chiavi false.

Non richiede server avviati — è un test offline sul client.
            """,
        },
        "3": {
            "name": "Manomissione del Bulletin Board (Ledger Tampering)",
            "file": "tests/security/ledger_tampering_test.py",
            "description": """
Dimostra che la struttura Merkle Tree del Bulletin Board rende
impossibile nascondere la manomissione retroattiva di un voto.

Un "amministratore corrotto" modifica un voto già registrato nel
Merkle Tree. Il test verifica che:
- La Merkle Root cambia dopo la modifica (rilevabile da chiunque).
- La ricevuta originale dell'elettore non è più valida con la nuova root.
- L'osservatore universale rileva immediatamente la discrepanza.

Non richiede server avviati — è un test offline sul Merkle Tree.
            """,
        },
        "4": {
            "name": "Attacco DoS / Flood con PoW invalida",
            "file": "tests/security/dos_attack_test.py",
            "description": """
Simula una botnet che invia 500 richieste concorrenti con Proof of Work
deliberatamente sbagliata all'Autorità Elettorale (AE).

Il test verifica che l'AE blocchi le richieste PRIMA di eseguire
operazioni crittografiche costose, rispondendo con HTTP 400 (Bad Request)
quasi istantaneamente. Almeno il 90% delle richieste deve essere rifiutato.

Il test avvia e termina l'AE automaticamente.
            """,
        },
        "5": {
            "name": "PoW Adattiva — Aumento e Recovery della Difficoltà",
            "file": "tests/security/pow_adaptive_test.py",
            "description": """
Verifica il meccanismo di PoW adattiva dell'AE in quattro fasi:

  Fase 1 — Baseline: la difficoltà a sistema a riposo deve essere
           al valore minimo (4 bit).
  Fase 2 — Flood: si inviano 60 richieste con PoW invalida per saturare
           la finestra di osservazione dell'AE.
  Fase 3 — Sotto carico: la difficoltà deve essere aumentata rispetto
           al baseline, proporzionalmente al numero di richieste in eccesso.
  Fase 4 — Recovery: dopo la scadenza della finestra (10 secondi), la
           difficoltà deve tornare al valore minimo.

Il test avvia e termina l'AE automaticamente.
            """,
        },
        "6": {
            "name": "Resilienza DoS durante la votazione",
            "file": "tests/security/dos_resilience_test.py",
            "description": """
Test in tre fasi che verifica il comportamento del sistema sotto attacco:

  Fase 1: 5 utenti onesti si autenticano presso il SA (pre-attacco).
  Fase 2: Un flood di richieste invalide viene avviato in parallelo
          mentre gli utenti onesti tentano di votare. Si misura la
          difficoltà PoW (deve aumentare) e si verifica che tutti i
          voti legittimi vengano comunque accettati.
  Fase 3: Si attende la scadenza della finestra di osservazione e si
          verifica che la difficoltà PoW torni al valore minimo.

Il test avvia e termina SA e AE automaticamente.
            """,
        },
        "7": {
            "name": "Double Voting / Token Replay",
            "file": "tests/security/double_voting_attack.py",
            "description": """
Simula un elettore malevolo che tenta di votare due volte con lo stesso
token di autenticazione.

Il primo voto viene accettato normalmente (HTTP 200). Il secondo invio,
con lo stesso token ma per un candidato diverso, deve essere rifiutato
con HTTP 409 "Token già usato": l'AE marca il nonce del token come usato
dopo la prima accettazione, impedendo riutilizzi successivi.

Il test avvia e termina SA e AE automaticamente.
            """,
        },
        "8": {
            "name": "Token Hoarding & Token Scaduto",
            "file": "tests/security/token_hoarding_test.py",
            "description": """
Verifica due proprietà della politica use-it-or-lose-it sui token:

  Test 1 — Token Hoarding: un elettore si autentica due volte presso il
           SA. Il SA deve restituire sempre lo stesso token (non emettere
           una seconda credenziale distinta), impedendo l'accumulo di
           più token di voto.

  Test 2 — Token scaduto: si costruisce un token con firma RSA-PSS
           valida ma con finestra temporale scaduta (expires_at nel
           passato). L'AE deve rifiutarlo con HTTP 401.

  Test 3 — Voto valido: si verifica che un token regolare venga
           accettato normalmente.

Il test avvia e termina SA e AE automaticamente.
            """,
        },
    }

    while True:
        clear_screen()
        print("\n" + "="*70)
        print("                   UNISAFE-VOTE - TEST DI SICUREZZA")
        print("="*70)
        print(colored(
            "\nOgni test è autocontenuto: inizializza la propria elezione,\n"
            "avvia i server necessari e fa teardown alla fine.\n"
            "Verrà aperto un nuovo terminale per seguire l'esecuzione.",
            ANSI_DIM
        ))

        print(f"\n{section_title('TEST CRITTOGRAFICI (offline — nessun server richiesto)')}")
        print(menu_option("1", TESTS["1"]["name"], available=True))
        print(menu_option("2", TESTS["2"]["name"], available=True))
        print(menu_option("3", TESTS["3"]["name"], available=True))

        print(f"\n{section_title('TEST DI ATTACCO (server avviati automaticamente)')}")
        print(menu_option("4", TESTS["4"]["name"], available=True))
        print(menu_option("5", TESTS["5"]["name"], available=True))
        print(menu_option("6", TESTS["6"]["name"], available=True))
        print(menu_option("7", TESTS["7"]["name"], available=True))
        print(menu_option("8", TESTS["8"]["name"], available=True))

        print(f"\n{section_title('NAVIGAZIONE')}")
        print(menu_option("0", "Torna al menu principale", available=True))
        print("="*70)

        choice = input("\nSeleziona un test (0-8): ").strip()

        if choice == "0":
            break

        if choice not in TESTS:
            print("\nOpzione non valida!")
            input("\nPremi Invio per continuare...")
            continue

        test = TESTS[choice]
        clear_screen()

        # Si mostra il nome e la descrizione del test prima di eseguirlo.
        print("\n" + "="*70)
        print(f"  TEST {choice}: {test['name'].upper()}")
        print("="*70)
        print(test["description"])
        print("-"*70)
        print("Il test verrà eseguito in un nuovo terminale.")
        print("Attendi la chiusura del terminale di test prima di procedere.")
        print("-"*70)

        risposta = input("\nAvviare il test? (s/n): ").strip().lower()
        if risposta != "s":
            print("Test annullato.")
            input("\nPremi Invio per tornare al menu dei test...")
            continue

        # Si lancia il file di test in un nuovo terminale visibile,
        # così l'utente può seguire le fasi intermedie e i risultati.
        launch_in_new_terminal(test["file"])
        print(f"\nTest '{test['name']}' avviato nel nuovo terminale.")
        input("\nPremi Invio quando hai terminato di leggere i risultati...")


def main_menu() -> None:
    """
    Mostra il menu principale e gestisce l'interazione con l'utente.
    
    Questo è il punto di partenza dell'applicazione. Visualizza le opzioni
    disponibili, gestisce l'input dell'utente e richiama le funzioni
    corrispondenti. Il menu include:
    
    - Controllo dello stato dei server SA e AE
    - Opzioni per avviare i server
    - Inizializzazione di nuove elezioni
    - Gestione dello scrutinio
    - Verifica finale dell'elezione
    
    Il ciclo continua finché l'utente non sceglie l'opzione '0' (esci).
    """
    while True:
        clear_screen()
        election_initialized = is_election_initialized()
        sa_active = check_server_running(SA_URL)
        ae_active = check_server_running(AE_URL)
        ae_status = get_ae_status() if ae_active else {}
        scrutinio_presente = has_scrutinio()
        merkle_root_presente = has_merkle_root()
        urn_state = get_urn_state(election_initialized, ae_active, ae_status, scrutinio_presente, merkle_root_presente)
        urn_open = urn_state == "aperte"
        has_configuration = has_election_configuration()

        print("\n" + "="*70)
        print("                   UNISAFE-VOTE - PANNELLO DI CONTROLLO")
        print("="*70)
        print(f"\nStato: elezione inizializzata = {'sì' if election_initialized else 'no'}, "
              f"SA = {'attivo' if sa_active else 'inattivo'}, "
              f"AE = {'attivo' if ae_active else 'inattivo'}, "
              f"urne = {urn_state}")
        print(colored("\nLe voci in grigio non sono disponibili: esegui prima i passaggi precedenti.", ANSI_DIM))

        print(f"\n{section_title('SEZIONE PREPARAZIONE')}")
        print(menu_option(
            "1",
            "Inizializza Elezione",
            available=not election_initialized,
            suffix="già inizializzata" if election_initialized else ""
        ))

        print(f"\n{section_title('SEZIONE SERVER')}")
        print(menu_option(
            "2",
            "Avvio SA (Sistema Autenticazione)",
            available=election_initialized and not sa_active,
            suffix="attivo" if sa_active else ("inizializza prima" if not election_initialized else "")
        ))
        print(menu_option(
            "3",
            "Avvio AE (Autorità Elettorale)",
            available=election_initialized and not ae_active,
            suffix="attivo" if ae_active else ("inizializza prima" if not election_initialized else "")
        ))

        print(f"\n{section_title('SEZIONE VOTO')}")
        print(menu_option(
            "4",
            "Apri Client Votante",
            available=election_initialized and sa_active,
            suffix="urne chiuse: verifica/ricevuta" if urn_state == "chiuse" else ("AE inattivo: voto non disponibile" if not ae_active else "servono SA e AE attivi")
        ))

        print(f"\n{section_title('SEZIONE RISULTATI')}")
        print(menu_option(
            "5",
            "Chiudi Urne e Avvia Scrutinio",
            available=election_initialized and ae_active and urn_open,
            suffix="urne chiuse" if election_initialized and urn_state == "chiuse" else "serve AE attivo e urne aperte"
        ))
        print(menu_option(
            "6",
            "Esegui Verifica Universale Finale (dopo scrutinio)",
            available=scrutinio_presente,
            suffix="scrutinio mancante" if not scrutinio_presente else "scrutinio pronto"
        ))
        print(menu_option(
            "7",
            "Reset configurazione elezione",
            available=has_configuration,
            suffix="nessuna configurazione" if not has_configuration else ""
        ))

        print(f"\n{section_title('TEST DI SICUREZZA')}")
        print(menu_option("8", "Esegui Test di Sicurezza", available=True))

        print(f"\n{section_title('USCITA')}")
        print(menu_option("0", "Esci", available=True))
        print("="*70)

        disabled_choices = {}
        if election_initialized:
            disabled_choices["1"] = "l'elezione è già inizializzata; usa Reset se vuoi ricominciare."
        if not election_initialized or sa_active:
            disabled_choices["2"] = "per avviare il SA devi prima inizializzare l'elezione e il SA non deve essere già attivo."
        if not election_initialized or ae_active:
            disabled_choices["3"] = "per avviare l'AE devi prima inizializzare l'elezione e l'AE non deve essere già attiva."
        if not election_initialized or not sa_active:
            disabled_choices["4"] = "il client richiede elezione inizializzata e SA attivo."
        if not election_initialized or not ae_active or not urn_open:
            if election_initialized and urn_state == "chiuse":
                disabled_choices["5"] = "le urne sono già chiuse; per la verifica finale usa l'opzione 6."
            else:
                disabled_choices["5"] = "la chiusura richiede elezione inizializzata, AE attivo e urne aperte."
        if not scrutinio_presente:
            disabled_choices["6"] = "la verifica universale finale richiede il blocco scrutinio; prima chiudi le urne ed esegui lo scrutinio."
        if not has_configuration:
            disabled_choices["7"] = "non esiste alcuna configurazione di elezione da resettare."

        choice = input("\nSeleziona un'opzione: ")

        if choice in disabled_choices:
            print(colored(f"\nOpzione non disponibile: {disabled_choices[choice]}", ANSI_DIM))
            input("\nPremi Invio per tornare al menu...")
            continue

        if choice == '1':
            init_election()
        elif choice == '2':
            start_sa()
        elif choice == '3':
            start_ae()
        elif choice == '4':
            open_client()
        elif choice == '5':
            close_election()
        elif choice == '6':
            run_observer()
        elif choice == '7':
            reset_election()
        elif choice == '8':
            run_security_tests()
        elif choice == '0':
            print("\nChiusura programma...")
            clear_screen()
            break
        else:
            print("\nOpzione non valida!")

        input("\nPremi Invio per tornare al menu...")


def stop_processes() -> None:
    """
    Termina i processi SA e AE avviati da questo programma.
    """
    global SA_PROCESS, AE_PROCESS
    
    # Invia richiesta di shutdown via HTTP agli endpoint /shutdown (per macOS/Linux/Windows)
    for url in (SA_URL, AE_URL):
        try:
            requests.post(url + '/shutdown', timeout=0.5)
        except Exception:
            # Ignora errori di connessione (es. server già spento o non in esecuzione)
            pass

    # Su Windows, termina i processi associati alla console aperta
    for name, proc in (('SA', SA_PROCESS), ('AE', AE_PROCESS)):
        if proc is not None:
            try:
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        proc.kill()
            except Exception:
                pass

    SA_PROCESS = None
    AE_PROCESS = None


if __name__ == "__main__":
    os.chdir(PROJECT_DIR)
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n\nChiusura programma...")
    finally:
        stop_processes()
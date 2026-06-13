
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
    SA_PROCESS = launch_in_new_terminal("sa.py")
    
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
    AE_PROCESS = launch_in_new_terminal("ae.py")
    
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
4. Permette di SCEGLIERE tra:
   - Sistema preconfigurato (liste stock + utenti già registrati)
   - Solo liste di voto (registrazione utenti abilitata)
    """)
    input("Premi Invio per continuare...")
    subprocess.run([sys.executable, "init_election.py"], cwd=PROJECT_DIR)


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

    if not (
        os.path.exists(bulletin_board_path)
        or os.path.exists(voters_path)
        or os.path.isdir(keys_dir)
        or os.path.isdir(receipts_dir)
        or os.path.exists(ae_state_path)
    ):
        print("Nessuna configurazione di elezione trovata da rimuovere.")
        return

    print_header("RESET CONFIGURAZIONE ELEZIONE")
    print_explanation("""
Questa operazione elimina i file di configurazione dell'elezione, le chiavi RSA,
lo stato privato dell'Autorità Elettorale e le ricevute JSON dei voti
delle elezioni passate.
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
    launch_in_new_terminal("client.py")


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

    bulletin_board_path = os.path.join(PROJECT_DIR, "data", "bulletin_board.json")
    scrutinio_presente = False
    if os.path.exists(bulletin_board_path):
        with open(bulletin_board_path, "r", encoding="utf-8") as f:
            bb = json.load(f)
        scrutinio_presente = any(block.get("type") == "scrutinio" for block in bb)

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
    launch_in_new_terminal("observer.py")


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
        print("\n" + "="*70)
        print("                   UNISAFE-VOTE - PANNELLO DI CONTROLLO")
        print("="*70)
        
        sa_status = "Attivo" if check_server_running(SA_URL) else "Inattivo"
        ae_status = "Attivo" if check_server_running(AE_URL) else "Inattivo"
        
        print("\nSEZIONE PREPARAZIONE")
        print("  1. Inizializza Elezione")
        print("\nSEZIONE SERVER")
        print(f"  2. Avvio SA (Sistema Autenticazione) [{sa_status}]")
        print(f"  3. Avvio AE (Autorità Elettorale) [{ae_status}]")
        print("\nSEZIONE VOTO")
        print("  4. Apri Client Votante")
        print("\nSEZIONE RISULTATI")
        print("  5. Chiudi Urne e Avvia Scrutinio")
        print("  6. Esegui Verifica Universale Finale (dopo scrutinio)")
        print("  7. Reset configurazione elezione")
        print("\nUSCITA")
        print("  0. Esci")
        print("="*70)
        
        choice = input("\nSeleziona un'opzione: ")
        
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
        elif choice == '0':
            print("\nArrivederci!")
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
        print("\n\nArrivederci!")
    finally:
        stop_processes()
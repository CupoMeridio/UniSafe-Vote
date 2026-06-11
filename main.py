
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

SA_PROCESS: Optional[subprocess.Popen] = None  # Riferimento al processo del server SA (Sistema di Autenticazione)
AE_PROCESS: Optional[subprocess.Popen] = None  # Riferimento al processo del server AE (Autorità Elettorale)
SA_URL = "http://localhost:5001"  # URL di base per connettersi al server SA
AE_URL = "http://localhost:5002"  # URL di base per connettersi al server AE
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))  # Percorso assoluto della cartella del progetto

# Utilità utilizzata per stampare un titolo con un banner
def print_header(title: str) -> None:
    print("\n" + "="*70)
    print(f"  {title}".center(70))
    print("="*70)

# Utilità utilizzata per stampare un testo esplicativo
def print_explanation(text: str) -> None:
    print(f"\n{text}")
    print("-" * 70)


def check_server_running(url: str) -> bool:
    """
    Verifica se un server è in esecuzione controllando l'endpoint `/status`.
    
    Args:
        url (str): URL del server da verificare
        
    Returns:
        bool: True se il server risponde con status 200, False altrimenti
    """
    try:
        response = requests.get(url + '/status', timeout=2)
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
    
    Questa funzione è un wrapper che esegue `sa.py` per avviare il server Flask di SA sulla porta 5001 in un nuovo terminale PowerShell. Prima dell'avvio viene visualizzato un messaggio esplicativo sulle funzionalità del SA.
    
    Il SA (in sa.py) gestisce:
    - Registrazione di nuovi elettori con validazione email UNISA
    - Autenticazione degli elettori e emissione di token firmati
    - Verifica dell'unicità dei token
    
    Returns:
        None
    """
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

Il server verrà avviato su porta 5001 in un nuovo terminale.
    """)
    
    subprocess.Popen(
        ["start", "powershell", "-NoExit", "-Command", f"cd '{PROJECT_DIR}'; python sa.py"],
        shell=True,
        cwd=PROJECT_DIR
    )
    
    if wait_for_server(SA_URL, "SA"):
        print("SA avviato con successo!")


def start_ae() -> None:
    """
    Avvia l'Autorità Elettorale (AE) su un nuovo terminale.
    
    Questa funzione è un wrapper che esegue `ae.py` per avviare il server Flask di AE sulla porta 5002 in un nuovo terminale PowerShell.
    Prima dell'avvio viene visualizzato un messaggio esplicativo sulle funzionalità dell'AE.
    
    L'AE (in ae.py) gestisce:
    - Ricezione e verifica dei voti cifrati
    - Costruzione e aggiornamento del Merkle Tree
    - Scrutinio dei voti al termine delle urne
    - Pubblicazione dei risultati sui registri pubblici
    
    Returns:
        None
    """
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

Il server verrà avviato su porta 5002 in un nuovo terminale.
    """)
    
    subprocess.Popen(
        ["start", "powershell", "-NoExit", "-Command", f"cd '{PROJECT_DIR}'; python ae.py"],
        shell=True,
        cwd=PROJECT_DIR
    )
    
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
   - Lista preconfigurata (5 elettori di test)
   - Lista personalizzata creata dall'amministratore
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

    if not (os.path.exists(bulletin_board_path) or os.path.exists(voters_path) or os.path.isdir(keys_dir)):
        print("Nessuna configurazione di elezione trovata da rimuovere.")
        return

    print_header("RESET CONFIGURAZIONE ELEZIONE")
    print_explanation("""
Questa operazione elimina i file di configurazione dell'elezione e le chiavi RSA.
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
    if os.path.isdir(keys_dir):
        for filename in os.listdir(keys_dir):
            file_path = os.path.join(keys_dir, filename)
            if os.path.isfile(file_path):
                os.remove(file_path)

    print("Configurazione elezione rimossa. È ora possibile inizializzare una nuova elezione.")


def open_client() -> None:
    """
    Apri il client votante in un nuovo terminale.
    
    Questa funzione è un wrapper che esegue `client.py` per avviare il client votante in un nuovo terminale PowerShell.
    
    Il client votante (in client.py) permette a un elettore di:
    - Registrarsi con un'email UNISA valida
    - Autenticarsi presso il SA
    - Esprimere il proprio voto cifrato
    - Salvare una ricevuta digitale
    - Verificare l'inclusione del voto
    
    Returns:
        None
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
    subprocess.Popen(
        ["start", "powershell", "-NoExit", "-Command", f"cd '{PROJECT_DIR}'; python client.py"],
        shell=True,
        cwd=PROJECT_DIR
    )


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
    6. Pubblica i risultati sul Bulletin Board
    
    Returns:
        None
    """
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
        # Invia una richiesta POST all'endpoint /close dell'AE per chiudere le urne
        response = requests.post(AE_URL + '/close', timeout=10)

        # Se il server risponde con codice 200, la chiusura e lo scrutinio sono andati a buon fine
        if response.status_code == 200:
            # Estrae il contenuto JSON della risposta
            result = response.json()
            print("\nScrutinio completato!")
            print("\nRISULTATO ELEZIONE:")

            # Stampa il risultato per ogni candidato presente nel JSON di risposta
            for candidate, votes in result['result'].items():
                print(f"   {candidate}: {votes} voti")
        else:
            # In caso di errore, stampa il messaggio di errore restituito dal server
            print(f"Errore: {response.json().get('error')}")
    except Exception as e:
        # Se la richiesta non riesce per qualsiasi motivo (server non raggiungibile, timeout, ecc.)
        print(f"Impossibile chiudere le urne: {str(e)}")


def run_observer() -> None:
    """
    Esegue la verifica universale dell'elezione.
    
    Questa funzione è un wrapper che esegue `observer.py` per avviare l'observer in un nuovo terminale PowerShell.
    
    L'Observer (in observer.py) permette a chiunque di verificare l'integrità dell'elezione analizzando il Bulletin Board e controlla:
    - La firma digitale di tutti i blocchi
    - L'integrità del Merkle Tree
    - La correttezza dello scrutinio
    - La corrispondenza tra voti cifrati e chiari
    
    Returns:
        None
    """
    print_header("VERIFICA UNIVERSALE (OBSERVER)")
    print_explanation("""
L'Observer permette di verificare:
1. L'integrità del Bulletin Board
2. La correttezza dello scrutinio
3. Che tutti i voti siano stati conteggiati

Verrà aperto un nuovo terminale per eseguire la verifica.
    """)
    input("Premi Invio per eseguire la verifica...")
    subprocess.Popen(
        ["start", "powershell", "-NoExit", "-Command", f"cd '{PROJECT_DIR}'; python observer.py"],
        shell=True,
        cwd=PROJECT_DIR
    )


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
        print("  6. Esegui Verifica Universale (Observer)")
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


if __name__ == "__main__":
    os.chdir(PROJECT_DIR)
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n\nArrivederci!")
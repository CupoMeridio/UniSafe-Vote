
"""
UNISAFE-VOTE - Sistema di Voto Elettronico Sicuro

Questo pacchetto completa il sviluppo di un sistema di votazione elettronica basato su blockchain (Merkle Tree) con i seguenti componenti principali:
- SA (Sistema di Autenticazione)
- AE (Autorità Elettorale)
- Client Votante
- Observer (Verifica Universale)

L'applicazione è organizzata come un menu principale che coordina l'avvio delle componenti e permette all'amministratore di gestire l'intero ciclo di vita di un'elezione:
1. Inizializzazione (generazione chiavi, Bulletin Board)
2. Avvio server SA/AE
3. Registrazione e voto degli elettori
4. Chiusura urne e scrutinio
5. Verifica finale dell'elezione

Funzionalità chiave del menu:
- Visualizzazione dello stato dei server (SA/AE)
- Avvio automatico di nuovi terminali per ogni componente (via powershell)
- Gestione dello scrutinio e pubblicazione dei risultati
- Integrazione con i sistemi di registrazione e verifica degli elettori

Questo file (`main.py`) è il punto di ingresso dell'applicazione. Mostra un menu interattivo che permette di:
- Inizializzare un'elezione
- Avviare il Sistema di Autenticazione (SA) su porta 5001
- Avviare l'Autorità Elettorale (AE) su porta 5002
- Aprire il client votante
- Chiudere le urne e avviare lo scrutinio
- Eseguire la verifica universale
- Gestire lo stato dei server
"""

import os
import subprocess
import sys
import time
import requests

SA_PROCESS = None
AE_PROCESS = None
SA_URL = "http://localhost:5001"
AE_URL = "http://localhost:5002"
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))


def print_header(title):
    print("\n" + "="*70)
    print(f"  {title}".center(70))
    print("="*70)


def print_explanation(text):
    print(f"\n{text}")
    print("-" * 70)


def check_server_running(url):
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


def wait_for_server(url, server_name, timeout=15):
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


def start_sa():
    """
    Avvia il Sistema di Autenticazione (SA) su un nuovo terminale.
    
    Questo avvia il server Flask di SA sulla porta 5001 in un nuovo terminale
    PowerShell che rimane aperto dopo l'avvio (`-NoExit`). Prima dell'avvio
    viene visualizzato un messaggio esplicativo sulle funzionalità del SA.
    
    Il SA gestisce:
    - Registrazione di nuovi elettori con validazione email UNISA
    - Autenticazione degli elettori e emissione di token firmati
    - Verifica dell'unicità dei token
    
    Returns:
        None
    """
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


def start_ae():
    """
    Avvia l'Autorità Elettorale (AE) su un nuovo terminale.
    
    Questo avvia il server Flask di AE sulla porta 5002 in un nuovo terminale
    PowerShell che rimane aperto dopo l'avvio (`-NoExit`). Prima dell'avvio
    viene visualizzato un messaggio esplicativo sulle funzionalità dell'AE.
    
    L'AE gestisce:
    - Ricezione e verifica dei voti cifrati
    - Costruzione e aggiornamento del Merkle Tree
    - Scrutinio dei voti al termine delle urne
    - Pubblicazione dei risultati sui registri pubblici
    
    Returns:
        None
    """
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


def init_election():
    """
    Inizializza una nuova elezione.
    
    Questo crea tutte le coppie di chiavi RSA necessarie, genera il
    Bulletin Board con i parametri dell'elezione e carica i dati iniziali.
    Chiede all'amministratore se preferisce una lista preconfigurata
    di elettori o di crearne uno personalizzato.
    
    Esegue lo script `init_election.py` che completa l'inizializzazione
    archiviando i dati in `data/`.
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


def open_client():
    """
    Apri il client votante in un nuovo terminale.
    
    Il client permette a un elettore di:
    - Registrarsi con un'email UNISA valida
    - Autenticarsi presso il SA
    - Esprimere il proprio voto cifrato
    - Salvare una ricevuta digitale
    - Verificare l'inclusione del voto
    
    Questo avvia il client Python su un nuovo terminale PowerShell
    tramite `subprocess.Popen` con l'opzione `-NoExit` per mantenere il
    terminale aperto dopo l'avvio.
    
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


def close_election():
    """
    Chiude le urne e avvia lo scrutinio.
    
    Questo è possibile solo se l'Autorità Elettorale (AE) è in esecuzione.
    Il processo:
    1. Pubblica il Merkle Root finale sul Bulletin Board
    2. Carica la chiave privata di decifratura
    3. Decifra tutti i voti
    4. Verifica i seed per garantire l'integrità
    5. Calcola il risultato aggregato
    5. Pubblica i risultati sul Bulletin Board
    
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
5. Calcola il risultato aggregato
6. Pubblica tutto sul Bulletin Board
    """)
    input("Premi Invio per chiudere le urne...")
    
    try:
        response = requests.post(AE_URL + '/close', timeout=10)
        if response.status_code == 200:
            result = response.json()
            print("\nScrutinio completato!")
            print("\nRISULTATO ELEZIONE:")
            for candidate, votes in result['result'].items():
                print(f"   {candidate}: {votes} voti")
        else:
            print(f"Errore: {response.json().get('error')}")
    except Exception as e:
        print(f"Impossibile chiudere le urne: {str(e)}")


def run_observer():
    """
    Esegue la verifica universale dell'elezione.
    
    L'Observer permette a chiunque di verificare l'integrità dell'elezione
    analizzando il Bulletin Board. Questoscript controlla:
    - La firma digitale di tutti i blocchi
    - L'integrità del Merkle Tree
    - La correttezza dello scrutinio
    - La corrispondenza tra voti cifrati e chiari
    
    Questo avvia l'observor Python su un nuovo terminale PowerShell
    tramite `subprocess.Popen` con l'opzione `-NoExit` per mantenere il
    terminale aperto dopo l'avvio.
    
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


def main_menu():
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
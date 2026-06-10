
#!/usr/bin/env python3
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
    try:
        response = requests.get(url + '/status', timeout=2)
        return response.status_code == 200
    except:
        return False

def wait_for_server(url, server_name, timeout=15):
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
    if check_server_running(SA_URL):
        print("SA e' gia' in esecuzione!")
        return
    
    print_header("AVVIO SISTEMA DI AUTENTICAZIONE (SA)")
    print_explanation("""
Il Sistema di Autenticazione (SA) ha il compito di:
1. Verificare le credenziali degli elettori
2. Generare e firmare token di autenticazione
3. Impedire voti multipli dallo stesso elettore

Il server verra' avviato su porta 5001 in un nuovo terminale.
    """)
    
    subprocess.Popen(
        ["start", "powershell", "-NoExit", "-Command", f"cd '{PROJECT_DIR}'; python sa.py"],
        shell=True,
        cwd=PROJECT_DIR
    )
    
    if wait_for_server(SA_URL, "SA"):
        print("SA avviato con successo!")

def start_ae():
    if check_server_running(AE_URL):
        print("AE e' gia' in esecuzione!")
        return
    
    print_header("AVVIO AUTORITA' ELETTORALE (AE)")
    print_explanation("""
L'Autorita' Elettorale (AE) ha il compito di:
1. Ricevere i voti cifrati dagli elettori
2. Verificare la Proof of Work (anti-spam)
3. Memorizzare i voti nel Bulletin Board
4. Calcolare il Merkle Tree
5. Eseguire lo scrutinio quando le urne sono chiuse

Il server verra' avviato su porta 5002 in un nuovo terminale.
    """)
    
    subprocess.Popen(
        ["start", "powershell", "-NoExit", "-Command", f"cd '{PROJECT_DIR}'; python ae.py"],
        shell=True,
        cwd=PROJECT_DIR
    )
    
    if wait_for_server(AE_URL, "AE"):
        print("AE avviato con successo!")

def init_election():
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
    if not check_server_running(AE_URL):
        print("AE non e' in esecuzione!")
        return
    
    print_header("CHIUSURA URNE E SCRUTINIO")
    print_explanation("""
Quando le urne vengono chiuse:
1. L'AE pubblica il Merkle Root finale
2. Carica la chiave privata di decifratura
3. Decifra tutti i voti
4. Verifica i seed per garantire l'integrita'
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
    print_header("VERIFICA UNIVERSALE (OBSERVER)")
    print_explanation("""
L'Observer permette di verificare:
1. L'integrita' del Bulletin Board
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
        print(f"  3. Avvio AE (Autorita' Elettorale) [{ae_status}]")
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

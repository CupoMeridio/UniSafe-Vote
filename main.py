
#!/usr/bin/env python3
import os
import subprocess
import sys
import time

try:
    import requests
except ImportError:
    print("\n" + "!"*50)
    print("ERRORE: La libreria 'requests' non è installata.")
    print("Sembra che tu non stia usando il Virtual Environment corretto.")
    print("!"*50)
    print("\nPer risolvere, esegui questi comandi nel terminale:")
    print(r"1. .\venv\Scripts\Activate.ps1 (se sei su Windows PowerShell)")
    print("2. python main.py")
    print("\nOppure usa direttamente il Python del venv:")
    print(r".\venv\Scripts\python.exe main.py")
    sys.exit(1)

SA_PROCESS = None
AE_PROCESS = None
SA_URL = "http://localhost:5001"
AE_URL = "http://localhost:5002"

def check_server_running(url):
    try:
        response = requests.get(url + '/status', timeout=2)
        return response.status_code == 200
    except:
        return False

def wait_for_server(url, server_name, timeout=10):
    print(f"Attendo che {server_name} si avvi...", end="", flush=True)
    for i in range(timeout):
        if check_server_running(url):
            print(" ✓ Pronto!")
            return True
        print(".", end="", flush=True)
        time.sleep(1)
    print(" ❌ Timeout!")
    return False

def start_sa():
    global SA_PROCESS
    if SA_PROCESS is not None:
        print("⚠️  SA è già in esecuzione!")
        return
    print("Avvio Sistema di Autenticazione (porta 5001)...")
    SA_PROCESS = subprocess.Popen(
        [sys.executable, "sa.py"],
        cwd=os.path.dirname(os.path.abspath(__file__)),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )
    wait_for_server(SA_URL, "SA")

def start_ae():
    global AE_PROCESS
    if AE_PROCESS is not None:
        print("⚠️  AE è già in esecuzione!")
        return
    print("Avvio Autorità Elettorale (porta 5002)...")
    AE_PROCESS = subprocess.Popen(
        [sys.executable, "ae.py"],
        cwd=os.path.dirname(os.path.abspath(__file__)),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )
    wait_for_server(AE_URL, "AE")

def stop_sa():
    global SA_PROCESS
    if SA_PROCESS is None:
        print("⚠️  SA non è in esecuzione!")
        return
    print("Arresto SA...")
    SA_PROCESS.terminate()
    SA_PROCESS.wait()
    SA_PROCESS = None
    print("✓ SA arrestato")

def stop_ae():
    global AE_PROCESS
    if AE_PROCESS is None:
        print("⚠️  AE non è in esecuzione!")
        return
    print("Arresto AE...")
    AE_PROCESS.terminate()
    AE_PROCESS.wait()
    AE_PROCESS = None
    print("✓ AE arrestato")

def init_election():
    print("\n=== INIZIALIZZAZIONE ELEZIONE ===")
    subprocess.run([sys.executable, "init_election.py"], cwd=os.path.dirname(os.path.abspath(__file__)))

def open_client():
    print("\n=== CLIENT VOTANTE ===")
    subprocess.run([sys.executable, "client.py"], cwd=os.path.dirname(os.path.abspath(__file__)))

def close_election():
    if not check_server_running(AE_URL):
        print("❌ AE non è in esecuzione!")
        return
    print("\nChiusura urne e avvio scrutinio...")
    try:
        response = requests.post(AE_URL + '/close', timeout=5)
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Scrutinio completato! Risultato: {result['result']}")
        else:
            print(f"❌ Errore: {response.json().get('error')}")
    except Exception as e:
        print(f"❌ Impossibile chiudere le urne: {str(e)}")

def run_observer():
    print("\n=== VERIFICA UNIVERSALE ===")
    subprocess.run([sys.executable, "observer.py"], cwd=os.path.dirname(os.path.abspath(__file__)))

def main_menu():
    while True:
        print("\n" + "="*50)
        print("       UNISAFE-VOTE - MENU PRINCIPALE")
        print("="*50)
        
        sa_status = "🟢 Attivo" if check_server_running(SA_URL) else "🔴 Inattivo"
        ae_status = "🟢 Attivo" if check_server_running(AE_URL) else "🔴 Inattivo"
        
        print(f"1. Inizializza Elezione")
        print(f"2. Avvio SA (Sistema Autenticazione) [{sa_status}]")
        print(f"3. Avvio AE (Autorità Elettorale) [{ae_status}]")
        print(f"4. Apri Client Votante")
        print(f"5. Chiudi Urne e Avvia Scrutinio")
        print(f"6. Esegui Verifica Universale (Observer)")
        print(f"7. Arresta SA")
        print(f"8. Arresta AE")
        print(f"0. Esci (arresta tutti i server)")
        print("="*50)
        
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
            stop_sa()
        elif choice == '8':
            stop_ae()
        elif choice == '0':
            print("\nArresto tutti i server in corso...")
            if SA_PROCESS:
                SA_PROCESS.terminate()
            if AE_PROCESS:
                AE_PROCESS.terminate()
            print("✓ Arrivederci!")
            break
        else:
            print("\n❌ Opzione non valida!")

if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n\nInterruzione ricevuta. Arresto tutti i server...")
        if SA_PROCESS:
            SA_PROCESS.terminate()
        if AE_PROCESS:
            AE_PROCESS.terminate()
        print("✓ Fatto!")

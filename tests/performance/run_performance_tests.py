
"""
Script helper per eseguire test di performance con Locust in modalità headless
"""
import os
import sys
import subprocess
import time


def run_baseline_test():
    """Test Scenario Ottimale (Baseline) con utenti legittimi per 1 minuti"""
    print("\n=== Esecuzione Scenario Ottimale (Baseline) ===")
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    subprocess.run([
        sys.executable, "-m", "locust",
        "-f", os.path.join("tests", "performance", "locustfile.py"),
        "--host", "http://localhost",
        "--headless",
        "-u", "10",  # 10 utenti legittimi
        "-r", "2",   # 2 nuovi utenti al secondo
        "-t", "1m",  # 1 minuto di test per velocità
        "--csv", os.path.join("tests", "output", "baseline_test")
    ], cwd=project_root)


def run_dos_test():
    """Test Scenario DoS con utenti malintenzionati"""
    print("\n=== Esecuzione Scenario DoS ===")
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    subprocess.run([
        sys.executable, "-m", "locust",
        "-f", os.path.join("tests", "performance", "locustfile.py"),
        "--host", "http://localhost",
        "--headless",
        "-u", "500",  # 500 utenti malintenzionati
        "-r", "50",  # 50 nuovi utenti al secondo
        "-t", "1m",  # 1 minuto di durata
        "--csv", os.path.join("tests", "output", "dos_test")
    ], cwd=project_root)


if __name__ == "__main__":
    print("=== UniSafe-Vote Performance Test Runner ===")
    print("\nScegli quale test eseguire:")
    print("1) Scenario Ottimale (Baseline)")
    print("2) Scenario DoS (Attacco PoW Invalida)")
    print("0) Esci")
    
    choice = input("\nInserisci il numero: ")
    
    if choice == "1":
        print("\nNota: Assicurati che SA (5001), AE (5002), e un'elezione siano inizializzati!")
        input("Premi Invio per continuare...")
        run_baseline_test()
    elif choice == "2":
        print("\nNota: Assicurati che SA (5001) e AE (5002) siano attivi!")
        input("Premi Invio per continuare...")
        run_dos_test()
    elif choice == "0":
        print("Arrivederci!")
    else:
        print("Scelta non valida!")


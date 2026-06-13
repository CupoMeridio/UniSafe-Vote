
#!/usr/bin/env python3
"""
Helper script per avviare il sistema UniSafe-Vote
"""
import os
import sys
import subprocess


def main():
    print("=== UniSafe-Vote System Starter ===")
    print("\nCosa vuoi avviare?")
    print("1) Main Menu")
    print("2) SA (Server Autenticazione, porta 5001)")
    print("3) AE (Autorità Elettorale, porta 5002)")
    print("4) Client")
    print("5) Observer")
    print("0) Esci")
    
    choice = input("\nInserisci il numero: ")
    project_root = os.path.dirname(os.path.abspath(__file__))
    
    if choice == "1":
        subprocess.run([sys.executable, os.path.join("src", "main.py")], cwd=project_root)
    elif choice == "2":
        subprocess.run([sys.executable, os.path.join("src", "sa.py")], cwd=project_root)
    elif choice == "3":
        subprocess.run([sys.executable, os.path.join("src", "ae.py")], cwd=project_root)
    elif choice == "4":
        subprocess.run([sys.executable, os.path.join("src", "client.py")], cwd=project_root)
    elif choice == "5":
        subprocess.run([sys.executable, os.path.join("src", "observer.py")], cwd=project_root)
    elif choice == "0":
        print("Arrivederci!")
    else:
        print("Scelta non valida!")


if __name__ == "__main__":
    main()


"""
Test script to verify rate limiting on SA endpoints!
"""
import os
import sys
import time
import requests
import subprocess

TESTS_SECURITY_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(TESTS_SECURITY_DIR, "..", ".."))
SRC_DIR = os.path.join(PROJECT_ROOT, "src")
sys.path.insert(0, SRC_DIR)
sys.path.insert(0, TESTS_SECURITY_DIR)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "tests"))

SA_CERT = os.path.join(PROJECT_ROOT, "data", "tls", "sa_cert.pem")


def sa_verify() -> str | bool:
    return SA_CERT if os.path.exists(SA_CERT) else True

from tls_config import ensure_tls_certs

def main():
    # Initialize election
    print("[*] Initializing election first...")
    ensure_tls_certs()
    subprocess.run([sys.executable, os.path.join(SRC_DIR, "init_election_non_interactive.py")], cwd=PROJECT_ROOT, check=True)

    # Start SA in background
    print("[*] Starting SA server for testing...")
    sa_proc = subprocess.Popen([sys.executable, os.path.join(SRC_DIR, "sa.py")], cwd=PROJECT_ROOT,
                               stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,
                               text=True)

    try:
        # Wait for server to come up
        print("[*] Waiting for SA to be ready...")
        time.sleep(3)

        # Test /authenticate rate limit
        print("\n[*] Testing /authenticate rate limit...")
        auth_url = "https://localhost:5001/authenticate"
        for i in range(15):
            print(f"[*] Request # {i+1} to /authenticate...")
            r = requests.post(auth_url, json={"username": "mario.rossi", "password": "password123"}, verify=sa_verify())
            print(f"    Status code: {r.status_code}")
            if r.status_code == 429:
                print("\n✅ Rate limit activated as expected!")
                break
        else:
            print("\n❌ Rate limit NOT activated!")

    finally:
        # Shutdown server
        print("\n[*] Shutting down SA...")
        try:
            requests.post("https://localhost:5001/shutdown", timeout=2, verify=sa_verify())
        except:
            pass
        sa_proc.terminate()
        try:
            sa_proc.wait(timeout=3)
        except:
            sa_proc.kill()


if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    try:
        main()
    finally:
        input("\nPremi Invio per chiudere...")

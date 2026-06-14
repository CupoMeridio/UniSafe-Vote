
"""
Test script to verify rate limiting on SA endpoints!
"""
import os
import sys
import time
import requests
import subprocess

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def main():
    # Initialize election
    print("[*] Initializing election first...")
    subprocess.run([sys.executable, "init_election_non_interactive.py"], cwd=os.path.dirname(os.path.abspath(__file__)), check=True)

    # Start SA in background
    print("[*] Starting SA server for testing...")
    sa_proc = subprocess.Popen([sys.executable, "sa.py"], cwd=os.path.dirname(os.path.abspath(__file__)),
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
        auth_url = "http://localhost:5001/authenticate"
        for i in range(15):
            print(f"[*] Request # {i+1} to /authenticate...")
            r = requests.post(auth_url, json={"username": "mario.rossi", "password": "password123"})
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
            requests.post("http://localhost:5001/shutdown", timeout=2)
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

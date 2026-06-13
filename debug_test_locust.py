
#!/usr/bin/env python3
"""Debug script to check locust imports and paths"""
import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.dirname(__file__))
SRC_DIR = os.path.join(PROJECT_ROOT, "src")
sys.path.insert(0, SRC_DIR)

print("PROJECT_ROOT:", PROJECT_ROOT)
print("SRC_DIR:", SRC_DIR)
print("sys.path:", sys.path[:3])

try:
    from crypto.keys import deserialize_public_key
    print("[OK] deserialize_public_key imported!")
except Exception as e:
    print("[ERROR] Failed to import deserialize_public_key:", type(e), str(e))
    import traceback
    traceback.print_exc()

try:
    BB_PATH = os.path.join(SRC_DIR, "data", "bulletin_board.json")
    print("Checking bulletin_board at:", BB_PATH)
    if os.path.exists(BB_PATH):
        import json
        with open(BB_PATH, "r", encoding="utf-8") as f:
            bb = json.load(f)
            print("[OK] Loaded bulletin_board, keys present:", "ae_encrypt_public" in bb[0]["data"])
    else:
        print("[ERROR] bulletin_board.json not found!")
except Exception as e:
    print("[ERROR] Error loading bulletin board:", type(e), str(e))
    import traceback
    traceback.print_exc()

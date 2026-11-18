"""
Test delle difese contro il brute force sul Sistema di Autenticazione (SA).

Fase 1 — Rate limit per IP: oltre 10 richieste al minuto dallo stesso IP il SA
         risponde HTTP 429.
Fase 2 — Aggiramento con IP falsificati: l'attaccante dichiara un IP diverso a
         ogni richiesta tramite l'header X-Forwarded-For. Il SA deve ignorare
         l'header (è impostato dal client) e bloccare comunque con HTTP 429.
Fase 3 — Blocco per account: dopo 5 password errate sullo stesso account
         l'account viene bloccato temporaneamente (HTTP 429), anche se poi
         arriva la password corretta. Ferma il brute force distribuito su
         molti IP, che il rate limit per IP non vede.
Fase 4 — Enumerazione degli username tramite i tempi di risposta: un login
         con username inesistente deve impiegare quanto uno con username
         esistente (PBKDF2 eseguito comunque su un hash fittizio).
Fase 5 — Endpoint amministrativi: /reconcile e /shutdown rispondono HTTP 403
         senza token amministrativo o con un token errato, e funzionano solo
         con il token corretto (header X-Admin-Token).

Il rate limit e i contatori sono in memoria: il SA viene riavviato tra una fase
e l'altra, così ogni fase parte da una finestra pulita.
"""
import os
import sys
import time
import statistics
import subprocess
import requests

TESTS_SECURITY_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(TESTS_SECURITY_DIR, "..", ".."))
SRC_DIR = os.path.join(PROJECT_ROOT, "src")
sys.path.insert(0, SRC_DIR)
sys.path.insert(0, TESTS_SECURITY_DIR)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "tests"))

from test_reporter import save_report
from tls_config import SA_URL, sa_verify, ensure_tls_certs, admin_headers
from common import clean_election_state

AUTH_URL = f"{SA_URL}/authenticate"
# Per la misura dei tempi si usa l'IP: su Windows "localhost" viene risolto prima
# in IPv6 (::1), su cui Flask non è in ascolto, e ogni connessione attende ~2s
# prima del fallback su IPv4. Quel ritardo coprirebbe la differenza da misurare
# (~100 ms di PBKDF2). Il certificato TLS include 127.0.0.1 tra i SAN.
AUTH_URL_IP = "https://127.0.0.1:5001/authenticate"
VALID_USER = {"username": "vitto.posti", "password": "password123"}
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
KEYS_DIR = os.path.join(DATA_DIR, "keys")


def clean_state() -> None:
    for fname in ["bulletin_board.json", "voters.json", "ae_state.json", "pins.json"]:
        p = os.path.join(DATA_DIR, fname)
        if os.path.exists(p):
            os.remove(p)
    if os.path.isdir(KEYS_DIR):
        clean_election_state()  # rimuove anche le quote in data/keys/trustees/


def start_sa() -> subprocess.Popen:
    proc = subprocess.Popen([sys.executable, os.path.join(SRC_DIR, "sa.py")], cwd=PROJECT_ROOT,
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(30):
        try:
            if requests.get(f"{SA_URL}/status", timeout=0.5, verify=sa_verify()).status_code == 200:
                return proc
        except Exception:
            pass
        time.sleep(0.5)
    raise RuntimeError("SA non risponde")


def stop_sa(proc: subprocess.Popen) -> None:
    try:
        requests.post(f"{SA_URL}/shutdown", headers=admin_headers(), timeout=2, verify=sa_verify())
    except Exception:
        pass
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
    time.sleep(0.5)


def auth(username: str, password: str, headers: dict = None, url: str = AUTH_URL) -> requests.Response:
    return requests.post(url, json={"username": username, "password": password},
                         headers=headers or {}, timeout=10, verify=sa_verify())


def main():
    print("=" * 80)
    print("  TEST DIFESE BRUTE FORCE DEL SA (rate limit, IP falsificati, blocco account, timing)")
    print("=" * 80)

    clean_state()
    print("\n[SETUP] Inizializzazione elezione...")
    ensure_tls_certs()
    subprocess.run([sys.executable, os.path.join(SRC_DIR, "init_election_non_interactive.py")],
                   cwd=PROJECT_ROOT, check=True, stdout=subprocess.DEVNULL)

    results = {}
    sa_proc = None
    try:
        # FASE 1 ------------------------------------------------------------
        print("\n" + "-" * 80)
        print("FASE 1 — Rate limit per IP (massimo 10 richieste al minuto)")
        print("-" * 80)
        sa_proc = start_sa()
        statuses = []
        for i in range(12):
            r = auth(**VALID_USER)
            statuses.append(r.status_code)
            print(f"  Richiesta {i + 1:>2}: HTTP {r.status_code}")
        first_429 = statuses.index(429) + 1 if 429 in statuses else None
        phase1 = first_429 == 11
        print(f"\n  Primo 429 alla richiesta: {first_429}  (attesa: 11)")
        print(f"  {'[PASS]' if phase1 else '[FAIL]'} Fase 1")
        results["phase1_ip_rate_limit"] = {"statuses": statuses, "first_429_at": first_429, "passed": phase1}
        stop_sa(sa_proc)

        # FASE 2 ------------------------------------------------------------
        print("\n" + "-" * 80)
        print("FASE 2 — Tentativo di aggirare il rate limit falsificando X-Forwarded-For")
        print("-" * 80)
        sa_proc = start_sa()
        statuses = []
        for i in range(12):
            fake_ip = f"203.0.113.{i + 1}"
            r = auth(**VALID_USER, headers={"X-Forwarded-For": fake_ip})
            statuses.append(r.status_code)
            print(f"  Richiesta {i + 1:>2} dichiarata da {fake_ip:<13}: HTTP {r.status_code}")
        first_429 = statuses.index(429) + 1 if 429 in statuses else None
        phase2 = first_429 == 11
        print(f"\n  Primo 429 alla richiesta: {first_429}  (attesa: 11 — l'header viene ignorato)")
        print(f"  {'[PASS]' if phase2 else '[FAIL]'} Fase 2")
        results["phase2_spoofed_xff"] = {"statuses": statuses, "first_429_at": first_429, "passed": phase2}
        stop_sa(sa_proc)

        # FASE 3 ------------------------------------------------------------
        print("\n" + "-" * 80)
        print("FASE 3 — Blocco dell'account dopo 5 password errate")
        print("-" * 80)
        sa_proc = start_sa()
        attempts = []
        for i, pwd in enumerate(["wrong1", "wrong2", "wrong3", "wrong4", "wrong5", "wrong6"]):
            r = auth(VALID_USER["username"], pwd)
            attempts.append(r.status_code)
            print(f"  Tentativo {i + 1} (password errata): HTTP {r.status_code} — {r.json().get('error')}")
        r = auth(**VALID_USER)
        correct_while_locked = r.status_code
        print(f"  Tentativo 7 (password CORRETTA, account bloccato): HTTP {r.status_code} — "
              f"{r.json().get('error', 'token rilasciato')}")
        retry_after = r.json().get("retry_after_seconds")
        phase3 = attempts[:5] == [401] * 5 and attempts[5] == 429 and correct_while_locked == 429
        print(f"\n  Blocco residuo dichiarato: {retry_after}s")
        print(f"  {'[PASS]' if phase3 else '[FAIL]'} Fase 3")
        results["phase3_account_lockout"] = {"wrong_password_statuses": attempts,
                                             "correct_password_while_locked": correct_while_locked,
                                             "retry_after_seconds": retry_after, "passed": phase3}
        stop_sa(sa_proc)

        # FASE 4 ------------------------------------------------------------
        print("\n" + "-" * 80)
        print("FASE 4 — Enumerazione degli username tramite i tempi di risposta")
        print("-" * 80)
        sa_proc = start_sa()
        auth("riscaldamento.inesistente", "x", url=AUTH_URL_IP)  # prima richiesta esclusa dalla misura
        t_existing, t_missing = [], []
        for i in range(4):
            start = time.perf_counter()
            auth(VALID_USER["username"], f"sbagliata{i}", url=AUTH_URL_IP)
            t_existing.append((time.perf_counter() - start) * 1000)
            start = time.perf_counter()
            auth(f"utente.inesistente{i}", f"sbagliata{i}", url=AUTH_URL_IP)
            t_missing.append((time.perf_counter() - start) * 1000)
        med_existing = statistics.median(t_existing)
        med_missing = statistics.median(t_missing)
        ratio = med_missing / med_existing if med_existing else 0
        print(f"  Username esistente,   password errata: mediana {med_existing:7.1f} ms  {[round(t) for t in t_existing]}")
        print(f"  Username inesistente, password errata: mediana {med_missing:7.1f} ms  {[round(t) for t in t_missing]}")
        print(f"  Rapporto inesistente/esistente: {ratio:.2f}  (atteso ≈ 1; senza la difesa ≈ 0.01)")
        phase4 = 0.7 <= ratio <= 1.4
        print(f"  {'[PASS]' if phase4 else '[FAIL]'} Fase 4")
        results["phase4_timing_enumeration"] = {"median_ms_existing": round(med_existing, 1),
                                                "median_ms_missing": round(med_missing, 1),
                                                "ratio": round(ratio, 2), "passed": phase4}

        # FASE 5 ------------------------------------------------------------
        print("\n" + "-" * 80)
        print("FASE 5 — Protezione degli endpoint amministrativi")
        print("-" * 80)
        checks = [
            ("/reconcile senza token", "reconcile", {}, 403),
            ("/reconcile con token errato", "reconcile", {"X-Admin-Token": "0" * 64}, 403),
            ("/shutdown senza token", "shutdown", {}, 403),
            ("/reconcile con token corretto", "reconcile", admin_headers(), 200),
        ]
        admin_results = []
        for label, endpoint, headers, expected in checks:
            r = requests.post(f"{SA_URL}/{endpoint}", headers=headers, timeout=10, verify=sa_verify())
            ok = r.status_code == expected
            admin_results.append({"check": label, "http_status": r.status_code, "expected": expected, "ok": ok})
            print(f"  {label:<32} HTTP {r.status_code}  (atteso {expected})  {'✓' if ok else '✗'}")
        alive = requests.get(f"{SA_URL}/status", timeout=5, verify=sa_verify()).status_code == 200
        print(f"  SA ancora attivo dopo /shutdown non autorizzato: {'sì' if alive else 'no'}")
        phase5 = all(c["ok"] for c in admin_results) and alive
        print(f"  {'[PASS]' if phase5 else '[FAIL]'} Fase 5")
        results["phase5_admin_endpoints"] = {"checks": admin_results, "alive_after_unauthorized_shutdown": alive,
                                             "passed": phase5}

        passed = phase1 and phase2 and phase3 and phase4 and phase5
        print("\n" + "=" * 80)
        print("RIEPILOGO")
        print("=" * 80)
        print(f"  Fase 1 — rate limit per IP:                     {'PASS' if phase1 else 'FAIL'}")
        print(f"  Fase 2 — X-Forwarded-For falsificato ignorato:  {'PASS' if phase2 else 'FAIL'}")
        print(f"  Fase 3 — blocco account dopo 5 errori:          {'PASS' if phase3 else 'FAIL'}")
        print(f"  Fase 4 — tempi indistinguibili (no enumeraz.):  {'PASS' if phase4 else 'FAIL'}")
        print(f"  Fase 5 — endpoint amministrativi protetti:      {'PASS' if phase5 else 'FAIL'}")
        print("=" * 80)

        save_report(
            test_id="sa_bruteforce_defenses",
            test_name="Difese del SA (rate limit, IP falsificati, blocco account, timing, endpoint admin)",
            outcome="PASS" if passed else "FAIL",
            details=results,
        )

    finally:
        print("\n[*] Spegnimento SA e pulizia...")
        if sa_proc:
            stop_sa(sa_proc)
        clean_state()
        print("[*] File di stato rimossi.")


if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    try:
        main()
    finally:
        input("\nPremi Invio per chiudere...")

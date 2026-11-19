"""
Test Double Voting CONCORRENTE (race condition check-then-act).

Il test di double voting sequenziale (double_voting_attack.py) invia lo stesso
token due volte, una dopo l'altra: il secondo invio trova il nonce già marcato
come usato e viene rifiutato. Un attaccante reale però può inviare molte
richieste con lo stesso token NELLO STESSO ISTANTE: se il server controlla
"token già usato?" e solo più tardi marca il token, tutte le richieste che
arrivano nella finestra tra controllo e marcatura superano il controllo
(race condition check-then-act) e il voto viene conteggiato più volte.

Il test verifica tre proprietà:
  Fase 2 — N schede diverse inviate in parallelo con lo STESSO token all'AE:
           deve esserne accettata esattamente una (HTTP 200), le altre
           rifiutate con HTTP 409 "Token già usato".
  Fase 3 — N autenticazioni parallele dello stesso elettore presso il SA:
           devono restituire tutte lo stesso token (stesso nonce). Due nonce
           distinti significherebbero due credenziali di voto valide.
  Fase 4 — Coerenza dello stato: l'AE dichiara un solo voto e il Bulletin
           Board contiene un solo blocco di voto.
"""

import os
import sys
import json
import threading
import requests

PROJECT_ROOT  = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TESTS_SEC_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TESTS_SEC_DIR)

# Setup, teardown e costruzione del payload sono gli stessi del test di
# double voting sequenziale: si riusano per garantire condizioni identiche.
import double_voting_attack as base
from test_reporter import save_report
from tls_config import AE_URL, SA_URL, ae_verify, sa_verify

PARALLEL_VOTES = 8   # Richieste di voto simultanee con lo stesso token
PARALLEL_AUTHS = 6   # Autenticazioni simultanee dello stesso elettore (sotto il rate limit SA)


def fire_in_parallel(n: int, fn) -> list:
    """
    Esegue fn(i) in n thread che partono nello stesso istante.

    Una barriera trattiene tutti i thread finché non sono pronti, così le
    richieste arrivano al server sovrapposte nel tempo: è la condizione
    necessaria per far emergere una race condition.
    """
    barrier = threading.Barrier(n)
    results = [None] * n

    def worker(i: int) -> None:
        barrier.wait()
        results[i] = fn(i)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results


def main():
    print("\n" + "=" * 70)
    print("  TEST DOUBLE VOTING CONCORRENTE (RACE CONDITION)")
    print("=" * 70)
    try:
        base.setup()

        # ------------------------------------------------------------------ #
        # FASE 1 — Autenticazione e ottenimento token                         #
        # ------------------------------------------------------------------ #
        print("\n" + "-" * 70)
        print("FASE 1 — Autenticazione e ottenimento token")
        print("-" * 70)
        token, token_signature = base.get_valid_token()
        token_nonce = json.loads(token)["nonce"]
        print(f"  Nonce del token: {token_nonce}")

        # ------------------------------------------------------------------ #
        # FASE 2 — N schede diverse, stesso token, inviate simultaneamente    #
        # ------------------------------------------------------------------ #
        print("\n" + "-" * 70)
        print(f"FASE 2 — {PARALLEL_VOTES} schede diverse con lo STESSO token, inviate in parallelo")
        print("-" * 70)
        print("  Preparazione delle schede (cifratura + Proof of Work)...")
        payloads = [
            base.create_vote_payload(token, token_signature, candidate_index=i % 3)
            for i in range(PARALLEL_VOTES)
        ]
        for i, p in enumerate(payloads):
            print(f"    Scheda {i}: candidato {i % 3}, enc_vote {p['enc_vote'][:24]}...")

        print(f"\n  Invio simultaneo di {PARALLEL_VOTES} richieste all'AE...")

        def send_vote(i: int) -> dict:
            r = requests.post(f"{AE_URL}/vote", json=payloads[i], timeout=30, verify=ae_verify())
            return {"scheda": i, "http_status": r.status_code, "response": r.json()}

        vote_results = fire_in_parallel(PARALLEL_VOTES, send_vote)
        for res in vote_results:
            esito = res["response"].get("error", f"accettata, leaf_index {res['response'].get('leaf_index')}")
            print(f"    Scheda {res['scheda']}: HTTP {res['http_status']} — {esito}")

        accepted = [r for r in vote_results if r["http_status"] == 200]
        rejected_409 = [r for r in vote_results if r["http_status"] == 409]
        phase2_pass = len(accepted) == 1 and len(rejected_409) == PARALLEL_VOTES - 1
        print(f"\n  Accettate: {len(accepted)}  (attese: 1)")
        print(f"  Rifiutate 409: {len(rejected_409)}  (attese: {PARALLEL_VOTES - 1})")
        print(f"  {'[PASS]' if phase2_pass else '[FAIL]'} Fase 2")

        # ------------------------------------------------------------------ #
        # FASE 3 — Autenticazioni parallele dello stesso elettore (SA)        #
        # ------------------------------------------------------------------ #
        print("\n" + "-" * 70)
        print(f"FASE 3 — {PARALLEL_AUTHS} autenticazioni simultanee dello stesso elettore")
        print("-" * 70)
        voter = base.VOTERS[1]
        print(f"  Elettore: {voter['username']} (non ancora autenticato)")

        def authenticate(i: int) -> dict:
            r = requests.post(f"{SA_URL}/authenticate",
                              json={"username": voter["username"], "password": voter["password"]},
                              timeout=30, verify=sa_verify())
            body = r.json()
            nonce = json.loads(body["token"])["nonce"] if r.status_code == 200 else None
            return {"richiesta": i, "http_status": r.status_code, "nonce": nonce}

        auth_results = fire_in_parallel(PARALLEL_AUTHS, authenticate)
        for res in auth_results:
            print(f"    Richiesta {res['richiesta']}: HTTP {res['http_status']} — nonce {res['nonce']}")

        nonces = {r["nonce"] for r in auth_results if r["http_status"] == 200}
        all_ok = all(r["http_status"] == 200 for r in auth_results)
        phase3_pass = all_ok and len(nonces) == 1
        print(f"\n  Nonce distinti emessi: {len(nonces)}  (atteso: 1)")
        print(f"  {'[PASS]' if phase3_pass else '[FAIL]'} Fase 3")

        # ------------------------------------------------------------------ #
        # FASE 4 — Coerenza dello stato AE e Bulletin Board                   #
        # ------------------------------------------------------------------ #
        print("\n" + "-" * 70)
        print("FASE 4 — Coerenza dello stato dopo l'attacco")
        print("-" * 70)
        status = requests.get(f"{AE_URL}/status", timeout=5, verify=ae_verify()).json()
        with open(base.BULLETIN_BOARD_PATH, "r", encoding="utf-8") as f:
            bb = json.load(f)
        vote_blocks = sum(1 for b in bb if b["type"] == "vote")
        print(f"  Voti dichiarati dall'AE (/status): {status['votes_received']}  (atteso: 1)")
        print(f"  Blocchi voto nel Bulletin Board:   {vote_blocks}  (atteso: 1)")
        phase4_pass = status["votes_received"] == 1 and vote_blocks == 1
        print(f"  {'[PASS]' if phase4_pass else '[FAIL]'} Fase 4")

        # ------------------------------------------------------------------ #
        # Riepilogo                                                           #
        # ------------------------------------------------------------------ #
        passed = phase2_pass and phase3_pass and phase4_pass
        print("\n" + "=" * 70)
        print("RIEPILOGO")
        print("=" * 70)
        print(f"  Fase 2 — un solo voto accettato su {PARALLEL_VOTES} paralleli: {'PASS' if phase2_pass else 'FAIL'}")
        print(f"  Fase 3 — un solo token per elettore con auth parallele:  {'PASS' if phase3_pass else 'FAIL'}")
        print(f"  Fase 4 — stato AE e Bulletin Board coerenti:             {'PASS' if phase4_pass else 'FAIL'}")
        if passed:
            print("\n  [SUCCESS] Controllo e marcatura del token sono atomici:")
            print("  richieste simultanee non producono voti né token multipli.")
        else:
            print("\n  [FAIL] Race condition rilevata: il sistema è vulnerabile al")
            print("  double voting tramite richieste concorrenti.")
        print("=" * 70)

        save_report(
            test_id="concurrent_double_voting",
            test_name="Double Voting Concorrente (Race Condition)",
            outcome="PASS" if passed else "FAIL",
            details={
                "token_nonce": token_nonce,
                "phase2_parallel_votes": {
                    "requests": PARALLEL_VOTES,
                    "accepted_200": len(accepted),
                    "rejected_409": len(rejected_409),
                    "results": [{"scheda": r["scheda"], "http_status": r["http_status"]} for r in vote_results],
                    "passed": phase2_pass,
                },
                "phase3_parallel_auth": {
                    "voter": voter["username"],
                    "requests": PARALLEL_AUTHS,
                    "distinct_nonces": len(nonces),
                    "passed": phase3_pass,
                },
                "phase4_state": {
                    "ae_votes_received": status["votes_received"],
                    "bulletin_board_vote_blocks": vote_blocks,
                    "passed": phase4_pass,
                },
                "protection_mechanism": "Lock sulle sezioni critiche di /vote (AE) e /authenticate (SA)",
            },
        )

    finally:
        base.teardown()


if __name__ == "__main__":
    os.chdir(PROJECT_ROOT)
    try:
        main()
    except Exception as e:
        print(f"\n[ERRORE] {e}")
    finally:
        input("\nPremi Invio per chiudere...")

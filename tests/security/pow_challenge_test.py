"""
Test della Proof of Work legata a una challenge del server e adattiva per IP.

La PoW si calcola su SHA-256(challenge || enc_vote || nonce), dove la challenge
è emessa dall'AE, autenticata con HMAC, legata all'IP, valida 2 minuti e
utilizzabile una sola volta; la difficoltà adattiva è calcolata per IP.

Gli attacchi messi in scena sono due:
- precalcolo: l'attaccante risolve offline, con tutto il tempo a disposizione,
  molte PoW per schede scelte da lui, per inviarle poi tutte insieme;
- amplificazione: l'attaccante risolve a raffica PoW facili sperando di alzare
  la difficoltà per tutti gli elettori onesti.

Il test usa direttamente le funzioni dell'AE con IP simulati (in locale tutte
le richieste arriverebbero da 127.0.0.1):

  [1] PoW precalcolata senza challenge          → rifiutata
  [2] PoW su challenge valida                    → accettata; riuso → rifiutato
  [3] Challenge con difficoltà abbassata a mano  → rifiutata (HMAC)
  [4] Challenge dell'IP A usata dall'IP B        → rifiutata
  [5] Challenge scaduta                          → rifiutata
  [6] Flood di PoW valide dall'IP A              → difficoltà alta per A, minima per B
  [7] Challenge facile ottenuta PRIMA del flood  → non basta più dopo il flood

Non richiede server avviati: è un test offline sulle funzioni dell'AE.
"""

import hashlib
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SRC_DIR = os.path.join(PROJECT_ROOT, "src")
TESTS_SEC_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SRC_DIR)
sys.path.insert(0, TESTS_SEC_DIR)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "tests"))

from test_reporter import save_report
from common import solve_pow
import ae

IP_A, IP_B = "203.0.113.10", "198.51.100.20"


def old_style_pow(enc_vote_hex: str, difficulty: int) -> str:
    """PoW precalcolata dall'attaccante senza challenge del server: SHA-256(enc_vote || nonce)."""
    data = bytes.fromhex(enc_vote_hex)
    nonce = 0
    while True:
        nb = nonce.to_bytes(8, "big")
        if int.from_bytes(hashlib.sha256(data + nb).digest(), "big") >> (256 - difficulty) == 0:
            return nb.hex()
        nonce += 1


def fresh_vote() -> str:
    return os.urandom(256).hex()


def main():
    print("=" * 80)
    print("  TEST PROOF OF WORK CON CHALLENGE DEL SERVER E DIFFICOLTÀ PER IP")
    print("=" * 80)
    results = {}

    # [1] ---------------------------------------------------------------------
    print("\n[1] PoW precalcolata offline dall'attaccante, senza challenge del server")
    vote = fresh_vote()
    nonce = old_style_pow(vote, ae.POW_MIN_DIFFICULTY)
    ok = ae.verify_pow(None, vote, nonce, IP_A)
    print(f"    nonce {nonce} valido per SHA-256(enc_vote || nonce) → accettata dall'AE? {ok}")
    results["precomputed_without_challenge_rejected"] = not ok

    # [2] ---------------------------------------------------------------------
    print("\n[2] PoW su una challenge valida, poi riuso della stessa challenge")
    ch = ae.issue_pow_challenge(IP_A)
    print(f"    challenge {ch['challenge'][:32]}...  difficoltà {ch['difficulty']} bit, scade in {ch['expires_in']} s")
    vote = fresh_vote()
    nonce = solve_pow(ch["challenge"], vote, ch["difficulty"])
    first = ae.verify_pow(ch["challenge"], vote, nonce, IP_A)
    vote2 = fresh_vote()
    replay = ae.verify_pow(ch["challenge"], vote2, solve_pow(ch["challenge"], vote2, ch["difficulty"]), IP_A)
    print(f"    prima PoW accettata? {first}   |   seconda PoW sulla stessa challenge accettata? {replay}")
    results["valid_challenge_accepted"] = first
    results["challenge_replay_rejected"] = not replay

    # [3] ---------------------------------------------------------------------
    print("\n[3] Challenge falsificata: difficoltà portata a 0 bit")
    ch = ae.issue_pow_challenge(IP_A)
    raw = bytearray(bytes.fromhex(ch["challenge"]))
    raw[24] = 0  # byte della difficoltà
    forged = bytes(raw).hex()
    vote = fresh_vote()
    ok = ae.verify_pow(forged, vote, "00" * 8, IP_A)
    print(f"    challenge alterata accettata con un nonce qualsiasi? {ok}")
    results["forged_challenge_rejected"] = not ok

    # [4] ---------------------------------------------------------------------
    print("\n[4] Challenge emessa per l'IP A usata dall'IP B")
    ch = ae.issue_pow_challenge(IP_A)
    vote = fresh_vote()
    nonce = solve_pow(ch["challenge"], vote, ch["difficulty"])
    ok = ae.verify_pow(ch["challenge"], vote, nonce, IP_B)
    print(f"    PoW corretta ma inviata da un altro IP accettata? {ok}")
    results["challenge_bound_to_ip"] = not ok

    # [5] ---------------------------------------------------------------------
    print("\n[5] Challenge scaduta")
    original_ttl = ae.POW_CHALLENGE_TTL_SECONDS
    ae.POW_CHALLENGE_TTL_SECONDS = -1  # challenge già scaduta al momento dell'emissione
    ch = ae.issue_pow_challenge(IP_A)
    ae.POW_CHALLENGE_TTL_SECONDS = original_ttl
    vote = fresh_vote()
    nonce = solve_pow(ch["challenge"], vote, ch["difficulty"])
    ok = ae.verify_pow(ch["challenge"], vote, nonce, IP_A)
    print(f"    PoW corretta su challenge scaduta accettata? {ok}")
    results["expired_challenge_rejected"] = not ok

    # [6] e [7] ---------------------------------------------------------------
    print("\n[6] Flood di PoW valide dall'IP A: la difficoltà cresce solo per A")
    early = ae.issue_pow_challenge(IP_A)  # challenge facile ottenuta prima del flood
    print(f"    (l'attaccante conserva una challenge a {early['difficulty']} bit ottenuta prima del flood)")
    accepted = 0
    for i in range(30):
        ch = ae.issue_pow_challenge(IP_A)
        vote = fresh_vote()
        if ae.verify_pow(ch["challenge"], vote, solve_pow(ch["challenge"], vote, ch["difficulty"]), IP_A):
            ae.record_valid_pow(IP_A)
            accepted += 1
    diff_a = ae.current_pow_difficulty(IP_A)
    diff_b = ae.current_pow_difficulty(IP_B)
    print(f"    PoW valide inviate da A: {accepted}")
    print(f"    Difficoltà per l'IP A (attaccante): {diff_a} bit")
    print(f"    Difficoltà per l'IP B (elettore onesto): {diff_b} bit")
    results["per_ip"] = {"accepted": accepted, "difficulty_attacker": diff_a, "difficulty_honest": diff_b}
    results["per_ip_isolation"] = diff_a > ae.POW_MIN_DIFFICULTY and diff_b == ae.POW_MIN_DIFFICULTY

    print("\n[7] La challenge facile ottenuta prima del flood non basta più")
    vote = fresh_vote()
    nonce = solve_pow(early["challenge"], vote, early["difficulty"])
    ok = ae.verify_pow(early["challenge"], vote, nonce, IP_A)
    print(f"    PoW a {early['difficulty']} bit accettata ora che A è a {diff_a} bit? {ok}")
    results["stale_easy_challenge_rejected"] = not ok

    checks = [
        ("[1] PoW precalcolata senza challenge rifiutata", results["precomputed_without_challenge_rejected"]),
        ("[2] PoW su challenge valida accettata", results["valid_challenge_accepted"]),
        ("[2] Riuso della challenge rifiutato", results["challenge_replay_rejected"]),
        ("[3] Challenge falsificata rifiutata", results["forged_challenge_rejected"]),
        ("[4] Challenge legata all'IP", results["challenge_bound_to_ip"]),
        ("[5] Challenge scaduta rifiutata", results["expired_challenge_rejected"]),
        ("[6] Difficoltà alzata solo per l'IP attaccante", results["per_ip_isolation"]),
        ("[7] Challenge facile pre-flood non più sufficiente", results["stale_easy_challenge_rejected"]),
    ]
    passed = all(ok for _, ok in checks)
    print("\n" + "=" * 80)
    print("RIEPILOGO")
    print("=" * 80)
    for label, ok in checks:
        print(f"  {'[PASS]' if ok else '[FAIL]'} {label}")
    print("=" * 80)

    save_report(
        test_id="pow_challenge",
        test_name="Proof of Work con challenge del server e difficoltà per IP",
        outcome="PASS" if passed else "FAIL",
        details=results,
    )


if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    try:
        main()
    finally:
        input("\nPremi Invio per chiudere...")

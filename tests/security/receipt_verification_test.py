"""
Test di Verifica Individuale delle Ricevute (Merkle Proof al momento del voto).

Ogni elettore riceve, al momento del voto, una ricevuta firmata dall'AE che
contiene la Merkle Proof della propria scheda. Poiché l'albero cresce con i
voti successivi, quella proof è valida rispetto alla root DI QUEL MOMENTO e
non rispetto alla root finale: per questo la ricevuta include anche
tree_size e merkle_root_at_vote, e il client, a urne chiuse:
  - verifica la proof contro merkle_root_at_vote;
  - controlla che i primi tree_size voti del Bulletin Board producano ancora
    quella root (il registro non è stato riscritto dopo il voto);
  - ricostruisce l'albero dal Bulletin Board e verifica l'inclusione nella
    root finale firmata.

Il test verifica, usando il codice reale del client (Client.verify_vote):
  Fase 1 — più elettori votano in sequenza;
  Fase 2 — l'AE viene riavviata a urne aperte e un altro elettore vota
           (l'albero deve essere ricostruito dal Bulletin Board);
  Fase 3 — chiusura urne: TUTTE le ricevute devono essere verificate,
           non solo quella dell'ultimo votante;
  Fase 4 — verifica universale (Observer) dell'elezione;
  Fase 5 — un'AE corrotta riscrive una scheda già registrata, ricalcola e
           RI-FIRMA la Merkle Root finale: le ricevute di chi ha votato
           da quel momento in poi devono rilevare la manomissione.
"""

import io
import os
import sys
import json
import time
import subprocess
import contextlib
import requests

PROJECT_ROOT  = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SRC_DIR       = os.path.join(PROJECT_ROOT, "src")
TESTS_SEC_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SRC_DIR)
sys.path.insert(0, TESTS_SEC_DIR)

# Setup e teardown sono quelli del test di double voting (elezione di test
# con SA e AE come sottoprocessi); si aggiungono elettori per avere più voti.
import double_voting_attack as base
from test_reporter import save_report
from tls_config import AE_URL, SA_URL, ae_verify, sa_verify, admin_cert
from common import close_payload

from client import Client
from crypto.keys import load_private_key, deserialize_public_key
from crypto.merkle import MerkleTree
from crypto.rsa_oaep import encrypt
from crypto.rsa_pss import sign

base.VOTERS = base.VOTERS + [
    {"id": "v004", "email": "s.esposito@studenti.unisa.it",
     "username": "sara.espo",  "password": "pass_sE99"},
    {"id": "v005", "email": "luca.ferrante@unisa.it",
     "username": "luca.ferr",  "password": "pass_lF01"},
    {"id": "v006", "email": "a.damico3@studenti.unisa.it",
     "username": "ale.damico", "password": "pass_aD03"},
]
VOTES_BEFORE_RESTART = 4     # elettori che votano prima del riavvio dell'AE
TAMPERED_LEAF = 2            # scheda riscritta dall'AE corrotta nella Fase 5
RECEIPTS_DIR = os.path.join(PROJECT_ROOT, "data", "receipts")


def authenticate(voter: dict):
    r = requests.post(f"{SA_URL}/authenticate",
                      json={"username": voter["username"], "password": voter["password"]},
                      timeout=10, verify=sa_verify())
    r.raise_for_status()
    body = r.json()
    return body["token"], body["signature"]


def cast_vote(voter: dict, candidate_index: int) -> dict:
    """Autentica l'elettore, vota e salva la ricevuta come farebbe il client."""
    token, sig = authenticate(voter)
    payload = base.create_vote_payload(token, sig, candidate_index=candidate_index)
    r = requests.post(f"{AE_URL}/vote", json=payload, timeout=10, verify=ae_verify())
    r.raise_for_status()
    receipt = r.json()
    os.makedirs(RECEIPTS_DIR, exist_ok=True)
    with open(os.path.join(RECEIPTS_DIR, f"{voter['username']}.json"), "w", encoding="utf-8") as f:
        json.dump(receipt, f, indent=2, ensure_ascii=False)
    print(f"    {voter['username']:<13} → candidato {candidate_index}  "
          f"leaf_index {receipt['leaf_index']}  tree_size {receipt['tree_size']}  "
          f"root_at_vote {receipt['merkle_root_at_vote'][:16]}...")
    return receipt


def verify_receipt(voter: dict) -> tuple:
    """Esegue Client.verify_vote() e ne restituisce (esito, ultima riga di output)."""
    client = Client()
    client.username = voter["username"]
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        ok = client.verify_vote()
    lines = [l for l in buf.getvalue().strip().splitlines() if l.strip()]
    message = next((l.strip() for l in lines if "fallita" in l or "non " in l.lower() and "!" in l),
                   lines[-1].strip() if lines else "")
    return bool(ok), message


def restart_ae() -> None:
    """Spegne l'AE e la riavvia come nuovo processo, a urne aperte."""
    try:
        requests.post(f"{AE_URL}/shutdown", cert=admin_cert(), timeout=2, verify=ae_verify())
    except Exception:
        pass
    if base.ae_process:
        try:
            base.ae_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            base.ae_process.kill()
    time.sleep(1)
    base.ae_process = subprocess.Popen(
        [sys.executable, os.path.join(SRC_DIR, "ae.py")],
        cwd=PROJECT_ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    assert base._wait_server(AE_URL, "AE"), "AE non risponde dopo il riavvio."


def corrupt_authority_rewrites_vote(leaf_index: int) -> dict:
    """
    Simula un'AE corrotta: sostituisce la scheda alla posizione leaf_index con
    una nuova scheda per un altro candidato, ricalcola la Merkle Root finale e
    la RI-FIRMA con la propria chiave. Il Bulletin Board resta quindi
    internamente coerente: solo le ricevute degli elettori possono accorgersene.
    """
    with open(base.BULLETIN_BOARD_PATH, "r", encoding="utf-8") as f:
        bb = json.load(f)
    ae_encrypt_public = deserialize_public_key(bb[0]["data"]["ae_encrypt_public"])
    ae_sign_private = load_private_key("ae_sign", base_path=base.KEYS_DIR)

    vote_blocks = [b for b in bb if b["type"] == "vote"]
    target = vote_blocks[leaf_index]
    old_enc = target["data"]["enc_vote"]
    target["data"]["enc_vote"] = encrypt(ae_encrypt_public, (1).to_bytes(1, "big"), seed=os.urandom(32)).hex()
    target["signature"] = sign(ae_sign_private, json.dumps(target["data"], sort_keys=True).encode()).hex()

    tree = MerkleTree()
    for b in vote_blocks:
        tree.add_leaf(json.dumps(b["data"], sort_keys=True).encode("utf-8"))
    root_block = next(b for b in bb if b["type"] == "merkle_root")
    old_root = root_block["data"]["merkle_root"]
    root_block["data"]["merkle_root"] = tree.get_root()
    root_block["signature"] = sign(ae_sign_private, json.dumps(root_block["data"], sort_keys=True).encode()).hex()

    with open(base.BULLETIN_BOARD_PATH, "w", encoding="utf-8") as f:
        json.dump(bb, f, indent=2, ensure_ascii=False)
    return {"leaf_index": leaf_index, "old_enc_vote": old_enc[:32] + "...",
            "new_enc_vote": target["data"]["enc_vote"][:32] + "...",
            "old_root": old_root, "new_root": root_block["data"]["merkle_root"]}


def main():
    print("\n" + "=" * 80)
    print("  TEST VERIFICA INDIVIDUALE DELLE RICEVUTE (MERKLE PROOF)")
    print("=" * 80)
    voters = base.VOTERS
    try:
        base.setup()

        # FASE 1 ------------------------------------------------------------
        print("\n" + "-" * 80)
        print(f"FASE 1 — {VOTES_BEFORE_RESTART} elettori votano in sequenza")
        print("-" * 80)
        receipts = {}
        for i, voter in enumerate(voters[:VOTES_BEFORE_RESTART]):
            receipts[voter["username"]] = cast_vote(voter, i % 3)
        root_before_restart = receipts[voters[VOTES_BEFORE_RESTART - 1]["username"]]["merkle_root_at_vote"]

        # FASE 2 ------------------------------------------------------------
        print("\n" + "-" * 80)
        print("FASE 2 — Riavvio dell'AE a urne aperte, poi altri voti")
        print("-" * 80)
        restart_ae()
        print("  AE riavviata.")
        for i, voter in enumerate(voters[VOTES_BEFORE_RESTART:], start=VOTES_BEFORE_RESTART):
            receipts[voter["username"]] = cast_vote(voter, i % 3)
        first_after = receipts[voters[VOTES_BEFORE_RESTART]["username"]]
        # Dopo il riavvio la nuova scheda deve proseguire la numerazione e la
        # root deve includere i voti precedenti (albero ricostruito).
        rebuilt_ok = first_after["leaf_index"] == VOTES_BEFORE_RESTART
        print(f"\n  Prima scheda dopo il riavvio: leaf_index {first_after['leaf_index']} "
              f"(atteso {VOTES_BEFORE_RESTART}) — albero {'ricostruito' if rebuilt_ok else 'NON ricostruito'}")
        print(f"  Root prima del riavvio: {root_before_restart[:32]}...")
        print(f"  {'[PASS]' if rebuilt_ok else '[FAIL]'} Fase 2")

        # FASE 3 ------------------------------------------------------------
        print("\n" + "-" * 80)
        print("FASE 3 — Chiusura urne e verifica individuale di TUTTE le ricevute")
        print("-" * 80)
        # La chiave di decifratura è protetta da Shamir 2-su-3: con una sola
        # quota l'AE deve rifiutare la chiusura e lasciare le urne aperte.
        early = requests.post(f"{AE_URL}/close", cert=admin_cert(), json=close_payload(1),
                              timeout=30, verify=ae_verify())
        still_open = requests.get(f"{AE_URL}/status", timeout=5, verify=ae_verify()).json()["urn_open"]
        one_share_rejected = early.status_code == 400 and still_open
        print(f"  Chiusura con 1 sola quota di scrutatore: HTTP {early.status_code} — "
              f"{early.json().get('error')}  (urne ancora aperte: {still_open})")
        print(f"  {'[PASS]' if one_share_rejected else '[FAIL]'} Una quota non basta per decifrare\n")

        requests.post(f"{SA_URL}/reconcile", cert=admin_cert(), timeout=10, verify=sa_verify()).raise_for_status()
        close = requests.post(f"{AE_URL}/close", cert=admin_cert(), json=close_payload(), timeout=60, verify=ae_verify())
        close.raise_for_status()
        print(f"  Scrutinio: {close.json()['result']}")
        with open(base.BULLETIN_BOARD_PATH, "r", encoding="utf-8") as f:
            final_root = next(b for b in json.load(f) if b["type"] == "merkle_root")["data"]["merkle_root"]
        print(f"  Merkle Root finale: {final_root[:32]}...\n")

        verification = {}
        for voter in voters:
            ok, msg = verify_receipt(voter)
            verification[voter["username"]] = ok
            r = receipts[voter["username"]]
            print(f"    {voter['username']:<13} leaf {r['leaf_index']}  tree_size {r['tree_size']}  "
                  f"→ {'✓ verificata' if ok else '✗ FALLITA: ' + msg}")
        phase3_pass = all(verification.values()) and one_share_rejected
        print(f"\n  Ricevute verificate: {sum(verification.values())}/{len(voters)}")
        print(f"  {'[PASS]' if phase3_pass else '[FAIL]'} Fase 3")

        # FASE 4 ------------------------------------------------------------
        print("\n" + "-" * 80)
        print("FASE 4 — Verifica universale (Observer)")
        print("-" * 80)
        obs = subprocess.run([sys.executable, os.path.join(SRC_DIR, "observer.py")],
                             cwd=PROJECT_ROOT, input="\n", capture_output=True, text=True,
                             encoding="utf-8", errors="replace")
        phase4_pass = "TUTTE LE VERIFICHE PUBBLICHE SONO RIUSCITE" in obs.stdout
        for line in obs.stdout.splitlines():
            if line.strip() and line.strip()[0].isdigit():
                print(f"    {line.strip()}")
        print(f"  {'[PASS]' if phase4_pass else '[FAIL]'} Fase 4")

        # Rimozione di un blocco: l'AE cancella dal registro la riconciliazione
        # del SA (firmata dal SA, quindi non falsificabile dall'AE), sperando che
        # l'assenza passi inosservata. Ogni blocco contiene l'hash del precedente
        # (prev_hash), quindi la sequenza rotta deve essere rilevata.
        with open(base.BULLETIN_BOARD_PATH, "r", encoding="utf-8") as f:
            intact_bb = json.load(f)
        removed_bb = [b for b in intact_bb if b["type"] != "reconciliation_sa"]
        with open(base.BULLETIN_BOARD_PATH, "w", encoding="utf-8") as f:
            json.dump(removed_bb, f, indent=2, ensure_ascii=False)
        obs_removed = subprocess.run([sys.executable, os.path.join(SRC_DIR, "observer.py")],
                                     cwd=PROJECT_ROOT, input="\n", capture_output=True, text=True,
                                     encoding="utf-8", errors="replace")
        with open(base.BULLETIN_BOARD_PATH, "w", encoding="utf-8") as f:
            json.dump(intact_bb, f, indent=2, ensure_ascii=False)
        removal_detected = "ALCUNE VERIFICHE PUBBLICHE HANNO FALLITO" in obs_removed.stdout
        chain_line = next((l.strip() for l in obs_removed.stdout.splitlines() if "Catena interrotta" in l), "")
        print(f"\n  Blocco reconciliation_sa rimosso dal registro → Observer: "
              f"{'FAIL (rilevato)' if removal_detected else 'OK (NON rilevato)'}")
        if chain_line:
            print(f"    {chain_line}")
        print(f"  {'[PASS]' if removal_detected else '[FAIL]'} Rimozione di un blocco rilevata dalla catena di hash")
        phase4_pass = phase4_pass and removal_detected

        # FASE 5 ------------------------------------------------------------
        print("\n" + "-" * 80)
        print(f"FASE 5 — AE corrotta riscrive la scheda {TAMPERED_LEAF} e ri-firma la Merkle Root")
        print("-" * 80)
        tamper = corrupt_authority_rewrites_vote(TAMPERED_LEAF)
        print(f"  enc_vote originale: {tamper['old_enc_vote']}")
        print(f"  enc_vote sostituito: {tamper['new_enc_vote']}")
        print(f"  Merkle Root ri-firmata: {tamper['old_root'][:24]}... → {tamper['new_root'][:24]}...")
        print("  (Il Bulletin Board è internamente coerente: firme e root tornano.)\n")

        tamper_results = {}
        phase5_pass = True
        for voter in voters:
            r = receipts[voter["username"]]
            # Chi ha votato PRIMA della scheda manomessa non è coinvolto (il suo
            # prefisso di registro è intatto); da quel voto in poi, ogni ricevuta
            # copre la scheda manomessa e deve rilevare l'alterazione.
            should_detect = r["tree_size"] > TAMPERED_LEAF
            ok, msg = verify_receipt(voter)
            detected = not ok
            tamper_results[voter["username"]] = {"should_detect": should_detect, "detected": detected,
                                                 "message": msg if detected else None}
            correct = detected == should_detect
            phase5_pass = phase5_pass and correct
            atteso = "rilevamento" if should_detect else "nessun impatto"
            esito = f"✗ manomissione rilevata: {msg}" if detected else "✓ verificata (non coinvolta)"
            print(f"    {voter['username']:<13} tree_size {r['tree_size']}  atteso: {atteso:<15} → {esito}"
                  f"{'' if correct else '   [ESITO INATTESO]'}")
        print(f"\n  {'[PASS]' if phase5_pass else '[FAIL]'} Fase 5")

        # RIEPILOGO ---------------------------------------------------------
        passed = rebuilt_ok and phase3_pass and phase4_pass and phase5_pass
        print("\n" + "=" * 80)
        print("RIEPILOGO")
        print("=" * 80)
        print(f"  Fase 2 — albero ricostruito dopo il riavvio dell'AE:     {'PASS' if rebuilt_ok else 'FAIL'}")
        print(f"  Fase 3 — tutte le ricevute verificate a urne chiuse:     {'PASS' if phase3_pass else 'FAIL'}")
        print(f"  Fase 4 — verifica universale dell'Observer:              {'PASS' if phase4_pass else 'FAIL'}")
        print(f"  Fase 5 — manomissione rilevata dalle ricevute coinvolte: {'PASS' if phase5_pass else 'FAIL'}")
        print("=" * 80)

        save_report(
            test_id="receipt_verification",
            test_name="Verifica Individuale delle Ricevute (Merkle Proof al momento del voto)",
            outcome="PASS" if passed else "FAIL",
            details={
                "voters": len(voters),
                "ae_restart_after_votes": VOTES_BEFORE_RESTART,
                "receipts": {u: {"leaf_index": r["leaf_index"], "tree_size": r["tree_size"],
                                 "merkle_root_at_vote": r["merkle_root_at_vote"]}
                             for u, r in receipts.items()},
                "final_merkle_root": final_root,
                "phase2_tree_rebuilt_after_restart": rebuilt_ok,
                "close_with_one_share_rejected": one_share_rejected,
                "phase3_individual_verification": verification,
                "phase4_observer_ok": phase4_pass,
                "block_removal_detected_by_hash_chain": removal_detected,
                "phase5_tampering": {"tamper": tamper, "results": tamper_results, "passed": phase5_pass},
            },
        )

    finally:
        base.teardown()
        if os.path.isdir(RECEIPTS_DIR):
            for f in os.listdir(RECEIPTS_DIR):
                if f.endswith(".json"):
                    os.remove(os.path.join(RECEIPTS_DIR, f))


if __name__ == "__main__":
    os.chdir(PROJECT_ROOT)
    try:
        main()
    except Exception as e:
        print(f"\n[ERRORE] {e}")
    finally:
        input("\nPremi Invio per chiudere...")

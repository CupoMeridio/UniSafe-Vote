"""
Modulo condiviso per il salvataggio dei risultati dei test di sicurezza.

Ogni test chiama `save_report(test_id, outcome)` alla fine della propria
esecuzione. Il report viene scritto come file JSON in tests/output/ con
nome strutturato:

    <test_id>_YYYYMMDD_HHMMSS.json

In questo modo ogni run produce un file distinto e l'intera storia delle
esecuzioni è consultabile ordinando per nome file.

Schema del file JSON generato
------------------------------
{
  "test_id":    "dictionary_attack",        // identificatore breve del test
  "test_name":  "Attacco Dizionario / ...", // nome leggibile
  "timestamp":  "2026-06-14T15:30:00Z",    // UTC ISO-8601
  "outcome":    "PASS" | "FAIL" | "ERROR", // esito complessivo
  "details":    { ... }                    // dati specifici di ogni test
}
"""

import json
import os
from datetime import datetime, UTC

# I report vengono salvati in tests/output/, nella stessa cartella in cui
# risiedono già i CSV prodotti da Locust.
_TESTS_DIR  = os.path.dirname(os.path.abspath(__file__))
_OUTPUT_DIR = os.path.join(os.path.dirname(_TESTS_DIR), "output")


def save_report(test_id: str, test_name: str, outcome: str, details: dict) -> str:
    """
    Serializza i risultati di un test in un file JSON datato.

    Parametri
    ----------
    test_id   : identificatore breve senza spazi (es. "dictionary_attack")
    test_name : nome leggibile mostrato nel report (es. "Attacco Dizionario")
    outcome   : "PASS", "FAIL" o "ERROR"
    details   : dizionario con i dati specifici del test (qualsiasi struttura)

    Ritorna il path assoluto del file creato.
    """
    os.makedirs(_OUTPUT_DIR, exist_ok=True)

    now       = datetime.now(UTC)
    timestamp = now.strftime("%Y%m%d_%H%M%S")
    filename  = f"{test_id}_{timestamp}.json"
    filepath  = os.path.join(_OUTPUT_DIR, filename)

    report = {
        "test_id":   test_id,
        "test_name": test_name,
        "timestamp": now.isoformat(),
        "outcome":   outcome,
        "details":   details,
    }

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"\n[REPORT] Risultati salvati in: {filepath}")
    return filepath

"""
Autenticazione delle operazioni amministrative di SA e AE.

Gli endpoint /close, /reconcile e /shutdown modificano lo stato dell'elezione
o spengono i server: senza protezione chiunque raggiunga il server potrebbe
chiudere le urne in anticipo o interrompere la votazione.

Meccanismo (adatto a un PoC eseguito in locale):
- al primo avvio, SA o AE generano un token casuale di 256 bit e lo salvano in
  data/keys/admin_token (cartella esclusa da git, come le chiavi private);
- il pannello di controllo e i test leggono il token dal file e lo inviano
  nell'header X-Admin-Token;
- i server confrontano l'header con il token a tempo costante.

Possedere il token equivale ad avere accesso in lettura a data/keys/, cioè
alla macchina che ospita i server: lo stesso livello di fiducia richiesto per
leggere le chiavi private.
"""

import hmac
import os
import secrets
import time
from functools import wraps

from flask import jsonify, request

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ADMIN_TOKEN_PATH = os.path.join(PROJECT_ROOT, "data", "keys", "admin_token")
ADMIN_HEADER = "X-Admin-Token"


def get_or_create_admin_token() -> str:
    """
    Restituisce il token amministrativo, creandolo se non esiste.

    La creazione usa O_EXCL: se SA e AE si avviano nello stesso istante, solo
    uno dei due crea il file e l'altro legge il token già scritto, così i due
    server condividono sempre lo stesso token.
    """
    os.makedirs(os.path.dirname(ADMIN_TOKEN_PATH), exist_ok=True)
    try:
        fd = os.open(ADMIN_TOKEN_PATH, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        # Un altro processo lo sta creando o lo ha già creato: attende che il
        # contenuto sia stato scritto.
        for _ in range(50):
            token = read_admin_token()
            if token:
                return token
            time.sleep(0.05)
        raise RuntimeError("Token amministrativo presente ma vuoto")
    token = secrets.token_hex(32)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(token)
    return token


def read_admin_token() -> str:
    """Legge il token amministrativo dal file; stringa vuota se assente."""
    try:
        with open(ADMIN_TOKEN_PATH, "r", encoding="utf-8") as f:
            return f.read().strip()
    except FileNotFoundError:
        return ""


def admin_headers() -> dict:
    """Header da allegare alle richieste amministrative verso SA e AE."""
    token = read_admin_token()
    return {ADMIN_HEADER: token} if token else {}


def require_admin(view):
    """Decoratore Flask: risponde 403 se l'header X-Admin-Token non è valido."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        expected = read_admin_token()
        provided = request.headers.get(ADMIN_HEADER, "")
        if not expected or not hmac.compare_digest(provided.encode(), expected.encode()):
            print(f"[ADMIN] Richiesta amministrativa rifiutata su {request.path} da {request.remote_addr}")
            return jsonify({"error": "Operazione amministrativa non autorizzata"}), 403
        return view(*args, **kwargs)
    return wrapper

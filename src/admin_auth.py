"""
Autenticazione delle operazioni amministrative di SA e AE tramite TLS mutuo.

Gli endpoint /close, /reconcile e /shutdown modificano lo stato dell'elezione
o spengono i server: senza protezione chiunque raggiunga il server potrebbe
chiudere le urne in anticipo o interrompere la votazione.

Il pannello amministrativo si autentica con un certificato client emesso dalla
CA dell'elezione (src/pki.py), con uso esteso "clientAuth":
- il server richiede il certificato client in modo FACOLTATIVO (gli elettori
  non ne hanno uno);
- se presentato, l'handshake TLS ne verifica la catena fino alla CA e la
  revoca tramite CRL: un certificato di un'altra CA, revocato o scaduto fa
  fallire la connessione;
- questo decoratore controlla poi che la connessione abbia presentato proprio
  il certificato del pannello (uso clientAuth e nome del pannello).

Rispetto a un token condiviso su file, il segreto (la chiave privata del
certificato client) non viene mai trasmesso al server: il pannello dimostra di
possederlo firmando durante l'handshake.
"""

from functools import wraps

from flask import jsonify, request

from tls_context import admin_client_cert_ok


def require_admin(view):
    """Decoratore Flask: risponde 403 se la richiesta non presenta il certificato del pannello."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not admin_client_cert_ok(request.environ.get("SSL_CLIENT_CERT")):
            print(f"[ADMIN] Richiesta amministrativa rifiutata su {request.path} da {request.remote_addr} "
                  f"(certificato client del pannello assente o non valido)")
            return jsonify({"error": "Operazione amministrativa non autorizzata: "
                                     "serve il certificato client del pannello"}), 403
        return view(*args, **kwargs)
    return wrapper

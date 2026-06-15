# UniSafe-Vote - Sistema di Voto Elettronico Sicuro

Proof of concept di un sistema di voto elettronico sicuro realizzato per l'esame di **Algoritmi e Protocolli per la Sicurezza**, anno accademico **2025-2026**, presso l'**Università degli Studi di Salerno**.

Il progetto **non è un sistema reale di voto**: è un proof of concept eseguito in ambiente locale, concentrato prevalentemente sulla correttezza e verificabilità dei protocolli crittografici implementati.

## Componenti del Sistema

Il sistema è composto dai seguenti moduli:

- **Sistema di Autenticazione (SA)**: gestisce la registrazione e l'autenticazione degli elettori, emettendo token firmati.
- **Autorità Elettorale (AE)**: riceve e verifica i voti cifrati, gestisce il Bulletin Board, calcola la Merkle Root ed esegue lo scrutinio.
- **Client Votante**: interfaccia CLI per registrazione, autenticazione, voto, conservazione della ricevuta e verifica individuale.
- **Observer**: strumento per la verifica universale dell'integrità dell'elezione analizzando il Bulletin Board.
- **Moduli Crittografici**: primitive crittografiche implementate in `src/crypto/` (RSA-OAEP per cifratura, RSA-PSS per firme digitali, Merkle Tree per integrità dei dati).
- **Main Menu**: pannello di controllo principale che coordina inizializzazione, avvio dei server, client, scrutinio, verifica universale e test di sicurezza.

## Struttura del Progetto

```text
UniSafe-Vote/
├── src/
│   ├── crypto/
│   │   ├── __init__.py
│   │   ├── keys.py              # Gestione chiavi RSA e cifratura chiavi private
│   │   ├── rsa_oaep.py          # Cifratura/decifratura RSA-OAEP
│   │   ├── rsa_pss.py           # Firma/verifica RSA-PSS
│   │   ├── merkle.py            # Merkle Tree e prove di inclusione
│   │   └── password.py          # Hash e verifica password
│   ├── data/
│   │   └── receipts/            # Ricevute JSON dei votanti
│   ├── __init__.py
│   ├── sa.py                    # Server Sistema di Autenticazione (porta 5001)
│   ├── ae.py                    # Server Autorità Elettorale (porta 5002)
│   ├── client.py                # Client CLI per il voto
│   ├── observer.py              # Verifica universale
│   ├── init_election.py         # Inizializzazione elezione interattiva
│   ├── init_election_non_interactive.py
│   └── generate_tls_certs.py    # Generazione certificati TLS self-signed
├── data/
│   ├── keys/                    # Chiavi RSA generate
│   ├── receipts/                # Ricevute dei votanti
│   ├── tls/                     # Certificati TLS self-signed SA/AE
│   ├── bulletin_board.json      # Registro pubblico append-only
│   ├── voters.json              # Lista degli aventi diritto
│   ├── pins.json                # Impronte trusted delle chiavi AE
│   └── ae_state.json            # Stato privato AE per prevenire token replay
├── tests/
│   ├── security/                # Test di sicurezza e attacchi simulati
│   └── performance/             # Test di performance
├── main.py                      # Pannello di controllo principale
└── requirements.txt             # Dipendenze
```

## Istruzioni per l'Esecuzione

### 1. Setup Ambiente

```bash
cd UniSafe-Vote
python -m venv venv
```

Su Windows PowerShell:

```powershell
.\venv\Scripts\Activate.ps1
```

Su Windows CMD classico:

```cmd
venv\Scripts\activate.bat
```

Su Linux/macOS:

```bash
source venv/bin/activate
```

Installazione dipendenze:

```bash
pip install -r requirements.txt
```

### 2. Avvio

```bash
python main.py
```

Il pannello permette di:

1. Inizializzare l'elezione.
2. Avviare SA e AE.
3. Aprire il client votante.
4. Chiudere le urne e avviare lo scrutinio.
5. Eseguire la verifica universale finale.
6. Reset della configurazione dell'elezione.
7. Eseguire test di sicurezza.
8. Uscire.

### 3. Canale TLS

L'inizializzazione genera anche certificati TLS self-signed in `data/tls/`:

```text
data/tls/sa_cert.pem
data/tls/sa_key.pem
data/tls/ae_cert.pem
data/tls/ae_key.pem
```

SA e AE vengono raggiunti tramite HTTPS:

```text
https://localhost:5001
https://localhost:5002
```

I client locali usano i certificati self-signed come CA bundle tramite il parametro `verify` di `requests`. In un sistema reale questi certificati dovrebbero essere rilasciati da una CA riconosciuta.

### 4. Modalità di Inizializzazione

Durante l'inizializzazione è possibile scegliere tra:

1. **Sistema preconfigurato**: liste stock ed elettori già registrati.
2. **Solo liste di voto**: configurazione personalizzata delle liste, con registrazione utenti abilitata successivamente tramite SA.

L'inizializzazione genera anche i certificati TLS self-signed usati dai client locali per verificare le connessioni HTTPS verso SA e AE.

Credenziali preconfigurate nella modalità demo:

```text
vitto.posti   / password123
matty.sanz    / password456
carlo.deluca  / pass_cDL92
sara.espo     / pass_sE99
luca.ferr     / pass_lF01
ale.damico    / pass_aD03
rob.mancini   / pass_rM97
fede.rugg     / pass_fR12
marco.salz    / pass_mS00
ire.silv      / pass_iS95
```

## Test di Sicurezza

Il progetto include test di sicurezza in `tests/security/`, eseguibili dal pannello principale. I test coprono scenari come:

- Attacco dizionario / analisi di frequenza su RSA-OAEP.
- Attacco MitM con sostituzione delle chiavi pubbliche AE.
- Manomissione del Bulletin Board.
- DoS con PoW invalida.
- PoW adattiva e recovery della difficoltà.
- Resilienza DoS durante la votazione.
- Double voting / token replay.
- Token hoarding e token scaduto.

## Avvio Manuale dei Server

**Terminale 1 - Sistema di Autenticazione:**

```bash
python src/sa.py
```

**Terminale 2 - Autorità Elettorale:**

```bash
python src/ae.py
```

Con i certificati TLS presenti in `data/tls/`, i server ascoltano su HTTPS.

## Chiusura Urne e Shutdown

Per chiudere le urne dall'AE:

```bash
curl -X POST https://localhost:5002/close --cacert data/tls/ae_cert.pem
```

Per spegnere i server:

```bash
curl -X POST https://localhost:5001/shutdown --cacert data/tls/sa_cert.pem
curl -X POST https://localhost:5002/shutdown --cacert data/tls/ae_cert.pem
```

Se `curl` non è disponibile su Windows, usare PowerShell o un client HTTP che consenta di specificare il certificato CA self-signed.

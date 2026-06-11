
# Sistema di Voto Elettronico Sicuro

Proof of Concept di un sistema di voto elettronico sicuro.

## Componenti del Sistema

Il sistema è composto dai seguenti moduli:

- **Sistema di Autenticazione (SA)**: Gestisce la registrazione e l'autenticazione degli elettori, emettendo token firmati.
- **Autorità Elettorale (AE)**: Riceve e verifica i voti cifrati, gestisce il Bulletin Board e calcola i risultati finali.
- **Client Votante**: Interfaccia per gli elettori per autenticarsi, esprimere il voto e salvare la ricevuta digitale.
- **Observer**: Strumento per la verifica universale dell'integrità dell'elezione analizzando il Bulletin Board.
- **Moduli Crittografici**: Forniscono le primitive crittografiche necessarie (RSA-OAEP per cifratura, RSA-PSS per firme digitali, Merkle Tree per l'integrità dei dati).
- **Main Menu**: Punto di ingresso principale che coordina l'avvio di tutti i componenti.

## Struttura del Progetto

```
voting-system/
├── crypto/
│   ├── __init__.py
│   ├── keys.py          # Gestione delle chiavi RSA
│   ├── rsa_oaep.py      # Cifratura/decifratura RSA-OAEP
│   ├── rsa_pss.py       # Firma/verifica RSA-PSS
│   └── merkle.py        # Merkle Tree e prove di inclusione
├── data/
│   ├── keys/            # Chiavi RSA generate
│   ├── receipts/        # Ricevute dei votanti
│   ├── bulletin_board.json  # Registro pubblico append-only
│   └── voters.json      # Lista degli aventi diritto
├── sa.py                # Server Sistema di Autenticazione (porta 5001)
├── ae.py                # Server Autorità Elettorale (porta 5002)
├── client.py            # Client CLI per il voto
├── observer.py          # Verifica universale
├── init_election.py     # Script di inizializzazione
├── main.py              # Menu principale
└── requirements.txt     # Dipendenze
```

## Istruzioni per l'Esecuzione

### 1. Setup Ambiente
```bash
cd UniSafe-Vote
python -m venv venv

# Windows
venv\Scripts\activate  #cmd
.\venv\Scripts\Activate.ps1  #powershell

# Linux/Mac
source venv/bin/activate

pip install -r requirements.txt
```

### 2. Utilizzo del Menu Centrale (Consigliato)
Avvia il menu principale con un solo comando:
```bash
python main.py
```

Il menu ti permette di:
- Inizializzare l'elezione
- Avviare/arrestare i server (SA e AE)
- Aprire il client votante
- Chiudere le urne e avviare lo scrutinio
- Eseguire la verifica universale

### 3. Istruzioni Manuali (Alternativa)
Se preferisci utilizzare i file singolarmente:

#### Inizializzazione Elezione
```bash
python init_election.py
```

#### Avvio Server
**Terminale 1 - Sistema di Autenticazione:**
```bash
python sa.py
```

**Terminale 2 - Autorità Elettorale:**
```bash
python ae.py
```

#### Voto (Client)
**Terminale 3 (o più terminali per più elettori):**
```bash
python client.py
```
Credenziali di test: `mario.rossi` / `password123`, `luigi.bianchi` / `password456`, ecc.

#### Chiusura Urne e Scrutinio
Invia una richiesta POST all'AE per chiudere le urne e avviare lo scrutinio:
```bash
# Con curl (se disponibile)
curl -X POST http://localhost:5002/close
```
Oppure usa un tool come Postman o scrivi un piccolo script Python.

#### Verifica Universale
```bash
python observer.py
```

### Shutdown dei server (SA / AE)

I server espongono un endpoint sicuro `/shutdown` che permette di fermarli in modo controllato.

- Per motivi di sicurezza è possibile impostare la variabile d'ambiente `SHUTDOWN_TOKEN` su entrambe le macchine (SA e AE). Se impostata, il server richiede che la richiesta includa l'header `X-SHUTDOWN-TOKEN` con lo stesso valore.
- Se `SHUTDOWN_TOKEN` non è impostato, il server accetta la richiesta di shutdown solo se proviene da `localhost`.

Esempi (da eseguire sulla macchina locale):

```bash
# Shutdown senza token (solo localhost)
curl -X POST http://localhost:5001/shutdown
curl -X POST http://localhost:5002/shutdown

# Shutdown con token
export SHUTDOWN_TOKEN=s3cr3t  # Linux/macOS
# Windows (PowerShell): $env:SHUTDOWN_TOKEN = 's3cr3t'
curl -X POST -H "X-SHUTDOWN-TOKEN: s3cr3t" http://localhost:5001/shutdown
curl -X POST -H "X-SHUTDOWN-TOKEN: s3cr3t" http://localhost:5002/shutdown
```

Nota: il `main.py` può essere configurato per inviare queste richieste automaticamente all'uscita per chiudere le finestre dei server se sono state avviate esternamente.

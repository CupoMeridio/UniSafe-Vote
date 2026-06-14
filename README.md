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
│   └── init_election_non_interactive.py
├── data/
│   ├── keys/                    # Chiavi RSA generate
│   ├── receipts/                # Ricevute dei votanti
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
6. Eseguire test di sicurezza.
7. Reset della configurazione dell'elezione.

### 3. Modalità di Inizializzazione

Durante l'inizializzazione è possibile scegliere tra:

1. **Sistema preconfigurato**: liste stock ed elettori già registrati.
2. **Solo liste di voto**: configurazione personalizzata delle liste, con registrazione utenti abilitata successivamente tramite SA.

Credenziali preconfigurate nella modalità demo:

```text
mario.rossi / password123
luigi.bianchi / password456
giulia.verdi / password789
francesca.neri / password012
paolo.gialli / password345
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

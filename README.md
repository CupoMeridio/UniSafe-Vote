
# Sistema di Voto Elettronico Sicuro

Proof of Concept di un sistema di voto elettronico sicuro basato sul protocollo definito nel WP2.

## Struttura del Progetto

```
voting-system/
├── crypto/
│   ├── __init__.py
│   ├── keys.py          # Generazione e gestione chiavi RSA
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
└── requirements.txt     # Dipendenze
```

## Istruzioni per l'Esecuzione

### 1. Setup Ambiente
```bash
cd UniSafe-Vote
python -m venv venv

# Windows
venv\Scripts\activate

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

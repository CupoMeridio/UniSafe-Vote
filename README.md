# UniSafe-Vote - Sistema di Voto Elettronico Sicuro

Proof of concept di un sistema di voto elettronico sicuro realizzato per l'esame di **Algoritmi e Protocolli per la Sicurezza**, anno accademico **2025-2026**, presso l'**Università degli Studi di Salerno**.

Il progetto **non è un sistema reale di voto**: è un proof of concept eseguito in ambiente locale, concentrato prevalentemente sulla correttezza e verificabilità dei protocolli crittografici implementati.

## Componenti del Sistema

Il sistema è composto dai seguenti moduli:

- **Sistema di Autenticazione (SA)**: gestisce la registrazione e l'autenticazione degli elettori, emettendo token firmati.
- **Autorità Elettorale (AE)**: riceve e verifica i voti cifrati, gestisce il Bulletin Board, calcola la Merkle Root ed esegue lo scrutinio.
- **Client Votante**: interfaccia CLI per registrazione, autenticazione, voto, conservazione della ricevuta e verifica individuale.
- **Observer**: strumento per la verifica universale dell'integrità dell'elezione analizzando il Bulletin Board.
- **Moduli Crittografici**: primitive crittografiche implementate in `src/crypto/` (RSA-OAEP per cifratura, RSA-PSS per firme digitali, Merkle Tree per integrità dei dati, Shamir Secret Sharing per l'escrow della chiave di decifratura).
- **Main Menu**: pannello di controllo principale che coordina inizializzazione, avvio dei server, client, scrutinio, verifica universale e test di sicurezza.

## Struttura del Progetto

```text
UniSafe-Vote/
├── src/
│   ├── crypto/
│   │   ├── keys.py              # Chiavi RSA ed escrow a soglia della chiave di decifratura AE
│   │   ├── rsa_oaep.py          # RSA-OAEP con seed iniettabile e decifratura verificabile (EM)
│   │   ├── rsa_pss.py           # Firma/verifica RSA-PSS
│   │   ├── merkle.py            # Merkle Tree (separazione di dominio foglie/nodi) e prove di inclusione
│   │   ├── shamir.py            # Shamir Secret Sharing k-su-n
│   │   └── password.py          # Hash e verifica password (PBKDF2-HMAC-SHA256, 600k iterazioni)
│   ├── sa.py                    # Server Sistema di Autenticazione (porta 5001)
│   ├── ae.py                    # Server Autorità Elettorale (porta 5002)
│   ├── admin_auth.py            # TLS mutuo per /close, /reconcile, /shutdown
│   ├── bb_chain.py              # Catena di hash (prev_hash) dei blocchi del Bulletin Board
│   ├── client.py                # Client CLI per il voto e la verifica individuale
│   ├── observer.py              # Verifica universale
│   ├── init_election.py         # Inizializzazione elezione interattiva
│   ├── init_election_non_interactive.py
│   ├── pki.py                   # Certification Authority: CSR, emissione, revoca, CRL
│   ├── tls_context.py           # Contesti TLS: catena, CRL, pin SPKI, certificato client
│   └── generate_tls_certs.py    # Generazione della PKI dell'elezione
├── data/
│   ├── keys/                    # Chiavi RSA, chiave AE cifrata
│   │   └── trustees/            # Quote Shamir degli scrutatori (simulazione PoC)
│   ├── receipts/                # Ricevute dei votanti
│   ├── tls/                     # PKI: CA, certificati SA/AE/pannello, CRL, pin SPKI
│   │   └── ca/                  # Chiave privata e registro della CA (non letti dai server)
│   ├── bulletin_board.json      # Registro pubblico append-only (blocchi firmati e concatenati)
│   ├── voters.json              # Lista degli aventi diritto
│   ├── pins.json                # Impronte trusted delle chiavi AE
│   └── ae_state.json            # Stato privato AE per prevenire token replay
├── tests/
│   ├── common.py                # Creazione dell'elezione di test e helper condivisi
│   ├── tls_config.py            # URL, CA e certificato client del pannello per i test
│   ├── test_flow.py             # Flusso completo end-to-end
│   ├── security/                # Test di sicurezza e attacchi simulati (report JSON in tests/output/)
│   └── performance/             # Test di performance e di carico (Locust)
├── main.py                      # Pannello di controllo principale
├── requirements.txt             # Dipendenze
└── requirements-dev.txt         # Dipendenze per i test di carico (Locust)
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

### 3. Canale TLS e PKI

L'inizializzazione crea una piccola PKI dell'elezione in `data/tls/` (`src/pki.py`):

```text
data/tls/ca_cert.pem                  certificato della CA radice (fiducia dei client)
data/tls/sa_cert.pem, sa_key.pem      certificato del SA (uso server), emesso su CSR
data/tls/ae_cert.pem, ae_key.pem      certificato dell'AE (uso server), emesso su CSR
data/tls/admin_cert.pem, admin_key.pem certificato client del pannello amministrativo
data/tls/crl.pem                      lista dei certificati revocati, firmata dalla CA
data/tls/tls_pins.json                impronte SPKI delle chiavi di SA e AE
data/tls/ca/                          chiave privata e registro della CA
```

SA e AE vengono raggiunti tramite HTTPS:

```text
https://localhost:5001
https://localhost:5002
```

Il client si connette solo se il certificato del server è emesso dalla CA dell'elezione, non è revocato e la chiave corrisponde al pin SPKI. Il pannello si autentica presso i server con il proprio certificato client (TLS mutuo). Per revocare un certificato e ripubblicare la CRL:

```bash
python src/pki.py status          # certificati emessi e revocati
python src/pki.py revoke ae       # revoca il certificato dell'AE
```

I server rileggono la CRL al riavvio, i client a ogni nuova connessione.

### 4. Modalità di Inizializzazione

Durante l'inizializzazione è possibile scegliere tra:

1. **Sistema preconfigurato**: liste stock ed elettori già registrati.
2. **Solo liste di voto**: configurazione personalizzata delle liste, con registrazione utenti abilitata successivamente tramite SA.

L'inizializzazione genera anche la PKI (CA, certificati, CRL e pin) usata per le connessioni HTTPS verso SA e AE.

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

## Meccanismi di Sicurezza

- **Anonimato del voto**: il SA rilascia un token opaco (nonce casuale firmato RSA-PSS), senza riferimenti all'identità; l'AE impone l'unicità del voto sul nonce.
- **Riservatezza**: il voto è cifrato con RSA-OAEP; la chiave privata di decifratura è protetta da un escrow a soglia (Shamir 2-su-3): la chiave AES che la cifra è divisa tra tre scrutatori, ne servono due per lo scrutinio e gli impegni sulle quote sono pubblicati nel blocco init firmato.
- **Integrità del registro**: ogni blocco del Bulletin Board è firmato e contiene l'hash del blocco precedente; i voti formano un Merkle Tree con separazione di dominio tra foglie e nodi.
- **Verifica individuale**: la ricevuta firmata contiene la Merkle Proof e la root del momento del voto; a urne chiuse il client verifica l'inclusione nella root finale e che il registro non sia stato riscritto.
- **Verifica universale**: per ogni scheda l'AE pubblica la decifratura `EM = c^d mod n`; chiunque verifica che `EM^e mod n == c` e ricostruisce il contenuto di ogni scheda, nulle comprese.
- **Anti-DoS e anti-brute force**: Proof of Work su una challenge del server (autenticata, legata all'IP, con scadenza, monouso) con difficoltà adattiva per IP; rate limit per IP e blocco per account sul SA; tempi di risposta uguali per username esistenti e inesistenti.
- **Concorrenza**: le sezioni critiche di SA e AE sono protette da lock (nessun doppio voto con richieste simultanee).
- **Canale e identità dei server**: TLS con certificati emessi dalla CA dell'elezione; il client verifica catena, revoca (CRL) e chiave del server (pin SPKI).
- **Operazioni amministrative**: `/close`, `/reconcile` e `/shutdown` richiedono il certificato client del pannello, emesso dalla CA e verificato con TLS mutuo.

## Test di Sicurezza

Il progetto include una suite di test in `tests/`, eseguibile dal pannello principale (opzione 8). Ogni test crea la propria elezione, stampa le fasi in forma leggibile e salva un report JSON datato in `tests/output/`.

**Attenzione:** i test usano la cartella `data/` e la ripuliscono al termine. Il pannello chiede una conferma esplicita se è presente un'elezione inizializzata o un server avviato.

Test offline (nessun server reale richiesto):

1. Attacco dizionario / analisi di frequenza su RSA-OAEP.
2. Attacco MitM con sostituzione delle chiavi AE: il blocco init viene ri-firmato dall'attaccante, quindi a fermarlo è il certificate pinning.
3. Manomissione del Bulletin Board, ricevute al momento del voto e attacco di seconda preimmagine sul Merkle Tree.
4. Escrow a soglia della chiave privata AE (Shamir 2-su-3).
5. Proof of Work con challenge del server e difficoltà per IP.
6. PKI lato client: impostori dell'AE (self-signed, altra CA, CA compromessa), pinning SPKI e revoca dopo il furto della chiave.

Test con server avviati automaticamente:

7. DoS con PoW invalida.
8. PoW adattiva e recovery della difficoltà.
9. Resilienza DoS durante la votazione.
10. Double voting / token replay.
11. Double voting concorrente (race condition).
12. Token hoarding, token scaduto e rinnovo con lo stesso nonce.
13. Elettore malevolo (seed corrotto) e AE che dichiara nulla una scheda valida.
14. Verifica individuale di tutte le ricevute, riavvio dell'AE, rimozione di blocchi e manomissione del registro.
15. Difese del SA: rate limit, IP falsificati, blocco account, timing, endpoint amministrativi.
16. Registrazione degli elettori (modalità solo liste).
17. Finestra temporale dell'elezione.
18. Flusso completo dell'elezione (end-to-end).
19. TLS mutuo per le operazioni amministrative.

## Test di Performance

```bash
python tests/performance/performance_test.py        # benchmark crittografici e di rete
pip install -r requirements-dev.txt                 # Locust, solo per i test di carico
python tests/performance/run_performance_tests.py   # scenari baseline e DoS con Locust
```

I test di carico simulano IP diversi tramite l'header `X-Forwarded-For`, che il SA considera solo se avviato con `UNISAFE_TRUST_PROXY_HEADERS=1` (in modalità normale l'header è ignorato perché falsificabile).

## Avvio Manuale dei Server

**Terminale 1 - Sistema di Autenticazione:**

```bash
python src/sa.py
```

**Terminale 2 - Autorità Elettorale:**

```bash
python src/ae.py
```

I server richiedono la PKI in `data/tls/` (generata all'inizializzazione o con `python src/generate_tls_certs.py`) e ascoltano solo su HTTPS.

## Chiusura Urne e Shutdown

La chiusura delle urne richiede il certificato client del pannello e le quote di almeno due scrutatori: va eseguita dal pannello principale (opzione 5), che simula la consegna delle quote da `data/keys/trustees/`.

Per spegnere i server:

```bash
curl -X POST https://localhost:5001/shutdown --cacert data/tls/ca_cert.pem --cert data/tls/admin_cert.pem --key data/tls/admin_key.pem
curl -X POST https://localhost:5002/shutdown --cacert data/tls/ca_cert.pem --cert data/tls/admin_cert.pem --key data/tls/admin_key.pem
```

Se `curl` non è disponibile su Windows, usare un client HTTP che consenta di specificare la CA (`ca_cert.pem`) e il certificato client del pannello.

## Limiti Noti

Il progetto è un proof of concept: alcuni limiti sono intrinseci al protocollo scelto e sono discussi nella relazione.

- **Anonimato basato sulla fiducia**: se SA e AE colludono possono collegare token e identità. La soluzione sono le firme cieche (RFC 9474).
- **Riempimento delle urne**: AE o SA possono aggiungere schede fino al numero di token emessi senza che l'Observer possa contestarle (anche questo si risolve con le firme cieche, che rendono pubblicabile il token).
- **Nessuna resistenza alla coercizione**: l'elettore conosce il seed e può dimostrare a terzi il proprio voto (servirebbero ElGamal omomorfico o mixnet).
- **Bulletin Board, pin, quote degli scrutatori e chiave della CA su disco locale**: in un sistema reale il registro sarebbe distribuito, ogni quota custodita dal proprio scrutatore e la chiave della CA conservata offline da un ente distinto dal gestore dei server.
- **Revoca letta all'avvio**: i server caricano la CRL all'avvio; una revoca pubblicata durante l'elezione diventa effettiva lato server solo al riavvio (i client la rileggono a ogni connessione).
- **Registrazione senza verifica dell'email**: il dominio è controllato, ma non il possesso della casella.

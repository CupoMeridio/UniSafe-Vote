
# UniSafe-Vote: Piano di Performance Testing e Benchmark di Sicurezza

## 1. Obiettivi
- Valutare il comportamento del sistema in condizioni di carico normale e sotto attacco
- Verificare l'efficacia dei meccanismi di mitigazione (PoW, token, Merkle Tree)
- Misurare throughput (RPS), latenza, tasso di successo
- Identificare colli di bottiglia

---

## 2. Metriche di Misurazione
- **Throughput**: Richieste per secondo (RPS)
- **Latenza**: Tempo di risposta medio, minimo, massimo, percentili (P50, P95, P99)
- **Tasso di Successo**: Percentuale di richieste che completano con successo
- **Overhead Computazionale**: Tempo aggiuntivo imposto dalle meccaniche di sicurezza rispetto a un sistema non protetto

---

## 3. Scenari di Test

### 3.1 Scenario Ottimale (Baseline)
- **Descrizione**: Carico normale, utenti legittimi autenticati che votano e verificano
- **Carico**: 10-1000 utenti concorrenti (scala progressiva)
- **Operazioni**:
  - Autenticazione (SA)
  - Voto (AE)
  - Verifica Merkle Proof
- **Metriche Target**:
  - Latenza &lt; 500ms per voto
  - Throughput &gt; 100 RPS
  - Tasso di successo &gt; 99%

---

### 3.2 Stress Test sotto Attacco DoS (Verifica PoW)
- **Descrizione**: Attacco volumetrico, scale progressiva fino a 1.000.000 richieste totali
- **Attacco**:
  - Client malintenzionato che invia richieste senza PoW valida
  - Utenti legittimi che tentano di votare contemporaneamente (10% della popolazione totale)
- **Metriche Target**:
  - Il server non crasha
  - Latenza per utenti legittimi &lt; 1000ms
  - Tasso di rifiuto attacchi &gt; 99.9%
  - Il sistema rimane reattivo

---

### 3.3 Performance Test sotto Mitigazione degli Attacchi
#### 3.3.1 Replay Attack (Token già utilizzato)
- **Descrizione**: 500 richieste al secondo con lo stesso token
- **Metriche**: Overhead di verifica token nel database
- **Risultato Atteso**: 100% rifiuti, overhead &lt; 5% rispetto a baseline

#### 3.3.2 Tentativi di Double-Voting di Massa
- **Descrizione**: 1000 utenti concorrenti che tentano di votare due volte consecutivamente
- **Metriche**: Overhead di controllo `used_tokens`
- **Risultato Atteso**: 100% rifiuti per il secondo tentativo

#### 3.3.3 Sybil Attack (Registro massivo di utenti)
- **Descrizione**: 1000 tentativi di registrazione al minuto con domini non autorizzati
- **Metriche**: Overhead di validazione email e registrazione utenti
- **Risultato Atteso**: 100% rifiuti per email non valide

---

## 4. Ambiente di Test
- **Server**: Macchina con 4 core CPU, 8GB RAM
- **Client**: Macchine separate (o container) per generare carico
- **Strumenti**: Locust (per carico), custom script Python

---

## 5. Report di Test
Per ogni test verrà generato un report con:
- Grafici di throughput e latenza nel tempo
- Tabelle di metriche per ogni scenario
- Confronto overhead tra baseline e scenario attaccato
- Conclusioni e raccomandazioni


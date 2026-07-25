# SQLiteWatch — Piano di sviluppo del PoC

## Stato iniziale

La cartella contiene la documentazione di riferimento:

- `architecture.md`
- `spec.md`

Il PoC iniziale sarà sviluppato con priorità **Linux x86_64**, usando:

- controller in Python;
- agent Frida in JavaScript;
- Frida come backend di instrumentation;
- processo principale soltanto, senza supporto iniziale ai processi figli;
- nessuna modifica al codice dell'applicazione target.

Frida non è attualmente installato nell'ambiente di sviluppo; Python, Node.js, GCC e SQLite di sistema sono disponibili.

---

## Obiettivo del PoC

Dimostrare che SQLiteWatch può avviare un processo arbitrario e intercettare le query SQLite a livello della C API, senza modificare l'applicazione.

Il primo comando obiettivo è:

```bash
python -m sqlitewatch -- ./fixture
```

Il primo criterio di successo è ricevere un evento `statement_prepared` contenente il testo SQL corretto.

Il PoC non deve inizialmente implementare aggregazione, regole o report complessi.

---

## Fase 0 — Bootstrap del progetto

### Obiettivi

- creare lo scheletro del progetto Python;
- aggiungere Frida come dipendenza;
- definire il primo protocollo eventi;
- predisporre test e fixture;
- mantenere separati controller, agent e dominio di analisi.

### Struttura proposta

```text
pyproject.toml
src/sqlitewatch/
  __main__.py
  cli.py
  process.py
  instrumentation/
    frida_backend.py
agent/
  sqlitewatch_agent.js
fixtures/
  c_dynamic/
  c_embedded/
  python_sqlite.py
  node_binding/
tests/
  test_events.py
  integration/
```

### Protocollo eventi iniziale

L'agent Frida invierà messaggi al controller tramite il canale nativo di Frida.

Formato minimo:

```json
{
  "type": "statement_prepared",
  "pid": 1234,
  "tid": 1234,
  "module": "libsqlite3.so",
  "statement": "0x123456",
  "database": "0x987654",
  "sql": "SELECT * FROM users WHERE id = ?"
}
```

Gli indirizzi nativi saranno serializzati come stringhe esadecimali.

Eventi iniziali previsti:

- `backend_ready`;
- `sqlite_detected`;
- `instrumentation_status`;
- `statement_prepared`;
- `instrumentation_error`;
- `process_exited`.

---

## Fase 1 — Hook minimo su `sqlite3_prepare_v2`

### Obiettivi

- avviare il processo con `frida.spawn()`;
- installare gli hook prima di riprendere il processo;
- enumerare i moduli già caricati;
- individuare `sqlite3_prepare_v2`;
- intercettare anche moduli caricati dopo l'avvio;
- estrarre il SQL e il puntatore `sqlite3_stmt*`;
- inoltrare l'evento al controller;
- stampare il SQL intercettato.

### Comportamento dell'hook

In ingresso:

- leggere il puntatore SQL;
- rispettare `nByte` quando disponibile;
- applicare una lunghezza massima configurabile;
- salvare temporaneamente gli argomenti necessari.

In uscita:

- verificare il codice di ritorno SQLite;
- leggere `sqlite3_stmt**`;
- creare l'identificativo dello statement;
- emettere `statement_prepared`.

### Criterio di successo

Una fixture C dinamica deve produrre almeno un evento contenente il SQL corretto, senza alterare SQL, parametri, risultati o transazioni.

---

## Fase 2 — Matrice di validazione

Il PoC sarà testato contro quattro scenari:

1. programma C linkato dinamicamente a `libsqlite3`;
2. programma C con `sqlite3.c` embedded;
3. Python con il modulo standard `sqlite3`;
4. Node.js con un binding SQLite nativo.

Per ogni scenario registrare:

```text
SQLite rilevato
modulo individuato
modello dinamico o embedded
simboli richiesti trovati
hook installato
SQL catturato
```

### Fixture C dinamica

- link con `-lsqlite3`;
- database `:memory:`;
- creazione tabella;
- insert parametrizzati;
- select parametrizzate;
- verifica del collegamento tramite `ldd`.

### Fixture C embedded

- usare una versione ufficiale e pinned dell'amalgamation SQLite;
- compilare `sqlite3.c` direttamente nell'eseguibile;
- mantenere i simboli individuabili;
- aggiungere eventualmente una variante negativa con simboli nascosti o stripped.

### Fixture Python

- usare esclusivamente `sqlite3` della standard library;
- creare ed eseguire statement ripetuti;
- registrare il modulo `_sqlite3` e le librerie SQLite caricate.

### Fixture Node.js

- usare inizialmente un binding nativo pinned, ad esempio `better-sqlite3`;
- usare un database in memoria;
- includere query parametrizzate e una query con sort;
- verificare il caricamento ritardato del modulo nativo.

Il binding Node potrà essere escluso dal primo gate se incompatibile con la versione locale di Node.js, ma il limite dovrà essere documentato esplicitamente.

---

## Fase 3 — Lifecycle degli statement

Aggiungere gli hook per:

```text
sqlite3_prepare_v3
sqlite3_step
sqlite3_reset
sqlite3_finalize
```

`sqlite3_step` deve essere incluso perché la sola preparazione non dimostra che uno statement sia stato eseguito.

Gestire almeno questi casi:

- `SQLITE_ROW`: esecuzione ancora attiva;
- `SQLITE_DONE`: esecuzione completata;
- errori terminali;
- `BUSY` e `LOCKED`;
- `reset` e `finalize` come boundary di sicurezza.

L'identità interna minima sarà:

```text
process_id + sqlite3_stmt*
```

Il contesto deve essere rimosso sempre durante `sqlite3_finalize` per evitare collisioni quando SQLite riutilizza un indirizzo.

---

## Fase 4 — Raccolta metriche runtime

Risolvere e utilizzare `sqlite3_stmt_status()` per raccogliere:

```text
SQLITE_STMTSTATUS_FULLSCAN_STEP
SQLITE_STMTSTATUS_VM_STEP
SQLITE_STMTSTATUS_SORT
SQLITE_STMTSTATUS_AUTOINDEX
```

Evento logico previsto:

```json
{
  "type": "statement_executed",
  "statement": "0x123456",
  "execution_number": 3,
  "sqlite_rc": 101,
  "fullscan_steps": 15000,
  "vm_steps": 43000,
  "sorts": 0,
  "autoindex": 0
}
```

### Decisione proposta sui contatori

Per rispettare il requisito di osservatore passivo, leggere i contatori con `resetFlag=0` e calcolare i delta tra esecuzioni. Non modificare i contatori dell'applicazione tramite `resetFlag=1`.

Questa scelta dovrà essere verificata con una fixture che riutilizzi lo stesso prepared statement attraverso più cicli `step → reset`.

---

## Fase 5 — Analisi e report

Dopo la validazione dell'instrumentation, aggiungere:

- tracking degli statement;
- normalizzazione conservativa del SQL;
- fingerprint delle query;
- aggregazione per query;
- conteggio esecuzioni;
- totali e massimi delle metriche;
- ordinamento per severità.

Struttura logica successiva:

```text
src/sqlitewatch/
  analysis/
    statement_tracker.py
    normalization.py
    aggregation.py
    rules.py
  reporting/
    terminal.py
    json.py
```

La normalizzazione dei literal SQL è rinviata. Inizialmente si applicheranno soltanto trasformazioni conservative, come trim e normalizzazione degli spazi.

---

## Fase 6 — Regole e modalità CI

Aggiungere le opzioni:

```text
--fail-fullscan-steps N
--fail-vm-steps N
--fail-on-autoindex
--format {terminal,json}
--output FILE
```

Le soglie si applicano al valore massimo per singola esecuzione, non ai totali aggregati, e falliscono soltanto con un confronto stretto `max > soglia`. Il valore `0` è valido; `--fail-on-autoindex` fallisce quando il totale autoindex è positivo.

Il report distingue contemporaneamente:

```text
Application failure
SQLiteWatch instrumentation failure
SQLiteWatch performance rule failure
```

La policy numerica degli exit code è:

| Condizione prioritaria | Exit code |
|---|---:|
| errore di emissione del report | `74` |
| instrumentation failure | `70` |
| target terminato da segnale | `128 + signal` |
| target exit non-zero | codice target |
| sole violazioni performance | `1` |
| nessuna failure | `0` |

Con regole abilitate, ogni stato di instrumentation diverso da `ACTIVE` (`FAILED`, `DETECTED_UNSUPPORTED`, `NOT_DETECTED`) fallisce con `70`; senza regole gli ultimi due stati restano informativi. In JSON stdout, stdout del target è rediretto su stderr per riservare stdout al solo documento JSON. Con `--output FILE`, il target conserva gli stream normali e il report UTF-8 viene scritto atomicamente con `os.replace()`; la directory padre non viene creata automaticamente.

---

## Fase 7 — Doctor mode e hardening

Implementare:

```bash
sqlitewatch doctor -- <command>
```

Il comando dovrà distinguere almeno:

```text
NOT_DETECTED
DETECTED_UNSUPPORTED
ACTIVE
FAILED
NO_ACTIVITY
```

Dovrà riportare:

- moduli caricati;
- implementazione SQLite rilevata;
- simboli richiesti;
- hook installati;
- eventuali motivi di incompatibilità.

Hardening successivo:

- SQL molto lunghi o puntatori non validi;
- concorrenza tra thread;
- overhead dell'invio eventi;
- errori Frida;
- recupero affidabile dell'exit code;
- comportamento con processi figli.

---

## Fuori scope del PoC

- processi figli;
- Windows e macOS;
- binary fingerprinting di binari stripped;
- baseline e regressioni;
- `EXPLAIN QUERY PLAN` automatico;
- suggerimenti di indici;
- detection N+1;
- attribuzione a call stack o codice sorgente;
- output SARIF, JUnit o HTML.

---

## Rischi e criteri go/no-go

### Go tecnico

- hook funzionante su Linux x86_64;
- SQL catturato dalla fixture C dinamica;
- SQL catturato dalla fixture C embedded con simboli visibili;
- eventi ricevuti dal controller;
- nessuna modifica al comportamento funzionale del target;
- errori e simboli mancanti riportati esplicitamente.

### Rischi principali

- SQLite caricato dopo l'avvio;
- simboli hidden, stripped o rinominati;
- runtime che usa `sqlite3_prepare_v3` invece di `prepare_v2`;
- riutilizzo degli indirizzi `sqlite3_stmt*`;
- contatori cumulativi e definizione del boundary di esecuzione;
- perdita dell'exit code del processo target;
- overhead eccessivo dovuto a eventi per ogni statement.

Il fallimento su C dinamico o C embedded con simboli individuabili è un **no-go** immediato. Il fallimento su Python o Node dovuto a SQLite statico/stripped va classificato come limite della strategia di instrumentation, non come assenza di attività SQLite.

---

## Primo passo operativo

Implementare nell'ordine:

1. `pyproject.toml` e dipendenza Frida;
2. CLI minima;
3. controller `spawn/attach/resume`;
4. agent con discovery dei moduli;
5. hook `sqlite3_prepare_v2`;
6. fixture C dinamica;
7. test end-to-end del primo evento SQL.

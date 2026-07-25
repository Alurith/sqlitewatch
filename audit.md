# Audit del codebase

## Sintesi esecutiva

SQLiteWatch è un PoC ben separato in controller, instrumentation, protocollo, analisi, regole e reporting. La suite esistente è ampia e passa interamente. Non ho rilevato P0, perdita dati del database, injection del comando target o dipendenze circolari significative.

I problemi principali riguardano però l’affidabilità del risultato CI:

1. **SQL completa marcata come troncata quando `pzTail` è usato normalmente**: l’esecuzione viene esclusa dall’analisi e una regola può passare falsamente.
2. **Le regole falliscono “open” su dati incompleti**: metriche nulle, SQL troncata, eventi unmatched o conflittuali producono comunque exit `0` se lo stato globale è `ACTIVE`.
3. **La copertura multi-modulo può essere certificata erroneamente**: un modulo completo ma inutilizzato può rendere `ACTIVE` l’attività di un altro modulo incompleto.
4. **Timeout/errori/interrupt possono lasciare vivi target e launcher**.
5. **Il socket di completion non autentica il peer**: il target può falsificare il proprio exit code.
6. Sono inoltre confermati problemi di cattura UTF-8, overhead elevato sulle SQL lunghe, crescita lineare della memoria, riuso del backend, reload dei moduli e output Unicode.

---

## Comprensione del progetto

### Stack

- Python `>=3.11,<3.14`, ambiente corrente Python `3.13.11`.
- Frida `17.16.1`, agent in JavaScript.
- Hatchling come build backend.
- Pytest `8.4.2`.
- Entry point: `sqlitewatch.cli:main`.
- Fixture native C, Python `sqlite3` e Node/better-sqlite3.

Riferimenti: `pyproject.toml:1-31`, `uv.lock`.

### Architettura e flusso principale

1. `cli.py` valida opzioni e comando target.
2. `ProcessController` avvia un launcher Python tramite Frida.
3. Il launcher usa `os.posix_spawnp()` e possiede il `waitpid()` del target.
4. Frida applica child gating, aggancia il target e carica l’agent JS.
5. L’agent intercetta `prepare_v2/v3`, `step`, `reset`, `finalize` e legge `sqlite3_stmt_status()`.
6. Gli eventi vengono validati dal protocollo Python.
7. `StatementTracker` ricostruisce le lifetime, quindi aggregation/rules/reporting producono risultato ed exit code.

Non esistono database applicativi, migrazioni, query ORM, servizi HTTP, API esterne o background job propri di SQLiteWatch. Il “database” appartiene sempre al processo osservato. L’unico servizio esterno è il runtime Frida locale; l’altro canale IPC è un socket AF_UNIX tra controller e launcher.

### Limiti intenzionali, non finding

Sono esplicitamente fuori scope:

- piattaforme diverse da Linux x86_64;
- processi figli;
- SQLite stripped/non individuabile;
- moduli tardivi non riconoscibili come SQLite;
- transazioni, N+1, baseline e query plan.

Riferimenti: `poc-plan.md:10-16,364-370`, `src/sqlitewatch/doctor.py:35-40`.

### Verifiche eseguite

- Unit test: **120 passed**, 9 integration esclusi.
- Integration test: **9 passed**, 120 esclusi.
- `uv lock --check`: superato.
- Build sdist/wheel corrente: superata; entrambi gli agent JS sono inclusi.
- Nessun linter o type checker è configurato nel progetto.
- Probe aggiuntivi eseguiti con fixture temporanee fuori repository:
  - `pzTail`;
  - SQL con UTF-8 finale;
  - target che ignora SIGTERM;
  - completion socket falsificato;
  - due run sullo stesso controller;
  - `dlopen/dlclose/dlopen`;
  - SQL lunghe;
  - 200.000 esecuzioni sintetiche;
  - stdout ASCII.
- Nessun file tracked modificato; nessun commit creato.

---

## Tabella dei finding

| Priority | Area | Finding | Evidence | Impact | Confidence |
|---|---|---|---|---|---|
| P1 | Correctness / CI | **Confermato:** `pzTail` valido fa marcare SQL completa come troncata | `agent/sqlitewatch_agent.js:142-164`; `statement_tracker.py:126-130`; `rules.py:54-76` | Query reali escluse; possibile falso PASS CI | Alta |
| P1 | Reliability / CI | **Confermato:** data quality incompleta non invalida le regole | `agent/sqlitewatch_agent.js:173-191`; `statement_tracker.py:99-130`; `outcome.py:27-31` | Profilo inconclusivo riportato come successo | Alta |
| P1 | Coverage | **Rischio concreto:** `ACTIVE` globale e Doctor possono combinare moduli diversi | `agent/sqlitewatch_agent.js:253-259`; `doctor.py:100-113` | Attività non monitorata certificata come supportata | Alta |
| P1 | Process lifecycle | **Confermato:** abort/timeout non attendono né fanno escalation | `process.py:152-170,292-328,380-386`; `frida_backend.py:178-183` | Target e launcher possono restare vivi | Alta |
| P2 | Security / IPC | **Confermato:** completion AF_UNIX non autentica il peer | `process.py:77-82,292-378` | Target può falsificare exit `0` e terminare prematuramente il profiler | Alta |
| P2 | Correctness | **Confermato:** SQL terminante con carattere UTF-8 multibyte diventa vuota | `agent/sqlitewatch_agent.js:157-164` | Fingerprint errati e query diverse aggregate sotto `""` | Alta |
| P2 | Performance | **Confermato:** lettura SQL byte-per-byte sul percorso caldo | `agent/sqlitewatch_agent.js:142-161`; `spec.md:809-821` | Overhead molto elevato su SQL lunghe/ripetute | Alta |
| P2 | Scalability | **Confermato:** retention lineare degli eventi e cache di normalizzazione inefficace | `process.py:49-50,215-222`; `statement_tracker.py:56-66,115-140`; `aggregation.py:129-133` | Memoria/tempo crescono con ogni esecuzione | Alta |
| P2 | Reliability | **Confermato:** un backend/controller non è riutilizzabile | `frida_backend.py:39,147-155,185-195`; `process.py:204-213` | La seconda run fallisce e il target viene abortito | Alta |
| P2 | Reliability | **Confermato:** unload/reload non reinstalla gli hook | `agent/sqlitewatch_agent.js:19-21,125-139,238-267` | Query dopo il reload non osservate | Alta |
| P2 | Output | **Confermato:** stdout usa l’encoding ambientale e può sollevare `UnicodeEncodeError` | `cli.py:211-224`; `reporting/json.py:52,114` | Stack trace ed exit non conforme al contratto | Alta |
| P3 | Security / UX | **Confermato:** output terminale contiene controlli non escaped | `reporting/terminal.py:42-43,83-85`; `reporting/doctor.py:56-68` | ANSI/OSC, newline o bidi possono alterare il report | Alta |
| P3 | Tests | **Confermato:** un unit test richiede Node, dichiarato opzionale | `tests/test_agent_source.py:51-55`; `fixtures/node_binding/README.md` | Suite unit fallisce su ambiente Python minimale | Alta |

---

# Finding dettagliati

## 1. `pzTail` trasforma SQL completa in SQL troncata

**Priority:** P1  
**Confidence:** Alta  
**Type:** Problema confermato  
**Files:** `src/sqlitewatch/agent/sqlitewatch_agent.js:142-164`, `src/sqlitewatch/analysis/statement_tracker.py:126-130`

**Problema**

Quando `pzTail` è non nullo, `available` viene ridotto alla distanza tra `zSql` e `*pzTail`. Subito dopo, la SQL è considerata troncata quando `bytes.length === available && nByte < 0`.

Ma `*pzTail` indica normalmente il primo byte dopo lo statement compilato: raggiungerlo significa aver catturato lo statement completo, non averlo troncato.

**Perché è un problema**

Una fixture con:

```c
sqlite3_prepare_v2(db, "SELECT 1", -1, &stmt, &tail);
```

ha prodotto:

- SQL `SELECT 1`;
- `sql_truncated=True`;
- metriche VM valide;
- zero aggregati;
- `--fail-vm-steps 0` non violata;
- exit finale `0`.

Anche una query interna SQLite è stata classificata nello stesso modo. È quindi un falso PASS su un uso ordinario dell’API SQLite.

**Mitigazioni esistenti**

Il tracker conta `truncated_sql_executions`, ma poi esclude completamente tali esecuzioni. Le fixture correnti passano prevalentemente `NULL` come `pzTail`, quindi non coprono il caso.

**Proposta**

Calcolare separatamente:

- fine logica dello statement;
- limite di cattura;
- presenza effettiva di byte oltre `maxSqlLength`.

Raggiungere un `pzTail` valido entro il limite deve significare SQL completa.

**Verification**

Aggiungere un’integrazione con `nByte=-1` e `pzTail` non nullo. La SQL deve essere aggregata e `fail_vm_steps=0` deve fallire.

---

## 2. Le regole passano su dati inconclusivi

**Priority:** P1  
**Confidence:** Alta  
**Type:** Problema confermato  
**Files:** `src/sqlitewatch/agent/sqlitewatch_agent.js:173-191`, `src/sqlitewatch/analysis/statement_tracker.py:99-130`, `src/sqlitewatch/analysis/rules.py:54-76`, `src/sqlitewatch/outcome.py:27-31`

**Problema**

Il tracker esclude esecuzioni con:

- metriche nulle;
- SQL troncata;
- lifetime non associabile;
- payload conflittuali.

Le regole vedono soltanto gli aggregati rimasti. `resolve_outcome()` considera sufficiente `instrumentation_status == "ACTIVE"`.

**Perché è un problema**

Un run sintetico `ACTIVE` con una query eseguita e tutte le metriche `null` produce:

- `observed_executions=1`;
- `null_metric_executions=1`;
- zero aggregati;
- regola VM abilitata;
- exit `0`.

Il problema può manifestarsi con overflow dei contatori, reset eseguiti dall’applicazione, errori del reader o cattura SQL incompleta.

**Mitigazioni esistenti**

La matrice di test rifiuta esplicitamente metriche tutte nulle in `tests/test_validation_matrix.py:69-78`, ma tale policy non è usata dal normale outcome CLI.

**Proposta**

Aggiungere un concetto esplicito di valutazione **completa/inconclusiva**. Con regole abilitate, null metrics, SQL troncata/non catturata, unmatched e conflitti devono produrre instrumentation failure `70`, non PASS. I duplicati identici possono restare diagnostici perché deduplicabili senza perdita.

**Verification**

Test parametrico per ogni categoria di data quality, con e senza regole. Con regole: exit `70` e motivo nel JSON; senza regole: warning informativo.

---

## 3. Copertura multi-modulo certificata in modo globale

**Priority:** P1  
**Confidence:** Alta  
**Type:** Rischio concreto  
**Files:** `src/sqlitewatch/agent/sqlitewatch_agent.js:253-259`, `src/sqlitewatch/doctor.py:100-113`

**Problema**

L’agent restituisce `ACTIVE` se **qualunque** modulo è completo. Doctor verifica che esista un modulo completo, ma conta poi qualsiasi `StatementPrepared` del PID, indipendentemente dal modulo.

**Perché è un problema**

Scenario realistico:

- l’applicazione carica una `libsqlite3` completa ma inutilizzata;
- un plugin usa una seconda SQLite embedded con solo prepare o senza reader metriche;
- il prepare del plugin è osservato;
- il modulo completo rende lo stato globale `ACTIVE`;
- Doctor attribuisce l’attività al PID e restituisce `ACTIVE`.

Il comportamento è stato riprodotto con eventi sintetici: modulo completo inutilizzato + modulo parziale attivo → Doctor `ACTIVE`.

**Mitigazioni esistenti**

Doctor non combina i singoli simboli tra moduli, e la matrice di test controlla capability same-module. Manca però la correlazione tra capability e attività effettiva.

**Proposta**

Identificare il modulo con una chiave stabile, includendo path/base negli eventi lifecycle. Marcare la run come parziale/inconclusiva quando attività osservata appartiene a un modulo incompleto. Doctor deve contare solo attività di moduli completi e segnalare attività mista.

**Verification**

Fixture con due implementazioni: completa inutilizzata e incompleta utilizzata. Doctor e run con regole non devono risultare attivi/passing.

---

## 4. Timeout e abort possono lasciare processi vivi

**Priority:** P1  
**Confidence:** Alta  
**Type:** Problema confermato  
**Files:** `src/sqlitewatch/process.py:152-170,292-328,380-386`, `src/sqlitewatch/instrumentation/frida_backend.py:178-183`

**Problema**

`_abort_launcher()` invia un solo segnale e ritorna. Non attende completion, non verifica la morte dei processi e non applica escalation.

**Perché è un problema**

Con un target che ignora SIGTERM e `completion_timeout=0.2`, il controller ha restituito instrumentation failure mentre:

- target ancora vivo;
- launcher ancora vivo e bloccato in `waitpid()`.

Lo stesso failure mode esiste dopo Ctrl-C se il target ignora SIGINT oltre i cinque secondi, o dopo altri errori di instrumentation.

**Mitigazioni esistenti**

Il launcher inoltra SIGTERM/SIGINT e reapa correttamente target cooperativi. I test correnti coprono solo questo caso.

**Proposta**

Centralizzare la shutdown:

1. segnale al launcher;
2. attesa bounded della completion;
3. se necessario SIGKILL diretto al target;
4. attesa del launcher che esegue `waitpid`;
5. SIGKILL del launcher solo come ultima risorsa;
6. conferma che entrambi non siano più vivi.

Preservare l’errore originale e aggiungere eventuali errori di cleanup.

**Verification**

Integration test con target che ignora SIGTERM/SIGINT. Dopo il ritorno nessuno dei due PID deve esistere.

---

## 5. Completion socket falsificabile dal target

**Priority:** P2  
**Confidence:** Alta  
**Type:** Problema confermato  
**Files:** `src/sqlitewatch/process.py:77-82,292-378`

**Problema**

Il controller accetta la prima connessione e valida solo il JSON e il PID dichiarato. Non controlla il PID reale del peer.

**Perché è un problema**

Un target può leggere `/proc/$PPID/cmdline`, ricavare il path del socket, connettersi e inviare il proprio PID con exit `0`. Il probe ha prodotto:

- `target_exit_code=0`;
- `instrumentation_failed=False`;
- target e launcher ancora vivi dopo il ritorno.

I permessi `0700/0600` bloccano altri utenti, ma non il target eseguito con lo stesso UID.

Non è privilege escalation — il target è già codice arbitrario — ma compromette integrità del report e lifecycle.

**Proposta**

Sul Linux attualmente supportato verificare `SO_PEERCRED`:

- peer PID uguale al launcher atteso;
- UID uguale all’UID corrente.

Applicare lo stesso controllo al record `launch_failure`. Integrare con la shutdown robusta del finding precedente.

**Verification**

Target malevolo che invia JSON formalmente valido: completion rifiutata, exit non zero, nessun processo residuo. Launcher reale: comportamento invariato.

---

## 6. SQL UTF-8 finale corrotta

**Priority:** P2  
**Confidence:** Alta  
**Type:** Problema confermato  
**Files:** `src/sqlitewatch/agent/sqlitewatch_agent.js:157-164`

**Problema**

Il ciclo che tenta di evitare un codepoint incompleto rimuove tutti i byte di continuazione finali, ma lascia il lead byte. Una sequenza UTF-8 valida che termina la SQL diventa quindi invalida; `readUtf8String()` fallisce e il catch restituisce SQL vuota senza errore.

**Perché è un problema**

`SELECT 1 AS café` è stata osservata come:

```text
sql=""
sql_truncated=False
captured_bytes=0
```

Query diverse possono quindi condividere fingerprint e aggregato della stringa vuota, rendendo il report non diagnosticabile.

**Mitigazioni esistenti**

Esistono test Unicode del protocollo e della normalizzazione, ma le fixture terminano l’accento con newline/quote e non esercitano questo boundary.

**Proposta**

Validare il prefisso UTF-8 completo, distinguendo esplicitamente `capture_failed` da una stringa vuota. Non usare il testo vuoto come fallback silenzioso.

**Verification**

Test con codepoint finali a 2, 3 e 4 byte e con il limite che cade in ogni posizione della sequenza.

---

## 7. Lettura SQL troppo costosa nel percorso caldo

**Priority:** P2  
**Confidence:** Alta  
**Type:** Problema confermato  
**Files:** `src/sqlitewatch/agent/sqlitewatch_agent.js:142-161`

**Problema**

Ogni byte viene letto con una chiamata Frida `pointer.add(i).readU8()`, seguito da più copie dell’array.

**Perché è un problema**

Probe indicativo sullo stesso host:

- 200 prepare di SQL da circa 60 KiB, senza instrumentation: circa `0,005 s`;
- sotto SQLiteWatch: circa `16,8 s`;
- una singola run instrumentata: circa `0,46 s`;
- 20 prepare: circa `1,99 s`.

L’overhead cresce quindi chiaramente per query e dimensione, alterando sensibilmente il comportamento del target.

**Mitigazioni esistenti**

La dimensione è bounded a 64 KiB di default e 1 MiB massimo; ciò protegge dall’input illimitato ma non dal costo sincrono.

**Proposta**

Usare letture bulk/chunk bounded supportate da Frida e ricerca del NUL in memoria JS. Doctor può evitare del tutto di catturare SQL completa, dato che conta solo l’attività.

**Verification**

Benchmark ripetibile con SQL corte/lunghe e numero crescente di prepare; assenza di chiamate native per singolo byte.

---

## 8. Memoria lineare e cache inefficace

**Priority:** P2  
**Confidence:** Alta  
**Type:** Problema confermato / rischio di scala  
**Files:** `src/sqlitewatch/process.py:49-50,215-222`, `src/sqlitewatch/analysis/statement_tracker.py:56-66,115-140`, `src/sqlitewatch/analysis/aggregation.py:129-133`

**Problema**

Il controller conserva tutti gli eventi. Il tracker crea ulteriori mappe/set e una lista per ogni esecuzione. Inoltre:

```python
normalized_cache.setdefault(sql, _normalized_fingerprint(sql))
```

valuta `_normalized_fingerprint()` anche quando la chiave esiste.

**Perché è un problema**

Su 200.000 esecuzioni sintetiche:

- circa 160 MiB RSS;
- circa 8,9 secondi di sola analisi.

Con 10.000 esecuzioni della stessa SQL, la normalizzazione è stata chiamata 10.000 volte anziché una.

Un profiler eseguito su test suite o servizi lunghi può esaurire memoria.

**Mitigazioni esistenti**

Il queue agent è bounded/batched e il controller drena periodicamente la propria queue; la lista finale `_events` resta però illimitata.

**Proposta**

Correzione immediata del lookup cache. Successivamente usare un reducer incrementale e non trattenere lifecycle raw nel percorso CLI normale; mantenere retention opt-in per debug/test. Aggiungere comunque un limite esplicito per fallire chiaramente invece di arrivare a OOM.

**Verification**

Stress test 200k–1M esecuzioni: normalizzazione una volta per SQL e memoria proporzionale a statement attivi/query uniche, non agli eventi totali.

---

## 9. Seconda run sullo stesso controller fallisce

**Priority:** P2  
**Confidence:** Alta  
**Type:** Problema confermato  
**Files:** `src/sqlitewatch/instrumentation/frida_backend.py:39,147-155`, `src/sqlitewatch/process.py:204-213`

**Problema**

L’agent riparte sempre dalla sequence lifecycle `1`; `_next_lifecycle_sequence` viene inizializzato solo nel costruttore del backend.

**Perché è un problema**

Due `run()` sullo stesso `ProcessController` hanno prodotto:

- prima run: `ACTIVE`, 21 esecuzioni;
- seconda: `FAILED`, “expected 14”, nessuna completion target.

**Mitigazioni esistenti**

La CLI crea un controller nuovo a ogni invocazione e la docstring del backend parla di “one run”. L’API Python non impedisce però il riuso né produce un errore preventivo chiaro.

**Proposta**

Reset per-run esplicito, con generazione dei callback per ignorare messaggi tardivi e rimozione/reuso controllato del listener `child-added`. In alternativa dichiarare e imporre formalmente un controller one-shot; il reset è preferibile.

**Verification**

Due run consecutive reali con lo stesso controller, entrambe con prima batch sequence `1`.

---

## 10. Reload dello stesso modulo perde gli hook

**Priority:** P2  
**Confidence:** Alta  
**Type:** Problema confermato  
**Files:** `src/sqlitewatch/agent/sqlitewatch_agent.js:19-21,125-139,238-267`

**Problema**

`onRemoved` cancella inventario e stato di scansione, ma non:

- `hookedAddresses`;
- `hookedSymbolNames`;
- listener restituiti da `Interceptor.attach()`.

I listener non vengono nemmeno conservati.

**Perché è un problema**

Nel probe `dlopen → SELECT 1 → dlclose → dlopen → SELECT 2` è stata osservata solo `SELECT 1`. La seconda copia è stata deduplicata e non agganciata.

**Mitigazioni esistenti**

Se è l’unico modulo, lo stato può diventare `DETECTED_UNSUPPORTED`, facendo fallire le regole. Se rimane un altro modulo completo, lo stato globale può però restare `ACTIVE`.

**Proposta**

Usare una chiave modulo che includa la base address, conservare i listener per modulo e, su unload, eseguire detach e rimuovere le chiavi di deduplicazione. Invalidare eventuali statement context appartenenti al modulo.

**Verification**

Due cicli di load/unload con SQL distinte; entrambi devono produrre prepare, execute e finalize.

---

## 11. Output Unicode su stdout non garantito

**Priority:** P2  
**Confidence:** Alta  
**Type:** Problema confermato  
**Files:** `src/sqlitewatch/cli.py:211-224`

**Problema**

Il file output usa UTF-8 esplicito, mentre stdout usa l’encoding ambientale. `UnicodeEncodeError` non è incluso nel blocco che converte gli errori di output in exit `74`.

**Perché è un problema**

Con `PYTHONIOENCODING=ascii` e una SQL contenente `café`, la CLI ha prodotto stack trace e exit `1`, invece di documento UTF-8 o output failure `74`.

**Proposta**

Scrivere byte UTF-8 tramite un helper centralizzato con fallback per stream testuali. Gestire anche `UnicodeError`.

**Verification**

Subprocess terminal e JSON con `PYTHONIOENCODING=ascii`; il risultato deve essere UTF-8 valido e senza traceback.

---

## 12. Controlli terminali non escaped

**Priority:** P3  
**Confidence:** Alta  
**Type:** Problema confermato  
**Files:** `src/sqlitewatch/reporting/terminal.py:42-43,83-85`, `src/sqlitewatch/reporting/doctor.py:56-68`

**Problema**

SQL, module, path e reason vengono interpolati direttamente, nonostante `render_run_terminal()` dichiari output senza sequenze ANSI.

**Perché è un problema**

SQL contenente newline, ESC, OSC, BEL o caratteri bidi può nascondere righe, modificare titolo/clipboard del terminale o rendere ambiguo un report salvato e successivamente visualizzato.

Il target può già scrivere sul terminale, quindi non è un confine di sandbox; resta però un problema per dati SQL non stampati direttamente dal target.

**Proposta**

Escape centralizzato per caratteri C0/C1, ESC, DEL, newline e Unicode di formattazione. JSON invariato.

**Verification**

Test con ANSI/OSC/bidi: nessun byte di controllo raw nel renderer terminale.

---

## 13. Node opzionale ma richiesto dalla suite unit

**Priority:** P3  
**Confidence:** Alta  
**Type:** Problema confermato  
**Files:** `tests/test_agent_source.py:51-55`

**Problema**

Il test chiama direttamente `node --check`; senza Node solleva `FileNotFoundError`. Il fixture Node è invece documentato come opzionale e gli integration test controllano la disponibilità.

**Proposta**

Risoluzione con `shutil.which()` e `pytest.mark.skipif`, oppure marker toolchain dedicato.

**Verification**

Eseguire la suite unit con Node assente: test skipped, non failure.

---

## Osservazioni non classificate come bug

- Il target viene avviato tramite argv e `os.posix_spawnp()`, senza shell: non è presente shell injection.
- Il writer su file usa temporaneo, `fsync()` e `os.replace()`: protegge da report parziali.
- Il protocollo rifiuta campi sconosciuti e valida atomicamente i batch.
- SQL e literal originali sono inclusi intenzionalmente nei report. Gli output vanno quindi trattati come dati potenzialmente sensibili; è opportuno documentarlo chiaramente.
- L’assenza di child-process instrumentation, supporto cross-platform e binary fingerprinting è esplicitamente dichiarata e non è stata classificata come difetto.

---

# Implementation Plan

## T1 — Correggere il contratto di cattura SQL

- [x] Implementazione e verifica automatizzata completate.

**Obiettivo:** eliminare falso truncation, corruzione UTF-8 e fallback vuoto ambiguo.

**File/moduli**
- `src/sqlitewatch/agent/sqlitewatch_agent.js`
- `src/sqlitewatch/events.py`
- `src/sqlitewatch/instrumentation/protocol.py`
- `src/sqlitewatch/analysis/statement_tracker.py`
- fixture/test protocollo e integrazione C

**Modifiche previste**

- Correggere la semantica `nByte`/`pzTail`.
- Introdurre uno stato esplicito `sql_capture_failed`.
- Rendere coerenti `captured_bytes`, truncation ed errore.
- Correggere il boundary UTF-8.
- Non aggregare fallback vuoti come SQL valida.

**Dipendenze:** nessuna.

**Rischi:** over-read oltre NUL e versionamento del protocollo.

**Test:** `pzTail`, multi-statement, UTF-8 2/3/4 byte, limiti esatti, pointer illeggibile.

**Accettazione:** il probe `SELECT 1` con `pzTail` viene aggregato; `SELECT … café` mantiene il testo completo.

---

## T2 — Rendere le regole fail-closed sui dati incompleti

- [x] Implementazione e verifica automatizzata completate.

**Obiettivo:** impedire PASS CI quando parte delle osservazioni non è valutabile.

**File/moduli**
- `analysis/statement_tracker.py`
- `analysis/aggregation.py`
- `analysis/rules.py`
- `outcome.py`
- `reporting/model.py`, `reporting/json.py`

**Modifiche previste**

- Aggiungere `evaluation_complete` e motivi di incompletezza.
- Considerare inconcludenti null metrics, truncation, capture failure, unmatched e conflitti.
- Con regole abilitate: classificare incompletezza come instrumentation failure `70`.
- Conservare nel report eventuali violazioni già trovate.
- Duplicati identici: deduplicazione diagnostica, non failure.

**Dipendenze:** T1, per non trasformare l’attuale bug `pzTail` in failure generalizzata.

**Rischi:** rendere troppo severi casi di qualità innocui; mantenere categorie distinte.

**Test:** un test per ogni contatore di qualità, con/senza regole.

**Accettazione:** nessun report `rules.passed=true` se un’esecuzione osservata è stata esclusa per perdita di dati.

---

## T3 — Correlare capability e attività per modulo

- [x] Implementazione e verifica automatizzata completate.

**Obiettivo:** impedire che un modulo completo certifichi l’attività di un altro modulo.

**File/moduli**
- agent JS
- `events.py`
- `instrumentation/protocol.py`
- `doctor.py`
- test Doctor e fixture multi-modulo

**Modifiche previste**

- Aggiungere path/identità modulo agli eventi lifecycle.
- Tracciare attività per modulo.
- Introdurre stato parziale/inconclusivo per attività su modulo incompleto.
- Doctor `ACTIVE` solo quando l’attività appartiene a moduli completi.
- Attività mista completa/incompleta deve essere esplicita.

**Dipendenze:** può procedere in parallelo con T2, coordinando le modifiche al protocollo.

**Rischi:** nomi modulo duplicati; usare path/base address, non solo basename.

**Test:** completo-inutilizzato + incompleto-attivo; due moduli completi; nomi uguali con path diversi.

**Accettazione:** il primo scenario non produce `ACTIVE` né exit `0` con regole.

---

## T4 — Hardenizzare completion e shutdown

- [x] Implementazione e verifica automatizzata completate.

**Obiettivo:** autenticare l’IPC e garantire che il controller non lasci processi residui.

**File/moduli**
- `src/sqlitewatch/process.py`
- `src/sqlitewatch/instrumentation/frida_backend.py`
- eventualmente `src/sqlitewatch/launcher.py`
- `tests/test_process.py`
- `tests/integration/test_process_exit.py`

**Modifiche previste**

- Verificare `SO_PEERCRED` per completion e launch failure.
- Passare separatamente PID launcher e target.
- Centralizzare abort/cleanup:
  - TERM/INT;
  - attesa bounded;
  - KILL target;
  - attesa reap del launcher;
  - KILL launcher solo come ultima risorsa.
- Preservare errore primario e registrare errori secondari di cleanup.

**Dipendenze:** nessuna; autenticazione e shutdown vanno integrate insieme.

**Rischi:** PID reuse e race tra completion e detach. Restare su primitive Linux compatibili con lo scope corrente.

**Test:** peer target falsificato, target che ignora TERM/INT, completion durante cleanup.

**Accettazione:** solo il launcher può completare la run; dopo ogni failure entrambi i PID sono terminati.

---

## T5 — Definire e correggere il lifecycle per-run del backend

- [x] Implementazione e verifica automatizzata completate.

**Obiettivo:** consentire riuso sicuro o imporre esplicitamente il contratto one-shot.

**File/moduli**
- `instrumentation/frida_backend.py`
- `process.py`
- `tests/test_instrumentation.py`
- `tests/test_process.py`

**Modifiche previste**

- Aggiungere `begin_run()` con reset sequence/callback/script.
- Registrare `child-added` una sola volta o rimuoverlo al detach.
- Associare i callback a una generazione per ignorare messaggi tardivi.
- Pulire tutti i riferimenti per-run in `detach()`.

**Dipendenze:** indipendente da T1–T3.

**Rischi:** callback concorrenti durante detach/reset.

**Test:** due run consecutive reali e messaggio tardivo simulato.

**Accettazione:** entrambe le run accettano sequence iniziale `1` senza callback duplicati.

---

## T6 — Gestire unload/reload degli hook

- [x] Implementazione e verifica automatizzata completate.

**Obiettivo:** riagganciare correttamente lo stesso modulo dopo `dlclose()`.

**File/moduli**
- `agent/sqlitewatch_agent.js`
- fixture/test `c_dynamic_late`

**Modifiche previste**

- Chiave modulo comprendente base address.
- Conservare i listener restituiti da `Interceptor.attach()`.
- Su `onRemoved`: detach listener, eliminazione dedup key e context.
- Ricalcolare status/hook count.
- Un detach ambiguo deve produrre failure esplicita.

**Dipendenze:** dopo T3 per condividere l’identità modulo.

**Rischi:** unload con statement ancora attivi.

**Test:** due cicli completi `dlopen/query/dlclose`.

**Accettazione:** SQL di entrambi i cicli presente, nessun “hook deduplicated”.

---

## T7 — Ridurre l’overhead della cattura SQL

- [x] Implementazione e verifica automatizzata completate.

**Obiettivo:** eliminare una chiamata Frida per byte.

**File/moduli**
- `agent/sqlitewatch_agent.js`
- benchmark/fixture dedicata

**Modifiche previste**

- Lettura bulk o chunk bounded con ricerca NUL in JavaScript.
- Evitare copie multiple.
- In Doctor, catturare solo il minimo necessario.
- Rendere visibile nel report il limite effettivo di cattura.

**Dipendenze:** dopo T1; coordinare con T6 perché modificano lo stesso agent.

**Rischi:** letture oltre pagine accessibili.

**Test:** matrice dimensione SQL × numero prepare, inclusi boundary di pagina.

**Accettazione:** forte riduzione rispetto al caso 200×60 KiB e assenza del loop `readU8()` per byte.

---

## T8 — Rendere analisi e retention bounded

- [x] Implementazione e verifica automatizzata completate.

**Obiettivo:** memoria non proporzionale a tutti gli eventi della run.

**File/moduli**
- `process.py`
- `analysis/statement_tracker.py`
- `analysis/aggregation.py`
- `cli.py`
- test stress

**Modifiche previste**

1. Correggere subito il `setdefault()` con lookup esplicito.
2. Introdurre reducer `consume()/finish()`.
3. Passare un event consumer al controller.
4. Nel percorso CLI non conservare lifecycle raw; retention opt-in per debug/test.
5. Aggiungere un limite di sicurezza per evitare OOM se il consumer non è usato.

**Dipendenze:** T2 per la semantica delle esecuzioni inconclusive.

**Rischi:** compatibilità con `RunResult.events` e gestione di duplicati tardivi.

**Test:** normalizzazione una volta per SQL; stress 200k–1M eventi; confronto report streaming/materializzato.

**Accettazione:** memoria proporzionale a statement attivi e query uniche, report invariato.

---

## T9 — Rendere l’output UTF-8 e terminal-safe

- [x] Implementazione e verifica automatizzata completate.

**Obiettivo:** rispettare il contratto UTF-8 e neutralizzare controlli terminali.

**File/moduli**
- `cli.py`
- `reporting/terminal.py`
- `reporting/doctor.py`
- relativi test

**Modifiche previste**

- Helper stdout UTF-8 binario con fallback per stream testuali.
- Gestione `UnicodeError` come output failure `74`.
- Escape centralizzato di ESC, C0/C1, DEL, newline e caratteri bidi/formattazione.
- Applicazione anche ai diagnostici stderr.
- JSON lasciato strutturalmente invariato.

**Dipendenze:** indipendente.

**Rischi:** compatibilità con pytest capture e embedding API.

**Test:** `PYTHONIOENCODING=ascii`, ANSI/OSC/BEL/bidi e multiline SQL.

**Accettazione:** nessun traceback Unicode e nessun controllo target-controlled raw nel terminale.

---

## T10 — Chiudere i gap di test e documentazione

- [x] Implementazione e verifica automatizzata completate.

**Obiettivo:** rendere permanenti i nuovi contratti.

**File/moduli**
- `tests/test_agent_source.py`
- tutte le suite interessate
- `spec.md`, `architecture.md`, `poc-plan.md`
- `pyproject.toml`/README se il progetto viene distribuito

**Modifiche previste**

- Skip esplicito del controllo sintattico JS quando Node manca.
- Documentare:
  - cattura SQL e data quality inconclusiva;
  - copertura per modulo;
  - peer authentication e shutdown;
  - limiti di memoria;
  - sensibilità dei report contenenti SQL raw.
- Valutare una CI basata sugli strumenti già presenti, senza introdurre framework ulteriori.
- Sostituire come metadata package il piano PoC con documentazione utente quando disponibile.

**Dipendenze:** ultimo task.

**Rischi:** nessuno significativo.

**Accettazione:** ogni finding ha almeno un test che fallisce sul comportamento attuale e passa dopo la correzione; suite completa, build e lock check verdi.

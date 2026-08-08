# Architecture Proposal — agent-task-journal v0.1

Статус: **предложение Итерации 0**. Окончательный event contract должен быть принят ADR в Итерации 1.

Позиционирование: **ALCOA+-inspired task journaling**, без заявлений о GxP/GMP/FDA/EMA compliance.

## 1. Рекомендуемая форма продукта

- Python 3.11+ package.
- Console script: `task-journal`.
- Установка: `uv tool install ...` и `pip install ...`.
- Core не зависит от Hermes/OpenClaw/Codex.
- JSON Schema Draft 2020-12.
- Локальное файловое хранилище.
- Нет обязательного daemon, GUI, web server или database.
- Минимальные runtime dependencies; предпочтительно одна библиотека JSON Schema, если стоимость vendoring/самописной validation выше.

## 2. Canonical storage

### Рекомендация: один JSONL stream на задачу

Предварительный layout:

```text
<journal-root>/
  tasks/
    <task_id>.jsonl
  locks/
    <task_id>.lock
```

- `tasks/<task_id>.jsonl` — единственная canonical truth для задачи.
- Одна строка — один immutable JSON event в UTF-8 с LF.
- Первое событие — `task_open`.
- Следующие события hash-linked внутри той же задачи.
- `show`, `list`, search/filter и exports — projections, полученные replay-ем streams.
- Mutable index не нужен в v0.1. Если появится позже, он должен быть rebuildable и non-canonical.

### Почему не один глобальный ledger

| Критерий | Global JSONL | Per-task JSONL |
|---|---|---|
| Global total order | Да | Нет; только timestamp + task_id order |
| Lock contention | Высокий | Только на одну задачу |
| Corruption blast radius | Весь journal | Одна задача |
| Backup/export одной задачи | Неудобнее | Просто |
| Lifecycle replay | Нужна фильтрация | Прямой последовательный replay |
| Простота `show`/`verify TASK` | Средняя | Высокая |
| Concurrent agents | Один bottleneck | Независимые tasks параллельны |

Для v0.1 global total order не является заявленной гарантией. Contemporaneous timestamps сохраняются, но одинаковые/несинхронизированные clocks не создают достоверного глобального порядка. Если позднее потребуется глобальный audit root, его лучше добавить как export/checkpoint layer, не ломая task streams.

## 3. Event pipeline

```text
adapter/CLI input
-> candidate event
-> schema validation
-> task replay and state-transition validation
-> artifact observation/hash (when available)
-> acquire per-task lock
-> re-read and verify current head
-> assign event sequence and previous hash
-> deterministic serialization and event hash
-> controlled binary append
-> flush + fsync
-> immediate read-back check
-> release lock
-> canonical task stream
```

Критическая race-защита: state replay и head hash должны быть повторно проверены **после** получения lock. Candidate, рассчитанный на старом head, не должен быть appended.

Crash safety не следует переоценивать: заранее сериализованные `bytes + LF` должны записываться через OS append semantics под lock с обработкой short writes; файл синхронизируется, а parent directory — после create/rename/lockfile operations там, где платформа это поддерживает. Crash всё ещё может оставить truncated final line. Такая задача становится `corrupt/unverifiable`; автоматическая правка canonical файла запрещена. Network filesystems считаются unsupported, пока их semantics не доказаны тестами.

## 4. Предварительный event envelope

Точный JSON выбирается в Итерации 1. Минимально envelope должен содержать:

- `schema_version`;
- `event_type`;
- `event_id`;
- `task_id`;
- `sequence`;
- `timestamp` с explicit UTC offset;
- `timezone` или честно определённую timezone identifier/offset policy;
- `actor` (кто поставил/инициировал);
- `agent` (какой агент принял задачу);
- `executor` (кто выполнил конкретное действие);
- `session_id`, nullable/optional;
- `source` (Hermes Desktop/CLI/OpenClaw/Codex/API/manual и locator, если доступен);
- `status` или event-specific status;
- event-specific payload;
- `previous_event_hash` (`null` только для open);
- `event_hash`;
- `hash_algorithm_version`.

### Event payloads

- `task_open`: исходное поручение **без normalization**, optional normalized goal отдельно.
- `task_event`: существенное действие, наблюдение, решение, ошибка, artifact update или progress.
- `task_close`: terminal execution status, outcome, errors, unfinished items, artifacts.
- `task_verify`: scope, verified head hash, verifier identity/tool version, result и findings.
- `correction` / `amendment`: target event ID/hash, reason, corrected fields/additional facts; старый event не меняется.

Одна schema может использовать stable envelope + `oneOf` по `event_type`; не создавать отдельный package format без необходимости.

## 5. Original instruction guarantee

Гарантия должна формулироваться строго:

> Журнал сохраняет instruction как точную последовательность Unicode code points, полученную core CLI от adapter/input mode, включая пробелы и переводы строк; он не доказывает неизменность данных до этой границы.

Рекомендации для Iteration 1:

- `open` поддерживает `--instruction-file` и stdin для multiline/trailing-newline input;
- stdin/file читаются binary API (`sys.stdin.buffer` / `rb`) до decoding, чтобы Windows text mode не преобразовал CRLF/BOM;
- core не вызывает `.strip()`, newline normalization или semantic rewrite;
- хранится `original_instruction` без text normalization;
- file/stdin bytes принимаются только по явной strict UTF-8/BOM policy; hash raw bytes и hash deterministic UTF-8 encoding декодированного text имеют разные имена и semantics;
- API string не имеет upstream raw-byte guarantee: core hash-ирует только deterministic UTF-8 encoding полученных code points;
- `normalized_goal` — отдельное optional поле и никогда не заменяет original;
- encoding/error policy должна быть детерминированной и документированной; test vectors включают CRLF/LF, BOM, trailing newline, NUL и invalid UTF-8 на Windows/Linux.

CLI argument mode допустим для короткого текста, но shell quoting не позволяет обещать сохранение bytes до запуска CLI.

## 6. Hash model

Итерация 1 должна зафиксировать ADR для hash preimage. Предпочтение:

- SHA-256;
- domain-separated preimage;
- canonical JSON bytes с `sort_keys`, fixed separators, UTF-8, запретом NaN/Infinity и явной newline policy;
- floats, `-0.0` и нецелые JSON numbers предпочтительно запретить в canonical envelope/payload v0.1; иначе numeric serialization должна быть полностью специфицирована golden vectors;
- `event_hash` исключается из собственного preimage;
- `previous_event_hash` включается;
- hash algorithm/canonicalization version фиксируется.

Не следует заявлять RFC 8785/JCS, если реализация использует более простой project-specific canonical JSON profile.

Hash chain даёт **tamper evidence для неизменённого trusted head**, но не tamper-proof storage: атакующий с правом переписать весь journal может пересчитать цепь. v0.1 не включает digital signatures, TSA или remote anchoring. Exported head hash/checkpoint полезен как внешний anchor, но может быть отложен.

## 6.1. Integrity threat model

**Защищаемые assets:** exact received instruction, порядок task-local events, lifecycle state, recorded artifact hashes и известный trusted head/checkpoint.

**Рассматриваемые сбои/атаки:** случайное редактирование, bit/line corruption, truncation/partial tail, reorder/insert/delete внутри chain, stale concurrent writer и artifact mismatch.

**Не предотвращаются одним hash chain:** полное удаление task stream; rollback/truncation до прежнего valid head без внешнего checkpoint; copy/replay stream под другим journal root; подмена всего root; пересчёт chain локальным writer/admin; compromised CLI/adapter, создающий false-but-valid events; clock spoofing; ложное semantic содержание.

**Меры v0.1:** deterministic verifier, task-local sequence/hash chain, strict root/ID containment, explicit corrupt status, optional exported trusted head/checkpoint, versioned tool/schema/hash metadata и честные non-guarantees. Digital signatures, remote transparency log и trusted time source остаются вне v0.1.

## 7. State machine

Предварительные execution statuses:

- `open`;
- terminal: `completed`, `partial`, `failed`, `cancelled`.

Базовые правила:

1. `task_open` — ровно один, sequence 1.
2. Обычный `task_event` допустим только пока execution state `open`.
3. `task_close` — ровно один, только из `open`.
4. Полный journaled lifecycle требует recorded `task_verify` после close; read-only integrity check не является event и не меняет lifecycle. Повторная recorded verification может быть допустима как новый event.
5. Correction/amendment может быть post-close, но не меняет raw lifecycle transition и не reopen-ит задачу. Если исправляется outcome/close payload, projection показывает amended outcome вместе с original terminal status и всей superseded chain.
6. Reopen не включать в v0.1 без отдельного решения.
7. Нельзя скрыть partial/failed/cancelled/error/unfinished fields через projected view.

Нужна отдельная verification state, чтобы не смешивать execution outcome и integrity verification result.

## 8. CLI contract

Рекомендуется сохранить предложенные команды:

```text
task-journal open
task-journal event
task-journal close
task-journal verify
task-journal show
task-journal list
task-journal search
task-journal export
```

### Семантика

- `open`: создаёт новый task stream exclusive-create; не перезаписывает existing ID.
- `event`: добавляет существенное event только в open task.
- `close`: закрывает task как completed/partial/failed/cancelled и требует явные outcome/errors/unfinished semantics.
- `verify`: по умолчанию read-only deterministic integrity check. Для завершения полного journaled lifecycle явный `--record` append-ит `task_verify` только после успешной проверки predecessor head; затем новая запись также проходит structural read-back. Failed integrity check выдаёт external/non-canonical report и не пытается append-ить в недоверенную chain. Точное UX/имя режима зафиксировать ADR.
- `show`: replay и human-readable/JSON view; raw mode показывает original events без correction folding.
- `list`: scan streams; filters по execution/verification status, actor/agent/source/time. Повреждённая задача не должна исчезать — показывается как `corrupt/unverifiable`.
- `search`: deterministic read-only search/filter projection; не создаёт canonical index.
- `export`: raw/verifiable и portable/redacted export profiles с явным manifest/head hashes; export не заменяет backup и не подтверждает доступность source root.

CLI должен иметь стабильные exit codes для success, validation error, state conflict, not found, lock conflict, integrity failure и artifact mismatch.

## 9. Idempotency

Agent retry может повторить команду после timeout. Предлагается:

- caller-supplied optional `operation_id`/idempotency key;
- уникальность в пределах task stream;
- duplicate key + identical canonical request digest → вернуть существующий event без append;
- duplicate key + другой digest → fail conflict;
- event ID всегда уникален;
- close и open retry-safe только при stable caller-supplied operation ID или иной заранее определённой deterministic identity; retry без неё может конфликтовать или дублироваться и не имеет общей idempotency guarantee.

Точный key scope и request digest входят в ADR Итерации 1.

## 10. Artifact model

Минимальная artifact entry:

- logical role;
- `portable_locator`: relative path/URI, пригодный для export, если безопасно вычислим;
- `local_private_locator`: optional machine-specific absolute path только по privacy policy и не включаемый в portable export по умолчанию;
- action (`created`, `modified`, `deleted`, `referenced`);
- SHA-256 и size для доступного regular file;
- hash status (`hashed`, `unavailable`, `unstable`, `deleted`, `unsupported`);
- observed timestamp;
- optional media/type.

Правила:

- directories не hash-ировать как файлы в v0.1;
- symlink policy определить явно;
- hash streaming;
- stat до/после hashing для обнаружения concurrent modification;
- artifact mismatch не переписывает старый event;
- `verify` различает missing/unavailable и confirmed mismatch;
- absolute path не является portable locator; raw local event может хранить его только как `local_private_locator` после privacy decision. Portable export по умолчанию исключает или явно редактирует это поле; machine-specific paths не встраиваются в installable adapter rules.

Artifact verification имеет три разных scope:

1. **Journal structural/integrity verification** проверяет event и point-in-time artifact hash как неизменную запись наблюдения.
2. **Current external artifact check** сравнивает нынешний объект по locator с историческим hash; mismatch означает изменение текущего объекта, а не опровержение исторического наблюдения.
3. **Managed snapshot verification** повторно проверяет content-addressed snapshot, только если journal явно владеет такой копией.

Без managed snapshot исторический artifact hash является point-in-time observation; enduring availability или повторная проверяемость содержимого не обещается.

## 11. Concurrency and durability

Минимальные гарантии должны включать:

- per-task exclusive lock;
- cross-platform protocol для Windows/Linux/WSL;
- timeout и owner metadata;
- осторожную stale-lock policy без автоматического небезопасного удаления;
- заранее сериализованный binary record и обработка short writes под lock;
- OS append semantics, flush + `fsync` file; parent-directory sync после create/rename там, где поддерживается;
- на Windows durability mapping должен определить `FlushFileBuffers`, sharing flags и reparse-point checks; WSL/MSYS/native Windows рассматриваются отдельно;
- создание task file exclusive;
- обнаружение truncated final line;
- отсутствие auto-repair canonical history в `verify`;
- documented filesystem assumptions (локальная FS; network shares могут иметь другие semantics).

Нужно решить, использовать ли маленькую dependency для locking или реализовать lockfile protocol на stdlib. Это должно решаться тестами на Windows и Linux, а не только желанием «zero dependencies».

## 12. Components

Предлагаемые логические модули (имена не окончательны):

1. **CLI** — parsing, input modes, stable exit codes.
2. **Application service** — open/event/close/verify/show/list use cases.
3. **Domain model** — event types, state replay, transitions, correction rules.
4. **Schema registry** — bundled schemas and version dispatch.
5. **Canonical codec** — deterministic JSON bytes and hash preimage.
6. **Journal store** — safe paths, lock, append, fsync, stream read.
7. **Artifact hasher** — streaming SHA-256 and stability checks.
8. **Verifier** — schema/hash/sequence/state/artifact checks.
9. **Projection** — human-readable show/list/search without becoming canonical.
10. **Adapters** — Hermes skill, HERMES rule, OpenClaw/Codex instructions; only invoke core CLI.

Dependency direction: adapters/CLI → application → domain ports; storage/schema/hash are deterministic infrastructure. Agent prompts не владеют гарантиями.

## 13. ALCOA+-inspired mapping

Это design targets и supporting controls, а не доказанные свойства или compliance claims.

| Свойство | Supporting control / target | Ограничение / не-гарантия |
|---|---|---|
| Attributable | declared actor/agent/executor/session/source в каждом event | Declaration без authentication, signature или identity proof |
| Legible | UTF-8 JSONL + human-readable projections | Зависит от сохранившегося readable journal root и поддерживаемой schema |
| Contemporaneous | core-generated `recorded_at`; caller-supplied `occurred_at` отдельно | Local clock может быть неверным/spoofed; timestamp не доказывает contemporaneous capture |
| Original | exact core-received code points/raw-input policy + hash; normalized goal отдельно | Не доказывает неизменность до core boundary; privacy redaction ослабляет Original |
| Accurate | Accuracy-supporting schema/state/hash/artifact checks и explicit statuses | Structural/integrity controls не доказывают semantic truth или фактическое выполнение |
| Complete | errors, partial, cancelled, unfinished обязательны/видимы | Agent может не сообщить неизвестный факт; corrupt/deleted root ограничивает completeness |
| Consistent | versioned envelope, sequence, state machine, canonical hash profile | Только внутри поддерживаемых schema/hash versions и task-local order |
| Enduring | logical append-only, bounded local durability, documented backup/export target | Не WORM; crash/admin/network-FS risks остаются; backup не возникает автоматически |
| Available | v0.1 target: show/list/search/export/verify без сервера | Только для доступного local root; export/search должны иметь отдельные acceptance tests |

## 14. Не-гарантии v0.1

- Не GxP/compliance система.
- Не WORM storage.
- Не защита от администратора, пересчитавшего всю chain.
- Не cryptographic attribution/signature.
- Не доказательство semantic truth или фактического выполнения.
- Не глобально синхронизированная timeline между машинами.
- Не transactional capture внешних filesystem/network side effects.
- Не гарантирует доступность artifact после его удаления.

## 15. Acceptance criteria для Итерации 1

Итерация 1 должна создать только contract/ADR artifacts и тестовые vectors/specification, не полный CLI. Минимально решить:

1. event envelope и event type schemas;
2. task/verification state machine;
3. ID format;
4. timestamp/timezone policy;
5. exact-input boundary;
6. canonical JSON/hash preimage и test vectors;
7. correction/amendment semantics;
8. idempotency semantics;
9. artifact path/hash policy;
10. lock/append guarantees и failure model;
11. read-only verify vs recorded `task_verify`;
12. schema version compatibility policy.
13. privacy/secret policy **до первой append**: refusal-before-write, explicit confirmation для sensitive data, file permissions/ACL и export redaction; redacted instruction не может одновременно считаться Original, secure deletion не обещается.
14. portable ASCII `task_id` profile: length, case policy, Unicode rejection/normalization, Windows reserved names (`CON`, `NUL` и др.), trailing dot/space и case-collision vectors.
15. deterministic projection order и tie-breakers, включая corrupt/unparseable tasks; baseline для решения — `(recorded_at, task_id)` для task list и `(task_id, sequence)` для events.
16. supported filesystem/durability matrix: production/release mutation is Linux/POSIX-only on qualified filesystems; Windows, WSL and network shares are unsupported until separately versioned and qualified; POSIX directory-sync semantics remain explicit.
17. privacy/security ADR дополнительно фиксирует data classification, retention/deletion policy, trusted-root assumptions, symlink/junction/reparse handling, local writer/admin boundary и release gates.
18. artifact verification scopes: historical point-in-time observation, current external object и managed snapshot.

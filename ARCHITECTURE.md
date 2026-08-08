# Phase Architecture

**Status:** Architecture north star
**Scope:** Target architecture, current implementation, and known gaps

## Purpose

Phase is infrastructure for managed transitions of information state within a controlled contour.

It accepts a proposed change to an information object, binds that proposal to an exact contract and trusted domain semantics, records the intended transition, applies the permitted physical effects, verifies the resulting state, and preserves machine-verifiable evidence of what occurred.

In its shortest form:

> **Phase conducts and proves changes to information.**

Phase is not primarily a file-writing tool. Files, blobs, descriptors, journals, repositories, and external services are physical representations of information. Create, append, copy, replace, publish, and similar operations are mechanisms used to realize information transitions.

## Architecture North Star

Every architectural decision in Phase must be evaluated by one question:

> Does this decision strengthen the controlled information transition and the provability of its result?

The primary architectural object is an information transition:

```text
information object
↓
proposed transition
↓
exact contract binding
↓
trusted domain semantics
↓
durable intent
↓
permitted physical effects
↓
verified resulting state
↓
transition evidence
```

## Controlled Contour

Phase does not claim to observe or control every change to information in every system.

Its guarantee applies to a controlled contour in which:

1. Phase has the exclusive write capability for managed resources.
2. Agents can read state and propose transitions but cannot mutate managed state directly.
3. Every permitted transition has an admitted contract, domain runtime, and physical mechanism.
4. Other agent-accessible tools are read-only or perform mutations only behind the Phase boundary.
5. Human emergency intervention uses an explicit break-glass process.
6. Changes made outside the contour are either technically prevented or detected and classified as drift.

The precise promise is:

> All managed changes inside the controlled information contour pass through Phase.

## Primary Concepts

### Information Object

A domain-addressable unit of information whose identity and state can be determined.

Depending on the domain, this may be:

- a source;
- a knowledge artifact;
- a task;
- a document version;
- a publication;
- a repository state;
- a relationship between information objects;
- another explicitly modeled information quantum.

### Information Identity

The stable rules used to determine what object is being discussed across observations and transitions.

Identity must be derived by the domain runtime and must not be inferred only from a physical path.

### Information State

The currently observed and verified condition of an information object.

State may include:

- absence or presence;
- content digest;
- semantic descriptor;
- version;
- lifecycle status;
- provenance bindings;
- relationships;
- publication status;
- domain-specific invariants.

### Information Transition

A proposed movement from one information state to another.

Examples include:

```text
absent → created
unadmitted source → admitted source
verified sources → admitted knowledge
task open → task completed
version A → version B published
object present → object removed
relationship absent → relationship established
```

Initial creation is not a special exception. It is a transition from a valid zero or absent state to a present state.

### Provenance

The evidence-supported account of where information came from, which prior information objects it depends on, and which transitions produced its current state.

### Transition Evidence

The durable, machine-verifiable record of:

```text
what was observed
what was proposed
which contract and runtime were used
what transition was intended
which effects were attempted
what resulting state was observed
how the result was verified
what outcome was classified
```

## Architectural Layers

### 1. Contract Package

The contract package constrains and binds a specific permitted transition.

It declares or binds:

- candidate and result schemas;
- contract identity and version;
- compatible runtime requirements;
- allowed effects;
- validators;
- write scope;
- limits;
- idempotency policy;
- recovery policy;
- outcome policy;
- evidence requirements;
- exact mechanism and runtime references;
- versioned, technology-neutral guarantee requirements for each exact mechanism.

A contract package does not need to encode all domain behavior as JSON. It selects and constrains trusted executable domain semantics.

### 2. Trusted Domain Runtime

The domain runtime defines the meaning of the transition.

It owns:

- information identity;
- state interpretation;
- candidate normalization;
- domain invariants;
- valid state transitions;
- provenance rules;
- deterministic effect derivation;
- domain result derivation;
- domain-specific verification.

A domain runtime may be implemented in Python or another admitted implementation language.

The architectural requirement is not that the runtime be expressed as declarative JSON. The requirement is that it be:

- explicitly identified;
- versioned;
- bound to the contract;
- deterministic for its declared inputs;
- capability-limited;
- testable through a stable ABI;
- prevented from bypassing the physical mechanism boundary.

### 3. Physical Mechanism

A mechanism performs a bounded physical effect on a managed resource.

It owns:

- physical write semantics;
- storage authority;
- commit-time precondition revalidation;
- concurrency behavior;
- durability behavior;
- read-back verification;
- partial and indeterminate classification;
- mechanism-specific recovery assessment.

Examples include:

- exclusive create;
- content-addressed copy;
- expected-head append;
- atomic replace;
- archive and publish;
- database compare-and-swap;
- publication through an external service adapter.

A mechanism must not contain domain semantics such as source identity, knowledge provenance, task state transitions, or publication meaning beyond its physical storage protocol.

### 4. Core Lifecycle

Core conducts the generic lifecycle.

It owns:

```text
resolve
→ verify contract guarantees against the installation authority profile
→ capture
→ normalize
→ freeze
→ validate
→ plan
→ reverify the actual plan mechanism closure
→ persist intent
→ execute
→ post-verify
→ reduce outcome
→ finalize receipt
→ inspect
```

Core owns:

- exact binding resolution;
- pre-capture guarantee admission;
- candidate capture;
- input freezing;
- lifecycle ordering;
- durable intent before mutation;
- effect-plan binding;
- execution dispatch;
- generic outcome reduction;
- canonical evidence production;
- independent inspection.

Core must not contain domain-specific identity rules, task semantics, knowledge semantics, source semantics, or other domain state machines.

### 5. Resource Installation Layer

Agents operate on logical resources, not arbitrary filesystem paths.

Examples:

```text
source_store
knowledge_store
task_journal
project_repository
publication_target
```

The host installation resolves a logical resource handle to an admitted write capability.

It also selects the exact authority guarantee profile as trusted installation configuration. A provider's self-report is a consistency check, not authority to select or strengthen that profile. Current contract generations are admitted only when every exact mechanism requirement is covered. Mechanism-managed append remains outside the authority-provider path.

The agent may select an allowed logical resource but must not choose an arbitrary absolute path or independently acquire a write capability.

## Fundamental Boundaries

The following boundaries are architectural invariants:

```text
Domain semantics must not live in Core.

Physical storage semantics must not live in Domain Runtime.

Agents must not own write capabilities for managed resources.

Contracts must not silently select unbound executable semantics.

Mechanisms must not claim stronger guarantees than they implement.

Evidence must not report a stronger outcome than the observed state supports.
```

## Generic Transition Lifecycle

Every managed transition follows the same abstract lifecycle:

1. **Resolve**
Resolve the exact contract package, domain runtime, validators, mechanisms, and resource capabilities.

2. **Capture**
Capture the exact proposed transition without trusting mutable caller state.

3. **Normalize**
Apply the admitted domain normalization rules.

4. **Freeze**
Bind all declared inputs to immutable snapshots or explicit revalidation rules.

5. **Validate**
Verify the candidate, domain invariants, resource state, authorization context, and transition preconditions.

6. **Plan**
Produce a static, bounded effect plan.

7. **Persist Intent**
Persist the exact intended transition and effect plan before any mutation.

8. **Execute**
Apply only the effects admitted by the bound contract and mechanism implementations.

9. **Verify**
Observe the resulting state independently of the mutation call result.

10. **Classify**
Classify the outcome truthfully, including partial, unverified, or indeterminate states.

11. **Finalize Evidence**
Persist the receipt, effect receipts, observations, and binding evidence.

12. **Inspect**
Permit later independent verification of the transition and its resulting state.

## Exclusive Write Contour

Phase can prove all managed changes only when it is the exclusive mutation channel.

For agent-operated resources:

```text
agent
├── may read
├── may reason
├── may construct candidates
└── may propose transitions

Phase
└── exclusively owns managed write capabilities
```

An agent must not simultaneously receive:

- writable filesystem access;
- a shell capable of mutating managed resources;
- direct Git commit or push access;
- direct database write access;
- direct publication APIs;
- writable task-tracker or knowledge-store tools;
- another MCP tool capable of bypassing Phase.

Such tools must be removed, made read-only, or placed behind Phase as physical effect adapters.

See the exclusive-write-contour ADR for the complete decision.

## Break-Glass Operations

A controlled system requires an emergency path for human intervention.

Break-glass access must:

- be available only to an authorized human;
- be explicitly invoked;
- bypass normal automation only when necessary;
- create separate audit evidence;
- record the actor, reason, time, scope, and affected resources;
- require subsequent reconciliation or drift inspection;
- never be silently treated as a normal Phase transition.

## Drift

A managed resource is in drift when its observed state differs from the latest state proven by Phase and no admitted transition explains the difference.

The preferred model is technical prevention through exclusive write capabilities.

Where external writes cannot be prevented, Phase must eventually support:

- drift detection;
- drift classification;
- reconciliation evidence;
- explicit restoration of the controlled contour.

## Decision Test for New Components

Every proposed component, contract, runtime, or mechanism must answer:

1. What information object does it serve?
2. What state transition does it implement?
3. Where are the domain invariants defined?
4. Which exact contract permits the transition?
5. Which domain runtime defines its meaning?
6. Which mechanism physically applies the change?
7. How is the resulting state observed and verified?
8. What evidence remains?
9. What partial or indeterminate states are possible?
10. Can an agent bypass Phase and mutate the resource directly?
11. Does the component introduce domain semantics into Core?
12. Does it introduce physical storage semantics into the Domain Runtime?

A component that cannot answer these questions does not yet have a valid place in the architecture.

## Current Implementation

The current repository already implements important parts of this architecture:

- exact registry-bound contracts;
- strict candidate canonicalization;
- input freeze strategies;
- pre-operation validation;
- static effect planning;
- durable intent before mutation;
- a bounded effect broker;
- filesystem mechanisms;
- post-operation verification;
- truthful terminal states;
- canonical receipts and evidence;
- independent run inspection;
- CLI and MCP adapters over a shared lifecycle;
- bundled Python implementations for Source Admission, Knowledge Admission, Publish New Version, and Task Journal behavior.

The current implementation is therefore not merely a file writer. It is an early implementation of the managed information-transition model.

## Known Architectural Gaps

The following target properties are not yet fully realized:

- the Domain Runtime ABI is not yet formalized;
- exact executable runtime identity is not yet independently bound in all run evidence;
- domain behavior is partially hardcoded in generic planning and validation dispatch;
- some runtime context is passed through hidden mutable attributes;
- domain runtimes can perform broader filesystem and evidence reads than the target capability model permits;
- Task Journal semantics partially leak into generic append logic;
- mechanism dispatch is not yet fully protocol-driven;
- physical mechanisms provide different levels of path, concurrency, durability, and crash guarantees;
- expected-head append requires stronger authority and commit-time revalidation;
- publication is not yet reader-atomic in all cases;
- logical resource handles and an installation registry are not yet the universal interface;
- the repository alone does not enforce an exclusive agent write contour;
- break-glass and drift-detection workflows are not yet complete;
- some declared policies and validator names are stronger than their current enforcement;
- historical inspection may depend on runtime packages still present in the active installation.

These are implementation gaps relative to the north star. They do not change the intended architecture.

## Non-Goals

Phase is not intended to become:

- an agent planner;
- a workflow scheduler;
- a multi-agent orchestrator;
- a general approval UI;
- a universal secrets manager;
- a general sandbox;
- a replacement for durable workflow engines;
- an unrestricted plugin host;
- a global observability platform.

Such systems may call Phase or host Phase workers, but they do not belong inside the trusted Core lifecycle.

## Summary

Phase is organized around one invariant:

> A managed information transition must be explicitly proposed, exactly bound, durably intended, narrowly executed, independently verified, and provable after the fact.

The target architecture is:

```text
immutable contract package
+
versioned trusted domain runtime
+
logical resource capability
+
generic transition lifecycle
+
bounded physical mechanism
+
independent transition evidence
```

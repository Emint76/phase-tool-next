---
name: phase-mutation-router
description: Route every conforming Hermes canonical filesystem mutation by semantic intent to an exact Phase contract; never write the canonical target directly.
version: 1.0.0
platforms: [linux]
---

# Phase Mutation Router

Use this skill before any Hermes file mutation. Decide semantics first, then run `scripts/route_mutation.py` or apply its exact table.

- new stable file -> `file_create.v1@1.0.0`
- new version at an existing stable path -> `publish_new_version.v1@1.0.0`
- immutable append-only record -> `append_stream.v1@1.0.0`
- immutable content-addressed object -> `content_addressed_publish.v1@1.0.0`
- source admission -> `source_admission.v1@1.0.0`
- knowledge admission -> `knowledge_admission.v1@1.0.0`

File extensions never select contracts; Phase treats content as opaque bytes. Unsupported or ambiguous mutations fail closed and must not become a direct write.

After routing, load `phase-mutation-preparation`; after preparation, load `phase-verified-execution`. Direct MCP `phase_execute` then `phase_inspect` is the primary transport. CLI fallback is permitted only when MCP is unavailable or explicitly requested.

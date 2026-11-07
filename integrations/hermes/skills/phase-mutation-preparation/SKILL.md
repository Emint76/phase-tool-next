---
name: phase-mutation-preparation
description: Deterministically prepare payload, candidate, paths, roots, evidence root, and run ID outside canonical targets for an exact Phase mutation request.
version: 1.0.0
platforms: [linux]
---

# Phase Mutation Preparation

This is an upstream preparation boundary, not a mutation boundary. It may create payload/candidate/request/evidence directories only outside the canonical target. It must never create, edit, append, replace, move, or delete a canonical file.

## Required product-instance layout

Use a dedicated instance parent as the canonical root and place the product checkout in its `toolkit/` child:

```text
<instance-parent>/
  toolkit/     Git checkout
  archive/     predecessor runtime history
```

Repository target locators must begin with `toolkit/`. Evidence and preparation roots must both be outside the instance parent and disjoint from each other. For version publication, never use the Git checkout root itself as the canonical root; otherwise `publish_new_version.v1@1.0.0` would place predecessor runtime history inside product Git instead of `<instance-parent>/archive/sha256/`.

1. Obtain a semantic route from `phase-mutation-router`.
2. Run `scripts/prepare_phase_mutation.py` with an intent JSON and three explicit roots.
3. Confirm normalized preparation/evidence roots are disjoint from the canonical root.
4. Use a fresh preparation root. The adapter creates a content-identified request directory and exclusive read-only leaves; an existing request directory is a blocker, never an overwrite target.
5. Read the emitted `phase-request.json` without rewriting it. It contains the exact contract digest, candidate path, and expected digest for every prepared input.
6. Immediately before MCP execute, hash each input read-only and require equality with `expected_input_digests`. The CLI fallback performs this check itself before execute and again before inspect.
7. Hand the exact request to `phase-verified-execution` for direct MCP execute -> inspect.

Supported adapters: create, publish_new_version, and append. Other routed domains require their dedicated preparation skill; absence of an adapter is a blocker, never permission for direct write.

## Fixed NTFS experiments

When the task or approved Hermes rules expressly allow the operation and result directory, resolve that authority through the deployment's existing approved installation scopes. A path mentioned in a task is not a grant. Ask only if the task authority is missing or ambiguous. If the authorized directory falls outside an admitted runtime scope, report that runtime limit.

The native preparation adapter assembles per-run bindings and requests for the fixed File v2 and Bundle v1 selectors. Stage the returned files in the approved installation and preparation locations, then call the standard native CLI or prepared MCP tool and start a fresh inspect. This needs no operator to hand-assemble each request. Follow the native installation guide for scope separation and retained history.

# Stage 5 Content-Addressed Copy Walkthrough

This walkthrough is based on the accepted Loop 5 CLI run written to `.stage5-tmp/loop5-walkthrough/stage5-cli-acceptance-summary.json` by `scripts/stage5_cli_acceptance.py`. The summary is disposable evidence and is not tracked.

## Accepted Example

Scenario: `03_execute_new_text`

Command path: real `phase execute` CLI with `PYTHONPATH` unset.

Source payload verification:

- before: `exists=true`, `length=16`, `sha256=d6631fa3b666c3f252ddda64da2b2d0c6a11b494f68da7e8afd0aa38609092cb`
- after: `exists=true`, `length=16`, `sha256=d6631fa3b666c3f252ddda64da2b2d0c6a11b494f68da7e8afd0aa38609092cb`

Content binding:

- SHA-256 digest: `sha256:d6631fa3b666c3f252ddda64da2b2d0c6a11b494f68da7e8afd0aa38609092cb`
- length: `16`
- canonical locator: `objects/d6631fa3b666c3f252ddda64da2b2d0c6a11b494f68da7e8afd0aa38609092cb`

Target verification:

- before target tree: empty
- after target tree: `objects/d6631fa3b666c3f252ddda64da2b2d0c6a11b494f68da7e8afd0aa38609092cb`, `length=16`, `sha256=d6631fa3b666c3f252ddda64da2b2d0c6a11b494f68da7e8afd0aa38609092cb`

Canonical result reference:

```json
{
  "authority_rule": "authority.content_digest_v1",
  "contract": {
    "id": "fixture_copy.v1",
    "package_digest": "sha256:033167055e3e688ee449ca81396713d35cd1fe961c4f89ea7fc039c3395a42ec",
    "version": "1.0.0"
  },
  "locator": "objects/d6631fa3b666c3f252ddda64da2b2d0c6a11b494f68da7e8afd0aa38609092cb",
  "owner_id": "fixture.copy.owner",
  "reference_version": "1.0",
  "root_binding": "fixture_result_root",
  "state": {
    "digest": "sha256:d6631fa3b666c3f252ddda64da2b2d0c6a11b494f68da7e8afd0aa38609092cb",
    "exists": true,
    "head_token": null,
    "length": 16
  }
}
```

Evidence paths for run `copy-execute`, relative to `.phase/runs/copy-execute/`:

The listed `intent.json` and `receipt.json` hashes are captured root-identity-bound evidence from the preserved acceptance root used for this run, not cross-root reproducibility invariants. Recreating the resolved target root intentionally changes the idempotency root identity and its downstream intent/receipt linkage; the effect plan, copied bytes, canonical result, and root-independent attachments remain stable.

- `attachments/effect-plan.json`, `length=1361`, `sha256=5163651358c05fb1adcace4129bf9c93d0a7f20680e63a792bdeaafb94ab0a77`
- `attachments/effect-receipts.json`, `length=532`, `sha256=6175ae761e454460a08857a0ea6419745d6aac0fc9aaa80e56a721cc586aec7a`
- `attachments/pre-validator-results.json`, `length=2426`, `sha256=573d6c593a76f64863d032ebc3bf6534c0d80578f498f02c9a32dd598db8046b`
- `attachments/validator-results.json`, `length=2755`, `sha256=ec919f0cd70c465f04ee9714d031f4c050fd0df83630cde8b090991695225dc5`
- `blobs/d6631fa3b666c3f252ddda64da2b2d0c6a11b494f68da7e8afd0aa38609092cb`, `length=16`, `sha256=d6631fa3b666c3f252ddda64da2b2d0c6a11b494f68da7e8afd0aa38609092cb`
- `intent.json`, `length=2677`, `sha256=9b2ce34d3171e24b084c5e9dfbda28f470da08d3e55fe459af8c19f3229b4abc`
- `receipt.json`, `length=5750`, `sha256=a3b087ae934d41c9851f59fd0ec6549a8fd1d19e161ade8e7f79c2c3e76790a3`

## Runtime Path

1. `src/phase_tool/core.py:661` defines `PhaseCore.run`, which coordinates contract resolution, guarantee admission, candidate capture, input freezing, validation, planning, durable intent, broker execution, verification, and receipt finalization.
2. `src/phase_tool/planning/__init__.py:188-206` derives the copy effect and content-addressed locator from the frozen input digest; the user does not select the final locator.
3. `src/phase_tool/planning/__init__.py:235` defines `validate_static_plan`, which validates the plan shape, root bindings, effect count, effect type, and locator safety before execution.
4. `src/phase_tool/mutation/broker.py:45` defines `EffectBroker`; its `execute` boundary begins at line 205 and validates durable intent and the attached plan before dispatching an authorized mechanism.
5. `src/phase_tool/mutation/content_addressed_copy.py:68` defines `execute_content_addressed_copy`; the locked implementation beginning at line 91 enforces content binding, locator binding, scoped authority, exclusive creation, readback verification, and no overwrite on conflict.
6. `contracts/fixtures/fixture_copy.v1.json:41` begins the exact contract identity, and its `content_addressed_copy` mechanism binding begins at line 68.

## Acceptance Coverage

The summary records 17 scenarios with command order, exit, terminal status, disposition, mutation flag, blockers, artifacts, source snapshots where applicable, and before/after target trees. It covers validate; plan with no target mutation; execute new text; inspect run and target; exact prior operation reuse; same operation key with different request digest conflict; existing-identical no-prior; existing-different; binary copy; unsafe locator rejection; corrupted frozen blob rejection via controlled Core helper; fixture create; fixture append; task journal; multi-effect execution rejection via controlled Core helper; destination-appears planning; and destination-appears conflict.

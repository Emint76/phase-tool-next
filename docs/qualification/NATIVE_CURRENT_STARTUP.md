# Current native create/read candidate: fixed registry integration

This remains software work for an **unqualified candidate**, not a supported NTFS release. Production installations are unchanged. A05, G01 and every unexecuted native guarantee remain NOT_VERIFIED. The minimum target remains direct NTFS results with qualified ext4 evidence/preparation (MIX); FULL is unavailable.

## Minimal integration correction

The current create factory, Core entrypoint and original-intent reader now select the same existing fixed candidate registry v4 as independent inspect, its Windows parent and its thin MCP adapter. The read-only mode controls capabilities, not historical registry selection. No new registry, provider, intent, journal, queue, receipt store, recovery owner or document-version system is added.

Before this change, HEAD `2fada739340ea0f0c5e5ea367f1d3d0009045ce4` selected v3 for current execution/original reading and v4 for inspection. Both safely refused the absent qualified profile before channel/evidence. That was not an admission escape or a reason to discard its CI. It was a latent composition inconsistency: a future executing original/manifest and independent reader must agree on the exact registry digest; v3 also retains an immutable candidate authority descriptor for the previous authority source. All current roles use existing v4 digest `sha256:2af8bac33feb42a583a14d6bff7b403de2ab0b63be3a962acc45807634a6ecca`.

Historical v1-v3 snapshots/loaders and candidate authority.v1 descriptor stay byte-exact. Their original wheels/bindings are required for their historical implementation identities. The current authority implementation and candidate authority.v2 descriptor are unchanged by this correction. No production-qualified native profile is added. `_native_qualified_profile`, its production key, registry trust, request shapes and rejection before channel/evidence remain enforced.

The ordinary execution path remains PhaseApplication -> PhaseCore -> EffectBroker -> native authority/parent/worker -> existing Core evidence, proof and receipt. Independent reading remains PhaseApplication.inspect -> inspect_run -> authority observation -> native read-only IO. The current implementation covers only file_create.v1, one exclusive effect, existing parents and the unchanged1MiB limit. Native publish_file2.0, publish_new_version and bundle support remain unimplemented. Large-array/version extensions are separate issue13 scope, not implied by this route.

## Accepted preceding build, precise boundary

[CI39917363583](https://github.com/Emint76/phase-tool-next/actions/runs/39917363583), attempt1, belongs to preceding HEAD `2fada739340ea0f0c5e5ea367f1d3d0009045ce4`, tree `ab32676607ae35c57a794a612368fe59618cddf1`. All three jobs succeeded. Both actual Python XMLs contain1228 unique cases:1227 PASS and one exact prior actual-NTFS skip; all1201 preceding case identities/statuses remain, with24 new inspection methods and3 new architecture parameter cases PASS. This is Linux component/regression evidence, not the complete REF qualification program or native admission.

Four retained packages match all230 Git product files; both wheel RECORDs verify236 entries; both sdists include all77 tracked test/helper files byte-exact. Saved clean installed ordinary ext4 CLI/MCP/recovery reports pass in both Python lanes. Saved resource reports cover64MiB/1GiB/2GiB file payloads and256-file256MiB bundle; their raw retained reports were audited without rerunning or rereading large workloads. This does not expand any publication limit or qualify those workloads on NTFS.

| Build | SHA-256 | Bytes |
|---|---|---:|
| py3.11 wheel | dd7e3f2c83deb1c85061d51c71570045627a7972785fa459a23b284a73f0372c |495431|
| py3.11 sdist | d2fec4e7fb0c46da1ece8d6c9b2bcd5a5ffcdd94e9e0e03aa37bc140737b3e76 |665017|
| py3.12 wheel |873330a856021e089128bb4789346de59eb76f86eaf6a7fa01c686f644d888ff |495431|
| py3.12 sdist |a5f2735268e25c75800c0278a0dd8e89c10e5976160fbc56b0fff21d76bc468d |665148|

These are CI candidate artifacts with package metadata1.2.0rc1, not release artifacts or a new supported version. Different lane bytes are individually identified. A later HEAD requires its own results; this green CI is not acceptance of the registry correction.

## Preserved evidence, including negative acquisition

The first artifact acquisition failed at py3.11 download exit1; HTTP cause is unknown. Immutable `g-ni-ci-39917363583-index`, raw SHA256 `278162b5f9d35a69fd6f2ea29144e4ac6922b0951a02b4c4b90347fff23edda1`,120974B, receipt `sha256:390e8f486ffbcc86b96f0411c69eb0d74d2fb4c341d44f59bf6774dd1d8bd95b`, remains PARTIAL/audit_failed/FAILED_OR_INCOMPLETE.

One explicitly reviewed acquisition continuation, not a CI rerun, saved `g-ni-ci-39917363583-cont1`: raw SHA256 `30467da32602c03f6745c36e4bce575d0c7238e820cf79426da21e15022112b9`,1960411B, receipt `sha256:bebbab29af1e1c3e28294eff8527b0d4a6bdb710f51f9df270bbe373a0c8bc82`. It reuses the exact earlier py3.12 Phase packet and holds the two remaining ZIPs inline under its own receipt, with no invented per-ZIP receipts. All769 private source entries/11270748 original bytes were independently restored by two reviewing agents, with all762 predecessors frozen and no missing/drift. Private source capsules are in the enclosing Phase evidence, never in public CI ZIPs.

The py3.12 packet is `g-ni-ci-39917363583-artifact-12485827963`, raw `2b00d906ce751f57b7e86f42d212e053abc95e4f8ceaa684bd163855c65b87e3`,1914472B, receipt `sha256:5f3c0895f23379ec1b85b35c1c248b7dffa9feee196c421b9ea0f4a707aeefdc`.

The one subsequent byte-audit is `g-ni-build-audit-1792746800329205600`, raw SHA256 `b2dff3d2867152e16ef04fde3015eb9d5d6c7bbe62a98d6718dd4d381db0252a`,104321B, receipt `sha256:4bcabdf6f099e63770be2154ab33f840f4f4d886557e119d4eba65fd035c53b9`. It verifies four builds, installed reports, all3 raw ZIP hashes and their exact enclosing/external receipt bindings. Native Phase receipt+separate official read-only inspect/readback protect these evidence objects. Two independent agents share the host/toolchain; this is not external certification or required GitHub approval. Full internal packets/logs stay private.

## Next-head verification and remaining mandatory work

The registry correction adds three negative component methods plus a corrected existing factory-selection oracle. The real qualification guard remains unmocked. Synthetic runtime/stdio/delivery shells only reach and observe refusal, not accepted execution. A source-review bug in a draft test patch target was corrected before any execution, and the rejected draft is retained privately. These new checks are UNEXECUTED until the new exact HEAD's CI, and no native-positive outcome is claimed.

A05 true Windows SYMLINK tag0xA000000C remains NOT_VERIFIED: both creation APIs returned1314; no safe owned fixture or authorized stand is available. Junction and LX_SYMLINK are not substitutes. G01 accepted executable/namespace lifetime remains NOT_VERIFIED. Use the separately authorized stand requirements in [A05_STAND_REQUIREMENTS.md](A05_STAND_REQUIREMENTS.md); current policies/privileges/ACLs must not change.

Still required: real admitted native Core create/receipt/independent inspect, accepted MCP canary, all six MIX publication/version/bundle contracts, applicable races/recovery/fault cases, full reference regression, final-artifact clean install and native old-new-old rollback preserving documents/archives/evidence. FULL is separately NOT_VERIFIED. No Source/Knowledge/append/journal or PCR-scientific change is qualified. Original9p no-replace EINVAL and C0000280/secondary-worker negative evidence remain unchanged. No merge-as-accepted or supported release until the original mandatory criteria pass. See [remaining qualification ledger](FINAL_QUALIFICATION_REMAINING.md).

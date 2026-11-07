# First corrected native Version2 functional result

This is one isolated synthetic functional experiment. NTFS support is not qualified or released. A05, applicable G01, external noncooperating leaf CAS and complete family qualification remain NOT_VERIFIED. The default production guard remains unchanged.

## Exact implementation and operation

Source commit `cac80df2177fdd1ce20a571304f2df9319d85641`, tree `cac8c40deb540b57dadae4a0b92ffa61416064be`. The selected experimental wheel has 827624 bytes, SHA256 `cbd8111ed896fe3c9416b443e5c7f3758cde561eee3bcdd4b553c88ff1947769`. [Exact-HEAD CI40775604170](https://github.com/Emint76/phase-tool-next/actions/runs/40775604170) passed both 1907-test suites (1906 PASS and one unchanged SKIP) and installed resource checks. Linux CI is separate from the Windows result below.

Run `ntfs-version2-b6fe9a1f-6228-43ee-8a0c-52784db5b69e` used real Core, the Windows worker and the existing `publish_new_version.v2@1.0.0` contract (package SHA256 `5a4e0ef57258674c32c430df3aecb47b0f65debfee9686f42463f1f753502065`). Experimental profile `phase.native.ntfs.experiment.version2.authority.v3@1.0.0` does not assert qualified coverage; it selects the unchanged version2 authority provider version 2.0.0 in the exact wheel. Evidence/preparation were separate own ext4 volumes; results/objects were written directly to the own NTFS root. No volume-to-NTFS delivery copy was used.

The initial 32-byte BEFORE was an explicitly declared L1 synthetic fixture, not a prior Phase-managed creation. One execute completed `succeeded_verified`, followed by one separate fresh inspect with `target_verified=true`, then one complete RO original collection. No retries, recovery or second execute were performed.

| Object | Bytes | SHA256 |
|---|---:|---|
| Previous content object |32|`9fd56bbb0bd2646b51bd6476ea9997d51bd0e2b09ed85f4e2d3c05bf784a83b2`|
| Current file |31|`f526f4ad17fcd007f836bb9059daed48b02ce6bae5951665239ce588fcae3ac1`|
| New content object |31|`f526f4ad17fcd007f836bb9059daed48b02ce6bae5951665239ce588fcae3ac1`|

Independent reads matched these bytes and three distinct recorded object identities; no staging entry remained. The old object is readable after the replacement. This experiment does not claim an archive-as-current restore operation, a multistep Version2 history or all failure/recovery paths. The earlier D0-create/D1-Version1/D2-Version1 shared-history result remains a separate accepted experiment/build.

## Evidence and worker completion

- Receipt: `sha256:c517e1697463fbb6ad559b72ac83eaf76de265c4b5694bbb8261b82284937a68`.
- Intent: `sha256:4df57686e052f18c95d0dface8748d8dc4fe6153b32abd65acfd02ce45781a23`.
- Plan: `sha256:f7e5e357243456d4beec3cbae056e47b2cd633953b2529db4ba2faec2893cc08`.
- Original collection: 66258 bytes/SHA256 `7d625cea94f92326d342ced2afe73a99c0b86466cd7593c5225c7bd49b52e6d1`, containing all 14 original files/47285 bytes across both evidence and preparation roots.
- Native terminal-proof attachment raw SHA256: `99a958df522bcf1a22491506caa89643d35b0386cfde48feb9630af424864a5c`.

Two independent reviewing agents on the same host/toolchain verified domain-prefixed intent/plan/receipt hashes, frozen content, admission/build bindings, validators and the separate inspect. Full internal originals remain private; this report contains only synthetic identifiers and hashes.

The 21-event mutation trace records two successful no-replace object publications and one class65/flags3 current replacement, followed by all three namespace flushes. It is not a trace of every read-open syscall. The exact selected wheel confines DELETE sharing to the retained current replacement-reader; default readers and ancestor/objects protection retain their existing behavior. This narrows the experiment to cooperating Phase writers under both root mutexes. It does not provide an external old-ID compare-and-swap.

Worker PID 416728, creation FILETIME `134377028516700349`, was checked through its retained creation process HANDLE: wait0/exit0, concrete exit established. All worker streams and that HANDLE closed without errors; zero mutation handles remained, both root mutexes closed and the mutation session sealed. A worker self-report or outer process exit was not substituted for this evidence.

## Preserved negative result and remaining work

The previous ee99 Version2 experiment failed with `0xc0000043` sharing violation at the replacement because its own current reader denied DELETE sharing. Its receipt `sha256:707b0f3d7acc2bc8fa60fa32d4975decd09538f970577f9e656aa1c2fd1d5471`, unchanged 32-byte current, two content objects and staging file are retained; it was not retried or relabelled as success. The corrected experiment uses a separate case and the reviewed profile revision.

Bundles, native interruption/conflict/recovery, native clean install/CLI-MCP, historical compatibility and native old-new-old rollback remain acceptance work. Earlier successful native routes used their recorded builds; this result does not qualify all six contracts on one final artifact. Production Phase/Hermes, scientific data and global Windows/Docker settings were not changed. No ISO or regulated-compliance claim is made.

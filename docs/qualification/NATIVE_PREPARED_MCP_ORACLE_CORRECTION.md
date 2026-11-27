# Prepared MCP: preserved negative CI and exact guard-oracle correction

PR #14 remains DRAFT, unqualified and incomplete. No production runtime/profile, scientific data, Windows policy or global Docker setting changed. No supported release is claimed.

[CI39975049795](https://github.com/Emint76/phase-tool-next/actions/runs/39975049795), attempt1, at HEAD `72c668d3d76746a36951d7616790fc5c421ac287`, tree `1c432a8fbe79b4a7fecc9013ed05366e10b7bd8a`, **FAILED** in both Python lanes. Each actual original XML contains1255 unique cases:1253PASS,1FAIL and one exact previous actual-NTFS skip. The only failure is `NativePreparedMCPTests.test_fixed_mcp_launcher_dispatch_precedes_binary_initial_reader`. The other13 prepared MCP/component methods and all10 prior composed delivery/mount methods passed. These facts do not accept the failed whole suite or qualify a native route.

The new static test takes the first `role in ...` comparison from breadth-first `ast.walk(main)`. That is the later parent-role branch at line117, not the actual top-level Windows-only guard at line102. Its assertion therefore fails despite the product guard containing the correct five Windows roles. Root and both source reviewers missed this traversal-order dependency. This is a concrete test-oracle defect, not evidence of a Windows/NTFS failure.

The minimal correction matches exactly one top-level AST call `need((os.name == 'nt') == (role in {'parent','inspect-parent','inspect-mcp','execute-mcp','worker'}))` and requires it before the execute-mcp branch. Existing early-dispatch checks remain. Only that test method changes; the other13 method ASTs, all14 names and all product/qualification/architecture guards are unchanged. The correction is **UNEXECUTED at source publication**, requiring a genuinely changed HEAD and its own complete CI/artifact acceptance. No rerun of the failed run is requested.

Both original failed-CI ZIPs, complete pytest logs/XML and the864-source preservation manifest with four new lossless capsules are retained under ONE own official Phase1.1/ext4 object: `g-ni-prep-negative-39975049795`, raw SHA-256 `b7fc81bf03ec16e18f2d83d448243d371dc338825780789ae93b4e4bce83a77e`,282154B, receipt `sha256:57e9fe72aa334bbfdb2e50b428653c6c63e1d0174adb7e2db8e39408143e3fae`. Other source bytes remain in the verified predecessor chain. Storage complete and successful inspect do not make CI successful. Original bad test/source79/failed CI remain available; no negative is replaced by this correction.

| Original ZIP | Bytes | SHA-256 |
|---|---:|---|
| Python3.12, ID12510983355 |49570|6018b600ee91ff0bf53f9d400b94e233b0aec6b66a3199e8ebff75dc419625c9|
| Python3.11, ID12510573908 |49685|36430152bda7c0bd94fc5b9dbf162ffa63896e8e3e10c0cf59236712d371fe32|

Workflow post-pytest build and installed smoke steps and the publication-resources job were SKIPPED. Pytest-internal build/install/resource fixtures are not excluded by that statement. There are no wheel/sdist assets in these retained ZIPs and no accepted four-package byte audit for this HEAD. Private source capsules/internal logs/paths are not published.

Prepared MCP continues to reuse one transient call owner and the existing Core/Windows-worker/independent-inspection path; there is no new journal, queue, receipt or version system. Memory retention, MCP disconnect/server exit and Docker CLI exit do not establish unknown-worker quiescence or accepted executable namespace lifetime. A05/G01, real admitted native Core create/receipt/independentinspect, accepted native CLI/MCP, fullREF, all six MIX contracts, FULL and native old-new-old rollback remain NOT_VERIFIED. High-level native wrappers, streaming create, version updates and bundles remain unimplemented. See [prepared MCP boundaries](NATIVE_PREPARED_MCP.md), [remaining qualification](FINAL_QUALIFICATION_REMAINING.md) and [isolated A05 stand](A05_STAND_REQUIREMENTS.md).

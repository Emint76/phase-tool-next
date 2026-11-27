# Ordinary native Bundle v2 MCP checkpoint

One ordinary SDK initialize/tools-list/phase_execute_prepared completed, followed by a distinct SDK process calling phase_inspect. The tested candidate is HEAD `dde6d8209ff43d8a8cb01bbca931305f9a3a5c22`, wheel SHA-256 `760d83f304b0d45526bebdebb1ccde9186ccbe6a03782266ed31471b39a5c049`. Run `ntfs-bundle2-b74df665-b29f-4aab-8cbe-8dbcebbd9ebf` has original receipt `sha256:bbf5e48b650452a6147e3b1a35e3de365eb582f358434c49aad1825616051a79`, intent `sha256:c31c6492349b51dfaac29df21690b98878b8d52787900fd316dc87da63bc9d41`, plan `sha256:27aa70029e27490e9c55b00058b3867cba5edfbecefdd0b1a35f9893c16b6257`.

Execute, original receipt, fresh MCP inspect and independent complete NTFS byte/stat census passed. The census covers five payload files, exact manifest and owner metadata, with no extra objects. Original proof confirms creation-HANDLE worker completion, sealed channels, one NOREPLACE directory commit, target-parent flush and durable PREPARED/ACK correlation. Complete original attachments/frozen blobs and all 26 trace events remain bound. A separate nonauthor audited the retained actual data; shared host/model/toolchain limits remain explicit.

The initial evidence oracle incorrectly expected only 524362 payload bytes. The existing implementation also writes 668 manifest bytes and 227 owner bytes: receipt, worker, effect attachment and six complete WriteFile acknowledgements all agree on 525257. A reviewed read-only evaluator corrected this calculation using the same original capture and the first independent Windows census. The failed oracle/source and original evidence were preserved; no physical operation, MCP request or backend snapshot was replayed. Accepted evaluation SHA-256: `9cef11a14db34bcf0325751b3d01a8177eb372dedfa6c6b23fc5a6bad228988e`; distinct actual-data review: `ad60c0fbc1609967cc35478bb7a26732b529a7f45d6a900558025ac6f3088491`.


## Status

This is a functional result on the exact candidate named above. A05/G01 and qualified MIX/FULL remain NOT_VERIFIED; release_eligible=false. Earlier prepared-failure recovery and shared-file-history results remain on their original recorded builds. Production and Hermes were not changed. The broader PR still requires final-build regression, reproducible native installation and native runtime rollback.

The MCP admission adapter adds only exact existing contexts and registry forwarding. Eight targeted portable Windows model tests pass; Linux regressions need new-head CI. Full private evidence and original negative oracles stay in the isolated Phase/ext4 delivery map, outside GitHub.

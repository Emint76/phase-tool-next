# File2 component fixture correction

Automatic CI run [40277842373](https://github.com/Emint76/phase-tool-next/actions/runs/40277842373)
at source `528916055207e00aa6ef6d383ab91f7381d48874` failed on Python3.11 and
3.12. Both JUnit files contain1685 cases:1640 pass,44 fail, one existing skip.
All1631 previous case IDs retain their earlier statuses. Of54 new cases,10 pass;
44 stop in the same fixture helper before their intended assertions execute.
Build, installed CLI/MCP, Host rollback and resource stages were skipped.
This failed result remains evidence; it is not an accepted candidate build.

The new file2 fixture passed the V6 registry to a historical file1 structural
fixture requiring one native-schema package. V6 deliberately retains historical
packages while selecting another current file1 package, so that helper correctly
rejected two matches. Its assertions must remain strict. The correction obtains
only the synthetic native claim template from the existing BundledRegistry.
Actual Host Core planning, original frozen payloads, new file2 contract resolution
and read-binding construction still use the unmodified fixed V6 registry.
No admission function, registry trust, current flag, package or guard is patched.

The unchanged44 cases need execution at the corrected HEAD because the failed
fixture prevented their bodies from running. The remaining tests and installed
checks must also pass for ordinary Linux CI acceptance. This source correction
has not itself executed at the time of preservation. A passing future Linux run
would verify software components and models within that boundary; it would not
qualify Windows execution, NTFS confinement, durability or native process lifetime.

The failed artifacts were preserved as original ZIP bytes through the isolated
Phase1.1.0/ext4 route, with independent receipts, inspect and exact readback.
Private full evidence is not embedded in this public report. Its canonical index
has SHA256 `6fa5b9763bc2d0eec65dfa1b717f4fbe75fefe06f058b585cfbaa6c9c6c85df2`
and receipt SHA256 `f9430d823a99fe1cdf103ddd885cd9f4e94bf45f43a609d48a41081c46cffd01`.

A05/G01 remain NOT_VERIFIED. FULL stays disabled. The file2 composition remains
unqualified and its real guard continues to refuse admission. Native bundle and
version2 integration, full contract lifecycle, rollback and supported release
still require their own completed mandatory checks. No production change.

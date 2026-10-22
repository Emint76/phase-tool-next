# RSS gate includes both larger measured workloads

The existing resource job measures separate Linux child processes for real
64MiB,1GiB and2GiB input files. A review of CI39775643190/HEAD610265c found that
its growth gate used only1GiB-64MiB, although the2GiB observation was retained.
A regression confined to2GiB could have passed that old gate.

The correction changes only selection: max(1GiB peak,2GiB peak)-64MiB baseline.
The method string states that formula. The128MiB threshold, all three workload
sizes/counts, non-sparse I/O, input generation outside measured workers, digest
and independent inspect checks, installed candidate and disposal policy stay.
No Phase contract/product limit or supported storage profile changes.

Five small pure regressions cover a2GiB-only threshold breach, a1GiB-only
breach, exact threshold, signed decreases and the retained old measurements.
They do not execute Phase, create large files or claim new RSS measurements.
The changed full script still needs the ordinary exact-HEAD CI resource job;
source review or these arithmetic tests cannot replace it. The existing resource
job retains SHA witnesses for the exact script/test sources before execution
and checks them again after both workloads. No additional workload/job is added.

Original report values42172416/42164224/42266624B remain unchanged. Its reported
growth was -8192B; corrected recomputation is +94208B (below128MiB), and all-run
span102400B. No actual old observation failed. Preserve old source/report and
their exact commit/run bindings rather than rewriting that evidence.

At this source checkpoint the corrected script and tests are unexecuted; new
CI acceptance must be recorded separately. This correction improves a Linux
resource regression gate; A05/G01/nativeCore/MIX/FULL/native rollback and the
supported NTFS release remain NOT_VERIFIED. No production/global changes.

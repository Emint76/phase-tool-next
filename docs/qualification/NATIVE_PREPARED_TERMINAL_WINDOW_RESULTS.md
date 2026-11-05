# Bundle v2 prepared-recovery terminal window

Status: implementation fix with portable regression evidence; new-build Windows recovery acceptance is pending. This report does not qualify NTFS storage or authorize a release.

The current installed Bundle v2 normal MCP publication already passed execute, receipt and independent inspect. A separate controlled prepared-recovery experience on the accepted pre-fix artifact failed: the original operation returned exit40 and no receipt; its terminal read expired with zero bytes. A retained creation-HANDLE witness established worker exit50. The real verifier refused `recovery.original_completion_unproven`. No commit or replay followed. Read-only inspection and a separate saved-evidence reviewer confirmed the complete prepared stage and unchanged evidence/preparation originals; that snapshot does not supply the missing completion.

Source analysis found mismatched reporting clocks: the parent exchange clock starts before worker bootstrap, whereas the worker starts its local ACK clock later. The former ACK-error drain used the parent's earlier effect deadline plus five seconds. Worker scheduling timestamps were not captured, so a late report is a source-supported explanation, not measured telemetry.

The minimal fix changes only the ACK-error terminal read to use the existing bounded terminal-report budget. Worker effect/GO/ACK deadlines, the healthy-path deadline, strict completion validation, retained-HANDLE clean-exit requirement and recovery admission remain unchanged. No second journal, queue, version system, contract or schema is added.

Eight portable component models were executed once against each exact implementation. The pre-fix wheel yielded two failures and one error; the fixed source passed all eight. These models exercise the real capture/framing/validation code with modeled OS, clock, launch and witness boundaries. They are not physical Windows recovery evidence. Negative raw results remain preserved.

The next physical acceptance requires a separately identified build, fresh owned synthetic case, genuine Core/worker execution, complete terminal bytes and clean HANDLE exit, then the existing MCP prepared-commit and fresh independent inspect. The failed original case is not replayable or recoverable under the current contract.

A05/G01, MIX and FULL remain NOT_VERIFIED. Production, Hermes and scientific data are untouched. Merge, release and working-profile rollout remain outside this checkpoint.

# Verification scope

34 automated regression tests pass: provenance, token-safe boundaries, oversized entries, duplicate handling, generic evidence rules, host/account scope, altered synthetic identities, invalid references, broken JSON retries, timeout persistence, checkpoint reuse, memory recycling guards, severity policy, independent rejection/reclassification, model-only discovery routing, admission control, and sparse-evidence authentication counts.

Live HTTP checks pass for invalid uploads, unsupported extension, binary content, foreign browser Origin, and dashboard response headers. The completed dashboard and evidence views were inspected in the browser. Report persistence was verified after restart.

A real local-model benign smoke test passes with Python-side external connections rejected. Host network adapters were not disabled. Runtime inference uses loopback and locally downloaded weights.

The initial long-lived model process exceeded the memory budget; the managed runtime now samples memory and recycles its own child between calls. This does not establish a hard instantaneous or whole-machine memory ceiling. Two inference/batch threads and one slot are configured, but an isolated two-vCPU/4-GB deployment was not certified here. Docker's engine was unavailable, so the optional container path is untested.

AI output remains probabilistic. Rules propose evidence-backed hypotheses; model discoveries are also reviewed and are not limited to rule matches. The local reviewer can reject or correct proposals. This is not a universal security detector. See README.md for limitations and AI_USAGE.md for corrections made during development.

GitHub CI runs the core regression suite on Windows and Ubuntu with Python 3.13. This checks source portability and deterministic behavior; it does not download weights or certify real-model accuracy or deployment memory use.

A fresh, uncached full-file run completed with no call failures, exercised nine managed-model recycles, and stayed within tokenizer and runtime-reported context budgets. Its conservative combined process high-water estimate remained below the configured application memory headroom. Detailed private measurements are retained locally; these do not include operating-system memory. The first independent-review prompt missed several supported signals; revised questions and explicit observed-signal presentation address visibility, but remaining model recall limits must be demonstrated honestly.

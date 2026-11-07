# Verification scope

22 automated regression tests pass: provenance, token-safe boundaries, oversized entries, duplicate handling, generic evidence rules, host/account scope, altered synthetic identities, invalid references, broken JSON retries, timeout persistence, checkpoint reuse, memory recycling guards, and severity policy.

Live HTTP checks pass for invalid uploads, unsupported extension, binary content, foreign browser Origin, and dashboard response headers. The completed dashboard and evidence views were inspected in the browser. Report persistence was verified after restart.

A real local-model benign smoke test passes with Python-side external connections rejected. Host network adapters were not disabled. Runtime inference uses loopback and locally downloaded weights.

The initial long-lived model process exceeded the memory budget; the managed runtime now samples memory and recycles its own child between calls. This does not establish a hard instantaneous or whole-machine memory ceiling. Two inference/batch threads and one slot are configured, but an isolated two-vCPU/4-GB deployment was not certified here. Docker's engine was unavailable, so the optional container path is untested.

AI output remains probabilistic. Generic evidence gates constrain supported incident families; they are not a universal security detector. See README.md for limitations and AI_USAGE.md for corrections made during development.

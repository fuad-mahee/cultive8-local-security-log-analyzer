# Recruiter-oriented review and improvements

This is an engineering assessment of the submission, not a prediction of the employer's decision. The original build had a working local model, source provenance, a usable dashboard, reproducible model metadata, and explicit limitations. I would nevertheless have requested revisions before acceptance because several core behaviors undermined the rubric.

| Rubric area | Original evidence and concern | Revision |
|---|---|---|
| Local model and resources — 20% | Real CPU inference worked, but the initial server exceeded the memory allowance. Later reported memory came from a resumed session. | Keep managed recycling; use process high-water measurements on Windows and run a new job from fresh processes without cached responses. State the scope of measurement precisely. |
| Splitting and correlation — 25% | Exact tokenizer use was good. Fragment budgeting measured a different shape from what was sent. Incident merging could combine unrelated hosts/accounts or different attacks sharing an IP/line. | Count the exact emitted fragment; reserve additional review overhead; group final incidents by class, identity and relevant host/account scope. Parse ISO timestamps for chronology. |
| Accuracy — 20% | Rule-generated hypotheses were forced to produce one finding of the selected type. Chunk-discovered findings were discarded. Plain text could therefore produce no final findings despite a model discovery. | Let the local reviewer reject and reclassify. Review both rule proposals and model discoveries. Preserve the model's actual verdict, evidence and identity. Parse common HTTP access-log fields. |
| Backend — 15% | SQLite checkpoints and retries were useful. Cache compatibility omitted schema/version and evidence permissions. Single-job admission had a check-then-start race. | Version response caches and revalidate their evidence references. Reserve the worker before accepting the job. Use atomic temporary download files and publish manifests only after checksum verification. |
| AI use — 15% | Documentation admitted early model mistakes, but forced confirmation hid weak model discrimination. | Balanced positive/negative examples and real-model tests for both false positives and false negatives. Record unsuccessful prompt variants honestly. |
| Interface — 5% | Upload/progress/evidence were usable. A transient server outage could stop polling permanently; in-progress zero findings could look like a clean result. | Retry polling, explain pending conclusions, and display resource and review information. |

## What would make this persuasive to a reviewer

1. A real local model that can disagree with a proposed attack and can find activity outside the handwritten rules.
2. A reproducible full-file run with no reused model responses, complete coverage, bounded tokens, and honest memory measurements.
3. Source citations that actually support each conclusion; no synthetic replacement of the model's evidence after review.
4. Tests for meaningful failures: cross-host/account isolation, duplicated delivery versus repeated events, out-of-order timestamps, oversized records, model rejection, retries, and restart persistence.
5. An explanation of tradeoffs the applicant can defend and modify during the interview.

## Remaining limits

A small quantized model can still miss attacks or invent semantic explanations. A second pass is not an independent statistical guarantee because it uses the same model. Rule thresholds are hypotheses rather than ground truth. Whole-machine four-GB compliance requires an appropriately constrained deployment; process high-water measurements alone exclude the operating system. Large correlation cases are reviewed in bounded batches and may still lose relationships outside the retained structured facts. This remains a focused assessment prototype rather than a production security product.

The explanation video and accessible repository are required delivery items. A strong video should show an accepted attack, a rejected benign proposal, distant-event linkage, a real evidence citation, and one correction made after observing an AI error. The applicant should explain the code in their own words.

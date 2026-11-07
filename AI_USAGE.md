# AI usage record

## Tools
Codex was used to inspect the supplied brief and log, plan the architecture, implement Python/HTML/JavaScript, and run checks. Web documentation was consulted for llama.cpp APIs and Qwen3.5 model configuration. Runtime log interpretation uses only the downloaded local Qwen3.5-2B model. No cloud AI API is used by this application.

## Key coding requests
The applicant asked for an assessment-specific implementation plan, then clarified a five-hour allowance, then requested implementation following that plan. The approach chosen was exact tokenizer budgeting, SQLite persistence, sequential inference, identity-based cross-file correlation, schema validation, and evidence provenance.

## Local prompts
The exact system prompt is SYSTEM in app.py. Per-call inputs contain `logs` and `prior_facts`. Logs include original line identities. Prior facts contain host, identity, account, authentication result, count, and source lines, derived by code rather than an LLM summary. The prompt explicitly treats logs and previous assessments as untrusted data, permits empty findings, and warns against calling ordinary errors attacks or treating HTTP 200 as proof of compromise.

## Token plan
Render the full chat template using the loaded model, tokenize using that same model, target 1,250 prompt tokens for chunk construction, permit at most 1,398 after relevant historical facts, reserve 650 output tokens, and check every call against the 2,048 ceiling. No character-based token estimation is used. Failed attempts use the same bounded prompt with another seed and slight sampling variation.

## Actual AI/development mistakes corrected
- Initial persistence code used six placeholders for a five-column table. The first full-file run exposed it. Corrected to five; completed responses are now stored transactionally.
- The first model smoke test returned the generic identity `IP` instead of the source address. Added a per-call identity enumeration in the output grammar and verification against cited records.
- Initial schema constrained syntax but allowed arbitrary severity/outcome strings. Added explicit enumerations plus independent validation.
- Initial startup recovery ran on module import, which could affect tests. Moved recovery to application startup.
- The runtime's latest stable release contained a nightly-tag pointer instead of binaries. Setup now follows that official pointer and records the resolved build.

## Human responsibilities
The applicant should review the code, verify conclusions, explain tradeoffs, and record their own explanation video. Do not represent generated documentation as proof of unperformed testing. Known limits and actual measured outcomes are retained in local validation records.
## Evidence validation added after real-model evaluation

The 2B model initially misclassified one failed login followed by success as brute force and missed the long-distance login case when supplied only a summary. The failed raw-model checks are retained locally. We therefore added a generic hypothesis layer in `candidates`: exact unique authentication counts by host/account/IP, encoded SQL patterns, distinct sensitive-path probes, forbidden/traversal requests, explicit rate counters, and instruction-like submitted text. Thresholds and patterns are generic; no sample addresses or source line numbers are embedded in detection code.

The local model still analyzes every chunk and assesses each evidence-supported final hypothesis. The final hypothesis schema requires one assessment of the proposed type; this improves consistency but means rule-generated hypotheses are not independently rejected by the model. False positives from the generic rules remain a known limitation. Unsupported free-form chunk assessments are preserved in the call audit but excluded from final incidents. The application is a hybrid detector, not an unrestricted model-only detector.


## Resource mistake corrected
During the long real-model run, the initially long-lived inference process grew to approximately 4.34 GB resident memory, exceeding the allowed budget. Added an owned-process runtime manager with two CPU/batch threads, one slot, sampled memory checks, and recycling after six calls. Checkpoints preserve completed findings across model restarts. This is a sampled safeguard rather than proof of a hard operating-system memory cap; final measurements are recorded separately.

Additional inference tests exposed SQLite connections remaining open after context-manager transactions. Replaced the connection helper with a context manager that commits/rolls back and always closes the connection. Retry, timeout, cached-response reuse, and pre-inference budget tests now pass.

Final evidence validation also exposed a context-reduction issue: the model cited real source lines listed in a hypothesis summary, but validation only allowed the smaller set of raw records still present in that prompt. Expanded the allowed set to the hypothesis's verified original source references. No nonexistent line is permitted. Larger evidence sets remain recoverable from source storage.

The local model assigned Medium severity to the source-backed suspected account-compromise incident. Added a generic High investigation-priority floor for that incident class, preserving `model_severity` and a policy explanation in the exported report. This is a documented application policy, not a claim that the model made the corrected prioritization itself.

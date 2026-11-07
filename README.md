# Sentinel — Local Security Log Analyzer

An offline-after-setup web app for security log analysis under a 2,048-token context. Python 3.13 standard library backend, SQLite checkpoints, and local Qwen3.5-2B Q4_K_M inference through llama.cpp. No cloud AI calls, Python runtime dependencies, or frontend CDN.

## Quick start (Windows, tested)

1. Install Python 3.13.
2. Run `python setup_local.py` with internet access. It downloads the pinned official CPU runtime and model, verifies the model SHA-256, and records MODEL_MANIFEST.json.
3. Run `python app.py` (or `./start.ps1`). The backend starts and manages its own local model process. Do not start a second llama.cpp server.
4. Open http://127.0.0.1:8000, upload a UTF-8 .log or .txt file (maximum 2 MB), and start analysis.

After setup, external networking is unnecessary. Both services bind to loopback by default. No API key is required. Stop with Ctrl+C; the backend terminates only its own model process. Analysis is sequential and may take several minutes on two CPU threads.

## Model and resources

- Qwen3.5-2B Q4_K_M, model revision and SHA-256 in MODEL_MANIFEST.json.
- Official llama.cpp CPU build b12110; two inference and batch threads, one inference slot, no GPU.
- Context limited to 2,048 tokens, including all input formatting and output.
- Backend owns the model process, samples combined model/backend resident memory, and recycles it after six inference calls or a 2.6-billion-byte sample. A post-call sample above 3.2 billion bytes also stops the child before further work. Completed results remain saved.
- Sampling is not an absolute instantaneous or whole-machine memory cap. For enforced limits, use a constrained environment. See CHECKS.md for verification scope and limitations.

## Pipeline

1. Store the upload under a generated ID. Parse JSON lines with original one-based source lines. Preserve plain text as line entries and warn about its unstructured format.
2. Deduplicate identical records with an explicit event/request ID, retaining every source line. Repeated unidentified text remains separate evidence.
3. Render the actual model chat template and tokenize it with the loaded model. Build entry-preserving chunks targeting at most 1,250 prompt tokens; fragment oversized entries with source identity.
4. Add relevant earlier authentication facts when space permits. Facts contain host/account/IP, unique failure counts, and source references. Cap complete prompts at 1,398 tokens, reserving 650 output tokens. Check every generation against 2,048; also check runtime-reported actual usage.
5. Analyze every chunk using the local model. Constrain JSON output, validate schema fields and evidence identities, retry bounded failures, and split failed batches where possible.
6. Combine model-discovered findings with generic cross-file hypotheses from observed evidence: five or more unique failed logins scoped by host/account/IP; later success; encoded SQL payloads; three distinct sensitive-path probes; traversal or denied admin requests; explicit rate counters; instruction-like submitted text.
7. Ask the local model to independently review each proposal using bounded evidence and relevant earlier facts. Empty findings are allowed, and the model may correct the proposed type. Both model discoveries and rule proposals reach this stage. Preserve the returned verdict and cited evidence; do not replace it with the proposal.
8. Consolidate final findings with original evidence and duplicate provenance. Mark any failed chunks or hypothesis calls as coverage gaps in a partial report.

This is a hybrid detector. No sample addresses, usernames, expected report, or source-line constants are embedded in detection code. Counts and source provenance come from deterministic code; interpretation, severity, and suggested action come from local inference. Rules propose candidates but do not limit model-discovered findings or compel acceptance. The same small model performs both passes, so review every conclusion manually.

## Dashboard and recovery

Upload and start analysis, inspect real chunk progress, select saved jobs, resume interrupted/partial jobs, expand evidence, and export JSON. SQLite saves completed model calls atomically. Cache keys include the rendered prompt, canonical model manifest, pipeline version, output schema, and allowed evidence references. Cached findings are revalidated. New configuration or changed inputs cause fresh calls. Existing completed reports remain available after restart.

Logs are untrusted data. The model has no tools or command-execution capability. UI evidence uses textContent. Upload paths are generated internally, and browser cross-origin job creation is rejected. No automatic incident response is performed.

## Verification

`python -m unittest discover -s tests -v`

Unit tests cover provenance, duplicates, chunk boundaries, oversized entries, authentication scope, changed identities, encoded payloads, false-positive gates, invalid evidence, broken JSON retries, timeout persistence, cache reuse, and pre-inference budget enforcement. `python test_http.py` exercises a running app's rejected uploads and origin checks.

Detailed assessment evaluation records are retained locally. See CHECKS.md for verification scope and AI_USAGE.md for actual prompt changes and mistakes corrected.

## Known limitations

- JSON-lines fields and common HTTP access-log fields receive the strongest structured support. Other text is analyzed by the model per line. Multiline stack traces are not automatically joined.
- Input is capped at 2 MB and retained in bounded application structures for cross-file correlation. This is not an unlimited streaming service.
- Authentication uses a fixed five-failure proposal threshold and parsed ISO timestamps. Missing/nonstandard timestamps prevent a reliable successful-login chronology. Timezone-naive ISO values are interpreted as UTC.
- Review evidence is split into bounded batches. Cross-batch authentication facts persist, but arbitrary semantic relationships may still be missed. Only model-cited lines become finding evidence.
- The model can still hallucinate semantic details. References and identities are validated; natural-language conclusions are probabilistic.
- Correlation and merging may over-merge or miss related incidents. There is no distributed job queue or multi-user authentication.
- CPU thread limits do not prove execution on an isolated two-vCPU machine. Memory samples do not include operating-system overhead.
- Windows is the tested setup path. The optional Dockerfile is provided for a constrained Linux evaluation and must be validated on a Docker-capable host.

## Optional Docker evaluation (not tested in this environment)

Download the model with setup first. Build with `docker build -t sentinel .`. Run with `docker run --rm --cpus=2 --memory=4g -p 127.0.0.1:8000:8000 -v "${PWD}/models:/app/models:ro" -v sentinel-data:/app/data sentinel`. This binds the published dashboard only to local host and applies a real container CPU/memory limit. First build requires internet; runtime uses only local files. An out-of-memory termination can still occur; resume from saved data after restart.

Suspected account compromise uses a High investigation-priority floor; exported JSON retains the original `model_severity` and policy explanation when adjusted. Other priorities remain model assessments and require review.

See REVIEW.md for the recruiter-oriented analysis and the rationale for these revisions.

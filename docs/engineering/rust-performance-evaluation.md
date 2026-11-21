# Rust Performance Evaluation — When (and When Not) to Introduce Rust in Indicative

**Status:** Evaluation & Recommendation (Not Adopted for MVP / v1)
**Decision:** Retain 100% TypeScript/Node.js for MVP and v1; revisit only if production stage-level telemetry triggers the thresholds in §5 and record as `ADR-014`.

---

## 1. Executive Summary

Performance in Indicative is overwhelmingly **not** bottlenecked in Node.js/TypeScript. Real scan execution timings from the Indicative regression corpus confirm that wall-clock time is dominated by:

1. **Native scanner binaries** — Semgrep (`~4.7–6.5s`), Trivy (`~2.3–5.5s`), Gitleaks (`~2.1–4.6s`)
2. **External I/O** — GitHub API / `git clone`, PostgreSQL queries, Redis/BullMQ round-trips, and optional LLM API latency

By contrast, TypeScript normalization, redaction, and HKDF+HMAC-SHA256 fingerprinting run in single-digit milliseconds for typical repositories. Rewriting the API, UI, worker orchestration, or scanners in Rust would add major polyglot CI/packaging complexity with negligible real-world latency reduction.

---

## 2. Critique of Candidate Rust Use Cases

| Candidate Area | Original Rust Pitch | Engineering Critique Against Actual Implementation |
|---|---|---|
| **Secret HMAC fingerprinting (`packages/security`)** | Pure CPU work (`ring`/`openssl`) | **Overstated.** Node's `crypto.hkdfSync` and `crypto.createHmac` already execute in native OpenSSL C/ASM. FFI (`napi-rs`) or IPC marshaling overhead can negate gains on small/medium payloads. The real JS risk is **ReDoS** in backtracking regexes — already addressed in TS via linear-time PEM block scrubbing, strictly bounded quantifiers, and 64 KB chunked windowing (or `re2` if ever needed). |
| **Repository ingestion (`apps/worker`)** | Streaming tarball decompression & file walking | **Misaligned with full-history scans.** Indicative intentionally uses native `git clone` (not GitHub tarballs) because Gitleaks requires full `.git` commit history. Workspace sanitization (`lstat`/`readdir`) is syscall/I/O-bound. |
| **Scanner output parsing (`packages/scanners`) & report exports (`packages/findings`)** | Avoid V8 heap OOMs on 100+ MB JSON outputs | **Better solved first in Node.js.** Pre-read `fs.stat` byte ceilings (`readBoundedTextFile`, default 64 MB) prevent V8 OOMs cleanly with `RESOURCE_LIMIT`, and Node `Readable` streaming exporters (`streamReportAsJson`, `streamReportAsSarif`, `streamReportAsCsv`) avoid monolithic in-memory strings without introducing Rust. |
| **Scanner runner supervisor (`services/scanner-runner`)** | Custom Rust binary for cgroups/seccomp/rlimits | **Wrong security investment.** Hand-rolling Linux cgroups/seccomp in a custom binary still shares the host kernel. Real multi-tenant security comes from running `scanner-runner` on **gVisor (`runsc`)**, **Kata Containers**, or **AWS Firecracker** (`infrastructure/sandbox/docker-compose.gvisor.yml`, `infrastructure/sandbox/gvisor-scanner-runner.yaml`). |
| **Client-side WASM redaction** | Sanitize in browser before upload | **Not applicable.** Indicative pulls repositories server-side via GitHub App tokens, and client-side redaction can never replace mandatory server-side redaction. |

---

## 3. Where Rust Is Never Worth It

- **Web dashboard (`apps/web`, Next.js/React)** — UI rendering is not CPU-bound.
- **API service (`apps/api`, Fastify)** — I/O-bound auth, validation, DB, and queue calls.
- **Worker orchestration (`apps/worker`, BullMQ)** — dominated by Redis and scanner wall-clock time.
- **AI Security Analyst (`packages/ai`)** — dominated by LLM provider network latency.
- **Database layer (`packages/database`)** — PostgreSQL performs heavy indexing/filtering.
- **Scanners themselves** — Semgrep, Trivy, and Gitleaks are already native compiled engines.

---

## 4. Higher-ROI Improvements Implemented Instead of Rust

Rather than introducing a polyglot Rust toolchain prematurely, Indicative implements four higher-leverage improvements directly in TypeScript and container/sandbox infrastructure:

1. **Multi-tenant sandbox runtime readiness (`gVisor` / `Kata`):** Explicit `SandboxRuntimeProfile` (`local-process`, `docker`, `gvisor`, `kata`), `productionMultiTenantReady` health reporting, hardened OCI `--runtime=runsc` / `--runtime=kata-runtime` arg builder, seccomp allowlist ([seccomp-scanner.json](../../infrastructure/sandbox/seccomp-scanner.json)), Compose gVisor override ([docker-compose.gvisor.yml](../../infrastructure/sandbox/docker-compose.gvisor.yml)), and Kubernetes zero-egress `NetworkPolicy` manifest ([gvisor-scanner-runner.yaml](../../infrastructure/sandbox/gvisor-scanner-runner.yaml)).
2. **ReDoS-hardened secret redaction:** Linear-time `O(n)` PEM block scrubber (`scrubPemPrivateKeyBlocks`), strictly bounded regex quantifiers, and 64 KB overlapping-window chunking in `packages/security/src/secrets.ts`, verified against multi-megabyte adversarial payloads.
3. **Bounded scanner output reading & streaming report exports:** `readBoundedTextFile` enforces pre-read byte caps (`SCANNER_MAX_REPORT_BYTES`) before V8 heap allocation, and `streamReportAsJson` / `streamReportAsSarif` / `streamReportAsCsv` stream findings chunk-by-chunk directly through Fastify.
4. **Stage-level latency & peak RSS telemetry:** `apps/worker/src/processors/scanProcessor.ts` emits per-stage durations (`ingestMs`, `scanMs`, `parseNormalizeMs`, `persistMs`, `aiMs`, `artifactMs`) and `peakRssMb` / `peakHeapUsedMb` to Prometheus (`/metrics`), structured logs, audit events, and `scans.summaryCounts`.

---

## 5. Objective Trigger Criteria for Reconsidering Rust (`ADR-014`)

Only introduce a Rust component if production telemetry on large repositories (100k+ files, >100 MB scanner JSON, >50k commits) demonstrates **both**:

1. `parseNormalizeMs` consistently exceeds **15% of total scan wall-clock time**, **or** worker `peakRssMb` exceeds **512 MB / causes OOMs** *after* streaming JSON parsing and bounded reading are in place; **and**
2. Pure-TypeScript streaming JSON parsing (`stream-json`) + `re2` cannot resolve the bottleneck.

**Preferred architecture if triggered:** Build a **single standalone Rust CLI binary** invoked over stdin/stdout NDJSON inside `services/scanner-runner` (covering `stream-parse → redact → HKDF+HMAC fingerprint`) rather than `napi-rs` native Node addons, avoiding cross-platform Node ABI packaging friction across Linux/macOS/Windows. Document the measured evidence in **`ADR-014`** inside [architecture-decisions.md](architecture-decisions.md).

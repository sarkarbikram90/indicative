# Suggestion — Where Rust Could Improve Indicative Performance

This document records a performance suggestion for Indicative. It is a **recommendation, not an implemented decision**. The MVP architecture remains Node.js/TypeScript unless a measurement justifies changing it.

## Short answer

For this MVP, performance is mostly **not** in the Node/TypeScript code. It is dominated by:

- GitHub API calls
- Redis queue round-trips
- PostgreSQL queries
- AI provider network latency
- The scanners themselves, which are already native binaries (Semgrep, Trivy, Gitleaks)

Rewriting the API or UI in Rust would add build complexity with almost no gain. Rust is worth considering only in a few CPU/memory-heavy glue paths *around* the scanners.

---

## Where Rust is genuinely a good fit

| Component | Why Rust helps | What it would replace |
|-----------|----------------|-----------------------|
| **Scanner output parsing + normalization** | Semgrep/Trivy JSON can be tens to hundreds of MB. Rust with `serde` parses faster and with lower peak memory than JS, using bounded buffers. | Parser/normalizer logic in `packages/findings` |
| **Secret redaction + HMAC fingerprinting** | Applied to all raw scanner output across full Git history. Pure CPU work: pattern matching, entropy checks, keyed HMAC, masking. Aho-Corasick / compiled regex automata plus `ring` or `openssl` are ideal. | Hot path in `packages/security` |
| **Repository ingestion** | Streaming tarball decompression, file walking, Git history traversal, symlink and size-limit checks. Rust can stream data instead of loading whole archives into memory and enforce limits precisely. | Trusted ingestion in `apps/worker` |
| **Scanner runner supervisor** | Process spawning, rlimits/cgroups, seccomp, timeouts, bounded stdout/stderr capture. A small Rust binary is leaner and gives tighter isolation control. | Process layer in `services/scanner-runner` |
| **Large report generation (SARIF/JSON/CSV)** | Streaming serialization of large finding sets avoids big in-memory objects. | Export code |

---

## Where Rust is **not** worth it

- **Web dashboard (Next.js/React)** — UI is not CPU-bound.
- **API service (Fastify)** — I/O-bound: auth, validation, database, queue. Fastify is already fast enough.
- **Worker orchestration (BullMQ)** — dominated by Redis round-trips and scanner wall-clock time.
- **AI Security Analyst** — dominated by network latency to the LLM provider.
- **Database layer** — PostgreSQL does the heavy lifting.

**Do not rewrite the scanners.** They are already optimized native tools. Optimize the code around them.

---

## Recommended adoption path

1. **Do not start with Rust in the MVP.** First get correctness, security, and the 12 acceptance criteria working. Measure real bottlenecks.
2. If profiling shows the findings/ingestion path is hot, extract **one Rust core library** (for example `packages/indicative-core`) covering: streaming scanner-output parsing → redaction → fingerprinting → deduplication inputs. Expose it to Node either as a CLI reading JSON/NDJSON from stdin, or via `napi-rs` bindings. Keep it behind the existing module boundary so nothing else changes.
3. Next candidate: a Rust **runner supervisor** — treat this as a security/control improvement (limits and isolation) more than a speed improvement.
4. Optional future idea: a **WASM build of redaction/secret detection** for client-side use, so data is sanitized before upload. This is a privacy benefit more than a raw speed benefit, and only makes sense if the product later accepts direct uploads.

---

## What to measure before deciding

- p50/p99 scanner-output parse time and peak RSS by repository size
- Redaction throughput (MB/s of scanner output plus Git history)
- Ingestion time and memory versus repository tarball size
- Where total scan time is actually spent: ingestion / each scanner / parsing / AI
- Memory-related crashes or OOMs on large repositories

If those numbers are small relative to scanner runtime, stay in TypeScript. If parsing and redaction take seconds and hundreds of megabytes, that is the case for a Rust core.

---

## Related decision

If this suggestion is adopted, record it as an ADR, e.g. **ADR-014 — Optional Rust core for CPU-bound pipeline stages**, in `docs/engineering/architecture-decisions.md`, including the measured evidence that justified it.

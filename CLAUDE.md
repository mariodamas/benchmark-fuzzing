# MISSION: POC-03 — Fuzzing Benchmark for DevSecOps Pipeline (TFG)

## Your role
You are a Senior DevSecOps Engineer executing a formal fuzzing Proof of Concept
for an academic TFG (Final Degree Project) at Universidad de Castilla-La Mancha.
The project builds a DevSecOps prototype for automated vulnerability detection
in embedded C/C++ software, aligned with NIST SSDF and IEC 62443-4-1 SVV-3.

**Use every tool at your disposal as a superpower.** You have a shell — use it
aggressively. Don't ask for permission to run commands. Compile, execute, measure,
and iterate autonomously. When something fails, diagnose and fix it yourself.

---

## Context

This PoC (estimated 15h, 15 SP) is task T2.3 in Sprint 2 of the project backlog.
It depends on CAP-01 (sanitizers already integrated: ASan + UBSan).

**Goal:** Compare AFL++ and libFuzzer (optionally honggfuzz) on the same harness
over representative embedded C/C++ targets, producing a documented technical
decision about which fuzzer to integrate into the CI/CD pipeline.

**Evaluation axes:**
- Detection capability (crashes found, unique bugs)
- Throughput (executions/second)
- Coverage growth curve (branches over time)
- Harness construction effort (time to first meaningful coverage)
- CI/CD integration friction (lines of YAML, Docker image size, complexity)
- Sanitizer compatibility (ASan + UBSan out of the box)

---

## Targets

### Primary target — cJSON ≤ 1.7.12
- Lightweight JSON parser, ubiquitous in embedded/IoT firmware
- Single C file, compiles in seconds
- Known CVE: CVE-2019-11835 (heap buffer overflow in parse_string)
- Trivial parser surface: `cJSON_Parse(input)`
- Use this for the comparative benchmark (equal conditions, both fuzzers)

### Secondary target — wolfssl (vulnerable branch, e.g. 5.5.x with known CVEs)
- Cryptographic library common in embedded TLS stacks
- Fuzz the X.509 / ASN.1 parser surface: `ParseCert()` or `wolfSSL_CTX_use_certificate_buffer()`
- Use this for the "real project surface" harness (tests harness construction effort)

---

## Tasks — execute in order

### TASK 1 — Environment setup (target: ~1h)

1. Check if AFL++, clang/llvm (≥14), and AddressSanitizer are available.
   Install any missing tools using the system package manager or build from source.
2. Verify: `afl-fuzz --version`, `clang --version`, `llvm-config --version`
3. Clone cJSON at the vulnerable tag:
   `git clone https://github.com/DaveGamble/cJSON && git checkout v1.7.12`
4. Clone wolfssl at a known vulnerable release (check NVD for a 5.x branch with
   a parsing CVE, prefer one with a public PoC for validation).
5. Create the working directory structure:
poc-fuzzing/
├── targets/
│   ├── cjson/
│   └── wolfssl/
├── harnesses/
├── corpus/
│   ├── cjson/
│   └── wolfssl/
├── findings/
│   ├── afl/
│   └── libfuzzer/
├── coverage/
└── report/

### TASK 2 — Harness construction for cJSON (target: ~1h)

Write `harnesses/fuzz_cjson.c`. Requirements:
- Entry point: `int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)`
- Null-terminate the input buffer before passing to `cJSON_Parse()`
- Always call `cJSON_Delete()` to avoid memory leaks skewing ASan
- No global state, no file I/O, no exit() calls

The SAME harness must compile for both fuzzers without modification.
Dual compilation:

```bash
# libFuzzer build
clang -fsanitize=fuzzer,address,undefined \
      -g -O1 \
      harnesses/fuzz_cjson.c targets/cjson/cJSON.c \
      -I targets/cjson/ \
      -o build/fuzz_cjson_libfuzzer

# AFL++ build
AFL_USE_ASAN=1 AFL_USE_UBSAN=1 \
afl-clang-fast -g -O1 \
      harnesses/fuzz_cjson.c targets/cjson/cJSON.c \
      -I targets/cjson/ \
      -o build/fuzz_cjson_afl
```

Verify both binaries execute without crashing on a valid JSON input before
proceeding.

### TASK 3 — Seed corpus construction for cJSON (target: ~15min)

Create a minimal but structurally diverse corpus in `corpus/cjson/`:
- A simple key-value object: `{"key": "value"}`
- A nested object with array: `{"a": [1, 2, {"b": true}]}`
- An empty object: `{}`
- A string with unicode escape: `{"x": "\u0041"}`
- A deeply nested structure (5+ levels)
- A large number value at boundary

Do NOT use random bytes as seed — a structured seed dramatically accelerates
early coverage. Save each as a separate file with no extension.

### TASK 4 — Benchmark run: libFuzzer vs AFL++ on cJSON (target: ~1.5h)

Run both fuzzers for exactly **30 minutes each** on the same machine, sequentially,
with equivalent resource allocation. Record start time.

**libFuzzer run:**
```bash
mkdir -p findings/libfuzzer/cjson
time ./build/fuzz_cjson_libfuzzer \
    -max_total_time=1800 \
    -print_final_stats=1 \
    -artifact_prefix=findings/libfuzzer/cjson/ \
    corpus/cjson/ \
    2>&1 | tee findings/libfuzzer/cjson/run.log
```

**AFL++ run:**
```bash
mkdir -p findings/afl/cjson
time afl-fuzz \
    -i corpus/cjson/ \
    -o findings/afl/cjson/ \
    -t 1000 \
    -- ./build/fuzz_cjson_afl @@
```
Let AFL++ run for 30 minutes then send SIGINT.

After each run, immediately record:
- Executions per second (from logs)
- Total executions
- Unique crashes found
- Coverage: edges/branches covered (use afl-showmap for AFL++,
  llvm-cov for libFuzzer)
- Time to first crash (if any)

### TASK 5 — Crash analysis for cJSON (target: ~30min)

For any crashes found:
1. Deduplicate by stack trace using `afl-cmin` (AFL++) or by inspecting
   libFuzzer's dedup output
2. For each unique crash, run the minimized input through the binary manually
   to confirm reproducibility
3. Cross-reference with CVE-2019-11835: does the fuzzer reproduce the known
   vulnerability? Document the result explicitly.
4. Save minimized crash inputs to `findings/crashes_dedup/cjson/`

### TASK 6 — Harness construction for wolfssl (target: ~2h)

Write `harnesses/fuzz_wolfssl_x509.c` targeting the certificate parser.
This task explicitly measures harness construction effort — track how long
each sub-step takes:
- Reading API documentation / source to identify the right entry point
- Writing the initial harness skeleton
- First successful compilation
- First non-trivial coverage (>100 branches)

The harness should:
- Initialize a `DecodedCert` struct with `InitDecodedCert()`
- Call `ParseCert()` with `NO_VERIFY` (avoids signature validation overhead)
- Call `FreeDecodedCert()` unconditionally
- Handle wolfssl's internal error codes gracefully (no exit on parse error)

If you hit compilation issues due to wolfssl's build system, use cmake with:
```bash
cmake -DWOLFSSL_EXAMPLES=no -DWOLFSSL_CRYPT_TESTS=no \
      -DWOLFSSL_ASN=yes ..
```

### TASK 7 — Wolfssl fuzzing campaign (target: ~1.5h)

Build corpus from real DER-encoded certificates:
```bash
# Extract certs from the system trust store as seed corpus
for cert in /etc/ssl/certs/*.pem; do
    openssl x509 -in "$cert" -outform DER \
        -out corpus/wolfssl/$(basename $cert .pem).der 2>/dev/null
done
```

Run both fuzzers for 30 minutes each. Same logging procedure as Task 4.

### TASK 8 — Coverage measurement (target: ~30min)

Generate a coverage report for libFuzzer runs using llvm-cov:

```bash
# Compile a coverage-instrumented binary (no fuzzer, just coverage)
clang -fprofile-instr-generate -fcoverage-mapping -g \
      harnesses/fuzz_cjson.c targets/cjson/cJSON.c \
      -I targets/cjson/ \
      -fsanitize=fuzzer \
      -o build/fuzz_cjson_cov

# Merge profiles from the corpus found by libFuzzer
llvm-profdata merge -sparse \
    findings/libfuzzer/cjson/*.profraw \
    -o coverage/cjson_libfuzzer.profdata

# Generate report
llvm-cov report ./build/fuzz_cjson_cov \
    -instr-profile=coverage/cjson_libfuzzer.profdata \
    targets/cjson/cJSON.c \
    > coverage/cjson_libfuzzer_report.txt
```

For AFL++, use `afl-showmap` to count edge coverage:
```bash
afl-showmap -o coverage/cjson_afl_edges.txt \
    -t 1000 -- ./build/fuzz_cjson_afl @@ \
    < findings/afl/cjson/queue/id:000000*
```

### TASK 9 — CI/CD integration assessment (target: ~30min)

For each fuzzer, write a minimal GitHub Actions workflow snippet that:
- Builds the fuzz target
- Runs a time-boxed campaign (5 minutes, suitable for CI)
- Fails the job if new crashes are found
- Caches the corpus between runs using `actions/cache`

Evaluate and document:
- Number of YAML lines required
- Additional Docker image size (if needed)
- Any required environment variables or secrets
- Whether the fuzzer exits cleanly on timeout (critical for CI)

### TASK 10 — Technical decision document (target: ~1.5h)

Generate `report/decision_fuzzing.md` in **Spanish**, structured as follows:

```markdown
# Decisión técnica: Selección de fuzzer para el pipeline DevSecOps

## 1. Resumen ejecutivo
## 2. Metodología del benchmark
## 3. Resultados cuantitativos

| Métrica                  | AFL++  | libFuzzer | Honggfuzz* |
|--------------------------|--------|-----------|------------|
| Exec/s (cJSON)           |        |           |            |
| Exec/s (wolfssl)         |        |           |            |
| Cobertura (branches %)   |        |           |            |
| Crashes únicos (cJSON)   |        |           |            |
| Crashes únicos (wolfssl) |        |           |            |
| Tiempo hasta 1er crash   |        |           |            |
| Esfuerzo harness (h)     |        |           |            |
| Líneas de YAML CI/CD     |        |           |            |
| Compatibilidad ASan+UBSan|        |           |            |
*Si hay tiempo, ejecutar honggfuzz como tercer candidato.

## 4. Análisis cualitativo
### 4.1 Integración en pipeline CI/CD
### 4.2 Compatibilidad con sanitizers
### 4.3 Mantenibilidad del harness
### 4.4 Licencia y soporte

## 5. Decisión recomendada y justificación
## 6. Riesgos identificados
## 7. Criterios de satisfacción (de POC-03) — verificación

Criterio 1: Se evaluaron al menos dos herramientas sobre el mismo harness → [✓/✗]
Criterio 2: Se documentan cobertura, crashes, esfuerzo e integración con sanitizers → [✓/✗]
Criterio 3: Se evalúa viabilidad de integración en pipeline CI/CD → [✓/✗]
Criterio 4: Resultado es una decisión técnica documentada → [✓/✗]

## 8. Trazabilidad normativa
IEC 62443-4-1 SVV-3, NIST SSDF RV.1, RV.3
```

---

## Constraints and ground rules

- **Never modify the target source code** to make fuzzing easier. The harness
  must work with the library as shipped.
- **All campaigns must be reproducible.** Log exact binary versions, compiler
  flags, and random seeds used.
- **If a tool is unavailable** on the system, document the installation steps
  taken and any obstacles — this is part of the "integration friction" metric.
- **If a campaign produces zero crashes** in 30 minutes, that is a valid result.
  Document it, don't extend the time budget.
- **Timebox strictly.** If you hit an unexpected blocker, note it, move on, and
  include it in the risk section of the report.

---

## Definition of done

POC-03 is complete when:
1. Both fuzzers have been run against both targets with reproducible results
2. At least one crash has been found and confirmed (or absence documented)
3. Coverage data has been collected for at least one target/fuzzer combination
4. `report/decision_fuzzing.md` exists, is complete, and satisfies all four
   acceptance criteria from the product backlog
5. All build artifacts, logs, and crash inputs are saved and organized

Begin with TASK 1. Go.
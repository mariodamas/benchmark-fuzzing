# POC-03 — Fuzzing Benchmark DevSecOps

**TFG:** Prototipo DevSecOps para detección automatizada de vulnerabilidades en software C/C++ embebido  
**Institución:** Universidad de Castilla-La Mancha  
**Sprint:** Sprint 2 — Tarea T2.3  
**Fecha:** 2026-04-14  
**Autor:** Mario Damas Sánchez  
**Normativa:** IEC 62443-4-1 SVV-3 · NIST SSDF RV.1, RV.3

---

## Descripción

Este repositorio contiene el **benchmark de fuzzers** desarrollado como prueba de concepto (POC-03) del TFG. Se evalúan tres herramientas de fuzzing — **libFuzzer**, **AFL++** y **Honggfuzz** — sobre dos targets representativos de software C/C++ embebido:

| Target | Versión | CVE objetivo |
|--------|---------|-------------|
| cJSON | 1.7.12 | CVE-2019-11835 (heap buffer overflow) |
| wolfSSL | 5.6.3 | CVE-2023-3724, CVE-2022-42905 (ASN.1/X.509) |

La decisión técnica resultante se documenta en [`poc-fuzzing/report/decision_fuzzing.md`](poc-fuzzing/report/decision_fuzzing.md).

---

## Estructura del repositorio

```
fuzzing_benchmark/                  ← raíz del repositorio
├── .github/
│   └── workflows/
│       ├── fuzz-libfuzzer.yml      # Pipeline CI/CD — libFuzzer (cJSON)
│       └── fuzz-aflplusplus.yml    # Pipeline CI/CD — AFL++ (cJSON)
├── README.md
├── RESULTS.md                      # Resumen ejecutivo de resultados
└── poc-fuzzing/
    ├── harnesses/
    │   ├── fuzz_cjson.c            # Harness LLVMFuzzerTestOneInput (cJSON)
    │   └── fuzz_wolfssl_x509.c     # Harness X.509/ASN.1 (wolfSSL)
    ├── targets/
    │   ├── cjson/                  # cJSON 1.7.12 (fuente vendorizada)
    │   └── wolfssl/                # wolfSSL 5.6.3 (fuente vendorizada)
    ├── corpus/
    │   ├── cjson/                  # 6 seeds JSON estructuralmente diversos
    │   ├── cjson_afl/              # Copia del corpus para AFL++ (evita race condition, R9)
    │   └── wolfssl/                # 146 certificados DER del almacén del sistema
    ├── build/                      # Binarios compilados (generados — no versionados)
    ├── findings/
    │   ├── libfuzzer/cjson/        # Logs libFuzzer — cJSON
    │   ├── libfuzzer/wolfssl/      # Logs libFuzzer — wolfSSL
    │   ├── afl/
    │   │   ├── cjson/              # Logs AFL++ — cJSON
    │   │   ├── wolfssl_noinst/     # Campaña AFL++ wolfSSL v1 (INVÁLIDA — sin instrumentación)
    │   │   └── wolfssl_instrumented/ # Campaña AFL++ wolfSSL v2 (resultado oficial)
    │   ├── honggfuzz/cjson/        # Logs Honggfuzz — cJSON
    │   ├── honggfuzz/wolfssl/      # Logs Honggfuzz — wolfSSL
    │   └── crashes_dedup/          # Análisis de ausencia de crashes
    ├── coverage/
    │   ├── cjson/                  # Reportes llvm-cov y afl-showmap — cJSON
    │   └── wolfssl/                # Reportes llvm-cov — wolfSSL
    └── report/
        ├── decision_fuzzing.md     # Documento de decisión técnica (resultado principal)
        ├── ci_libfuzzer.yml        # Referencia de snippet CI — libFuzzer
        └── ci_aflplusplus.yml      # Referencia de snippet CI — AFL++
```

> **Nota:** los directorios `build/`, `corpus/` y `targets/honggfuzz/` están excluidos del repositorio mediante `.gitignore` por su tamaño.

---

## Entorno de desarrollo

Entorno probado: **WSL2 — Ubuntu 24.04 LTS** sobre Windows 11.

```bash
# Compilador LLVM/Clang
sudo apt-get install -y clang llvm

# AFL++
sudo apt-get install -y afl++

# Dependencias de build de wolfSSL
sudo apt-get install -y autoconf automake libtool

# Dependencias para compilar Honggfuzz desde fuente
sudo apt-get install -y binutils-dev libunwind-dev libblocksruntime-dev make

# Verificar versiones
clang --version         # >= 14
afl-fuzz --version      # >= 4.0
llvm-cov --version
llvm-profdata --version
```

### Compilar Honggfuzz desde fuente

```bash
git clone https://github.com/google/honggfuzz /home/$USER/honggfuzz
cd /home/$USER/honggfuzz
make -j$(nproc) CC=clang
export HF=/home/$USER/honggfuzz
```

> **Advertencia WSL2:** Honggfuzz en modo instrumentado (`hfuzz-clang`) usa ptrace + shared memory, incompatible con WSL2. LeakSanitizer (integrado en ASan) también conflicta con ptrace. Solución: compilar sin sanitizers y ejecutar con `--noinst`. Ver §3.4 de [`report/decision_fuzzing.md`](poc-fuzzing/report/decision_fuzzing.md).

---

## Paso 1 — Preparar los targets

> Los fuentes de cJSON y wolfSSL están vendorizados en `targets/`. No es necesario clonarlos de nuevo. Los pasos siguientes asumen que los fuentes ya están presentes.

Si se parten de cero:

```bash
cd poc-fuzzing

# cJSON 1.7.12
git clone https://github.com/DaveGamble/cJSON targets/cjson
cd targets/cjson && git checkout v1.7.12 && cd ../..

# wolfSSL 5.6.3
git clone https://github.com/wolfSSL/wolfssl targets/wolfssl
cd targets/wolfssl && git checkout v5.6.3-stable && cd ../..
```

---

## Paso 2 — Compilar los harnesses

### cJSON — libFuzzer

```bash
mkdir -p build
clang -fsanitize=fuzzer,address,undefined -g -O1 \
    harnesses/fuzz_cjson.c \
    targets/cjson/cJSON.c \
    -I targets/cjson/ \
    -o build/fuzz_cjson_libfuzzer
```

### cJSON — AFL++

```bash
AFL_USE_ASAN=1 AFL_USE_UBSAN=1 \
afl-clang-fast -g -O1 \
    harnesses/fuzz_cjson.c \
    targets/cjson/cJSON.c \
    -I targets/cjson/ \
    -o build/fuzz_cjson_afl
```

### cJSON — Honggfuzz (modo noinst, requerido en WSL2)

```bash
clang -g -O1 \
    harnesses/fuzz_cjson_hf.c \
    targets/cjson/cJSON.c \
    -I targets/cjson/ \
    -o build/fuzz_cjson_hf_plain
```

---

## Paso 3 — Compilar wolfSSL

wolfSSL debe compilarse como librería estática con el compilador del fuzzer correspondiente.

### wolfSSL — libFuzzer

```bash
cd targets/wolfssl
./autogen.sh
CC=clang CFLAGS="-fsanitize=fuzzer-no-link,address,undefined -g -O1 -DWOLFSSL_PUBLIC_MP" \
./configure --enable-static --disable-shared \
    --enable-asn --enable-certgen --enable-certext \
    --enable-opensslextra --disable-examples --disable-crypttests
CC=clang CFLAGS="-fsanitize=fuzzer-no-link,address,undefined -g -O1 -DWOLFSSL_PUBLIC_MP" \
make -j$(nproc)
cd ../..

clang -fsanitize=fuzzer,address,undefined -g -O1 \
    -include targets/wolfssl/wolfssl/options.h \
    harnesses/fuzz_wolfssl_x509.c \
    -I targets/wolfssl/ \
    targets/wolfssl/src/.libs/libwolfssl.a -lm \
    -o build/fuzz_wolfssl_libfuzzer
```

### wolfSSL — AFL++

> **Importante:** `libwolfssl.a` debe recompilarse con `afl-clang-fast`. Sin esto, AFL++ solo captura ~3 edges del harness (ver riesgo R8 en [`report/decision_fuzzing.md`](poc-fuzzing/report/decision_fuzzing.md)).

```bash
cd targets/wolfssl && make distclean
CC=afl-clang-fast CFLAGS="-g -O1 -DWOLFSSL_PUBLIC_MP" \
./configure --enable-static --disable-shared \
    --enable-asn --enable-certgen --enable-certext \
    --enable-opensslextra --disable-examples --disable-crypttests
CC=afl-clang-fast CFLAGS="-g -O1 -DWOLFSSL_PUBLIC_MP" \
make -j$(nproc)
cd ../..

AFL_USE_ASAN=1 AFL_USE_UBSAN=1 \
afl-clang-fast -g -O1 \
    -include targets/wolfssl/wolfssl/options.h \
    harnesses/fuzz_wolfssl_x509.c \
    -I targets/wolfssl/ \
    targets/wolfssl/src/.libs/libwolfssl.a -lm \
    -o build/fuzz_wolfssl_afl
```

Verificar instrumentación antes de la campaña:

```bash
afl-showmap -o /dev/stdout -t 1000 -- build/fuzz_wolfssl_afl < corpus/wolfssl/cert0.der
# Debe mostrar >= 100 tuples. Si muestra < 10, libwolfssl.a no está instrumentada.
```

### wolfSSL — Honggfuzz (noinst)

```bash
cd targets/wolfssl && make distclean
CC=clang CFLAGS="-g -O1 -DWOLFSSL_PUBLIC_MP" \
./configure --enable-static --disable-shared \
    --enable-asn --enable-certgen --enable-certext \
    --enable-opensslextra --disable-examples --disable-crypttests
CC=clang CFLAGS="-g -O1 -DWOLFSSL_PUBLIC_MP" make -j$(nproc)
cd ../..

clang -g -O1 \
    -include targets/wolfssl/wolfssl/options.h \
    harnesses/fuzz_wolfssl_hf.c \
    -I targets/wolfssl/ \
    targets/wolfssl/src/.libs/libwolfssl.a -lm \
    -o build/fuzz_wolfssl_hf_plain
```

---

## Paso 4 — Construir el corpus inicial

### cJSON (incluido en el repositorio)

```
corpus/cjson/01_empty.json      → {}
corpus/cjson/02_simple.json     → {"key":"value"}
corpus/cjson/03_nested.json     → {"a":[1,2,{"b":true}]}
corpus/cjson/04_unicode.json    → {"x":"A"}
corpus/cjson/05_deep.json       → {"a":{"b":{"c":{"d":{"e":1}}}}}
corpus/cjson/06_numbers.json    → {"n":1.7976931348623157e+308}
```

### wolfSSL — certificados DER del sistema

```bash
mkdir -p corpus/wolfssl
for cert in /etc/ssl/certs/*.pem; do
    openssl x509 -in "$cert" -outform DER \
        -out "corpus/wolfssl/$(basename $cert .pem).der" 2>/dev/null
done
echo "Corpus wolfSSL: $(ls corpus/wolfssl/*.der | wc -l) certificados"
```

---

## Paso 5 — Ejecutar las campañas (30 minutos)

### libFuzzer — cJSON

```bash
mkdir -p findings/libfuzzer/cjson
./build/fuzz_cjson_libfuzzer \
    -max_total_time=1800 \
    -print_final_stats=1 \
    -artifact_prefix=findings/libfuzzer/cjson/ \
    corpus/cjson/ \
    2>&1 | tee findings/libfuzzer/cjson/run.log
```

### AFL++ — cJSON

```bash
mkdir -p findings/afl/cjson
cp -r corpus/cjson/ corpus/cjson_afl/
echo core | sudo tee /proc/sys/kernel/core_pattern

AFL_NO_UI=1 AFL_SKIP_CPUFREQ=1 \
timeout 1860 afl-fuzz \
    -i corpus/cjson_afl/ \
    -o findings/afl/cjson/ \
    -t 1000 \
    -- ./build/fuzz_cjson_afl @@ \
    2>&1 | tee findings/afl/cjson/run.log
```

### Honggfuzz — cJSON (noinst)

```bash
mkdir -p findings/honggfuzz/cjson/workspace
$HF/honggfuzz \
    --input corpus/cjson/ \
    --workspace findings/honggfuzz/cjson/workspace \
    --run_time 1800 \
    --noinst \
    --threads 1 \
    --logfile findings/honggfuzz/cjson/hf.log \
    -- ./build/fuzz_cjson_hf_plain ___FILE___ \
    2>&1 | tee findings/honggfuzz/cjson/run.log
```

### libFuzzer — wolfSSL

```bash
mkdir -p findings/libfuzzer/wolfssl
./build/fuzz_wolfssl_libfuzzer \
    -max_total_time=1800 \
    -print_final_stats=1 \
    -artifact_prefix=findings/libfuzzer/wolfssl/ \
    corpus/wolfssl/ \
    2>&1 | tee findings/libfuzzer/wolfssl/run.log
```

### AFL++ — wolfSSL

```bash
mkdir -p findings/afl/wolfssl
AFL_NO_UI=1 AFL_SKIP_CPUFREQ=1 \
timeout 1860 afl-fuzz \
    -i corpus/wolfssl/ \
    -o findings/afl/wolfssl/ \
    -t 1000 \
    -- ./build/fuzz_wolfssl_afl @@ \
    2>&1 | tee findings/afl/wolfssl/run.log
```

### Honggfuzz — wolfSSL (noinst)

```bash
mkdir -p findings/honggfuzz/wolfssl/workspace
$HF/honggfuzz \
    --input corpus/wolfssl/ \
    --workspace findings/honggfuzz/wolfssl/workspace \
    --run_time 1800 \
    --noinst \
    --threads 1 \
    --logfile findings/honggfuzz/wolfssl/hf.log \
    -- ./build/fuzz_wolfssl_hf_plain ___FILE___ \
    2>&1 | tee findings/honggfuzz/wolfssl/run.log
```

---

## Paso 6 — Medir cobertura (libFuzzer)

```bash
# Compilar binario de cobertura
clang -fprofile-instr-generate -fcoverage-mapping -g \
    -fsanitize=fuzzer \
    harnesses/fuzz_cjson.c targets/cjson/cJSON.c \
    -I targets/cjson/ \
    -o build/fuzz_cjson_cov

# Ejecutar sobre corpus
LLVM_PROFILE_FILE="coverage/cjson_%p.profraw" \
    ./build/fuzz_cjson_cov findings/libfuzzer/cjson/ -runs=0

# Mergear y reportar
llvm-profdata merge -sparse coverage/cjson_*.profraw \
    -o coverage/cjson_libfuzzer.profdata

llvm-cov report ./build/fuzz_cjson_cov \
    -instr-profile=coverage/cjson_libfuzzer.profdata \
    targets/cjson/cJSON.c
```

---

## Resultados obtenidos

> Campañas ejecutadas el **2026-04-14** en WSL2 (Ubuntu 24.04, clang 18.1.3, afl++ 4.09c, Honggfuzz 2.6).

### cJSON 1.7.12

| Métrica | libFuzzer | AFL++ | Honggfuzz |
|---------|-----------|-------|-----------|
| Exec/s | 8.733 | **41.836** | 167 ⚠ |
| Total ejecuciones | 15.728.892 | 40.227.601 | 301.404 |
| Cobertura (edges propios) | **575** (SanCov) | 195 (bitmap) | 0 (noinst) |
| Cobertura llvm-cov líneas | **24,50%** | — | — |
| Cobertura llvm-cov branches | **27,71%** | 11,44% | — |
| Corpus final | 422 entradas | 488 entradas | sin cambios |
| Crashes únicos | 0 | 0 | 0 |
| Peak RSS | 595 MB | N/D | 7 MB |

### wolfSSL 5.6.3

| Métrica | libFuzzer | AFL++ | Honggfuzz |
|---------|-----------|-------|-----------|
| Exec/s | 25.962 | **40.073** | 171 ⚠ |
| Total ejecuciones | 46.758.003 | 74.312.792 | 309.166 |
| Cobertura (edges propios) | **1.578+** (SanCov) | 907 (bitmap) | 0 (noinst) |
| Corpus final | +694 entradas | +106 entradas | sin cambios |
| Crashes únicos | 0 | 0 | 0 |
| Peak RSS | 448 MB | 430 MB | 8 MB |

> ⚠ Honggfuzz ejecutado en modo `--noinst` por incompatibilidad de ptrace con WSL2. Los 167–171 exec/s reflejan overhead de fork externo, no el rendimiento real del modo instrumentado (~10.000–100.000 exec/s en Linux nativo).

### Crashes

**Ningún fuzzer encontró crashes en campañas de 30 minutos.** Resultado esperado y documentado:

- **CVE-2019-11835 (cJSON):** requiere surrogate pair UTF-16 exacto al límite del buffer interno. Sin seed dirigido, la probabilidad de alcanzarlo en 30 min es baja. Ver [`findings/crashes_dedup/cjson/README.md`](poc-fuzzing/findings/crashes_dedup/cjson/README.md).
- **CVE-2023-3724 / CVE-2022-42905 (wolfSSL):** superficie ASN.1 con miles de ramas de validación; necesita corpus DER malformado específico y campañas de varias horas.

---

## Decisión técnica

| Escenario | Fuzzer recomendado | Razón |
|-----------|--------------------|-------|
| **CI/CD pipeline** (GitHub Actions) | **libFuzzer** | Terminación limpia con `-max_total_time=N`; sin configuración de kernel; mayor cobertura por ejecución; mismo harness para ambos fuzzers |
| **Campañas offline** (>1h) | **AFL++** | ~5× más throughput; cmplog/redqueen para paths complejos |
| **Honggfuzz** | Descartado en WSL2 | Requiere ptrace; incompatible con LSan/ASan en WSL2; viable en Linux nativo |

El harness `LLVMFuzzerTestOneInput` compila para libFuzzer y AFL++ **sin modificación**, maximizando la reutilización entre CI y campañas offline.

Para el análisis completo (metodología, análisis cualitativo, tabla de riesgos R1–R11, trazabilidad normativa), ver [`poc-fuzzing/report/decision_fuzzing.md`](poc-fuzzing/report/decision_fuzzing.md).

Los pipelines CI/CD funcionales están en [`.github/workflows/`](.github/workflows/).

---

*POC-03 — TFG "Prototipo DevSecOps para detección automatizada de vulnerabilidades en software C/C++ embebido" — UCLM 2025/2026*

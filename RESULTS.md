# Resultados — POC-03 Fuzzing Benchmark

**TFG:** Prototipo DevSecOps para detección automatizada de vulnerabilidades en software C/C++ embebido  
**Autor:** Mario Damas Sánchez — Universidad de Castilla-La Mancha  
**Fecha de campaña:** 2026-04-14  
**Entorno:** WSL2 — Ubuntu 24.04 LTS · clang 18.1.3 · afl++ 4.09c · Honggfuzz 2.6

---

## Propósito

El objetivo de esta prueba de concepto fue seleccionar la herramienta de fuzzing más adecuada para integrarse en el pipeline de la plataforma DevSecOps. La evaluación no buscaba demostrar la ausencia de errores en las librerías analizadas, sino determinar qué herramienta ofrecía el mejor equilibrio entre integración en CI/CD, exploración de código, reproducibilidad de artefactos y compatibilidad con el entorno de trabajo.

---

## Configuración del benchmark

Se evaluaron comparativamente **libFuzzer**, **AFL++** y **Honggfuzz** sobre dos librerías C representativas del dominio embebido:

| Target | Versión | Harness | CVE objetivo | Corpus inicial |
|--------|---------|---------|-------------|----------------|
| cJSON | 1.7.12 | `fuzz_cjson.c` | CVE-2019-11835 | 6 entradas JSON diversas |
| wolfSSL | 5.6.3 | `fuzz_wolfssl_x509.c` | CVE-2023-3724, CVE-2022-42905 | 146 certificados DER del sistema |

Los harnesses de libFuzzer y AFL++ se compilaron con **ASan + UBSan** para maximizar la detección de errores de memoria y comportamientos indefinidos. Las campañas tuvieron una duración de **30 minutos** por herramienta y target.

> **Limitación WSL2 — Honggfuzz:** en la configuración utilizada, Honggfuzz presentó conflictos en modo instrumentado por el uso de `ptrace` y memoria compartida. Se ejecutó en modo `--noinst` (sin guía por cobertura), por lo que sus métricas de velocidad y cobertura no son comparables directamente con las de libFuzzer y AFL++.

---

## Resultados cuantitativos

> **Nota sobre cobertura:** la cobertura reportada por libFuzzer (SanCov edges) y la cobertura bitmap de AFL++ no son magnitudes equivalentes — corresponden a modelos de instrumentación distintos. Se utilizan para valorar el progreso interno de cada herramienta, no como comparación aritmética directa entre fuzzers.

### cJSON 1.7.12

| Métrica | libFuzzer | AFL++ | Honggfuzz |
|---------|-----------|-------|-----------|
| Velocidad (exec/s) | 8.733 | **41.836** | 167 ⚠ |
| Total de ejecuciones | 15.728.892 | **40.227.601** | 301.404 |
| Cobertura de aristas | 575 (SanCov) | 195 (bitmap) | 0 (noinst) |
| Cobertura llvm-cov líneas | **24,50 %** | 11,44 % | N/D |
| Cobertura llvm-cov ramas | **27,71 %** | — | N/D |
| Corpus final | 422 entradas | 488 entradas | sin cambios |
| Crashes únicos | 0 | 0 | 0 |
| Peak RSS | 595 MB | N/D | 7 MB |

### wolfSSL 5.6.3

| Métrica | libFuzzer | AFL++ | Honggfuzz |
|---------|-----------|-------|-----------|
| Velocidad (exec/s) | 25.962 | **40.073** | 171 ⚠ |
| Total de ejecuciones | 46.758.003 | **74.312.792** | 309.166 |
| Cobertura de aristas | 1.578+ (SanCov) | 907 (bitmap) | 0 (noinst) |
| Corpus final | +694 entradas | +106 entradas | sin cambios |
| Crashes únicos | 0 | 0 | 0 |
| Peak RSS | 448 MB | 430 MB | 8 MB |

⚠ Honggfuzz en modo `--noinst` (fork externo sin feedback de cobertura). En Linux nativo con modo instrumentado se esperan 10.000–100.000 exec/s.

---

## Interpretación de los resultados

**AFL++** alcanzó la mayor velocidad de ejecución en ambos targets (~5× sobre cJSON, ~1,5× sobre wolfSSL respecto a libFuzzer). Sin embargo, **libFuzzer** ofreció mayor cobertura medida con `llvm-cov` en cJSON y una integración más directa con el toolchain LLVM/clang, ASan y UBSan.

La **ausencia de crashes en 30 minutos no permite concluir que las librerías estén libres de defectos**. Los resultados deben interpretarse como evidencia de exploración efectiva dentro del tiempo disponible:

- **CVE-2019-11835 (cJSON):** requiere una secuencia de escape `𐀀` exacta al límite del buffer interno en `parse_string()`. Sin seed dirigido, la probabilidad de alcanzar ese path en 30 min es baja. Ver análisis completo en [`poc-fuzzing/findings/crashes_dedup/cjson/README.md`](poc-fuzzing/findings/crashes_dedup/cjson/README.md).
- **CVE-2023-3724 / CVE-2022-42905 (wolfSSL):** superficie ASN.1 con miles de ramas de validación; requiere corpus DER malformado específico y campañas de varias horas.

---

## Decisión adoptada

A partir de los resultados obtenidos se adoptó una **estrategia diferenciada** según el tipo de ejecución:

| Escenario | Herramienta | Justificación |
|-----------|-------------|---------------|
| **Pipeline CI/CD** | **libFuzzer** | Terminación limpia con `-max_total_time=N`; sin configuración de kernel; integración directa con ASan/UBSan; mismo harness para ambos fuzzers |
| **Campañas offline** (>1 h) | **AFL++** | ~5× más throughput en cJSON; estrategias avanzadas de mutación (cmplog, redqueen) para paths con validaciones complejas |
| **Honggfuzz** | Descartado (WSL2) | Incompatibilidad ptrace + LSan/ASan en modo instrumentado; viable en Linux nativo |

El harness `LLVMFuzzerTestOneInput` compila **sin modificación** para libFuzzer y AFL++ (mediante `libAFLDriver.a`), lo que permite ejecutar libFuzzer en CI y AFL++ en campañas nocturnas reutilizando el mismo código.

Esta estrategia permite integrar fuzzing en el pipeline sin requisitos adicionales de configuración del kernel, manteniendo AFL++ como alternativa para campañas más intensivas fuera del flujo ordinario de integración.

---

## Artefactos

| Artefacto | Ubicación |
|-----------|-----------|
| Logs libFuzzer — cJSON | [`poc-fuzzing/findings/libfuzzer/cjson/run_libfuzzer_cjson.log`](poc-fuzzing/findings/libfuzzer/cjson/run_libfuzzer_cjson.log) |
| Logs libFuzzer — wolfSSL | [`poc-fuzzing/findings/libfuzzer/wolfssl/run_libfuzzer_wolfssl.log`](poc-fuzzing/findings/libfuzzer/wolfssl/run_libfuzzer_wolfssl.log) |
| Logs AFL++ — cJSON | [`poc-fuzzing/findings/afl/cjson/run_afl_cjson.log`](poc-fuzzing/findings/afl/cjson/run_afl_cjson.log) |
| Logs AFL++ — wolfSSL (campaña válida) | [`poc-fuzzing/findings/afl/wolfssl_instrumented/run_afl_wolfssl_v2.log`](poc-fuzzing/findings/afl/wolfssl_instrumented/run_afl_wolfssl_v2.log) |
| Logs Honggfuzz — cJSON | [`poc-fuzzing/findings/honggfuzz/cjson/run_honggfuzz_cjson.log`](poc-fuzzing/findings/honggfuzz/cjson/run_honggfuzz_cjson.log) |
| Logs Honggfuzz — wolfSSL | [`poc-fuzzing/findings/honggfuzz/wolfssl/run_honggfuzz_wolfssl.log`](poc-fuzzing/findings/honggfuzz/wolfssl/run_honggfuzz_wolfssl.log) |
| Análisis de crashes | [`poc-fuzzing/findings/crashes_dedup/`](poc-fuzzing/findings/crashes_dedup/) |
| Reportes de cobertura llvm-cov — cJSON | [`poc-fuzzing/coverage/cjson/`](poc-fuzzing/coverage/cjson/) |
| Documento de decisión técnica completo | [`poc-fuzzing/report/decision_fuzzing.md`](poc-fuzzing/report/decision_fuzzing.md) |
| Pipeline CI/CD — libFuzzer | [`.github/workflows/fuzz-libfuzzer.yml`](.github/workflows/fuzz-libfuzzer.yml) |
| Pipeline CI/CD — AFL++ | [`.github/workflows/fuzz-aflplusplus.yml`](.github/workflows/fuzz-aflplusplus.yml) |

---

*POC-03 — TFG "Prototipo DevSecOps para detección automatizada de vulnerabilidades en software C/C++ embebido" — UCLM 2025/2026*

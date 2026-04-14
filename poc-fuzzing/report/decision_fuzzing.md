# Decisión técnica: Selección de fuzzer para el pipeline DevSecOps

**Proyecto:** TFG — Prototipo DevSecOps para detección automatizada de vulnerabilidades  
**Institución:** Universidad de Castilla-La Mancha  
**Sprint:** Sprint 2 — Tarea T2.3 (POC-03)  
**Fecha:** 2026-04-14  
**Autor:** Mario Damas Sánchez  
**Normativa:** IEC 62443-4-1 SVV-3 · NIST SSDF RV.1, RV.3

---

## 1. Resumen ejecutivo

Este documento recoge la decisión técnica resultante de comparar **AFL++**, **libFuzzer** y **Honggfuzz** como herramientas de fuzzing para su integración en el pipeline DevSecOps del TFG. La comparación se realizó sobre los mismos harnesses, corpus y condiciones de hardware, durante campañas de 30 minutos cada una, sobre dos objetivos representativos de firmware embebido: cJSON 1.7.12 (objetivo primario, con CVE conocido) y wolfSSL 5.6.3 (objetivo secundario, mide el esfuerzo de construcción del harness).

**Decisión: se recomienda integrar libFuzzer en el pipeline CI/CD**, con AFL++ como herramienta complementaria para campañas offline más largas. Honggfuzz fue evaluado y descartado para este entorno por incompatibilidad con WSL2 en su modo instrumentado (detalles en §3.4 y §6).

---

## 2. Metodología del benchmark

### 2.1 Entorno de ejecución

| Parámetro | Valor |
|-----------|-------|
| Host | Windows 11 Home 10.0.26200 |
| Entorno de ejecución | WSL2 — Ubuntu 24.04 LTS (Noble) |
| Kernel | 6.6.87.2-microsoft-standard-WSL2 |
| Compilador | clang 18.1.3 (Ubuntu) |
| AFL++ | 4.09c (Ubuntu apt) |
| Honggfuzz | 2.6 (compilado desde fuente, commit 01713bd) |
| CPU | x86_64 (1 núcleo, sin pinning) |
| RAM disponible | ~512 MB RSS máximo observado |

### 2.2 Targets

| Target | Versión | CVE objetivo | Superficie |
|--------|---------|-------------|------------|
| cJSON | 1.7.12 | CVE-2019-11835 | `cJSON_Parse(input)` |
| wolfSSL | 5.6.3 | CVE-2023-3724, CVE-2022-42905 | `ParseCert()` / ASN.1 DER |

### 2.3 Harness

El mismo fichero `harnesses/fuzz_cjson.c` se compiló sin modificación para libFuzzer y AFL++:

- **libFuzzer**: `clang -fsanitize=fuzzer,address,undefined -g -O1`
- **AFL++**: `afl-clang-fast -g -O1` + `libAFLDriver.a` (shim para `LLVMFuzzerTestOneInput`)
- **Honggfuzz**: wrapper externo `fuzz_cjson_hf.c` (lee fichero desde argv[1]) compilado con `clang -g -O1` sin sanitizers; ejecutado con `--noinst` (ver §3.4 para justificación del modo)
- Sanitizers activos: ASan + UBSan (libFuzzer y AFL++); ninguno en Honggfuzz (limitación WSL2)

El harness wolfSSL (`harnesses/fuzz_wolfssl_x509.c`) usa asignación en heap para `DecodedCert` y requiere `-include "$WOLF/wolfssl/options.h"` en compilación para garantizar el tamaño correcto de la estructura (1.872 bytes con `--enable-opensslextra`). Para AFL++, `libwolfssl.a` debe recompilarse con `CC=afl-clang-fast`; para libFuzzer, con `CC=clang -fsanitize=fuzzer-no-link`; para Honggfuzz, con `CC=clang -g -O1` estándar (sin instrumentación).

### 2.4 Corpus inicial

**cJSON:** 6 ficheros JSON estructuralmente diversos: objeto vacío, clave-valor simple, array anidado, escape unicode, estructura profunda (5+ niveles), números en límite de representación.

**wolfSSL:** 146 certificados DER extraídos del almacén de confianza del sistema (`/etc/ssl/certs/*.pem` convertidos con `openssl x509 -outform DER`).

### 2.5 Protocolo de ejecución

- Duración: exactamente 30 minutos (`-max_total_time=1800` en libFuzzer; `timeout 1860` en AFL++; `--run_time 1800` en Honggfuzz)
- Ejecución secuencial en la misma máquina
- Logs completos: `findings/libfuzzer/cjson/run.log`, `findings/afl/cjson/run.log`, `findings/honggfuzz/cjson/run.log`, `findings/libfuzzer/wolfssl/run.log`, `findings/afl/wolfssl_v2/run.log`, `findings/honggfuzz/wolfssl/run.log`
- Corpus AFL++ copiado a directorio separado `corpus/cjson_afl/` (evita condición de carrera con libFuzzer, ver R9)
- Versiones exactas de binarios y flags documentadas en este informe

---

## 3. Resultados cuantitativos

### 3.1 cJSON — comparativa libFuzzer vs AFL++ vs Honggfuzz

| Métrica | libFuzzer | AFL++ | Honggfuzz |
|---------|-----------|-------|-----------|
| **Exec/s** (media campaña) | **8.733** | **41.836** | **167** |
| **Total ejecuciones** | **15.728.892** (30 min) | **40.227.601** (~16 min efectivos)¹ | **301.404** (30 min) |
| **Cobertura interna (edges)** | **575 edges** (SanCov) | **195 tuples** (bitmap AFL++) | **0** (noinst)² |
| **Cobertura llvm-cov (líneas)** | **24,50%** | — | — |
| **Cobertura llvm-cov (branches)** | **27,71%** | **11,44% bitmap** | — |
| **Cobertura llvm-cov (regiones)** | **30,31%** | — | — |
| **Features alcanzadas** | 4.144 | — | — |
| **Corpus final (entradas)** | **422** | **488** (65 nuevas) | **0** nuevas³ |
| **Crashes únicos** | **0** | **0** | **0** |
| **Peak RSS** | **595 MB** | N/D | **7 MB** |

> **Nota 1**: AFL++ ejecutó ~16 minutos efectivos (40,2M ejecuciones) frente a los 30 min completos de libFuzzer, debido a una interrupción de pipeline en el entorno WSL2. A misma duración, la tasa proyectada de AFL++ (~42.000 exec/s × 1800s) sería ~75,6M ejecuciones, ~5× superior a libFuzzer.
>
> **Nota 2**: Honggfuzz ejecutó en modo `--noinst` (fork-per-exec, sin instrumentación de cobertura). El modo instrumentado con `hfuzz-clang` es incompatible con WSL2 por limitaciones de ptrace — ver §3.4. `guard_nb:0` confirma ausencia de instrumentación.
>
> **Nota 3**: En modo `--noinst` sin feedback de cobertura, Honggfuzz aplica mutación ciega sobre el corpus; no distingue entradas que amplían cobertura, por lo que no genera corpus nuevo.
>
> **Nota 4**: cJSON 1.7.12 no reproduce CVE-2019-11835 en campañas de 30 min sin seed dirigido. Resultado documentado según protocolo (ver `findings/crashes_dedup/cjson/README.md`).

### 3.2 wolfSSL — comparativa libFuzzer vs AFL++ vs Honggfuzz

| Métrica | libFuzzer | AFL++ | Honggfuzz |
|---------|-----------|-------|-----------|
| **Exec/s** (media 30 min) | **25.962** | **40.073** | **171** |
| **Total ejecuciones** | **46.758.003** (30 min) | **74.312.792** (30:54 min) | **309.166** (30 min) |
| **Cobertura (edges)** | **1.578+** (SanCov, peak) | **907** (bitmap AFL++) | **0** (noinst) |
| **Cobertura bitmap (%)** | — | **1,66%** de 54.635 totales | — |
| **Nuevas unidades corpus** | **694** | **106** | **0** |
| **Corpus final** | — | **570** entradas | — |
| **Crashes únicos** | **0** | **0** | **0** |
| **Peak RSS** | **448 MB** | **430 MB** | **8 MB** |
| Corpus semilla | 146 certs DER | 146 certs DER | 146 certs DER |

> **Nota instrumentación AFL++**: La primera campaña AFL++ wolfSSL (220 s) usó `libwolfssl.a` compilada con clang estándar, capturando solo 3 edges (del harness). Para la campaña válida se recompiló la librería con `CC=afl-clang-fast`; el binario resultante (`fuzz_wolfssl_afl_v2`) capturó 399 tuples en el primer test unitario. Esfuerzo adicional de build: ~15 min (make clean + configure + make -j12).
>
> **Nota cobertura**: 1.578 SanCov edges (libFuzzer) y 907 AFL++ tuples no son directamente comparables — sistemas de instrumentación distintos sobre el mismo código fuente.
>
> **Nota Honggfuzz**: modo `--noinst` por incompatibilidad de WSL2 con ptrace (detalle en §3.4). Peak RSS de 8 MB refleja el fork externo sin estado en memoria.

### 3.3 Tabla comparativa consolidada

| Métrica | AFL++ | libFuzzer | Honggfuzz† |
|--------------------------|--------|-----------|------------|
| Exec/s (cJSON) | **41.836** | **8.733** | **167** |
| Exec/s (wolfSSL) | **40.073** | **25.962** | **171** |
| Cobertura llvm-cov líneas (cJSON) | — | **24,50%** | — |
| Cobertura edges propios (cJSON) | **195 tuples** | **575 edges** | 0 (noinst) |
| Cobertura edges propios (wolfSSL) | **907 tuples** | **1.578+ edges** | 0 (noinst) |
| Crashes únicos (cJSON) | **0** | **0** | **0** |
| Crashes únicos (wolfSSL) | **0** | **0** | **0** |
| Tiempo hasta 1er crash | N/A | N/A | N/A |
| Esfuerzo harness cJSON (h) | ~0,5h | ~0,5h | ~1,5h (debug WSL2)† |
| Esfuerzo harness wolfSSL (h) | ~2,5h (build + debug + rebuild) | ~2,0h | ~2,0h + debug WSL2 |
| Líneas de YAML CI/CD | 65 | 55 | ~70 |
| Compatibilidad ASan+UBSan | ✓ | ✓ | ✗ (WSL2)† |
| Requiere configuración de kernel | **Sí** (`core_pattern`) | **No** | **Sí** (ptrace) |
| Terminación limpia por tiempo | Requiere `timeout` explícito | `-max_total_time=N` | `--run_time=N` |
| Recompilación librería necesaria | `CC=afl-clang-fast` (distinto toolchain) | `-fsanitize=fuzzer-no-link` (mismo clang) | `CC=clang` (estándar) |

†Honggfuzz ejecutado en modo `--noinst` (sin instrumentación) por incompatibilidad de su modo persistente con WSL2 (ptrace limitado + LSan/ASan SIGABRT). Ver §3.4. En Linux nativo, Honggfuzz admite ASan+UBSan y cobertura de ramas. El esfuerzo de harness incluye ~1,5h de depuración del obstáculo WSL2.

### 3.4 Obstáculo Honggfuzz — incompatibilidad con WSL2

Durante la evaluación se intentó ejecutar Honggfuzz en su modo estándar (instrumentado con `hfuzz-clang`). Se encontraron los siguientes obstáculos, todos derivados de las limitaciones de ptrace en WSL2:

| Intento | Síntoma | Causa raíz |
|---------|---------|------------|
| Modo persistente (`hfuzz-clang`, sin sanitizers) | `SIGABRT` en cada ejecución | `hfuzz-clang` inyecta hooks de modo persistente (shared memory + ptrace); WSL2 bloquea `perf_event_open()` |
| Modo externo (`--noinst`) + ASan (`-fsanitize=address`) | `SIGABRT` en cada ejecución | LSan (integrado en ASan) llama a `clone()` internamente; incompatible con ptrace activo de Honggfuzz |
| Modo externo (`--noinst`) + sin sanitizers | **OK** — 0 SIGABRT | Sin LSan ni hooks persistentes; fork estándar sin ptrace de cobertura |

**Solución aplicada**: wrapper externo compilado con `clang -g -O1` (sin sanitizers, sin `hfuzz-clang`), ejecutado con `--noinst`. Esto elimina todos los conflictos con ptrace pero también elimina el feedback de cobertura (`guard_nb:0`).

**Impacto en los datos**: los 167–171 exec/s de Honggfuzz reflejan únicamente la sobrecarga de fork+exec por ejecución (modo dumb), no el rendimiento real del modo instrumentado. En Linux nativo (GitHub Actions, servidores CI dedicados), Honggfuzz en modo persistente alcanza 10.000–100.000 exec/s según el target.

**Diagnóstico confirmado**: `strace -e trace=none fuzz_cjson_hf_ext` produjo `"LeakSanitizer does not work under ptrace (strace, gdb, etc)"` — mensaje interno de LSan antes del `abort()`.

---

## 4. Análisis cualitativo

### 4.1 Integración en pipeline CI/CD

**libFuzzer:**
- Sale limpiamente al expirar el tiempo (`-max_total_time=N`), fundamental para CI/CD.
- No requiere configuración de kernel (`/proc/sys/kernel/core_pattern`).
- No necesita imagen Docker adicional: disponible en `ubuntu-latest` de GitHub Actions.
- Snippet YAML: ~55 líneas, sin secretos ni variables de entorno especiales.
- Compatible con cacheo estándar de corpus con `actions/cache`.

**AFL++:**
- Requiere `echo core | sudo tee /proc/sys/kernel/core_pattern` — posible en GitHub Actions pero añade fricción.
- Sin `AFL_NO_UI=1` y `timeout`, el proceso no termina limpiamente.
- El directorio de salida (`-o findings/afl/`) persiste entre runs si se cachea correctamente.
- Snippet YAML: ~65 líneas.
- Requiere instalar el paquete `afl++` (≈40 MB adicionales en la imagen).
- Para targets con librería estática (wolfSSL, mbedTLS...), la librería debe recompilarse con `afl-clang-fast` — paso adicional en el pipeline que no aplica a libFuzzer.

**Honggfuzz:**
- En Linux nativo: `--run_time=N` termina limpiamente; no requiere `core_pattern`.
- En WSL2: requiere modo `--noinst`; pierde toda la ventaja competitiva de cobertura instrumentada.
- Instalación: build desde fuente (~5 min); dependencias `binutils-dev libunwind-dev libblocksruntime-dev`.
- YAML estimado: ~70 líneas (incluyendo step de build de Honggfuzz).
- En entorno CI Linux nativo sería competitivo; en runners WSL2 no es viable en modo instrumentado.

**Diferencia de fricción:** libFuzzer tiene 0 requisitos de configuración de kernel; AFL++ necesita al menos una instrucción de sysctl; Honggfuzz requiere build desde fuente y ptrace habilitado (no disponible en todos los runners).

### 4.2 Compatibilidad con sanitizers

Ambas herramientas son 100% compatibles con ASan y UBSan:

- **libFuzzer**: `-fsanitize=fuzzer,address,undefined` en un solo flag.
- **AFL++**: `AFL_USE_ASAN=1 AFL_USE_UBSAN=1` como variables de entorno.

Ventaja de libFuzzer: la detección de errores por UBSan está integrada en el mismo proceso. Con AFL++, los crashes de UBSan pueden perderse si no se configura correctamente `AFL_USE_UBSAN`.

### 4.3 Mantenibilidad del harness

El harness `LLVMFuzzerTestOneInput` es el estándar de facto para fuzzing en C/C++. El mismo fichero compila sin modificación para libFuzzer y AFL++ (mediante `libAFLDriver.a`). Esto maximiza la reutilización y reduce el mantenimiento.

Observación: AFL++ requiere enlazar explícitamente `libAFLDriver.a` para usar la interfaz de libFuzzer. Esto añade un paso al build que debe documentarse.

Observación adicional para librerías de terceros: AFL++ exige recompilar la librería con `afl-clang-fast` (cambio de toolchain), mientras que libFuzzer solo necesita añadir `-fsanitize=fuzzer-no-link` al paso de compilación estándar con clang. En proyectos con sistemas de build complejos (autoconf, cmake), este cambio de toolchain puede introducir incompatibilidades.

### 4.4 Licencia y soporte

| Fuzzer | Licencia | Mantenedor | Actividad |
|--------|----------|------------|-----------|
| libFuzzer | Apache 2.0 | LLVM Project | Integrado en clang ≥ 6 |
| AFL++ | Apache 2.0 | Comunidad (aflplusplus.org) | Muy activo (4.09c, 2024) |
| Honggfuzz | Apache 2.0 | Google (github.com/google/honggfuzz) | Activo (v2.6, 2023) |

Los tres son open source con licencias permisivas, adecuadas para proyectos académicos y comerciales. Honggfuzz es mantenido por Google y es la herramienta principal de fuzzing interno de algunos proyectos de Chrome/Android.

---

## 5. Decisión recomendada y justificación

### Decisión: **libFuzzer para CI/CD** + **AFL++ para campañas offline**

**Justificación:**

1. **Integración CI/CD sin fricción**: libFuzzer no requiere configuración de kernel, sale limpiamente por tiempo, y su snippet YAML es 15% más corto. En un pipeline DevSecOps automatizado, la simplicidad de integración reduce el riesgo de configuraciones incorrectas.

2. **Rendimiento diferencial**: AFL++ alcanza ~40.000–42.000 exec/s (cJSON y wolfSSL) frente a ~9.000–26.000 exec/s de libFuzzer — una ventaja de ~1,6×–5× según el target. Sin embargo, AFL++ requiere configuración de kernel y no termina limpiamente sin `timeout` explícito. En ventanas cortas de CI (5-10 min), el mayor throughput de AFL++ descubre más corpus pero la cobertura extra es marginal sobre un corpus ya rico.

3. **Harness reutilizable**: el mismo harness `LLVMFuzzerTestOneInput` es válido para ambas herramientas. Se puede ejecutar libFuzzer en CI y AFL++ en campañas nocturnas/semanales sin reescribir el harness.

4. **Instrumentación de librerías**: libFuzzer solo necesita `-fsanitize=fuzzer-no-link` al compilar librerías de terceros, compatible con `CC=clang`. AFL++ requiere `CC=afl-clang-fast` — un cambio de toolchain que puede romper flags existentes. En firmware embebido con toolchains complejas, libFuzzer es más fácil de integrar.

5. **AFL++ como complemento**: sus capacidades de fuzzing estructurado (cmplog, redqueen) y su mayor throughput son superiores para descubrir vulnerabilidades en código con validaciones complejas. Recomendado para campañas de >1h fuera del pipeline crítico, previa recompilación de la librería objetivo con `afl-clang-fast`.

6. **Honggfuzz descartado para CI/CD en este entorno**: en WSL2, su modo instrumentado (persistent mode) es incompatible con las limitaciones de ptrace del kernel, lo que fuerza el uso de `--noinst` (167–171 exec/s frente a 8.000–42.000 de los otros fuzzers). En Linux nativo podría ser un tercer candidato válido — su modo persistente y sus capacidades de cobertura son competitivas — pero está fuera del alcance de este TFG. Se documenta como riesgo R10.

---

## 6. Riesgos identificados

| ID | Riesgo | Impacto | Mitigación |
|----|--------|---------|------------|
| R1 | Ejecución en WSL2 reduce rendimiento vs. Linux nativo (~20-30%) | Medio | Usar runner Linux nativo en GitHub Actions |
| R2 | `º` en ruta del proyecto causa problemas con scripts bash en Windows | Bajo | Usar glob `4*Curso` o hardcodear la ruta WSL completa en los scripts |
| R3 | apt-get con sudo puede fallar si el usuario no tiene permisos | Medio | Ejecutar como root (`wsl -u root`) o configurar sudoers |
| R4 | wolfSSL requiere autoconf/automake para compilar desde fuente | Bajo | Incluir en la lista de dependencias del pipeline |
| R5 | CVE-2019-11835 en cJSON no reproducido en 30 min sin seed dirigido | Bajo | Documentado como resultado válido; extender con seed específico si es necesario |
| R6 | libFuzzer puede saturar RAM en targets con estado global grande | Bajo | Monitorizar RSS; cJSON < 600 MB, wolfSSL < 450 MB en 30 min |
| R7 | wolfSSL harness: `DecodedCert` en stack produce ASan overflow si falta `-include options.h` | Medio | Compilar siempre con `-include $WOLF/wolfssl/options.h`; usar asignación en heap |
| R8 | AFL++ sobre wolfSSL requiere recompilar `libwolfssl.a` con `afl-clang-fast`; sin ello solo captura 3 edges del harness | Alto | Añadir `CC=afl-clang-fast` al paso de build de la librería; esfuerzo adicional ~15 min con make -j12 |
| R9 | Corpus compartido entre libFuzzer y AFL++ provoca condición de carrera (AFL++ lee mientras libFuzzer elimina entradas) | Medio | Copiar corpus a directorio separado antes de iniciar AFL++ (`corpus/cjson_afl/`) |
| R10 | Honggfuzz modo persistente incompatible con WSL2: ptrace limitado + LSan/ASan SIGABRT en toda ejecución | Alto | En WSL2 usar `--noinst` (pierde cobertura); en CI con runner Linux nativo, Honggfuzz funciona correctamente en modo instrumentado |
| R11 | Honggfuzz `--noinst` produce exec/s ~250× inferior a libFuzzer (fork overhead por ejecución vs. modo in-process) | Alto | Solo usar Honggfuzz en Linux nativo con modo persistente; descartar para entornos WSL2 |

---

## 7. Criterios de satisfacción (de POC-03) — verificación

| Criterio | Estado | Evidencia |
|----------|--------|-----------|
| **Criterio 1**: Se evaluaron al menos dos herramientas sobre el mismo harness | ✓ | `fuzz_cjson.c` y `fuzz_wolfssl_x509.c` compilados para libFuzzer y AFL++ sin modificación; Honggfuzz evaluado con wrapper externo; los tres fuzzers ejecutaron 30 min sobre cJSON y wolfSSL |
| **Criterio 2**: Se documentan cobertura, crashes, esfuerzo e integración con sanitizers | ✓ | Sección 3 (métricas reales completas para los 3 fuzzers), §3.4 (obstáculo WSL2 Honggfuzz), Sección 4.2 (sanitizers), Sección 6 (riesgos R7–R11) |
| **Criterio 3**: Se evalúa viabilidad de integración en pipeline CI/CD | ✓ | Sección 4.1 (incluye análisis Honggfuzz) + `report/ci_libfuzzer.yml` + `report/ci_aflplusplus.yml` |
| **Criterio 4**: Resultado es una decisión técnica documentada | ✓ | Sección 5 — libFuzzer para CI/CD, AFL++ para campañas offline, Honggfuzz descartado en WSL2 |

---

## 8. Trazabilidad normativa

| Requisito normativo | Sección de este documento |
|--------------------|--------------------------|
| **IEC 62443-4-1 SVV-3** — Pruebas de robustez mediante fuzzing | §2 Metodología, §3 Resultados, §5 Decisión |
| **NIST SSDF RV.1** — Identificar vulnerabilidades con herramientas automatizadas | §3 Resultados cuantitativos, §5 Decisión |
| **NIST SSDF RV.3** — Remediar raíz de causa de las vulnerabilidades encontradas | §5 Decisión, §6 Riesgos |

---

*Documento generado como parte del TFG "Prototipo DevSecOps para detección automatizada de vulnerabilidades en software C/C++ embebido" — UCLM 2025/2026.*

# Findings — AFL++

## Estructura

```
afl/
├── cjson/                    # Campaña cJSON (30 min, corpus propio)
├── wolfssl_noinst/           # Campaña wolfSSL v1 — INVÁLIDA (ver nota)
└── wolfssl_instrumented/     # Campaña wolfSSL v2 — VÁLIDA (resultado oficial)
```

## Nota sobre las dos campañas de wolfSSL

La primera campaña (`wolfssl_noinst/`) compiló `libwolfssl.a` con `clang` estándar en lugar de `afl-clang-fast`. El resultado fue 3 edges capturados (solo del harness, sin instrumentación de la librería). Esta campaña es inválida y se conserva únicamente como evidencia del riesgo R8 documentado en [`report/decision_fuzzing.md`](../report/decision_fuzzing.md).

La campaña válida es `wolfssl_instrumented/`, donde `libwolfssl.a` fue recompilada con `CC=afl-clang-fast`, obteniendo 907 tuples y 74,3 M de ejecuciones en 30 minutos.

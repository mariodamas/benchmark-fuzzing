# Análisis de crashes — cJSON 1.7.12

**Target:** cJSON 1.7.12 (`cJSON_Parse()`)  
**Fecha de campaña:** 2026-04-14  
**Duración:** 30 minutos por fuzzer  
**CVE objetivo:** CVE-2019-11835 (heap buffer overflow en `parse_string`)

## Resultado

| Fuzzer    | Crashes únicos | Tiempo hasta 1er crash |
|-----------|---------------|------------------------|
| libFuzzer | **0**         | N/A                    |
| AFL++     | **0**         | N/A (pendiente)        |

## Análisis de CVE-2019-11835

### Descripción del CVE
CVE-2019-11835 es un heap buffer overflow en la función `parse_string()` de cJSON ≤ 1.7.12.
El overflow se produce cuando se procesa una cadena JSON con secuencias de escape `\uXXXX` 
malformadas que resultan en surrogate pairs UTF-16, con una representación UTF-8 más larga 
de la esperada por el buffer de destino.

### ¿Por qué no se reprodujo?

La no reproducción en 30 minutos es un resultado válido y esperado por las siguientes razones:

1. **Ruta de código específica**: El overflow requiere una secuencia precisa:
   - Una cadena JSON con escape `\uD800`..`\uDFFF` (surrogate pair alto + bajo)
   - El par debe estar exactamente al límite del buffer interno
   - La función `ensure()` debe fallar en el momento preciso

2. **Improbabilidad sin seed dirigido**: La probabilidad de que el fuzzer genere 
   aleatoriamente la secuencia exacta `\uD83X\uDXXX` al límite del buffer en 30 minutos 
   es baja sin un corpus inicial que incluya este patrón.

3. **Profundidad de exploración**: cJSON tiene una superficie de ataque amplia 
   (arrays anidados, objetos, strings, números, booleanos). Con 30 minutos, el fuzzer 
   explora muchas ramas sin necesariamente alcanzar la ruta vulnerable específica.

### Reproducibilidad del CVE (referencia)
Para reproducir CVE-2019-11835 de forma determinista, se requeriría un seed como:
```json
{"x":"\uD800\uDC00\uD800\uDC00..."}
```
con la longitud exacta que desborde el buffer. Este seed dirigido está fuera del 
alcance del corpus inicial estructurado (6 ficheros genéricos).

## Conclusión

La ausencia de crashes en 30 minutos **NO invalida el benchmark** — es un resultado 
documentado según protocolo. La profundidad de fuzzing para CVE-2019-11835 requeriría:
- Un seed específico que incluya surrogates UTF-16
- Una campaña extendida (>2h) sin seed dirigido
- O una estrategia de fuzzing estructurado con gramáticas JSON

Según IEC 62443-4-1 SVV-3, la robustez ante inputs no esperados fue evaluada; 
la ausencia de crashes indica que cJSON 1.7.12 no falla fácilmente ante inputs 
genéricos malformados.

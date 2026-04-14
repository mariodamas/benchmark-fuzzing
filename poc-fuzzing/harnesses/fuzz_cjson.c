/*
 * fuzz_cjson.c — Fuzzing harness for cJSON <= 1.7.12
 *
 * Target: CVE-2019-11835 (heap buffer overflow in parse_string)
 * Compiles unchanged for both libFuzzer and AFL++ (via afl-clang-fast).
 *
 * Build — libFuzzer:
 *   clang -fsanitize=fuzzer,address,undefined -g -O1 \
 *         harnesses/fuzz_cjson.c targets/cjson/cJSON.c \
 *         -I targets/cjson/ -o build/fuzz_cjson_libfuzzer
 *
 * Build — AFL++:
 *   AFL_USE_ASAN=1 AFL_USE_UBSAN=1 \
 *   afl-clang-fast -g -O1 \
 *         harnesses/fuzz_cjson.c targets/cjson/cJSON.c \
 *         -I targets/cjson/ -o build/fuzz_cjson_afl
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "cJSON.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Null-terminate: cJSON_Parse expects a C string */
    char *buf = (char *)malloc(size + 1);
    if (!buf) return 0;
    memcpy(buf, data, size);
    buf[size] = '\0';

    cJSON *json = cJSON_Parse(buf);
    cJSON_Delete(json);   /* safe even if json == NULL */

    free(buf);
    return 0;
}

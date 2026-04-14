/*
 * fuzz_wolfssl_x509.c — Fuzzing harness for wolfSSL X.509/ASN.1 parser
 *
 * Target surface: DecodedCert / ParseCert() — ASN.1 DER certificate parsing
 * Tested with wolfSSL 5.6.3 (CVEs: CVE-2023-3724, CVE-2022-42905)
 * Uses NO_VERIFY to skip signature validation (maximises code coverage).
 *
 * Build — libFuzzer:
 *   clang -fsanitize=fuzzer,address,undefined -g -O1 \
 *         harnesses/fuzz_wolfssl_x509.c \
 *         -I targets/wolfssl -I targets/wolfssl/wolfssl \
 *         targets/wolfssl/src/ssl.c targets/wolfssl/wolfcrypt/src/asn.c \
 *         ... (use cmake build instead — see Makefile)
 *
 * Build — AFL++:
 *   AFL_USE_ASAN=1 AFL_USE_UBSAN=1 afl-clang-fast ... (same flags)
 *
 * NOTE: wolfssl requires WOLFSSL_USER_SETTINGS or ./configure flags.
 *       See build/wolfssl_build.sh for the recommended cmake invocation.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* wolfssl headers — adjust include path if needed */
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;

    /*
     * Heap allocation avoids stack-buffer-overflow: wolfssl built with
     * --enable-opensslextra and related flags expands DecodedCert to ~1872 B,
     * which exceeds a typical stack slot.  malloc() uses sizeof() evaluated
     * with the same -include options.h so the size is always correct.
     */
    DecodedCert *cert = (DecodedCert *)malloc(sizeof(DecodedCert));
    if (!cert) return 0;

    /*
     * InitDecodedCert: associate the DER buffer with the DecodedCert struct.
     * The cast is safe — InitDecodedCert takes a const byte* in 5.x.
     */
    InitDecodedCert(cert, (const byte *)data, (word32)size, NULL);

    /*
     * ParseCert with CERT_TYPE and NO_VERIFY skips signature verification,
     * exercising the ASN.1 parser without needing a valid CA chain.
     * We intentionally ignore the return code — parse errors are expected.
     */
    (void)ParseCert(cert, CERT_TYPE, NO_VERIFY, NULL);

    /* Always free — prevents memory leaks from skewing ASan reports */
    FreeDecodedCert(cert);
    free(cert);

    return 0;
}

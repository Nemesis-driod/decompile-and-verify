/* Reconstructed from the decompiled output of sample_stripped (not from sample.c). */
#include <stdio.h>
#include <string.h>

static unsigned int fnv1a_16(const unsigned char *p) {          /* FUN_00101250: 0x811c9dc5 / 0x1000193 = FNV-1a */
    unsigned int h = 0x811c9dc5u;
    for (int i = 0; i < 16; i++) { h ^= p[i]; h *= 0x01000193u; }
    return h & 0x7fffffffu;
}

static int license_ok(const char *key) {                        /* FUN_00101280: length 16 and checksum % 97 == 42 */
    return strlen(key) == 16 && (int)fnv1a_16((const unsigned char *)key) % 97 == 42;
}

int main(int argc, char **argv) {                               /* FUN_001010a0; FUN_001012b0 returns the folded constant 90.0 */
    printf("total=%.2f\n", 90.0);
    if (argc > 1) printf("license %s\n", license_ok(argv[1]) ? "ok" : "bad");
    printf("endpoint=%s config=%s\n", "https://licensing.example-corp.test/v2/activate", "api_key=NOT-A-REAL-KEY-0123456789");
    return 0;
}

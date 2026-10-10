#include <stdio.h>
#include <string.h>

#define LICENSE_ENDPOINT "https://licensing.example-corp.test/v2/activate"
static const char *CONFIG = "api_key=NOT-A-REAL-KEY-0123456789"; /* demo value, not a real credential */

typedef struct { int id; int tier; double rate; } Account;

__attribute__((noinline)) static double apply_discount(const Account *a, double amount) {
    if (a->tier >= 3) return amount * (1.0 - a->rate * 2.0);
    if (a->tier == 2) return amount * (1.0 - a->rate);
    return amount;
}

__attribute__((noinline)) static int checksum(const unsigned char *buf, int len) {
    unsigned int h = 2166136261u;
    for (int i = 0; i < len; i++) { h ^= buf[i]; h *= 16777619u; }
    return (int)(h & 0x7fffffff);
}

__attribute__((noinline)) static int validate_license(const char *key) {
    if (strlen(key) != 16) return 0;
    return (checksum((const unsigned char *)key, 16) % 97) == 42;
}

int main(int argc, char **argv) {
    Account a = {1, 3, 0.05};
    printf("total=%.2f\n", apply_discount(&a, 100.0));
    if (argc > 1) printf("license %s\n", validate_license(argv[1]) ? "ok" : "bad");
    printf("endpoint=%s config=%s\n", LICENSE_ENDPOINT, CONFIG);
    return 0;
}

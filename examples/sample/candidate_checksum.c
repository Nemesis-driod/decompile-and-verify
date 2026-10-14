/* Candidate for the checksum function recovered from sample_stripped (FUN_00101250).
   Compile as a shared library and check it against the ORIGINAL machine code with verify_emulated.py. */
unsigned int fnv1a_16(const unsigned char *p) {
    unsigned int h = 0x811c9dc5u;
    for (int i = 0; i < 16; i++) { h ^= p[i]; h *= 0x01000193u; }
    return h & 0x7fffffffu;
}

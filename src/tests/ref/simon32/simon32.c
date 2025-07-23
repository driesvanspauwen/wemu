#include <stdint.h>

#ifndef ROUNDS
    #define ROUNDS 32
#endif

#define ROR(x, r) ((x >> r) | (x << (16 - r)))
#define ROL(x, r) ((x << r) | (x >> (16 - r)))
#define SIMON_ROUND(x, y, k) \
    tmp = (ROL(x, 1) & ROL(x, 8)) ^ y ^ ROL(x, 2); \
    y = x; \
    x = tmp ^ k;

typedef unsigned char byte;

void ref_simon_encrypt_c(byte* input, byte* key, byte* output) {
    uint16_t x = input[1] | (input[0] << 8);
    uint16_t y = input[3] | (input[2] << 8);
    uint16_t keys[ROUNDS];
    uint16_t tmp;

    for (int i = 0; i < 4; ++i) {
        keys[3 - i] = key[i * 2 + 1] | (key[i * 2] << 8);
    }
    uint32_t z0 = 0b10110011100001101010010001011111;
    for (int i = 4; i < ROUNDS; ++i) {
        tmp = ROR(keys[i - 1], 3);
        tmp ^= keys[i - 3];
        tmp ^= ROR(tmp, 1);
        keys[i] = ~keys[i - 4] ^ tmp ^ 3 ^ ((z0 >> (i - 4)) & 1);
    }
    for (int i = 0; i < ROUNDS; ++i) {
        SIMON_ROUND(x, y, keys[i]);
    }
    output[0] = x >> 8;
    output[1] = x;
    output[2] = y >> 8;
    output[3] = y;
}
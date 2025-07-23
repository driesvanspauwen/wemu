#include <stdint.h>

#define ROL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define C1 0x5A827999
#define C2 0x6ED9EBA1
#define C3 0x8F1BBCDC
#define C4 0xCA62C1D6

void ref_sha1_round_c(unsigned* inputs, unsigned w, unsigned* outputs, unsigned round) {
    unsigned a = inputs[0];
    unsigned b = inputs[1];
    unsigned c = inputs[2];
    unsigned d = inputs[3];
    unsigned e = inputs[4];
    const unsigned constants[4] = {C1, C2, C3, C4};

    unsigned f;
    switch(round) {
        case 0:
            f = (b & c) | ((~b) & d);
            break;
        case 1:
            f = b ^ c ^ d;
            break;
        case 2:
            f = (b & c) | (b & d) | (c & d);
            break;
        case 3:
        default:
            f = b ^ c ^ d;
            break;
    }
    unsigned temp = ROL(a, 5) + f + e + w + constants[round];

    outputs[0] = temp;
    outputs[1] = a;
    outputs[2] = ROL(b, 30);
    outputs[3] = c;
    outputs[4] = d;
}
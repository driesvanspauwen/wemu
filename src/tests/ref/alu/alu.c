#include <stdint.h>

typedef unsigned char byte;

void ref_alu_c(byte* x, byte* y, byte* control, byte* out) {
    uint8_t x_int = x[0];
    uint8_t y_int = y[0];
    uint8_t out_int = 0;

    // zx
    if (control[0] & 1) { x_int = 0; }
    // nx
    if (control[0] & 2) { x_int = ~x_int; }
    // zy
    if (control[0] & 4) { y_int = 0; }
    // ny
    if (control[0] & 8) { y_int = ~y_int; }
    // f
    if (control[0] & 0x10) { out_int = x_int + y_int; }
    else { out_int = x_int & y_int; }
    // no
    if (control[0] & 0x20) { out_int = ~out_int; }

    out_int &= 0xF;
    // out_int -> out[0:3]
    out[0] = out_int;

    // zr
    if (out_int == 0) { out[0] |= 0x10; }
    // ng
    if (out[0] & 8) { out[0] |= 0x20; }
}
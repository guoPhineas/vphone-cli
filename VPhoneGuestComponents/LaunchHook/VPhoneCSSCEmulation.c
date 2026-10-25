#include "VPhoneCSSCEmulation.h"
#include <stddef.h>

// Arm A64 FEAT_CSSC integer encodings. SIMD instructions with the same
// mnemonics are deliberately outside these masks.
bool vp_cssc_emulate(uint32_t instruction, uint64_t registers[31]) {
    if (registers == NULL) return false;
    unsigned width = (instruction >> 31) ? 64 : 32;
    uint64_t mask = width == 64 ? UINT64_MAX : UINT32_MAX;
    uint64_t sign = UINT64_C(1) << (width - 1);
    unsigned rd = instruction & 31;
    unsigned rn = (instruction >> 5) & 31;
    uint64_t a = rn == 31 ? 0 : registers[rn] & mask;
    uint64_t result;

    switch (instruction & UINT32_C(0x7FFFFC00)) {
    case 0x5AC02000: // ABS; unsigned subtraction also defines ABS(INT_MIN).
        result = a & sign ? (0 - a) & mask : a;
        break;
    case 0x5AC01C00: // CNT (scalar).
        result = 0;
        for (uint64_t bits = a; bits; bits &= bits - 1) result++;
        break;
    case 0x5AC01800: // CTZ; zero has width trailing zero bits.
        result = width;
        if (a != 0) {
            result = 0;
            while ((a & 1) == 0) { result++; a >>= 1; }
        }
        break;
    default: {
        uint32_t operation = instruction & UINT32_C(0x7FE0FC00);
        bool immediate = false;
        unsigned kind;
        switch (operation) {
        case 0x1AC06000: kind = 0; break; // SMAX
        case 0x1AC06400: kind = 1; break; // UMAX
        case 0x1AC06800: kind = 2; break; // SMIN
        case 0x1AC06C00: kind = 3; break; // UMIN
        default:
            immediate = true;
            switch (instruction & UINT32_C(0x7FFC0000)) {
            case 0x11C00000: kind = 0; break;
            case 0x11C40000: kind = 1; break;
            case 0x11C80000: kind = 2; break;
            case 0x11CC0000: kind = 3; break;
            default: return false;
            }
        }
        bool is_signed = (kind & 1) == 0;
        uint64_t b;
        if (immediate) {
            b = (instruction >> 10) & 255;
            if (is_signed && (b & 128)) b |= UINT64_MAX << 8;
            b &= mask;
        } else {
            unsigned rm = (instruction >> 16) & 31;
            b = rm == 31 ? 0 : registers[rm] & mask;
        }
        // Flipping the sign bit orders signed integers without signed overflow
        // or implementation-defined conversions of values above INT64_MAX.
        uint64_t order_sign = is_signed ? sign : 0;
        bool less = (a ^ order_sign) < (b ^ order_sign);
        bool minimum = (kind & 2) != 0;
        result = (less == minimum) ? a : b;
        break;
    }
    }
    if (rd != 31) registers[rd] = result;
    return true;
}

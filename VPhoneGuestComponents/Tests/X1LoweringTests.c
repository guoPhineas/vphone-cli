#include "../LaunchHook/VPhoneX1Lowering.h"
#include "../LaunchHook/VPhoneCSSCEmulation.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>

static void expect(uint32_t input, uint32_t expected) {
    uint32_t output = 0;
    assert(vp_x1_lower_instruction(input, &output));
    assert(output == expected);
}

static void reject(uint32_t input) {
    uint32_t output = 0xAAAAAAAA;
    assert(!vp_x1_lower_instruction(input, &output));
    assert(output == 0xAAAAAAAA);
}

int main(void) {
    uint64_t registers[31] = {0};
    const uint32_t unary[] = {0x5AC02000, 0x5AC01C00, 0x5AC01800};
    for (unsigned wide = 0; wide < 2; wide++) {
        uint32_t sf = wide ? 0x80000000 : 0;
        uint64_t sign = UINT64_C(1) << (wide ? 63 : 31);
        registers[1] = sign;
        assert(vp_cssc_emulate(sf | unary[0] | (1 << 5), registers));
        assert(registers[0] == sign); // ABS(INT_MIN) wraps, does not saturate.
        registers[1] = UINT64_MAX;
        assert(vp_cssc_emulate(sf | unary[1] | (1 << 5), registers));
        assert(registers[0] == (wide ? 64 : 32));
        registers[1] = 0;
        assert(vp_cssc_emulate(sf | unary[2] | (1 << 5), registers));
        assert(registers[0] == (wide ? 64 : 32));
        registers[1] = UINT64_C(1) << 31;
        assert(vp_cssc_emulate(sf | unary[2] | (1 << 5) | 1, registers));
        assert(registers[1] == 31); // Destination aliases the source.
        for (unsigned kind = 0; kind < 4; kind++) {
            registers[1] = wide ? UINT64_MAX : UINT32_MAX;
            registers[2] = 7;
            uint32_t reg_op = sf | (0x1AC06000 + kind * 0x400) | (2 << 16) | (1 << 5) | 2;
            assert(vp_cssc_emulate(reg_op, registers));
            uint64_t expected = (kind == 0 || kind == 3) ? 7 : (wide ? UINT64_MAX : UINT32_MAX);
            assert(registers[2] == expected);
            // Signed immediate -1 and unsigned immediate 255.
            registers[1] = 0;
            uint32_t imm_op = sf | (0x11C00000 + kind * 0x40000) | (255 << 10) | (1 << 5);
            assert(vp_cssc_emulate(imm_op, registers));
            const uint64_t expected_imm[] = {0, 255, wide ? UINT64_MAX : UINT32_MAX, 0};
            assert(registers[0] == expected_imm[kind]);
        }
        registers[0] = 123;
        assert(vp_cssc_emulate(sf | unary[2] | (31 << 5) | 31, registers));
        assert(registers[0] == 123); // ZR writes are discarded, not SP writes.
    }
    registers[0] = 456;
    assert(!vp_cssc_emulate(0xD503201F, registers));
    assert(!vp_cssc_emulate(0x4E205800, registers)); // NEON CNT is not scalar CSSC.
    assert(registers[0] == 456);
    assert(!vp_cssc_emulate(0xDAC01800, NULL));
    expect(0xDAC1A7FE, 0xD503237F); // PACIBSPPC -> PACIBSP
    expect(0xDAC187FE, 0xD503237F); // PACNBIBSPPC -> PACIBSP
    expect(0xDAC1A3FE, 0xD503233F); // PACIASPPC -> PACIASP
    expect(0xDAC183FE, 0xD503233F); // PACNBIASPPC -> PACIASP
    expect(0xF3A0009F, 0xD50323FF); // AUTIBSPPCi -> AUTIBSP
    expect(0xF3BFFFFF, 0xD50323FF); // AUTIBSPPCi, maximum distance -> AUTIBSP
    expect(0xDAC1947E, 0xD50323FF); // AUTIBSPPCr -> AUTIBSP
    expect(0xF38000DF, 0xD50323BF); // AUTIASPPCi -> AUTIASP
    expect(0xF39FFFFF, 0xD50323BF); // AUTIASPPCi, maximum distance -> AUTIASP
    expect(0xDAC1909E, 0xD50323BF); // AUTIASPPCr -> AUTIASP
    expect(0x5520011F, 0xD65F0FFF); // RETABSPPCi -> RETAB
    expect(0x5520053F, 0xD65F0FFF); // fsck cold-boot RETABSPPCi -> RETAB
    expect(0x55200B1F, 0xD65F0FFF); // fsck later RETABSPPCi -> RETAB
    expect(0x553FFFFF, 0xD65F0FFF); // RETABSPPCi, maximum distance -> RETAB
    expect(0xD65F0FE5, 0xD65F0FFF); // RETABSPPCr -> RETAB
    expect(0x5500015F, 0xD65F0BFF); // RETAASPPCi -> RETAA
    expect(0x551FFFFF, 0xD65F0BFF); // RETAASPPCi, maximum distance -> RETAA
    expect(0xD65F0BE6, 0xD65F0BFF); // RETAASPPCr -> RETAA
    expect(0xDAC1BBFE, 0xD503219F); // AUTIA171615 -> AUTIA1716
    expect(0xDAC1BFFE, 0xD50321DF); // AUTIB171615 -> AUTIB1716

    expect(0x9A022020, 0x8B020020); // ADDPT x0,x1,x2
    reject(0x9A043FE3);             // SP plus shift 7 has no ordinary equivalent
    expect(0x9A0630BF, 0x8B2670BF); // ADDPT sp,x5,x6,lsl #4
    expect(0xDA092D07, 0xCB090D07); // SUBPT x7,x8,x9,lsl #3
    expect(0xDA0A27FF, 0xCB2A67FF); // SUBPT sp,sp,x10,lsl #1
    expect(0x9B620C20, 0x9B020C20); // MADDPT x0,x1,x2,x3
    expect(0x9B661CA4, 0x9B061CA4); // MADDPT x4,x5,x6,x7
    expect(0x9B6AAD28, 0x9B0AAD28); // MSUBPT x8,x9,x10,x11
    expect(0x9B6EBDAC, 0x9B0EBDAC); // MSUBPT x12,x13,x14,x15

    reject(0xDAC18BFE); // PACIA171615 deliberately unsupported
    reject(0xDAC18FFE); // PACIB171615 deliberately unsupported
    reject(0x00000000); // UDF and every unrelated instruction are forwarded
    reject(0xD503201F); // NOP
    assert(!vp_x1_lower_instruction(0xDAC1A7FE, NULL));
    puts("X1LoweringTests: PASS");
    return 0;
}

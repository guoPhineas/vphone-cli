#ifndef VPHONE_CSSC_EMULATION_H
#define VPHONE_CSSC_EMULATION_H

#include <stdbool.h>
#include <stdint.h>

// X0...X30. Register 31 in a CSSC encoding is the zero register, never SP.
// Unknown encodings leave the register file unchanged.
bool vp_cssc_emulate(uint32_t instruction, uint64_t registers[31]);

#endif

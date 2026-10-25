@testable import FirmwarePatcher
import Darwin
import Foundation
import Testing
import VPhonePatchKit

@_silgen_name("sys_icache_invalidate")
private func invalidateCSSCTestCode(_ address: UnsafeMutableRawPointer, _ length: Int)

@Suite("CSSC compatibility")
struct CustomFirmwareCSSCTests {
    @Test func `fallback encoders match Keystone 0_9_2`() {
        let cases: [(Data?, UInt32)] = [
            (ARM64Encoder.encodeReverseBits(rd: 10, rn: 21, width64: false), 0x5AC002AA),
            (ARM64Encoder.encodeReverseBits(rd: 30, rn: 31, width64: true), 0xDAC003FE),
            (ARM64Encoder.encodeCountLeadingZeros(rd: 10, rn: 10, width64: false), 0x5AC0114A),
            (ARM64Encoder.encodeCountLeadingZeros(rd: 30, rn: 30, width64: true), 0xDAC013DE),
            (ARM64Encoder.encodeCompareRegister(rn: 16, rm: 17, width64: false), 0x6B11021F),
            (ARM64Encoder.encodeCompareRegister(rn: 16, rm: 31, width64: true), 0xEB1F021F),
            (ARM64Encoder.encodeConditionalSelect(rd: 16, rn: 16, rm: 17, condition: .lo, width64: false), 0x1A913210),
            (ARM64Encoder.encodeConditionalSelect(rd: 16, rn: 17, rm: 16, condition: .mi, width64: true), 0x9A904230),
            (ARM64Encoder.encodeLogicalShiftRight(rd: 16, rn: 16, shift: 1, width64: false), 0x53017E10),
            (ARM64Encoder.encodeLogicalShiftRight(rd: 16, rn: 16, shift: 63, width64: true), 0xD37FFE10),
            (ARM64Encoder.encodeReadNZCV(rt: 16), 0xD53B4210), (ARM64Encoder.encodeWriteNZCV(rt: 17), 0xD51B4211),
            (ARM64Encoder.encodeReadNZCV(rt: 14), 0xD53B420E), (ARM64Encoder.encodeWriteNZCV(rt: 15), 0xD51B420F),
        ]
        for (bytes, expected) in cases { #expect(bytes == ARM64.encodeU32(expected)) }
        #expect(ARM64Encoder.encodeReverseBits(rd: 32, rn: 0, width64: true) == nil)
        #expect(ARM64Encoder.encodeLogicalShiftRight(rd: 0, rn: 0, shift: 32, width64: false) == nil)
    }

    @Test func `signed standalone CSSC lowering is reversible and idempotent`() throws {
        var (image, _) = CustomFirmwareArm64eX1Tests.signedFixture()
        image.replaceSubrange(0x200 ..< 0x204, with: ARM64.encodeU32(0x9AC16D08)) // UMIN x8,x8,x1
        let before = image
        let (result, slots) = try CustomFirmwareArm64eX1.lowerAndReattest(&image, identifier: "test-cssc")
        #expect(result.records.contains { $0.beforeDisasm.hasPrefix("umin ") })
        #expect(!slots.isEmpty)
        #expect(image.count == before.count)
        for record in result.records {
            #expect(record.patchedBytes.count == 4)
            #expect(record.fileOffset >= 0x200) // Leave executable load-command expansion space alone.
            #expect(!(0x300 ..< 0x303).contains(record.fileOffset)) // LC_FUNCTION_STARTS metadata.
        }
        let after = image
        #expect(try CustomFirmwareArm64eX1.lowerAndReattest(&image, identifier: "test-cssc").result.records.isEmpty)
        #expect(image == after)
        var restored = image
        for record in result.records { restored.replaceSubrange(record.fileOffset ..< record.fileOffset + 4, with: record.originalBytes) }
        for slot in slots { restored.replaceSubrange(slot.hashFileOffset ..< slot.hashFileOffset + slot.before.count, with: slot.before) }
        #expect(restored == before)
    }

    @Test func `nonzero padding is never used and a failed plan leaves bytes intact`() throws {
        var (image, _) = CustomFirmwareArm64eX1Tests.signedFixture()
        image.replaceSubrange(0x200 ..< 0x204, with: ARM64.encodeU32(0x9AC16D08))
        for gap in try CustomFirmwareCSSC.padding(in: image) {
            image.replaceSubrange(gap, with: Data(repeating: 0xCC, count: gap.count))
        }
        let before = image
        #expect(throws: (any Error).self) { try CustomFirmwareArm64eX1.lowerAndReattest(&image, identifier: "test-cssc") }
        #expect(image == before)
    }

    @Test func `cache padding excludes overlapping segments and large unowned gaps`() {
        let segments = [0x5000 ..< 0x5800, 0x1000 ..< 0x1800,
                        0x1700 ..< 0x1F00, 0x2000 ..< 0x2800,
                        0x2000 ..< 0x2800, 0x9000 ..< 0x9800]
        #expect(CustomFirmwareCSSC.cacheAlignmentPadding(between: segments) == [0x1F00 ..< 0x2000])
    }

    @Test(arguments: [false, true], [8, 32])
    func `distant thunks use register preserving branch relays in both directions`(cache: Bool, nearSize: Int) throws {
        let ranges = [0x0800_0000 - nearSize ..< 0x0800_0000, 0x0800_1000 ..< 0x0800_1100]
        let padding = try cache ? CustomFirmwareCSSC.Padding(makeRanges: { ranges }, read: { _, count in Data(count: count) })
            : CustomFirmwareCSSC.Padding(ranges: ranges, read: { _, count in Data(count: count) })
        let instruction = try #require(ARM64Disassembler().disassembleOne(ARM64.encodeU32(0x9AC16D08), at: 0))
        let records = try #require(try padding.lower(instruction, identifier: "test-cssc"))
        let decoder = ARM64Disassembler()
        func destination(_ source: Int) throws -> Int {
            let record = try #require(records.first { $0.fileOffset == source })
            let branch = try #require(decoder.disassembleOne(record.patchedBytes, at: UInt64(source)))
            #expect(branch.mnemonic == "b")
            return Int(try #require(branch.detail?.operands.first?.imm))
        }
        let outbound = try destination(0)
        #expect(outbound < 0x0800_1000)
        #expect(try destination(outbound) >= 0x0800_1000)
        let tail = try #require(records.filter { $0.fileOffset >= 0x0800_1000 }.max { $0.fileOffset < $1.fileOffset })
        let inbound = try destination(tail.fileOffset)
        #expect(inbound != outbound)
        #expect(try destination(inbound) == 4)
    }

    @Test func `cache planning uses a whole gap without a fixed relay reservation`() throws {
        let padding = CustomFirmwareCSSC.Padding(makeRanges: { [0x1000 ..< 0x1024] }, read: { _, count in Data(count: count) })
        let instruction = try #require(ARM64Disassembler().disassembleOne(ARM64.encodeU32(0x9AC16D08), at: 0))
        let records = try #require(try padding.lower(instruction, identifier: "test-cssc"))
        #expect(records.count == 10)
        #expect(Set(records.map(\.fileOffset)).count == records.count)
    }

    @Test func `global planning gives scarce local space to the constrained site first`() throws {
        let padding = CustomFirmwareCSSC.Padding(makeRanges: { [0x0100_0000 ..< 0x0100_0024, 0x0F00_0000 ..< 0x0F00_0024] },
            read: { _, count in Data(count: count) })
        let decoder = ARM64Disassembler()
        for site: UInt64 in [0x0800_0000, 0] {
            padding.append([.init(instruction: try #require(decoder.disassembleOne(ARM64.encodeU32(0x9AC16D08), at: site)), identifier: "test-cssc")])
        }
        let records = try padding.finish()
        for (site, target) in [(0, 0x0100_0000), (0x0800_0000, 0x0F00_0000)] {
            let record = try #require(records.first { $0.fileOffset == site })
            let branch = try #require(decoder.disassembleOne(record.patchedBytes, at: UInt64(site)))
            #expect(branch.detail?.operands.first?.imm == Int64(target))
        }
    }

    @Test func `a failed round trip rolls back its thunk before trying another gap`() throws {
        // Entry can reach the first thunk through this pair, but its tail is
        // beyond the return branch's range. A farther two-pair route works.
        let failed = 0x2FFF_FFF8 ..< 0x3000_001C, relay = 0x27FF_FFFC ..< 0x2800_0004
        let padding = try CustomFirmwareCSSC.Padding(ranges: [failed, relay, 0x1900_0000 ..< 0x1900_0008,
            0x1200_0000 ..< 0x1200_0008, 0x0E00_0000 ..< 0x0E00_0024]) { _, count in Data(count: count) }
        let decoder = ARM64Disassembler()
        let instruction = try #require(decoder.disassembleOne(ARM64.encodeU32(0x9AC16D08), at: 0x2000_0000))
        let records = try #require(try padding.lower(instruction, identifier: "test-cssc"))
        #expect(!records.contains { failed.contains($0.fileOffset) || relay.contains($0.fileOffset) })
        let next = try #require(decoder.disassembleOne(ARM64.encodeU32(0x9AC16D08), at: 0x3000_0100))
        #expect(try padding.lower(next, identifier: "test-cssc")?.contains { failed.contains($0.fileOffset) } == true)
    }

    @Test func `failed global plans retain their original padding and queued requests`() throws {
        let padding = try CustomFirmwareCSSC.Padding(ranges: [0x1000 ..< 0x1024]) { _, count in Data(count: count) }
        let decoder = ARM64Disassembler()
        for site: UInt64 in [0, 4] {
            padding.append([.init(instruction: try #require(decoder.disassembleOne(ARM64.encodeU32(0x9AC16D08), at: site)), identifier: "test-cssc")])
        }
        for _ in 0 ..< 2 {
            #expect(throws: (any Error).self) { try padding.finish() }
        }
    }

    @Test func `global retry preserves local capacity for short thunks in a dense cluster`() throws {
        let padding = try CustomFirmwareCSSC.Padding(ranges: [0x1000 ..< 0x1068, 0x07FF_FFF0 ..< 0x07FF_FFF8,
                                                             0x0F00_0000 ..< 0x0F00_0100]) { _, count in Data(count: count) }
        let decoder = ARM64Disassembler()
        for site: UInt64 in stride(from: 0, through: 20, by: 4) {
            let encoding: UInt32 = site < 8 ? 0x9AC16D08 : 0xDAC01808
            padding.append([.init(instruction: try #require(decoder.disassembleOne(ARM64.encodeU32(encoding), at: site)), identifier: "test-cssc")])
        }
        var messages: [String] = []
        let records = try padding.finish(log: { messages.append($0) })
        #expect(messages.contains { $0.contains("retrying the complete plan") })
        #expect(Set(records.map(\.fileOffset)).count == records.count)
        #expect(records.filter { (0 ... 20).contains($0.fileOffset) }.count == 6)
        #expect(try padding.finish().isEmpty)
    }

    @Test func `short minmax requires a proven independent flag overwrite`() throws {
        let decoder = ARM64Disassembler()
        let compare = try #require(ARM64Encoder.encodeCompareRegister(rn: 0, rm: 1, width64: true))
        func dead(_ bytes: Data) -> Bool {
            let decoded = Dictionary(uniqueKeysWithValues: decoder.disassemble(bytes, at: 4).map { (Int($0.address), $0) })
            return CustomFirmwareCSSC.flagsAreDead(after: 0, instructionAt: { decoded[$0] })
        }
        #expect(dead(ARM64.nop + compare))
        #expect(dead(try #require(ARM64Encoder.encodeLdrXUnsignedOffset(rt: 0, rn: 1, offset: 0)) + compare))
        #expect(dead(ARM64.encodeU32(0xDAC01808) + compare)) // CTZ preserves NZCV.
        #expect(!dead(ARM64.ret + compare))
        #expect(!dead(Data(repeating: 0, count: 4) + compare))
        #expect(!dead(try #require(ARM64Encoder.encodeReadNZCV(rt: 9)) + compare))
        #expect(!dead(try #require(ARM64Encoder.encodeConditionalSelect(rd: 0, rn: 1, rm: 2, condition: .eq, width64: true)) + compare))
        #expect(!dead(ARM64.nop))
        let carryWriter = ARM64Instruction(isDecoded: true, address: 4, size: 4, bytes: [], mnemonic: "adcs", operandString: "",
            detail: .init(conditionCode: nil, updatesFlags: true, postIndex: false, operands: []), isJump: false, isCall: false, isReturn: false)
        #expect(!CustomFirmwareCSSC.flagsAreDead(after: 0, instructionAt: { $0 == 4 ? carryWriter : nil }))

        var (image, _) = CustomFirmwareArm64eX1Tests.signedFixture()
        image.replaceSubrange(0x200 ..< 0x20C, with: ARM64.encodeU32(0x9AC16D08) + compare + ARM64.ret)
        let result = try CustomFirmwareArm64eX1.lowerAndReattest(&image, identifier: "test-cssc").result
        #expect(result.records.filter { $0.beforeDisasm == "executable zero padding" }.count == 3)

        let immediate = try #require(decoder.disassembleOne(ARM64.encodeU32(0x91C83D09), at: 0)) // SMIN x9,x8,#15
        let operation = try #require(CustomFirmwareCSSC.Operation(immediate))
        #expect(try operation.thunk(at: 0x1000, resume: 4, flagsDead: true).count == 16)
        let alias = try #require(decoder.disassembleOne(ARM64.encodeU32(0x91C83D08), at: 0))
        let preserving = try #require(CustomFirmwareCSSC.Operation(alias))
        #expect(try preserving.thunk(at: 0x1000, resume: 4, flagsDead: true) == preserving.thunk(at: 0x1000, resume: 4))
    }

    #if arch(arm64)
    /// Execute only the baseline fallback on the host. The wrapper records
    /// NZCV, both scratch registers, SP and the complete Darwin red zone.
    private func execute(_ encoding: UInt32, a: UInt64, b: UInt64, rn: UInt32, rm: UInt32?, rd: UInt32, flagsDead: Bool = false) throws -> [UInt64] {
        let allocation = mmap(nil, 0x4000, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0)
        let memory = try #require(allocation != MAP_FAILED ? allocation : nil)
        defer { munmap(memory, 0x4000) }
        var code = Data()
        func put(_ bytes: Data?) throws { code += try #require(bytes) }
        try put(ARM64Encoder.encodeSubImm12(rd: 31, rn: 31, imm12: 288))
        try put(ARM64Encoder.encodeAddImm12(rd: 31, rn: 31, imm12: 128))
        try put(ARM64Encoder.encodeCompareRegister(rn: 0, rm: 1, width64: true))
        try put(ARM64Encoder.encodeReadNZCV(rt: 16))
        try put(ARM64Encoder.encodeStrXUnsignedOffset(rt: 16, rn: 2, offset: 24))
        try put(ARM64Encoder.encodeMovzX(rd: 16, imm16: 0x1234))
        try put(ARM64Encoder.encodeMovzX(rd: 17, imm16: 0x5678))
        try put(ARM64Encoder.encodeMovzX(rd: 14, imm16: 0xAAAA))
        try put(ARM64Encoder.encodeMovzX(rd: 15, imm16: 0xBBBB))
        for offset: Int32 in stride(from: -128, through: -16, by: 16) {
            try put(ARM64Encoder.encodeStpX(rt1: 16, rt2: 17, rn: 31, offset: offset))
        }
        try put(ARM64Encoder.encodeAddImm12(rd: 3, rn: 31, imm12: 0))
        try put(ARM64Encoder.encodeStrXUnsignedOffset(rt: 3, rn: 2, offset: 40))
        try put(ARM64Encoder.encodeMovX(rd: rn, rm: 0))
        if let rm, rm != rn { try put(ARM64Encoder.encodeMovX(rd: rm, rm: 1)) }
        let site = code.count, thunkAddress = 0x1000
        try put(ARM64Encoder.encodeB(from: site, to: thunkAddress))
        let resume = code.count
        if flagsDead { try put(ARM64Encoder.encodeCompareRegister(rn: 0, rm: 0, width64: true)) }
        try put(ARM64Encoder.encodeStrXUnsignedOffset(rt: rd, rn: 2, offset: 0))
        try put(ARM64Encoder.encodeStrXUnsignedOffset(rt: 16, rn: 2, offset: 8))
        try put(ARM64Encoder.encodeStrXUnsignedOffset(rt: 17, rn: 2, offset: 16))
        try put(ARM64Encoder.encodeStrXUnsignedOffset(rt: 14, rn: 2, offset: 184))
        try put(ARM64Encoder.encodeStrXUnsignedOffset(rt: 15, rn: 2, offset: 192))
        try put(ARM64Encoder.encodeReadNZCV(rt: 16))
        try put(ARM64Encoder.encodeStrXUnsignedOffset(rt: 16, rn: 2, offset: 32))
        try put(ARM64Encoder.encodeAddImm12(rd: 3, rn: 31, imm12: 0))
        try put(ARM64Encoder.encodeStrXUnsignedOffset(rt: 3, rn: 2, offset: 48))
        try put(ARM64Encoder.encodeSubImm12(rd: 4, rn: 31, imm12: 128))
        for index: UInt32 in 0 ..< 16 {
            try put(ARM64Encoder.encodeLdrXUnsignedOffset(rt: 3, rn: 4, offset: index * 8))
            try put(ARM64Encoder.encodeStrXUnsignedOffset(rt: 3, rn: 2, offset: 56 + index * 8))
        }
        try put(ARM64Encoder.encodeAddImm12(rd: 31, rn: 31, imm12: 160))
        code += ARM64.ret
        let instruction = try #require(ARM64Disassembler().disassembleOne(ARM64.encodeU32(encoding), at: UInt64(site)))
        let operation = try #require(CustomFirmwareCSSC.Operation(instruction))
        let thunk = try operation.thunk(at: thunkAddress, resume: resume, flagsDead: flagsDead)
        code.copyBytes(to: memory.assumingMemoryBound(to: UInt8.self), count: code.count)
        thunk.copyBytes(to: memory.advanced(by: thunkAddress).assumingMemoryBound(to: UInt8.self), count: thunk.count)
        try #require(mprotect(memory, 0x4000, PROT_READ | PROT_EXEC) == 0)
        invalidateCSSCTestCode(memory, 0x4000)
        typealias Function = @convention(c) (UInt64, UInt64, UnsafeMutablePointer<UInt64>) -> Void
        let function = unsafeBitCast(memory, to: Function.self)
        var output = [UInt64](repeating: 0, count: 25)
        output.withUnsafeMutableBufferPointer { function(a, b, $0.baseAddress!) }
        #expect(output[4] == (flagsDead ? 0x6000_0000 : output[3])) // NZCV after the independent overwrite.
        #expect(output[5] == output[6]) // SP
        for index in 0 ..< 16 { #expect(output[7 + index] == (index.isMultiple(of: 2) ? 0x1234 : 0x5678)) }
        #expect(output[23] == 0xAAAA)
        #expect(output[24] == 0xBBBB)
        return output
    }

    @Test func `native fallbacks preserve flags scratch registers and red zone`() throws {
        for wide in [false, true] {
            let sf: UInt32 = wide ? 0x80000000 : 0
            let mask: UInt64 = wide ? .max : UInt64(UInt32.max)
            let sign: UInt64 = wide ? 1 << 63 : 1 << 31
            let cases: [(UInt32, UInt64, UInt64, UInt64)] = [
                (0x5AC01800, 0, 0, wide ? 64 : 32), (0x5AC01800, sign, 0, wide ? 63 : 31),
                (0x5AC01C00, .max, 0, wide ? 64 : 32), (0x5AC01C00, 0x101, 0, 2),
                (0x5AC02000, sign, 0, sign), (0x5AC02000, mask - 6, 0, 7),
                (0x1AC06000, mask, 7, 7), (0x1AC06400, mask, 7, mask),
                (0x1AC06800, mask, 7, mask), (0x1AC06C00, mask, 7, 7),
                (0x11C3FC00, 0, 0, 0), (0x11C7FC00, 0, 0, 255),
                (0x11CBFC00, 0, 0, mask), (0x11CFFC00, 0, 0, 0),
            ]
            for (base, a, b, expected) in cases {
                let binary = base & 0x7FE00000 == 0x1AC00000
                for (rn, rm, rd): (UInt32, UInt32, UInt32) in [(8, 9, 10), (16, 17, 16), (17, 16, 17), (8, 9, 8), (8, 9, 9)] {
                    let word = sf | base | (rn << 5) | rd | (binary ? rm << 16 : 0)
                    let output = try execute(word, a: a, b: b, rn: rn, rm: binary ? rm : nil, rd: rd)
                    #expect(output[0] == expected)
                    if rd != 16 { #expect(output[1] == (rn == 16 ? a : binary && rm == 16 ? b : 0x1234)) }
                    if rd != 17 { #expect(output[2] == (rn == 17 ? a : binary && rm == 17 ? b : 0x5678)) }
                    if binary || (base & 0x7F00_0000 == 0x1100_0000 && rd != rn) {
                        let short = try execute(word, a: a, b: b, rn: rn, rm: rm, rd: rd, flagsDead: true)
                        #expect(short[0] == expected)
                        if rd != 16 { #expect(short[1] == output[1]) }
                        if rd != 17 { #expect(short[2] == output[2]) }
                    }
                }
            }
        }
    }
    #endif
}

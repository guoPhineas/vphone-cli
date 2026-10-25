import Foundation
import VPhonePatchKit

/// CSSC needs multiple baseline instructions. Keep every original address by
/// branching to zero-filled, executable segment padding outside all sections.
enum CustomFirmwareCSSC {
    static let mnemonics: Set<String> = ["abs", "cnt", "ctz", "smax", "smin", "umax", "umin"]

    struct Request {
        let instruction: ARM64Instruction
        let identifier: String
        var flagsDead = false
    }

    /// Prove a complete NZCV overwrite on a short straight-line path. Unknown
    /// instructions, calls, branches and carry-dependent flag writers stop it.
    static func flagsAreDead(after address: Int, instructionAt: (Int) -> ARM64Instruction?) -> Bool {
        let writers: Set<String> = ["cmp", "cmn", "tst", "adds", "subs", "ands", "negs"]
        let transparent: Set<String> = ["nop", "mov", "movz", "movn", "movk", "add", "sub", "neg",
            "mul", "madd", "msub", "and", "orr", "eor", "bic", "orn", "eon", "lsl", "lsr", "asr", "ror",
            "ubfx", "sbfx", "ubfiz", "sbfiz", "bfi", "bfxil", "uxtb", "uxth", "sxtb", "sxth", "sxtw",
            "adr", "adrp", "clz", "rbit", "rev", "rev16", "rev32", "extr", "udiv", "sdiv",
            "ldr", "ldrb", "ldrh", "ldrsb", "ldrsh", "ldrsw", "ldur", "ldurb", "ldurh", "ldursb", "ldursh", "ldursw",
            "str", "strb", "strh", "stur", "sturb", "sturh", "ldp", "ldpsw", "stp"]
        for step in 1 ... 16 {
            guard let instruction = instructionAt(address + step * 4), instruction.isDecoded,
                  instruction.size == 4, !instruction.isJump, !instruction.isCall, !instruction.isReturn,
                  let detail = instruction.detail, detail.conditionCode == nil else { return false }
            if writers.contains(instruction.mnemonic) { return detail.updatesFlags }
            guard !detail.updatesFlags,
                  transparent.contains(instruction.mnemonic) || Operation(instruction) != nil else { return false }
        }
        return false
    }

    struct Operation {
        let name: String
        let rd: UInt32
        let rn: UInt32
        let rm: UInt32?
        let immediate: Int64?
        let width64: Bool

        init?(_ instruction: ARM64Instruction) {
            guard mnemonics.contains(instruction.mnemonic), let ops = instruction.detail?.operands,
                  (2 ... 3).contains(ops.count), ops[0].type == .register, ops[1].type == .register
            else { return nil }
            func register(_ reg: ARM64Register, wide: Bool) -> UInt32? {
                if reg == (wide ? .xzr : .wzr) { return 31 }
                return (0 ... 30).first { reg == (wide ? .x($0) : .w($0)) }.map(UInt32.init)
            }
            let wide = register(ops[0].reg, wide: true) != nil
            guard let rd = register(ops[0].reg, wide: wide), let rn = register(ops[1].reg, wide: wide) else { return nil }
            let unary = ["abs", "cnt", "ctz"].contains(instruction.mnemonic)
            guard ops.count == (unary ? 2 : 3) else { return nil }
            var rm: UInt32?, immediate: Int64?
            if !unary {
                if ops[2].type == .register { rm = register(ops[2].reg, wide: wide) }
                else if ops[2].type == .immediate { immediate = ops[2].imm }
                guard rm != nil || immediate != nil else { return nil }
                if let immediate {
                    let legal = instruction.mnemonic.hasPrefix("s") ? (-128 ... 127) : (0 ... 255)
                    guard legal.contains(Int(immediate)) else { return nil }
                }
            }
            name = instruction.mnemonic; self.rd = rd; self.rn = rn
            self.rm = rm; self.immediate = immediate; width64 = wide
        }

        private var condition: ARM64Condition {
            switch name {
            case "smin": .lt
            case "smax": .gt
            case "umin": .lo
            default: .hi
            }
        }

        var canUseShortThunk: Bool { rm != nil || (immediate != nil && rd != rn) }

        func thunk(at address: Int, resume: Int, flagsDead: Bool = false) throws -> Data {
            var code = Data()
            func put(_ bytes: Data?) throws {
                guard let bytes else { throw PatcherError.invalidFormat("unencodable CSSC fallback") }
                code += bytes
            }
            func loadImmediate(_ immediate: Int64, into register: UInt32) throws {
                let value = UInt64(bitPattern: immediate)
                try put(ARM64Encoder.encodeMovzX(rd: register, imm16: UInt16(truncatingIfNeeded: value)))
                if immediate < 0 {
                    for shift: UInt32 in stride(from: 16, through: width64 ? 48 : 16, by: 16) {
                        try put(ARM64Encoder.encodeMovkX(rd: register, imm16: 0xFFFF, shift: shift))
                    }
                }
            }
            if flagsDead, canUseShortThunk {
                // An immediate can use the destination as its temporary only
                // when that does not overwrite the source before the compare.
                let second = rm ?? rd
                if let immediate { try loadImmediate(immediate, into: second) }
                try put(ARM64Encoder.encodeCompareRegister(rn: rn, rm: second, width64: width64))
                try put(ARM64Encoder.encodeConditionalSelect(rd: rd, rn: rn, rm: second, condition: condition, width64: width64))
            } else if name == "ctz" {
                try put(ARM64Encoder.encodeReverseBits(rd: rd, rn: rn, width64: width64))
                try put(ARM64Encoder.encodeCountLeadingZeros(rd: rd, rn: rd, width64: width64))
            } else if name == "abs" {
                // Copying through W CSEL clears the upper half without
                // changing flags; both inputs are identical, so EQ is immaterial.
                try put(ARM64Encoder.encodeConditionalSelect(rd: rd, rn: rn, rm: rn, condition: .eq, width64: width64))
                try put(ARM64Encoder.encodeTestBitBranch(nonzero: false, register: rd, bit: width64 ? 63 : 31,
                    from: address + code.count, to: address + code.count + (width64 ? 8 : 12)))
                try put(ARM64Encoder.encodeAddSubXShifted(subtract: true, rd: rd, rn: 31, rm: rd))
                if !width64 { try put(ARM64Encoder.encodeConditionalSelect(rd: rd, rn: rd, rm: rd, condition: .eq, width64: false)) }
            } else {
                // Select scratch registers absent from *all* operands. Darwin
                // reserves 128 bytes below SP; the saved pair sits below it.
                let scratch = [UInt32(16), 17, 15, 14].filter { $0 != rd && $0 != rn && $0 != rm }
                let flags = scratch[0], temporary = immediate != nil ? scratch[1] : scratch[0]
                try put(ARM64Encoder.encodeSubImm12(rd: 31, rn: 31, imm12: 144))
                let needsPair = immediate != nil
                try put(needsPair ? ARM64Encoder.encodeStpX(rt1: flags, rt2: temporary, rn: 31, offset: 0)
                    : ARM64Encoder.encodeStrXUnsignedOffset(rt: flags, rn: 31, offset: 0))
                if name == "cnt" {
                    // No flag-writing instructions are needed for popcount.
                    try put(ARM64Encoder.encodeMovX(rd: rd, rm: rn))
                    try put(ARM64Encoder.encodeMovzX(rd: flags, imm16: 0))
                    let loop = address + code.count
                    try put(ARM64Encoder.encodeCompareBranch(nonzero: false, register: rd,
                        from: loop, to: loop + 20, width64: width64))
                    try put(ARM64Encoder.encodeTestBitBranch(nonzero: false, register: rd, bit: 0,
                        from: loop + 4, to: loop + 12))
                    try put(ARM64Encoder.encodeAddImm12(rd: flags, rn: flags, imm12: 1))
                    try put(ARM64Encoder.encodeLogicalShiftRight(rd: rd, rn: rd, shift: 1, width64: width64))
                    try put(ARM64Encoder.encodeB(from: loop + 16, to: loop))
                    try put(ARM64Encoder.encodeMovX(rd: rd, rm: flags))
                } else {
                    try put(ARM64Encoder.encodeReadNZCV(rt: flags))
                    let second: UInt32
                    if let rm { second = rm }
                    else {
                        second = temporary
                        try loadImmediate(immediate!, into: second)
                    }
                    try put(ARM64Encoder.encodeCompareRegister(rn: rn, rm: second, width64: width64))
                    try put(ARM64Encoder.encodeConditionalSelect(rd: rd, rn: rn, rm: second, condition: condition, width64: width64))
                    try put(ARM64Encoder.encodeWriteNZCV(rt: flags))
                }
                try put(ARM64Encoder.encodeLdrXUnsignedOffset(rt: flags, rn: 31, offset: 0))
                if needsPair { try put(ARM64Encoder.encodeLdrXUnsignedOffset(rt: temporary, rn: 31, offset: 8)) }
                try put(ARM64Encoder.encodeAddImm12(rd: 31, rn: 31, imm12: 144))
            }
            try put(ARM64Encoder.encodeB(from: address + code.count, to: resume))
            return code
        }

    }

    final class Padding {
        private var ranges: [Range<Int>] = []
        private var requests: [Request] = []
        private var prepare: (() throws -> [Range<Int>])?

        private static func branchFits(from source: Int, to target: Int) -> Bool {
            let (delta, overflow) = target.subtractingReportingOverflow(source)
            return !overflow && delta & 3 == 0 && (-0x0800_0000 ... 0x07FF_FFFC).contains(delta)
        }

        init(ranges: [Range<Int>], read: @escaping (Int, Int) throws -> Data) throws {
            prepare = { try Self.zeroRanges(ranges, read: read) }
        }

        init(makeRanges: @escaping () throws -> [Range<Int>], read: @escaping (Int, Int) throws -> Data) {
            prepare = { try Self.zeroRanges(makeRanges(), read: read) }
        }

        private static func zeroRanges(_ ranges: [Range<Int>], read: (Int, Int) throws -> Data) throws -> [Range<Int>] {
            var zeros: [Range<Int>] = []
            var unique: [Range<Int>] = []
            for range in ranges.sorted(by: { $0.lowerBound < $1.lowerBound }) {
                if let previous = unique.last, range.lowerBound <= previous.upperBound {
                    unique[unique.count - 1] = previous.lowerBound ..< max(previous.upperBound, range.upperBound)
                } else { unique.append(range) }
            }
            for range in unique {
                guard range.count <= 1_048_576 else { continue }
                let start = (range.lowerBound + 3) & ~3, end = range.upperBound & ~3
                guard end > start else { continue }
                let bytes = try read(start, end - start)
                var run = start
                for address in stride(from: start, to: end, by: 4) {
                    if bytes.loadLE(UInt32.self, at: address - start) != 0 {
                        if address > run { zeros.append(run ..< address) }
                        run = address + 4
                    }
                }
                if end > run { zeros.append(run ..< end) }
            }
            return zeros
        }

        func append(_ requests: [Request]) { self.requests += requests }

        /// Plan the entire bootstrap closure before any image is changed. The
        /// original pool survives a failed plan, allowing a clean retry.
        func finish(log: (String) -> Void = { _ in }) throws -> [PatchRecord] {
            guard !requests.isEmpty else { return [] }
            if requests.contains(where: { Operation($0.instruction)?.rd != 31 }), let prepare {
                ranges = try prepare()
                self.prepare = nil
            }
            let original = ranges
            var planned = 0
            do {
                let ranked = try requests.map { request -> (request: Request, capacity: Int, size: Int) in
                    let operation = Operation(request.instruction)!
                    let size = try operation.thunk(at: 0, resume: 0, flagsDead: request.flagsDead).count
                    let site = Int(request.instruction.address)
                    let capacity = ranges.reduce(0) { total, range in
                        let start = max(range.lowerBound, site - 0x0800_0000)
                        let end = min(range.upperBound, site + 0x0800_0000)
                        return total + max(0, end - start) / size
                    }
                    return (request, capacity, size)
                }.sorted {
                    if $0.capacity != $1.capacity { return $0.capacity < $1.capacity }
                    if $0.size != $1.size { return $0.size > $1.size }
                    return $0.request.instruction.address < $1.request.instruction.address
                }
                let compact = ranked.filter { $0.request.flagsDead && Operation($0.request.instruction)?.canUseShortThunk == true }.count
                log("  [.] CSSC bootstrap: \(ranked.count) sites, \(compact) compact thunks, \(ranked.reduce(0) { $0 + $1.size }) thunk bytes; \(ranges.reduce(0) { $0 + $1.count }) padding bytes")
                func placeAll(preferRemote: Bool) throws -> [PatchRecord] {
                    planned = 0
                    var records: [PatchRecord] = []
                    // Keep contiguous local slots for compact code before
                    // relay pairs split those gaps into unusable fragments.
                    let order = preferRemote ? ranked.filter { $0.size <= 16 } + ranked.filter { $0.size > 16 } : ranked
                    for item in order {
                        records += try allocate(item.request, preferRemote: preferRemote)
                        planned += 1
                    }
                    return records
                }
                let records: [PatchRecord]
                do { records = try placeAll(preferRemote: false) }
                catch {
                    // A dense cluster can exhaust its local pool even with
                    // per-site retries. Replan from pristine space, placing
                    // larger thunks remotely while the bridges still exist.
                    ranges = original
                    log("  [.] CSSC bootstrap: retrying the complete plan with short thunks first and larger thunks remote")
                    records = try placeAll(preferRemote: true)
                }
                requests.removeAll()
                return records.sorted { $0.fileOffset < $1.fileOffset }
            } catch {
                log("  [!] CSSC bootstrap planning stopped after \(planned) of \(requests.count) sites; no cache writes applied")
                ranges = original
                throw error
            }
        }

        func lower(_ instruction: ARM64Instruction, identifier: String) throws -> [PatchRecord]? {
            guard Operation(instruction) != nil else { return nil }
            append([Request(instruction: instruction, identifier: identifier)])
            return try finish()
        }

        private func allocate(_ request: Request, preferRemote: Bool) throws -> [PatchRecord] {
            let instruction = request.instruction, identifier = request.identifier
            let operation = Operation(instruction)!
            let site = Int(instruction.address)
            let decoder = ARM64Disassembler()
            func record(_ address: Int, before: Data, after: Data) -> PatchRecord {
                let decoded = decoder.disassembleOne(after, at: UInt64(address))
                return PatchRecord(patchID: identifier + ".cssc.\(address)", component: "Mach-O", fileOffset: address,
                    originalBytes: before, patchedBytes: after, beforeDisasm: address == site
                        ? "\(instruction.mnemonic) \(instruction.operandString)" : "executable zero padding",
                    afterDisasm: "\(decoded?.mnemonic ?? "?") \(decoded?.operandString ?? "")",
                    description: request.flagsDead && operation.canUseShortThunk
                        ? "CSSC \(operation.name) fallback; incoming NZCV is dead before its next use"
                        : "CSSC \(operation.name) fallback; preserves NZCV, scratch registers and red zone")
            }
            if operation.rd == 31 { return [record(site, before: Data(instruction.bytes), after: ARM64.nop)] }
            let size = try operation.thunk(at: 0, resume: 0, flagsDead: request.flagsDead).count
            func reserve(_ address: Int, size: Int, in index: Int, pool: inout [Range<Int>]) {
                let range = pool.remove(at: index)
                if range.lowerBound < address { pool.append(range.lowerBound ..< address) }
                if address + size < range.upperBound { pool.append(address + size ..< range.upperBound) }
            }
            // A64 B reaches only 128 MiB. Large cached images can exhaust
            // local tails; four-byte branch relays reach more distant padding
            // without clobbering any register (including LR).
            func roundTrip(to target: Int) throws -> (entry: Data, tail: Data, records: [PatchRecord]) {
                var position = site, returnTarget = site + 4, relays: [Int] = []
                let tail = target + size - 4
                while !Self.branchFits(from: position, to: target) || !Self.branchFits(from: tail, to: returnTarget) {
                    var best: (index: Int, address: Int)?
                    let pool = ranges
                    for index in pool.indices where pool[index].count >= 8 {
                        let range = pool[index]
                        let address = target > position ? min(range.upperBound - 8, position + 0x07FF_FFFC)
                            : max(range.lowerBound, position - 0x07FF_FFFC)
                        guard range.contains(address), address + 8 <= range.upperBound,
                              abs(target - address) < abs(target - position),
                              Self.branchFits(from: position, to: address),
                              Self.branchFits(from: address + 4, to: returnTarget) else { continue }
                        if best == nil || abs(target - address) < abs(target - best!.address) { best = (index, address) }
                    }
                    guard let best else {
                        throw PatcherError.invalidFormat("CSSC round-trip relay from 0x\(String(position, radix: 16)) to 0x\(String(target, radix: 16)) has no reachable executable padding")
                    }
                    // Reserve entry/return words together. Independent routing
                    // can spend the final bridge on entry, then fail on return
                    // for every remaining remote candidate.
                    reserve(best.address, size: 8, in: best.index, pool: &ranges)
                    relays.append(best.address)
                    position = best.address
                    returnTarget = best.address + 4
                }
                var records: [PatchRecord] = []
                for (index, address) in relays.enumerated() {
                    records.append(record(address, before: Data(count: 4), after: ARM64Encoder.encodeB(from: address,
                        to: index + 1 < relays.count ? relays[index + 1] : target)!))
                    records.append(record(address + 4, before: Data(count: 4), after: ARM64Encoder.encodeB(from: address + 4,
                        to: index > 0 ? relays[index - 1] + 4 : site + 4)!))
                }
                return (ARM64Encoder.encodeB(from: site, to: relays.first ?? target)!,
                        ARM64Encoder.encodeB(from: tail, to: returnTarget)!, records)
            }
            // Prefer a complete direct round trip. Try both ends of every gap;
            // an unreachable nearest candidate must not consume the pool.
            // Disconnected cache regions cannot be reached even with relays.
            // Compute optimistic bounds once instead of trying every remote
            // gap and rediscovering the same missing bridge each time.
            let ordered = ranges.sorted { $0.lowerBound < $1.lowerBound }
            var upper = site + 0x07FF_FFFC, lower = site - 0x0800_0000
            for range in ordered where range.count >= 8 && range.upperBound > site {
                if range.lowerBound > upper { break }
                upper = max(upper, range.upperBound - 4 + 0x07FF_FFFC)
            }
            for range in ordered.reversed() where range.count >= 8 && range.lowerBound < site {
                if range.upperBound - 4 < lower { break }
                lower = min(lower, range.lowerBound - 0x0800_0000)
            }
            let candidates = ordered.filter { $0.count >= size }.flatMap { range in
                range.count == size ? [range.lowerBound] : [range.lowerBound, range.upperBound - size]
            }.filter { (lower ... upper).contains($0) }.map { address in
                (address: address, direct: Self.branchFits(from: site, to: address) &&
                    Self.branchFits(from: address + size - 4, to: site + 4), distance: abs(address - site))
            }.sorted {
                if $0.direct != $1.direct { return preferRemote && size > 16 ? !$0.direct : $0.direct }
                return $0.distance == $1.distance ? $0.address < $1.address : $0.distance < $1.distance
            }.map(\.address)
            var lastError: (any Error)?
            for address in candidates {
                let original = ranges
                do {
                    let index = ranges.firstIndex { $0.contains(address) && address + size <= $0.upperBound }!
                    reserve(address, size: size, in: index, pool: &ranges)
                    let trip = try roundTrip(to: address)
                    var code = try operation.thunk(at: address, resume: address + size, flagsDead: request.flagsDead)
                    code.replaceSubrange(size - 4 ..< size, with: trip.tail)
                    return [record(site, before: Data(instruction.bytes), after: trip.entry)] + trip.records
                        + stride(from: 0, to: code.count, by: 4).map {
                            record(address + $0, before: Data(count: 4), after: code.subdata(in: $0 ..< $0 + 4))
                        }
                } catch {
                    ranges = original
                    lastError = error
                }
            }
            let local = ranges.reduce(0) { total, range in
                total + max(0, min(range.upperBound, site + 0x0800_0000) - max(range.lowerBound, site - 0x0800_0000))
            }
            throw PatcherError.invalidFormat("CSSC \(operation.name) at 0x\(String(site, radix: 16)) cannot place a \(size)-byte fallback (\(local) local padding bytes remain). \(lastError.map { String(describing: $0) } ?? "No contiguous candidate fits.")")
        }
    }

    /// The cache packs images on 4 KiB boundaries. Only consider a short
    /// alignment tail bounded by the next image, never arbitrary mapping gaps.
    static func cacheAlignmentPadding(between segments: [Range<Int>]) -> [Range<Int>] {
        var end: Int?, gaps: [Range<Int>] = []
        for segment in segments.sorted(by: { $0.lowerBound < $1.lowerBound }) {
            if let previous = end, previous < segment.lowerBound,
               previous <= Int.max - 0xFFF,
               (previous + 0xFFF) & ~0xFFF == segment.lowerBound {
                gaps.append(previous ..< segment.lowerBound)
            }
            end = max(end ?? segment.upperBound, segment.upperBound)
        }
        return gaps
    }

    /// Coordinates are file offsets for a standalone image and VMAs in a cache.
    static func padding(in header: Data, cachedAt imageAddress: Int? = nil) throws -> [Range<Int>] {
        guard header.count >= 32 else { throw PatcherError.invalidFormat("truncated CSSC Mach-O header") }
        let end = 32 + Int(header.loadLE(UInt32.self, at: 20))
        guard end <= header.count else { throw PatcherError.invalidFormat("truncated CSSC load commands") }
        // launchd gains an injected load command later in CFW installation.
        // Reserve standalone header expansion space. Cache headers do not grow.
        let firstSection = MachOParser.parseSections(from: header).values.map { Int($0.fileOffset) }
            .filter { $0 >= end }.min() ?? end
        let headerEnd = imageAddress != nil ? end : firstSection
        var reserved: [Range<Int>] = []
        if imageAddress == nil {
            var commandOffset = 32
            let dataCommands: Set<UInt32> = [0x1D, 0x1E, 0x26, 0x29, 0x2B, 0x2E, 0x80000033, 0x80000034]
            for _ in 0 ..< header.loadLE(UInt32.self, at: 16) {
                guard commandOffset + 8 <= end else { throw PatcherError.invalidFormat("invalid CSSC metadata command") }
                let command = header.loadLE(UInt32.self, at: commandOffset)
                let size = Int(header.loadLE(UInt32.self, at: commandOffset + 4))
                guard size >= 8, size <= end - commandOffset else { throw PatcherError.invalidFormat("invalid CSSC metadata size") }
                func protect(_ offset: Int, _ length: Int) { if length > 0 { reserved.append(offset ..< offset + length) } }
                if dataCommands.contains(command), size >= 16 {
                    protect(Int(header.loadLE(UInt32.self, at: commandOffset + 8)), Int(header.loadLE(UInt32.self, at: commandOffset + 12)))
                } else if command == 2, size >= 24 { // LC_SYMTAB
                    protect(Int(header.loadLE(UInt32.self, at: commandOffset + 8)), Int(header.loadLE(UInt32.self, at: commandOffset + 12)) * 16)
                    protect(Int(header.loadLE(UInt32.self, at: commandOffset + 16)), Int(header.loadLE(UInt32.self, at: commandOffset + 20)))
                } else if [0x22, 0x80000022].contains(command), size >= 48 { // LC_DYLD_INFO[_ONLY]
                    for field in stride(from: 8, through: 40, by: 8) {
                        protect(Int(header.loadLE(UInt32.self, at: commandOffset + field)), Int(header.loadLE(UInt32.self, at: commandOffset + field + 4)))
                    }
                }
                commandOffset += size
            }
        }
        var position = 32, gaps: [Range<Int>] = []
        for _ in 0 ..< header.loadLE(UInt32.self, at: 16) {
            guard position + 8 <= end else { throw PatcherError.invalidFormat("invalid CSSC load command") }
            let command = header.loadLE(UInt32.self, at: position)
            let size = Int(header.loadLE(UInt32.self, at: position + 4))
            guard size >= 8, size <= end - position else { throw PatcherError.invalidFormat("invalid CSSC command size") }
            defer { position += size }
            guard command == 0x19, size >= 72, header.loadLE(UInt32.self, at: position + 60) & 4 != 0 else { continue }
            let base64 = header.loadLE(UInt64.self, at: position + (imageAddress == nil ? 40 : 24))
            let length64 = header.loadLE(UInt64.self, at: position + 48)
            guard let base = Int(exactly: base64), let length = Int(exactly: length64),
                  length <= Int.max - base else { throw PatcherError.invalidFormat("CSSC segment overflow") }
            let segment = base ..< base + length
            var occupied = reserved
            let headerStart = imageAddress ?? 0
            occupied.append(headerStart ..< headerStart + headerEnd)
            let count = Int(header.loadLE(UInt32.self, at: position + 64))
            guard count <= (size - 72) / 80 else { throw PatcherError.invalidFormat("invalid CSSC section table") }
            for section in 0 ..< count {
                let offset = position + 72 + section * 80
                let start64 = imageAddress == nil ? UInt64(header.loadLE(UInt32.self, at: offset + 48))
                    : header.loadLE(UInt64.self, at: offset + 32)
                let size64 = header.loadLE(UInt64.self, at: offset + 40)
                guard let start = Int(exactly: start64), let size = Int(exactly: size64), size <= Int.max - start
                else { throw PatcherError.invalidFormat("CSSC section overflow") }
                if size > 0 { occupied.append(start ..< start + size) }
            }
            var cursor = segment.lowerBound
            for used in occupied.sorted(by: { $0.lowerBound < $1.lowerBound }) where used.overlaps(segment) {
                let start = max(segment.lowerBound, used.lowerBound)
                if cursor < start { gaps.append(cursor ..< start) }
                cursor = max(cursor, min(segment.upperBound, used.upperBound))
            }
            if cursor < segment.upperBound { gaps.append(cursor ..< segment.upperBound) }
        }
        return gaps
    }
}

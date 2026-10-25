// Static ARM64E_X1 lowering for the pre-handler and fork-sensitive boot closure.

import Foundation
import MachO
import VPhonePatchKit

public enum CustomFirmwareArm64eX1 {
    public struct Result {
        public let records: [PatchRecord]
        public let unvisitedCandidates: Int
        public let unvisitedExamples: [Int]

        init(records: [PatchRecord], unvisitedCandidates: Int, unvisitedExamples: [Int] = []) {
            self.records = records; self.unvisitedCandidates = unvisitedCandidates; self.unvisitedExamples = unvisitedExamples
        }
    }

    private static let loweredMnemonics: Set<String> = [
        "pacibsppc", "paciasppc", "pacnbibsppc", "pacnbiasppc",
        "autibsppc", "autiasppc", "autibsppcr", "autiasppcr",
        "retabsppc", "retaasppc", "retabsppcr", "retaasppcr", "addpt", "subpt", "maddpt", "msubpt",
        "autia171615", "autib171615",
    ]

    public static func lower(_ data: inout Data) throws -> Result {
        try lower(&data, identifier: FirmwareGuestSystemPatchSet.arm64eX1DyldBootstrap)
    }

    public static func lower(_ data: inout Data, identifier: String) throws -> Result {
        if isUniversal(data) { return try lowerUniversal(&data, identifier: identifier, reattest: false).result }
        guard data.count >= 32, data.loadLE(UInt32.self, at: 0) == 0xFEED_FACF,
              data.loadLE(UInt32.self, at: 4) == 0x0100_000C,
              data.loadLE(UInt32.self, at: 8) & 0x00FF_FFFF == 12,
              data.loadLE(UInt32.self, at: 12) != UInt32(MH_KEXT_BUNDLE)
        else { return Result(records: [], unvisitedCandidates: 0) }
        let segments = MachOParser.parseSegments(from: data)
        let sections = MachOParser.parseSections(from: data).values.filter {
            $0.size > 0 && ($0.sectionName == "__text" || $0.flags & 0x8000_0400 != 0)
        }
        guard !sections.isEmpty else { return Result(records: [], unvisitedCandidates: 0) }
        var (seeds, excluded) = try entryPoints(data, segments: segments)
        func fileOffset(_ address: UInt64, length: Int) throws -> Int {
            guard let segment = segments.first(where: {
                address >= $0.vmAddr && address - $0.vmAddr <= $0.fileSize &&
                UInt64(length) <= $0.fileSize - (address - $0.vmAddr)
            }), let offset = Int(exactly: segment.fileOffset + address - segment.vmAddr),
                  offset <= data.count, length <= data.count - offset else {
                throw PatcherError.invalidFormat("X1 exception metadata outside Mach-O")
            }
            return offset
        }
        if let text = segments.first(where: { $0.name == "__TEXT" }) {
            let exceptionVMAs = try exceptionEntries(sections: Array(MachOParser.parseSections(from: data).values),
                imageBase: text.vmAddr, readMemory: { address, length in
                    let offset = try fileOffset(address, length: length)
                    return data.subdata(in: offset ..< offset + length)
                })
            seeds += try exceptionVMAs.map { try fileOffset($0, length: 4) }
        }
        guard !seeds.isEmpty else {
            throw PatcherError.invalidFormat("X1 lowering requires function starts and executable text")
        }
        var ranges: [(address: Int, data: Data)] = []
        for section in sections {
            guard let start = Int(exactly: section.fileOffset),
                  let size = Int(exactly: section.size),
                  start <= data.count, size <= data.count - start else {
                throw PatcherError.invalidFormat("X1 text outside Mach-O")
            }
            ranges.append((start, data.subdata(in: start ..< start + size)))
        }
        let original = data
        let cssc = try CustomFirmwareCSSC.Padding(ranges: CustomFirmwareCSSC.padding(in: data)) { address, length in
            guard address >= 0, address <= original.count, length <= original.count - address else {
                throw PatcherError.invalidFormat("CSSC padding outside Mach-O")
            }
            return original.subdata(in: address ..< address + length)
        }
        let planned = try planCode(ranges: ranges, seeds: seeds, excluded: excluded,
                                  identifier: identifier, cssc: cssc, readMemory: { address, length in
            guard address <= original.count, length <= original.count - address else {
                throw PatcherError.invalidFormat("X1 switch table outside image")
            }
            return original.subdata(in: address ..< address + length)
        })
        let records = (planned.records + (try cssc.finish())).sorted { $0.fileOffset < $1.fileOffset }
        let result = Result(records: records, unvisitedCandidates: planned.unvisitedCandidates,
                            unvisitedExamples: planned.unvisitedExamples)
        for record in result.records { data.replaceSubrange(record.fileOffset ..< record.fileOffset + 4, with: record.patchedBytes) }
        return result
    }

    static func planCode(ranges: [(address: Int, data: Data)], seeds: [Int], excluded: [Range<Int>], identifier: String,
                         cssc: CustomFirmwareCSSC.Padding? = nil,
                         readMemory: ((Int, Int) throws -> Data)? = nil,
                         authenticatedPointer: ((UInt64, UInt16) throws -> UInt64?)? = nil) throws -> Result {
        let decoder = ARM64Disassembler()
        var dataRanges = excluded
        var candidates: [Int] = [], frameEntries: [Int] = []
        // Recover coalesced entries from return-PAC plus an SP frame setup.
        for range in ranges {
            for block in stride(from: 0, to: range.data.count, by: 0x4000) {
                let end = min(range.data.count, block + 0x4004)
                let decoded = decoder.disassemble(range.data.subdata(in: block ..< end), at: UInt64(range.address + block))
                for (index, item) in decoded.enumerated() where item.address < UInt64(range.address + block + 0x4000) {
                    let address = Int(item.address)
                    guard !excluded.contains(where: { $0.contains(address) }) else { continue }
                    if loweredMnemonics.contains(item.mnemonic) || CustomFirmwareCSSC.Operation(item) != nil {
                        candidates.append(address)
                    }
                    if ["pacibsppc", "paciasppc", "pacnbibsppc", "pacnbiasppc", "pacibsp", "paciasp"].contains(item.mnemonic), index + 1 < decoded.count {
                        let next = decoded[index + 1], ops = next.detail?.operands ?? []
                        let savesFrame = ["stp", "str"].contains(next.mnemonic) && ops.last?.type == .memory && ops.last?.mem.base == .sp
                        let allocatesFrame = next.mnemonic == "sub" && ops.count == 3 && ops[0].reg == .sp && ops[1].reg == .sp && ops[2].type == .immediate
                        if savesFrame || allocatesFrame { frameEntries.append(address) }
                    }
                }
            }
        }
        var decodedPage: [ARM64Instruction] = [], pageAddress = -1
        var pages: [Int: [ARM64Instruction]] = [:], pageUses: [Int: Int] = [:], tick = 0
        func decodedInstruction(at address: Int) -> ARM64Instruction? {
            guard !dataRanges.contains(where: { $0.contains(address) }),
                  let range = ranges.first(where: { address >= $0.address && address < $0.address + $0.data.count }) else { return nil }
            let relative = address - range.address
            let block = relative / 0x4000 * 0x4000
            if pageAddress != range.address + block {
                pageAddress = range.address + block
                tick += 1
                pageUses[pageAddress] = tick
                if let cached = pages[pageAddress] {
                    decodedPage = cached
                } else {
                    let end = min(range.data.count, block + 0x4000)
                    decodedPage = decoder.disassemble(range.data.subdata(in: block ..< end), at: UInt64(pageAddress))
                    if pages.count >= 16, let oldest = pageUses.filter({ $0.key != pageAddress }).min(by: { $0.value < $1.value })?.key {
                        pages.removeValue(forKey: oldest)
                        pageUses.removeValue(forKey: oldest)
                    }
                    pages[pageAddress] = decodedPage
                }
            }
            let index = (address - pageAddress) / 4
            guard address & 3 == 0, index < decodedPage.count,
                  decodedPage[index].address == UInt64(address) else { return nil }
            return decodedPage[index]
        }
        var scheduled = Set(seeds + frameEntries)
        var pending = scheduled.sorted(by: >), visited = Set<Int>()
        func schedule(_ address: Int) {
            if !visited.contains(address), scheduled.insert(address).inserted {
                pending.append(address)
            }
        }
        var records: [PatchRecord] = []
        var csscRequests: [CustomFirmwareCSSC.Request] = []
        while let entry = pending.popLast() {
            var offset = entry
            while visited.insert(offset).inserted, let instruction = decodedInstruction(at: offset), instruction.isDecoded, instruction.size == 4 {
                if CustomFirmwareCSSC.Operation(instruction) != nil {
                    guard cssc != nil else { throw PatcherError.invalidFormat("CSSC startup instruction requires executable padding") }
                    csscRequests.append(.init(instruction: instruction, identifier: identifier,
                        flagsDead: CustomFirmwareCSSC.flagsAreDead(after: offset, instructionAt: decodedInstruction(at:))))
                } else if let replacement = try replacement(for: instruction) {
                    let after = decoder.disassembleOne(replacement, at: instruction.address)
                    records.append(PatchRecord(patchID: identifier + ".\(offset)", component: "Mach-O", fileOffset: offset,
                        originalBytes: Data(instruction.bytes), patchedBytes: replacement,
                        beforeDisasm: "\(instruction.mnemonic) \(instruction.operandString)",
                        afterDisasm: "\(after?.mnemonic ?? "?") \(after?.operandString ?? "")",
                        description: "X1 compatibility lowering; PC PAC/CPA checks reduced"))
                }
                let mnemonic = instruction.mnemonic
                if mnemonic == "br", let readMemory,
                   let table = try switchTable(at: offset, instructionAt: decodedInstruction(at:), readMemory: readMemory) {
                    dataRanges.append(table.data)
                    for target in table.targets { schedule(target) }
                }
                if mnemonic == "braa", let authenticatedPointer,
                   let table = try authenticatedDispatch(at: offset, instructionAt: decodedInstruction(at:),
                                                         pointer: authenticatedPointer) {
                    dataRanges.append(table.data)
                    for target in table.targets {
                        guard decodedInstruction(at: target)?.isDecoded == true else {
                            throw PatcherError.invalidFormat("authenticated X1 dispatch target outside executable code")
                        }
                        schedule(target)
                    }
                }
                if mnemonic == "b" || mnemonic == "bl" || mnemonic.hasPrefix("b.") || ["cbz", "cbnz", "tbz", "tbnz"].contains(mnemonic) {
                    if let target = instruction.detail?.operands.last, target.type == .immediate,
                       let destination = Int(exactly: target.imm) {
                        schedule(destination)
                    }
                    if mnemonic == "b" { break }
                }
                if instruction.isReturn || mnemonic.hasPrefix("ret") ||
                    ["br", "braa", "brab", "braaz", "brabz", "brk", "hlt", "udf"].contains(mnemonic) { break }
                offset += 4
            }
        }
        records.removeAll { record in dataRanges.contains(where: { $0.contains(record.fileOffset) }) }
        cssc?.append(csscRequests.filter { request in
            !dataRanges.contains(where: { $0.contains(Int(request.instruction.address)) })
        })
        let unvisited = candidates.filter { address in !visited.contains(address) && !dataRanges.contains(where: { $0.contains(address) }) }
        records.sort { $0.fileOffset < $1.fileOffset }
        return Result(records: records, unvisitedCandidates: unvisited.count, unvisitedExamples: Array(unvisited.prefix(16)))
    }

    static func exceptionEntries(sections: [MachOSectionInfo], imageBase: UInt64,
                                 readMemory: (UInt64, Int) throws -> Data) throws -> [UInt64] {
        guard let unwind = sections.first(where: { $0.sectionName == "__unwind_info" && $0.size > 0 }) else { return [] }
        let bytes = try readMemory(unwind.address, Int(unwind.size))
        guard bytes.count >= 28, bytes.loadLE(UInt32.self, at: 0) == 1 else {
            throw PatcherError.invalidFormat("invalid X1 compact unwind header")
        }
        let index = Int(bytes.loadLE(UInt32.self, at: 20)), count = Int(bytes.loadLE(UInt32.self, at: 24))
        guard index <= bytes.count, count <= (bytes.count - index) / 12 else {
            throw PatcherError.invalidFormat("X1 unwind index outside section")
        }
        guard count > 1 else { return [] }
        var entries: [(function: UInt64, lsda: UInt64)] = []
        for page in 0 ..< count - 1 {
            let start = Int(bytes.loadLE(UInt32.self, at: index + page * 12 + 8))
            let end = Int(bytes.loadLE(UInt32.self, at: index + (page + 1) * 12 + 8))
            guard start <= end, end <= bytes.count, (end - start) % 8 == 0 else {
                throw PatcherError.invalidFormat("invalid X1 LSDA index range")
            }
            for offset in stride(from: start, to: end, by: 8) {
                let (function, fOverflow) = imageBase.addingReportingOverflow(UInt64(bytes.loadLE(UInt32.self, at: offset)))
                let (lsda, lOverflow) = imageBase.addingReportingOverflow(UInt64(bytes.loadLE(UInt32.self, at: offset + 4)))
                guard !fOverflow, !lOverflow else { throw PatcherError.invalidFormat("X1 LSDA address overflow") }
                entries.append((function, lsda))
            }
        }
        guard !entries.isEmpty else { return [] }
        let executable = sections.filter { $0.sectionName == "__text" || $0.flags & 0x8000_0400 != 0 }
        let addresses = Set(entries.map(\.lsda)).sorted()
        let following = Dictionary(uniqueKeysWithValues: zip(addresses, addresses.dropFirst()))
        var result = Set<UInt64>()
        for entry in entries {
            guard let section = sections.first(where: {
                $0.sectionName == "__gcc_except_tab" && entry.lsda >= $0.address && entry.lsda - $0.address < $0.size
            }) else { throw PatcherError.invalidFormat("X1 LSDA outside exception section") }
            let remaining = Int(section.size - (entry.lsda - section.address))
            let next = following[entry.lsda]
            let length = min(remaining, next.map { Int($0 - entry.lsda) } ?? remaining)
            let lsda = try readMemory(entry.lsda, length)
            var cursor = 0
            func byte() throws -> UInt8 {
                guard cursor < lsda.count else { throw PatcherError.invalidFormat("truncated X1 LSDA") }
                defer { cursor += 1 }
                return lsda[cursor]
            }
            func uleb() throws -> UInt64 {
                var value: UInt64 = 0, shift: UInt64 = 0
                while true {
                    let part = try byte()
                    guard shift < 64, shift < 63 || part & 0x7F <= 1 else { throw PatcherError.invalidFormat("X1 LSDA ULEB overflow") }
                    value |= UInt64(part & 0x7F) << shift
                    if part & 0x80 == 0 { return value }
                    shift += 7
                }
            }
            // Apple AArch64 LSDAs use the function start and ULEB call-site offsets.
            guard try byte() == 0xFF else { throw PatcherError.invalidFormat("unsupported X1 LSDA landing base") }
            if try byte() != 0xFF { _ = try uleb() }
            guard try byte() == 1 else { throw PatcherError.invalidFormat("unsupported X1 LSDA call-site encoding") }
            let tableLength = try uleb()
            guard tableLength <= lsda.count - cursor else { throw PatcherError.invalidFormat("X1 LSDA call-site table outside section") }
            let end = cursor + Int(tableLength)
            while cursor < end {
                _ = try uleb() // protected start
                _ = try uleb() // protected length
                let landing = try uleb()
                _ = try uleb() // action-table index
                guard cursor <= end else { throw PatcherError.invalidFormat("X1 LSDA call-site entry crosses table") }
                if landing != 0 {
                    let (target, overflow) = entry.function.addingReportingOverflow(landing)
                    guard !overflow, target & 3 == 0, executable.contains(where: {
                        target >= $0.address && target - $0.address < $0.size
                    }) else { throw PatcherError.invalidFormat("X1 exception landing outside executable section") }
                    result.insert(target)
                }
            }
        }
        return result.sorted()
    }

    private static func authenticatedDispatch(at branch: Int, instructionAt: (Int) -> ARM64Instruction?,
                                              pointer: (UInt64, UInt16) throws -> UInt64?) throws -> (targets: [Int], data: Range<Int>)? {
        guard let jump = instructionAt(branch), jump.mnemonic == "braa",
              let j = jump.detail?.operands, j.count == 2,
              let modifier = instructionAt(branch - 4), modifier.mnemonic == "mov",
              let m = modifier.detail?.operands, m.count == 2, m[0].reg == j[1].reg,
              m[1].type == .immediate, (0 ... 65535).contains(m[1].imm) else { return nil }
        func aliases(_ lhs: ARM64Register, _ rhs: ARM64Register) -> Bool {
            if lhs == rhs { return true }
            return (0 ... 30).contains { (lhs == .x($0) && rhs == .w($0)) || (lhs == .w($0) && rhs == .x($0)) }
        }
        func writes(_ instruction: ARM64Instruction, _ register: ARM64Register) -> Bool {
            let ops = instruction.detail?.operands ?? []
            return ops.contains { $0.type == .register && $0.writesRegister && aliases($0.reg, register) }
                || (instruction.detail?.writeback == true && ops.contains { $0.type == .memory && aliases($0.mem.base, register) })
        }
        var loadAddress = branch - 8
        if let extra = instructionAt(loadAddress), ["mov", "ldr"].contains(extra.mnemonic),
           !writes(extra, j[0].reg), !writes(extra, j[1].reg) {
            loadAddress -= 4
        }
        guard let load = instructionAt(loadAddress), load.mnemonic == "ldr",
              let l = load.detail?.operands, l.count == 2, l[0].reg == j[0].reg,
              l[1].type == .memory, l[1].shift.type == .lsl, l[1].shift.amount == 3,
              l[1].mem.disp == 0, !aliases(l[1].mem.base, l[1].mem.index) else { return nil }
        var hasByteTag = false
        for distance in 1 ... 4 {
            guard let instruction = instructionAt(loadAddress - distance * 4) else { break }
            let o = instruction.detail?.operands ?? []
            if instruction.mnemonic == "lsr", o.count == 2, o[0].reg == l[1].mem.index,
               o[1].type == .register, o[1].shift.type == .lsr, o[1].shift.amount == 56 {
                hasByteTag = true
                break
            }
            if writes(instruction, l[1].mem.index) || instruction.isCall || instruction.isJump || instruction.isReturn { break }
        }
        guard hasByteTag else { return nil }
        var table: UInt64?
        let base = l[1].mem.base
        let calleeSaved = (19 ... 28).contains { base == .x($0) }
        for distance in 1 ... 64 {
            let address = loadAddress - distance * 4
            guard let instruction = instructionAt(address) else { break }
            if instruction.isReturn || ["brk", "hlt", "udf"].contains(instruction.mnemonic) { break }
            if instruction.isCall && !calleeSaved { break }
            guard writes(instruction, base) else { continue }
            let o = instruction.detail?.operands ?? []
            guard instruction.mnemonic == "add", o.count == 3, o[0].reg == base, o[1].reg == base,
                  o[2].type == .immediate, o[2].imm >= 0, o[2].shift.amount == 0,
                  let page = instructionAt(address - 4), page.mnemonic == "adrp",
                  let p = page.detail?.operands, p.count == 2, p[0].reg == base, p[1].type == .immediate else { break }
            let (value, overflow) = p[1].imm.addingReportingOverflow(o[2].imm)
            if !overflow { table = UInt64(exactly: value) }
            break
        }
        guard let table, table & 7 == 0 else { return nil }
        var targets: [Int] = []
        for index in 0 ..< 256 {
            let (entry, overflow) = table.addingReportingOverflow(UInt64(index * 8))
            guard !overflow else { throw PatcherError.invalidFormat("X1 dispatch table overflow") }
            guard let target = try pointer(entry, UInt16(m[1].imm)) else { break }
            guard target & 3 == 0, let target = Int(exactly: target) else {
                throw PatcherError.invalidFormat("invalid authenticated X1 dispatch target")
            }
            targets.append(target)
        }
        guard targets.count >= 2, let start = Int(exactly: table), start <= Int.max - targets.count * 8 else { return nil }
        return (targets, start ..< start + targets.count * 8)
    }

    private static func switchTable(at branch: Int, instructionAt: (Int) -> ARM64Instruction?,
                                    readMemory: (Int, Int) throws -> Data) throws -> (targets: [Int], data: Range<Int>)? {
        let window = (0 ... 7).compactMap { instructionAt(branch - (7 - $0) * 4) }
        guard window.count == 8 else { return nil }
        let c = window.map { $0.detail?.operands ?? [] }
        guard window[7].mnemonic == "br", c[7].count == 1,
              window[6].mnemonic == "add", c[6].count == 3,
              c[6][0].reg == c[7][0].reg,
              window[5].mnemonic == "adr", c[5].count == 2,
              c[5][0].reg == c[6][1].reg, c[5][1].type == .immediate,
              window[4].mnemonic == "ldrsw", c[4].count == 2,
              c[4][0].reg == c[6][2].reg, c[4][1].type == .memory,
              c[4][1].shift.type == .lsl, c[4][1].shift.amount == 2,
              window[3].mnemonic == "add", c[3].count == 3,
              c[3][0].reg == c[4][1].mem.base, c[3][1].reg == c[3][0].reg,
              c[3][2].type == .immediate, c[3][2].shift.amount == 0,
              window[2].mnemonic == "adrp", c[2].count == 2,
              c[2][0].reg == c[3][0].reg, c[2][1].type == .immediate,
              window[1].mnemonic == "csel", window[1].detail?.conditionCode == .ls, c[1].count == 3,
              c[1][0].reg == c[4][1].mem.index, c[1][1].reg == c[1][0].reg, c[1][2].reg == .xzr,
              window[0].mnemonic == "cmp", c[0].count == 2, c[0][0].reg == c[1][0].reg,
              c[0][1].type == .immediate, c[0][1].imm >= 0, c[0][1].imm < 4096
        else { return nil }
        let (tableAddress, overflow) = c[2][1].imm.addingReportingOverflow(c[3][2].imm)
        guard !overflow, let table = Int(exactly: tableAddress), table >= 0,
              let base = Int(exactly: c[5][1].imm) else { return nil }
        let count = Int(c[0][1].imm) + 1
        let bytes = try readMemory(table, count * 4)
        guard bytes.count == count * 4 else { throw PatcherError.invalidFormat("truncated X1 switch table") }
        var targets: [Int] = []
        for index in 0 ..< count {
            let (target, overflow) = base.addingReportingOverflow(Int(bytes.loadLE(Int32.self, at: index * 4)))
            guard !overflow, target & 3 == 0, !(table ..< table + count * 4).contains(target), instructionAt(target) != nil else {
                throw PatcherError.invalidFormat("invalid X1 switch destination at \(branch)")
            }
            targets.append(target)
        }
        return (targets, table ..< table + count * 4)
    }

    public static func lowerAndReattest(_ data: inout Data, identifier: String) throws -> (result: Result, slots: [CustomFirmwareSlotRehash]) {
        if isUniversal(data) { return try lowerUniversal(&data, identifier: identifier, reattest: true) }
        var patched = data
        let result = try lower(&patched, identifier: identifier)
        guard !result.records.isEmpty else { return (result, []) }
        guard let directories = CustomFirmwareMachOCodeSignature.codeDirectories(in: patched), !directories.isEmpty,
              directories.allSatisfy({ directory in
                  directory.hashType == 2 && directory.hashSize == 32 && result.records.allSatisfy { record in
                      directory.slotRange(record.fileOffset / directory.pageSize)?.contains(record.fileOffset + 3) == true
                  }
              }) else {
            throw PatcherError.invalidFormat("X1 instruction edits require complete SHA-256 signature coverage")
        }
        let slots = try CustomFirmwareMachOCodeSignature.reattest(&patched, modifiedOffsets: result.records.map(\.fileOffset))
        data = patched
        return (result, slots)
    }

    private static func isUniversal(_ data: Data) -> Bool {
        data.count >= 8 && [UInt32(0xBEBA_FECA), 0xBFBA_FECA].contains(data.loadLE(UInt32.self, at: 0))
    }

    private static func lowerUniversal(_ data: inout Data, identifier: String, reattest: Bool) throws -> (result: Result, slots: [CustomFirmwareSlotRehash]) {
        let wide = data.loadLE(UInt32.self, at: 0) == 0xBFBA_FECA
        let stride = wide ? 32 : 20
        let count = Int(UInt32(bigEndian: data.loadLE(UInt32.self, at: 4)))
        guard count > 0, count <= (data.count - 8) / stride else {
            throw PatcherError.invalidFormat("truncated X1 universal architecture table")
        }
        var slices: [Range<Int>] = [], selected: [Range<Int>] = []
        for index in 0 ..< count {
            let entry = 8 + index * stride
            let cpu = UInt32(bigEndian: data.loadLE(UInt32.self, at: entry))
            let subtype = UInt32(bigEndian: data.loadLE(UInt32.self, at: entry + 4))
            let offset = wide ? UInt64(bigEndian: data.loadLE(UInt64.self, at: entry + 8))
                : UInt64(UInt32(bigEndian: data.loadLE(UInt32.self, at: entry + 8)))
            let size = wide ? UInt64(bigEndian: data.loadLE(UInt64.self, at: entry + 16))
                : UInt64(UInt32(bigEndian: data.loadLE(UInt32.self, at: entry + 12)))
            guard let start = Int(exactly: offset), let length = Int(exactly: size),
                  start >= 8 + count * stride, length >= 32, start <= data.count, length <= data.count - start else {
                throw PatcherError.invalidFormat("X1 universal slice outside container")
            }
            let range = start ..< start + length
            guard !slices.contains(where: { $0.overlaps(range) }) else {
                throw PatcherError.invalidFormat("overlapping X1 universal slices")
            }
            slices.append(range)
            guard cpu == 0x0100_000C, subtype & 0x00FF_FFFF == 12 else { continue }
            guard data.loadLE(UInt32.self, at: start) == 0xFEED_FACF,
                  data.loadLE(UInt32.self, at: start + 4) == cpu,
                  data.loadLE(UInt32.self, at: start + 8) == subtype else {
                throw PatcherError.invalidFormat("X1 universal architecture disagrees with slice header")
            }
            selected.append(range)
        }
        var patched = data, records: [PatchRecord] = [], slots: [CustomFirmwareSlotRehash] = [], examples: [Int] = []
        var unvisited = 0
        for range in selected {
            var slice = data.subdata(in: range)
            let result: Result
            let hashes: [CustomFirmwareSlotRehash]
            let id = identifier + ".slice\(range.lowerBound)"
            if reattest {
                (result, hashes) = try lowerAndReattest(&slice, identifier: id)
            } else {
                result = try lower(&slice, identifier: id)
                hashes = []
            }
            let base = range.lowerBound
            records += result.records.map {
                PatchRecord(patchID: $0.patchID, component: $0.component, fileOffset: base + $0.fileOffset,
                    virtualAddress: $0.virtualAddress, originalBytes: $0.originalBytes, patchedBytes: $0.patchedBytes,
                    beforeDisasm: $0.beforeDisasm, afterDisasm: $0.afterDisasm, description: $0.patchDescription)
            }
            slots += hashes.map {
                CustomFirmwareSlotRehash(codeDirectoryOffset: base + $0.codeDirectoryOffset, slotType: $0.slotType,
                    pageIndex: $0.pageIndex, pageStart: base + $0.pageStart, pageEnd: base + $0.pageEnd,
                    hashFileOffset: base + $0.hashFileOffset, before: $0.before, after: $0.after, pageSize: $0.pageSize)
            }
            unvisited += result.unvisitedCandidates
            examples += result.unvisitedExamples.map { base + $0 }
            patched.replaceSubrange(range, with: slice)
        }
        data = patched
        return (Result(records: records.sorted { $0.fileOffset < $1.fileOffset }, unvisitedCandidates: unvisited,
                       unvisitedExamples: Array(examples.prefix(16))), slots)
    }

    public static func patch(fileAt url: URL, log: (String) -> Void = { print($0) }) throws {
        try patch(fileAt: url, identifier: FirmwareGuestSystemPatchSet.arm64eX1DyldBootstrap, log: log)
    }

    public static func patch(fileAt url: URL, identifier: String, log: (String) -> Void = { print($0) }) throws {
        var data = try Data(contentsOf: url)
        let (result, slots) = try lowerAndReattest(&data, identifier: identifier)
        guard !result.records.isEmpty else {
            log("  [·] X1: no reachable instructions to lower (unvisited candidates: \(result.unvisitedCandidates))")
            return
        }
        try data.write(to: url)
        for record in result.records { log(record.description) }
        log("  [+] X1: lowered \(result.records.count) instructions, re-attested \(slots.count) slots; unvisited candidates: \(result.unvisitedCandidates)")
    }

    private static func replacement(for instruction: ARM64Instruction) throws -> Data? {
        do {
            return try VPhoneArm64eX1Lowering.replacement(for: instruction)
        } catch {
            throw PatcherError.invalidFormat(String(describing: error))
        }
    }

    private static func entryPoints(_ data: Data, segments: [MachOSegmentInfo]) throws -> ([Int], [Range<Int>]) {
        guard let text = segments.first(where: { $0.name == "__TEXT" }) else {
            throw PatcherError.invalidFormat("X1 image has no __TEXT")
        }
        let count = Int(data.loadLE(UInt32.self, at: 16))
        var position = 32, seeds: [Int] = [], excluded: [Range<Int>] = []
        for _ in 0 ..< count {
            guard position <= data.count - 8 else { throw PatcherError.invalidFormat("truncated X1 load commands") }
            let command = data.loadLE(UInt32.self, at: position), size = Int(data.loadLE(UInt32.self, at: position + 4))
            guard size >= 8, size <= data.count - position else { throw PatcherError.invalidFormat("invalid X1 load command") }
            if command == 0x26 || command == 0x29 {
                guard size >= 16 else { throw PatcherError.invalidFormat("short X1 linkedit command") }
                let start = Int(data.loadLE(UInt32.self, at: position + 8)), length = Int(data.loadLE(UInt32.self, at: position + 12))
                guard start <= data.count, length <= data.count - start else { throw PatcherError.invalidFormat("X1 linkedit outside image") }
                if command == 0x26 {
                    var cursor = start, address = text.vmAddr
                    while cursor < start + length {
                        var delta: UInt64 = 0, shift = 0
                        while true {
                            guard cursor < start + length, shift < 63 else { throw PatcherError.invalidFormat("invalid function-start ULEB") }
                            let byte = data[cursor]; cursor += 1
                            delta |= UInt64(byte & 0x7F) << shift
                            if byte & 0x80 == 0 { break }
                            shift += 7
                        }
                        if delta == 0 { break }
                        let (next, overflow) = address.addingReportingOverflow(delta)
                        guard !overflow else { throw PatcherError.invalidFormat("function-start overflow") }
                        address = next
                        if let offset = MachOParser.vaToFileOffset(address, segments: segments) { seeds.append(offset) }
                    }
                } else {
                    guard length % 8 == 0 else { throw PatcherError.invalidFormat("invalid data-in-code table") }
                    for entry in stride(from: start, to: start + length, by: 8) {
                        let offset = Int(data.loadLE(UInt32.self, at: entry)), length = Int(data.loadLE(UInt16.self, at: entry + 4))
                        guard offset <= data.count, length <= data.count - offset else { throw PatcherError.invalidFormat("data-in-code outside image") }
                        excluded.append(offset ..< offset + length)
                    }
                }
            } else if command == 5, size >= 288, data.loadLE(UInt32.self, at: position + 8) == 6 {
                if let entry = MachOParser.vaToFileOffset(data.loadLE(UInt64.self, at: position + 272), segments: segments) { seeds.append(entry) }
            } else if command == 0x8000_0028, size >= 24 {
                let entry = data.loadLE(UInt64.self, at: position + 8)
                if entry < UInt64(data.count) { seeds.append(Int(entry)) }
            }
            position += size
        }
        return (seeds, excluded)
    }
}

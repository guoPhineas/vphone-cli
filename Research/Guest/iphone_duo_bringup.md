# iPhone Duo single-display bring-up

## Scope and inputs (2026-10-23)

This experiment attempts to boot the iPhone Duo userland on the existing
vphone600 virtual hardware. It registers one outer panel, not two displays or a hinge.
The inner panel, folding poses and physical Duo hardware are not emulated.

- Host: Apple Silicon, macOS 27.0.1 (26A434), without CSSC, CPA or PAuth_LR.
- Guest: `iPhone19,4`, board `v68ap`, iOS 27.1 (24A94425).
- IPSW: <https://updates.cdn-apple.com/2026FallFCS/3f41a447-d8a6-48ae-83ae-056a64f57fd4/iPhone19,4_27.1_24A94425_Restore.ipsw>.
- Size: 12,724,731,538 bytes.
- SHA-256, verified after download:
  `58fbfda85615e90221136d55288f64c9f41386510f8cd77feb8c9d20cc0a782e`.
- CloudOS: 26.4 beta (23E5207q), the existing recommended vphone600 image.
- Preset: `standard`; boot ROMs: the bundle's OpenAVB and OpenSEP.
- VM configuration: 8 CPUs, 8192 MiB RAM, 64 GiB disk, created without a template.
- Core Bundle: a local 2.12.0 build; installed and passed execution policy
  and host preflight.

## Evidence and initial implementation

The restore archive's `BuildManifest.plist` and `Restore.plist` both name
`iPhone19,4`, build 24A94425 and device class `v68ap`. Restore.plist records
CPID 33120 (`0x8160`), BDID 14 (`0x0e`), platform `t8160`.

The archive contains `Firmware/all_flash/DeviceTree.v68ap.im4p`. Its `/product`
records `app-macho-architecture = arm64e.x1`, `artwork-device-idiom = phone`,
`artwork-device-subtype = 2034`, `artwork-scale-factor = 3`, plus `display0`
and `display1` children. The former has display index 0, rotation 0 and scale
3; the latter has index 1, rotation 270 and scale 3. Those are source device
properties, not proof that both panels work in the VM.

The initial model entry uses the outer display's 1398 x 2034 pixels at 460
ppi and 3x, as published in [Apple's technical specifications](https://www.apple.com/iphone-duo/specs/).
The catalog adds only the released 27.1 IPSW, paired with the existing
recommended cloudOS. No new instruction patch or preset is introduced;
the current iOS 27 and ARM64E_X1 patches are exercised on this new userland.

`VPhoneCoreKitTests/GuestDeviceTests` and
`VPhoneCoreKitTests/FirmwareCatalogReportTests` passed: 26 tests total.
The complete `VPhone` Debug build passed. Its finished bundle and a ZIP
round-trip both passed strict, nested, all-architecture signature validation
before the local bundle was installed through Launchpad.

## Boot validation

**Result: does not boot to userspace on this host.** Firmware preparation,
boot-chain patching, DFU restore and CFW installation completed. Template
setup failed while waiting for vphoned because the guest panicked. A subsequent
windowed `vm start <name> --wait --timeout 300` reproduced it before any guest
agent connection or SpringBoard UI:

```text
initproc failed to start -- exit reason namespace 2 subcode 0x4 description: none
Panicked task ... pid 1: launchd
Kernel UUID: 784F88D3-2AF5-3D4A-AB00-365607646E44
```

Namespace 2/subcode 4 reports SIGILL. The saved user-space backtrace LR is not
a recovered fault PC or a verified unslid symbol address. Do not infer an
exact instruction from it without the image load address and fault state.
Runtime addresses and local machine identifiers are omitted from this record.
The VM was stopped after preserving the console log. Its disk,
firmware and installed guest environment remain available for investigation.

### Identified instruction compatibility gap

Host feature queries return zero for `hw.optional.arm.FEAT_CSSC`,
`hw.optional.arm.FEAT_CPA` and `hw.optional.arm.FEAT_PAuth_LR`.
The installed, already X1-lowered `/usr/lib/dyld` still contains scalar CSSC
instructions: for example `UMIN X8,X8,X1` at image offset `0x9570`, `UMAX`
at `0x8ba8`, and `CTZ W10,W21` at `0x1af04`. These are measured offsets in
the 24A94425 dyld, for investigation only, never patch-site constants.

`VPhoneArm64eX1Lowering` and the runtime X1 handler currently lower PAuth_LR
and CPA forms, not these CSSC operations. CSSC therefore is a confirmed
compatibility gap and a candidate explanation for the SIGILL, not yet a
proved fault-site attribution. The cache's early-boot closure and later
runtime code also need auditing before claiming 27.1 support. A safe fix
needs correct register width, operand aliasing, NZCV preservation and immediate
forms; replacing a min/max with an unconditional move is not equivalent.

### Other observed gaps

- Four optional VirtualAudio patches failed together because the old reveal
  expected a `retab` after the throw at `0x171cd0`:
  `system-virtualaudio-cfw-mute_set_throw`,
  `system-virtualaudio-cfw-speaker_protection_gate`,
  `system-virtualaudio-cfw-speaker_route_throws`, and
  `system-virtualaudio-cfw-volume_mode_precondition`.
- The shared-region preflight attempted the ordinary arm64e filename and
  skipped its check; later cache patching correctly found 79 X1 chunks and
  measured `sharedRegionSize = 0x17ce04000`, `maxSlide = 0x20000000`, then
  zeroed maxSlide. No cache-size overflow was reported by that later stage.
- Existing X1 lowering reported 2735 instructions in launchd, with zero
  unvisited candidates. This only counts the instruction forms it recognizes;
  it does not establish support for every instruction in the binary.

The registered model and catalog entry are experimental bring-up inputs,
not a claim of successful Duo support. No CSSC or audio patch was added by
this experiment. Supporting this firmware on hosts without CSSC requires
additional instruction compatibility work; emulating both displays and the
hinge is a separate gap. These results establish limitations of the current
implementation, not that supporting the device is technically impossible.

The original manifests and device tree were extracted by HTTP ranges with
the repository's `VPhoneRemoteZip`. Raw logs and scratch artifacts remain
local; host paths, per-machine identifiers and runtime addresses are not
included in this research record.

## Experimental CSSC fallback (2026-10-25)

The M3 Pro repro uses the same 24A94425 userland and cloudOS 26.4 kernel
UUID recorded above. Its console reports PID 1 SIGILL; host sysctl reports
CSSC, CPA and PAuth_LR absent. The fault PC is still not captured. PR #728
reports a successful boot on an M5 Pro with native CSSC, then fixes later
X1 fault volume, audio and service-profile issues. That PR adds no CSSC
fallback and is not incorporated here.

This branch extends the existing X1 bootstrap patches rather than adding
a kernel instruction emulator. CSSC sites keep their original address and
branch to baseline A64 thunks in verified zero-filled, executable segment
padding outside load commands and all sections. Cached thunks can additionally
use entirely zero-filled 4 KiB alignment tails between adjacent image segments,
after subtracting all image segment ranges and checking a single executable
cache mapping. B-only relays bridge the 128 MiB direct-branch limit without
clobbering LR or another register. Each relay reserves two adjacent branch
words for entry and return together; the entry path cannot consume the final
bridge needed to return. Requests from all bootstrap images are
collected before allocation, with sites having less direct capacity handled
first. Thunks and relays share one pool; there is no fixed percentage reserved
for either. Both ends of candidate gaps are considered, direct round trips
take priority, and a failed outbound/return allocation rolls back before the
next candidate is tried. If the complete direct-first plan fails, a bounded
second pass restores the original pool, places short thunks before relay pairs
fragment their local slots, then tries larger thunks remotely. Optimistic reachability bounds exclude cache
regions disconnected from the site before routing tries candidate gaps.
Both failed passes restore the original pool.
Planning
refuses missing space or an unreachable path before writing. The existing
re-attestation, original backups and cache undo records cover every changed
word, including thunks and relays. Scratch registers, NZCV and the 128-byte
Darwin red zone are preserved; W-register results clear their upper 32 bits.

Register MIN/MAX can use CMP/CSEL/B (12 bytes instead of 36) when the next
16 instructions contain a proven independent NZCV overwrite before any use.
The proof accepts only known flag-transparent integer and load/store operations and stops
at calls, branches, returns, conditional operations, carry-dependent writes,
system-register accesses, unknown instructions or a missing decode. Other
forms and inconclusive sites keep their complete preserving fallback. For an
immediate MIN/MAX with the same NZCV proof, a destination distinct from the
source can hold the immediate without a scratch register; source/destination
aliases keep the preserving form. Existing encoders generate these sequences.

The runtime fallback evaluates scalar ABS, CNT, CTZ, SMAX, SMIN, UMAX and UMIN
(register and immediate forms), updates only the destination and PC, and
forwards unknown encodings. Native capability probing includes CSSC.
Runtime-emulated sites fault on every execution, so this is a correctness
fallback, not a performance claim. Other X1 cache faults still use the
existing path on this branch; #728's performance work remains complementary.

Read-only inspection of the installed standalone images found 80 CSSC sites
in dyld and 9 in launchd. Patched scratch copies have no scalar CSSC remaining
in their instruction sections; all 343 dyld and 150 launchd SHA-256 code slots
were independently verified. Host execution checks 140 generated fallback
cases, including W/X results, aliases, flags, scratch registers and red-zone
preservation. The portable C emulator and arm64e guest dylib build also pass.
New instruction encoders were checked with Keystone 0.9.2 outside the repository.

The preceding implementation passed 94 tests in 12 suites, covering CSSC, existing X1 lowering,
cache bootstrap planning fixtures, encoders and the required patch catalogue,
version, selection, declaration, resolution and gate suites. The complete
`VPhone` workspace build and bundle admission pass.

**The preceding real-cache dry-run failed.** That cache validation used the
user-selected VM's iOS 27.1 (24A94425) volume, with the mounted backing image
checked separately from the mountpoint name. Segment-internal padding alone runs
out near Foundation. Inter-image alignment tails, compact thunks and B-only
relays let planning finish Foundation and libswiftCore, but a later bootstrap
CSSC site could not reach the remaining thunk space. The allocator refused
the complete plan before any file write. The revised global allocator and
short thunks require a new cache dry-run after the implementation is complete.
Do not infer native-CSSC-host compatibility
from the host unit tests either: the new static lowering currently runs for
X1 inputs regardless of the host's CSSC support.

The creation log also showed the failed bootstrap patch being reported as a
warning, after which installation continued and setup boot panicked. Selected
X1 patches for dyld, launchd, fsck, mount and the bootstrap cache now abort
installation on failure. Cache failures retain their underlying error in the
thrown message; optional audio and other patches retain their existing policy.
This error handling prevents a misleading later connect failure; it does not
establish the instruction responsible for the original panic.

The final revision passed 122 tests in 13 suites, the guest lowering tests,
and the complete VPhone Debug bundle build and admission. Its actual Banana
cache dry-run still failed after planning 10,559 of 11,523 CSSC sites: a
36-byte SMIN fallback at 0x1832f72f0 had no contiguous reachable candidate.
The failed plan wrote no cache files. This branch is an experimental checkpoint,
not a successful M3 Pro boot fix; allocator tuning is discontinued.

A separate boot of an independent Banana disk clone captured the actual fatal
instruction in the same research kernel UUID: saved EL0 PC 0x2bd6380e8,
ESR 0x02000000, and runtime exception codes {1, 0xdac1a7fe}. The word is
PACIBSPPC, in /usr/lib/libSystem.B.dylib at image offset 0x10e8, and matches
the original cache chunk. The kernel's user-instruction copy and exception
code stores were verified in its live disassembly. Thus this installed image
dies on PAuth_LR before a CSSC fault has been demonstrated. The creation log
shows CSSC planning failing the entire X1 cache operation, leaving the existing
PAuth/CPA conversion unapplied while installation continued. CSSC remains a
separate confirmed host compatibility gap.

No source VM disk has been written or redeployed. The diagnostic clone was
stopped after capture. Entering SpringBoard on this host remains unverified.

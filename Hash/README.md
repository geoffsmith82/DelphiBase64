# FastHash: assembly versions of the System.Hash algorithms

FastHash gives every hash in Delphi's `System.Hash` a hand-written assembly
implementation. Each one has the same API and gives byte-identical results,
on Windows (x86/x64) and on ARM64 (macOS, iOS, Android):

| System.Hash       | FastHash              | Windows x86/x64 | ARM64 |
|-------------------|-----------------------|-----------------|-------|
| `THashMD5`        | `THashMD5Fast`        | Scalar | Scalar |
| `THashSHA1`       | `THashSHA1Fast`       | Scalar, AVX2+BMI2, SHA-NI | Scalar, ARMv8 crypto |
| `THashSHA2` (SHA224, SHA256) | `THashSHA2Fast` | Scalar, AVX2+BMI2, SHA-NI | Scalar, ARMv8 crypto |
| `THashSHA2` (SHA384, SHA512, SHA512_224, SHA512_256) | `THashSHA2Fast` | Scalar (SSE2 schedule), AVX2+BMI2 | Scalar, ARMv8.2 SHA-512 crypto |
| `THashBobJenkins` | `THashBobJenkinsFast` | Scalar | Scalar |
| `THashFNV1a32`    | `THashFNV1a32Fast`    | Scalar | Scalar |
| `THashFNV1a64`    | `THashFNV1a64Fast`    | Scalar | Scalar |

"ARMv8 crypto" is the ARMv8 Cryptographic Extension: the SHA1C/SHA1P/SHA1M,
SHA256H/H2 and SHA512H/H2 instructions, which work on NEON registers. Every
Apple Silicon chip and most Android SoCs have SHA-1/SHA-256. SHA-512
(ARMv8.2) is on Apple M1/A14 and later.

Every algorithm also has a portable Pascal implementation. It is the
fallback on other platforms (macOS x64, Linux) and the tests use it as a
reference. The code path is chosen at start-up from the CPU's features:
CPUID on x86, `sysctlbyname` on Apple, and `getauxval(AT_HWCAP)` on Android.

```delphi
uses FastHash;

s := THashSHA2Fast.GetHashString('abc');                         // SHA-256, like THashSHA2
s := THashSHA2Fast.GetHashString('abc', THashSHA2Fast.TSHA2Version.SHA512);
d := THashMD5Fast.GetHashBytesFromFile('C:\big.iso');
m := THashSHA1Fast.GetHMAC('data', 'key');

var h := THashSHA2Fast.Create;   // incremental, exactly like the RTL records
h.Update(Buffer, Len);
h.Update(MoreBytes);
Digest := h.HashAsBytes;
```

**Using it in a project:** add both `Hash` and `Hash\Arm` to the project's
search path.

- The ARM64 targets link a precompiled object from `Hash\Arm`: one per
  platform, already checked in.
- MSBuild and the IDE pass the search path to the linker as the object path.
  On the command line, pass it as both `-U` and `-O`.
- Windows needs only `Hash`.

## Files

| Path | Purpose |
|------|---------|
| `FastHash.pas` | The public records (`THash*Fast`), level control (`FastHashSetMaxLevel`, `FastHashActiveLevel`, `FastHashActiveImplementation`). |
| `FastHash.CPU.pas` | CPU feature detection, the level enum, the implementation registry types, aligned constants. |
| `FastHash.inc` | Platform switches: `FASTHASH_X86ASM` (Windows) and `FASTHASH_ARM64` (macOS/iOS/Android ARM64). |
| `FastHash.MD5.pas`, `.SHA1.pas`, `.SHA256.pas`, `.SHA512.pas`, `.NonCrypto.pas` | Per algorithm: Pascal reference, asm bindings, and the list of implementations in order of preference. |
| `Asm\*.x86.inc`, `Asm\*.x64.inc` | Generated x86/x64 inline asm (Windows). |
| `Arm\fasthash_arm64.S` | Generated AArch64 assembly. |
| `Arm\fasthash_arm64.c` | AArch64 C versions (intrinsics for the crypto instructions) and the CPU feature probe. |
| `Arm\fasthash_*_arm64.o` | The clang-built objects the Delphi ARM64 targets link (macOS, iOS, iOS simulator, Android). Checked in. |
| `Arm\build_arm64.sh` | Builds those objects: Apple objects with clang on a Mac (over ssh), the Android one with RAD Studio's NDK. `selftest` also runs `Arm\selftest.c` on the Mac. |
| `Tools\gen_*.pl` | Perl generators for the unrolled asm (x86 and AArch64). Perl ships with Git for Windows. |
| `Tests\FastHashTests.dpr` | DUnitX test project. |
| `Bench\FastHashBench.dpr` | Benchmark against System.Hash and Indy, plus every implementation side by side. |
| `build.cmd` | Builds the tests and the benchmark for Win32 and Win64. |
| `arm64.sh` | Cross-builds them on Windows for macOS ARM64, macOS x64, the iOS simulator, iOS devices and Android ARM64. `test` and `bench` run them on the Mac and in the iOS simulator. |

The SHA and MD5 cores are fully unrolled, so they come from small Perl
scripts rather than being written out by hand. Building needs only Delphi:
the generated files and the ARM objects are checked in. Re-run a
generator, and for ARM `Arm\build_arm64.sh`, only if you change the asm.

## API notes

- **Same surface as the RTL.** The records mirror it method for method,
  including all overloads, default parameters, `GetHMAC`/`GetHMACAsBytes`,
  stream and file hashing, `GetBlockSize`/`GetHashSize`, and the
  BobJenkins/FNV `Reset(seed)`, `GetHashValue`, `HashAsInteger` and
  `RawByteString` overloads.
- **RTL behaviour reproduced on purpose:**
  - `Update(string)` hashes UTF-8 for MD5/SHA, but the raw UTF-16 bytes
    for BobJenkins/FNV-1a.
  - `THashBobJenkinsFast.Update` re-hashes each chunk seeded with the
    previous value, so it is not a streaming hash.
  - `HashAsString` is lower-case hex for MD5/SHA and upper-case
    (`IntToHex`) for BobJenkins/FNV-1a.
  - The digest can be read repeatedly. `Update` after the digest has been
    read raises `EFastHashException` (the RTL raises `EHashException`).
- **No dependency on System.Hash.**
- **Levels:**
  - `fhlPascal`, `fhlScalar`, `fhlSIMD`, `fhlCrypto`. The old names
    `fhlAVX2` and `fhlSHANI` still work as aliases.
  - `FastHashLevelName` gives the platform's name for a level: AVX2/SHA-NI
    on x86, NEON/ARMv8-CE on ARM64.
  - `FastHashSetMaxLevel(fhlScalar)` (etc.) lowers the fastest path each
    algorithm may use. It exists for testing and benchmarking and is not
    thread-safe.
- **Several implementations per level:** a level can have more than one
  implementation, for example the hand-written AArch64 asm and its C twin.
  - `XxxImplementations` (in the algorithm units) lists them all, in order
    of preference.
  - `XxxActiveImplementation` / `FastHashActiveImplementation` names the
    one in use.

## Implementation

All block functions process a run of whole blocks:
`Compress(State, Data, Blocks)`. Pascal code does the buffering and
padding, and hands each `Update`'s complete blocks to the asm in one call.

### Windows x86/x64 (Delphi inline asm)

- **MD5:** unrolled integer rounds. The G step uses the disjoint-bits form
  `(b and d) + (c and not d)` to shorten the critical path.
- **SHA-1 / SHA-256 Scalar:** unrolled rounds with a 16-word circular
  schedule. Maj is computed from the previous round's `a xor b`. On Win32,
  SHA-256 keeps `a` and `e` in registers and the rest in a stack ring whose
  slot names rotate with the round number.
- **AVX2 (SHA-1, SHA-256, SHA-512):**
  - The W+K schedule for two blocks is computed together in ymm registers:
    block A in the low lane, block B in the high lane.
  - A's schedule is interleaved with A's rounds.
  - The rounds use BMI1/BMI2 (`rorx`, `andn`).
  - Ch is added before Σ1 to keep the `e` chain short.
- **SHA-NI (SHA-1, SHA-256):** the Intel SHA extensions.
- **SHA-512 Scalar:** an SSE2 schedule, then 64-bit integer rounds (Win64)
  or the 64-bit lanes of xmm registers (Win32).
- **BobJenkins / FNV-1a:** unrolled, register-only loops. On Win32,
  FNV-1a 64 replaces the RTL's per-byte call to the 64-bit multiply helper
  with three instructions, because the prime is 2^40 + 0x1B3.
- **Win64 frames:** the asm uses `.PUSHNV`/`.SAVENV` and stack locals, so
  exceptions unwind correctly.
- **macOS x64 and Linux64:** Delphi's compilers for these have no inline
  assembler, so they use the Pascal paths.

### ARM64 (external object: hand-written assembly and C)

Delphi's ARM64 compilers have no inline assembler. The AArch64 code is
therefore built with clang into one object per platform and declared with
`external FastHashArmObj name '...'`.

**Two versions of every kernel.** Each kernel is written twice, and both
are registered, tested and benchmarked:

- **Hand-written assembly** (`fasthash_arm64.S`, generated by
  `Tools\gen_arm64.pl`):
  - MD5 uses `bic`/`orn` for the G and I steps.
  - The scalar SHA cores keep the whole 16-word schedule in registers and
    get the Σ/σ rotations from A64's free `ror`-shifted `eor` operand.
  - The crypto kernels use SHA1C/P/M/H/SU0/SU1, SHA256H/H2/SU0/SU1, and
    SHA512H/H2/SU0/SU1.
- **C** (`fasthash_arm64.c`): plain C for the scalar paths, and
  `arm_neon.h` intrinsics for the crypto instructions. Clang does the
  scheduling.

**SHA-512 with the crypto extension.** Each step does two rounds. The state
lives in five 128-bit registers whose roles (ab, cd, ef, gh, spare) rotate
by the rule `(ab, cd, ef, gh, spare) := (i3, i0, i4, i2, i1)`. The 80-word
schedule is computed in place in eight registers.

**Which version is used.** The benchmark's per-implementation table
decides; the full results are below. On the Apple M4:

- the assembly wins clearly for MD5 and for scalar and crypto SHA-1/SHA-256
  (8–30%);
- the assembly ties with C for SHA-512 crypto, BobJenkins and FNV.

So the assembly is first in every list. The C versions remain as tested
alternatives: on a core that preferred them, changing the choice is one
line per unit (the order of the `Implementations` list).

**Platform objects.** `FASTHASH_ARM64` covers macOS, iOS, the iOS simulator
and Android, each with its own object:

- Mach-O for macOS, iOS and the iOS simulator;
- ELF for Android.

All four are built from the same two source files.

## Tests

`Tests\FastHashTests` is a DUnitX console runner with 101 tests. Every
algorithm test runs once per level name (`Pascal`, `Scalar`, `SIMD`,
`Crypto`):

- **Known-answer vectors:** RFC 1321 (MD5) and FIPS 180 for every
  SHA-1/SHA-2 variant (`""`, `"abc"`, the 448- and 896-bit messages,
  10^6 × `'a'`), each fed as one Update and in pieces. HMAC vectors come
  from RFC 2202 (MD5, SHA-1) and RFC 4231 (SHA-224/256/384/512). Also
  lookup3.c's self-test values and the FNV-1a reference values.
- **Byte-for-byte comparison with System.Hash:**
  - every length from 0 to 300, sparser lengths up to about 4.5 KB, and
    1 MB + 13;
  - random-sized pieces;
  - every two-piece split of a 300-byte message;
  - HMAC over a grid of key and data lengths;
  - BobJenkins/FNV-1a at four alignments with seeds and chained Updates.
- **Every implementation:** each registered block function and non-crypto
  hash, including the variants the dispatcher did not pick, against the
  Pascal reference. That covers 0..40 blocks from random states, and
  lengths 0..300 at four alignments.
- **API surface:** Unicode strings, streams, files, every HMAC overload,
  sizes, repeated digest reads, `Reset`, and `Update` after the digest.

A level the CPU or platform lacks, or that an algorithm doesn't implement,
ends with `Assert.Pass('SKIPPED: ...')`, because DUnitX has no runtime
ignore. The runner then prints which levels and implementations actually
ran, with the reason for each skip.

**Results: 101/101** on all of the following.

| Platform | Hardware | Paths exercised |
|----------|----------|-----------------|
| Win32, Win64 | i7-10750H | Pascal, x86 asm, AVX2 |
| Win32, Win64 | Celeron J4105 | Pascal, x86 asm, SHA-NI |
| macOS ARM64 | Apple M4 | Pascal, A64 asm + C, ARMv8 crypto asm + C, SHA-512 included |
| iOS simulator ARM64 | same M4 | as macOS ARM64 |
| macOS x64 | M4, under Rosetta 2 | Pascal |

The **iOS device** and **Android ARM64** builds compile and link, and their
binaries contain the crypto instructions. They could not be run because
neither a device nor an ARM emulator was available. They use the same
kernel source as the macOS/iOS-simulator objects, which were run.

## Benchmark

```
Win64\Release\FastHashBench.exe          16 MB buffer (default)
Win64\Release\FastHashBench.exe 64       64 MB buffer
Win64\Release\FastHashBench.exe 16 -impl only the per-implementation table
Win64\Release\FastHashBench.exe -makefile big.bin 1024   write a 1 GB test file
Win64\Release\FastHashBench.exe -file big.bin           hash it with each library's file API
./arm64.sh bench osx                     macOS ARM64 on the Mac (or iossim, osx64)
```

The benchmark has two parts, plus a file mode (`-file`, below):

- **Per-implementation table.** Every registered block function and
  non-crypto hash is timed on a 1 MB cache-resident buffer, so this
  measures the kernel rather than memory. This is how the asm-vs-C choice
  was made.
- **Per-algorithm comparison.** It first checks that all contenders agree
  on the digest. It then times a 16 MB buffer (best and median), 1 KB
  messages and 64-byte messages, each message hashed with
  `Create`/`Update`/`HashAsBytes`. Contenders:
  - System.Hash;
  - every FastHash level the CPU supports;
  - Indy, through whatever OpenSSL it can load (on macOS it found the
    system's), otherwise its native MD5/SHA-1. Indy has no SHA-512/224,
    SHA-512/256, BobJenkins or FNV-1a.

Indy hashers are created once and reused. With `IdSSLOpenSSL` linked but
no OpenSSL DLLs present, constructing an Indy hash object on Windows costs
about 4 ms, because it retries loading the DLLs.

### Results

All figures are MB/s (2^20 bytes per second) hashing a 16 MB buffer, best
of several runs. "×" is FastHash's speedup over System.Hash. FastHash uses
the best path the CPU supports, shown in brackets. Each table column comes
from one benchmark run of the current build.

#### ARM64: Apple M4, macOS 26 (native)

| Algorithm | System.Hash | FastHash | × | Indy (macOS OpenSSL) |
|-----------|------------:|---------:|--:|---------------------:|
| MD5         | 111 | 850 (A64 asm) | **7.6×** | 745 |
| SHA-1       | 111 | 2935 (ARMv8 crypto) | **26.5×** | 1042 |
| SHA-224     | 143 | 2968 (ARMv8 crypto) | **20.8×** | 2415 |
| SHA-256     | 148 | 2892 (ARMv8 crypto) | **19.5×** | 2550 |
| SHA-384     | 229 | 1637 (ARMv8.2 crypto) | **7.1×** | 798 |
| SHA-512     | 219 | 1592 (ARMv8.2 crypto) | **7.3×** | 803 |
| SHA-512/224 | 217 | 1598 (ARMv8.2 crypto) | **7.4×** | – |
| SHA-512/256 | 223 | 1642 (ARMv8.2 crypto) | **7.4×** | – |
| BobJenkins  | 827 | 3326 (A64 asm) | **4.0×** | – |
| FNV-1a 32   | 460 | 964 (A64 asm) | **2.1×** | – |
| FNV-1a 64   | 331 | 954 (A64 asm) | **2.9×** | – |

FastHash beats the OpenSSL that Indy loads on every algorithm, and runs
SHA-512 at twice its speed.

#### ARM64: Apple M4, iOS simulator

| Algorithm | System.Hash | FastHash | × | Indy (native) |
|-----------|------------:|---------:|--:|--------------:|
| MD5         | 110 | 827 (A64 asm) | **7.5×** | 367 |
| SHA-1       | 115 | 2942 (ARMv8 crypto) | **25.6×** | 204 |
| SHA-224     | 146 | 2892 (ARMv8 crypto) | **19.8×** | – |
| SHA-256     | 145 | 2985 (ARMv8 crypto) | **20.5×** | – |
| SHA-384     | 238 | 1623 (ARMv8.2 crypto) | **6.8×** | – |
| SHA-512     | 230 | 1642 (ARMv8.2 crypto) | **7.2×** | – |
| SHA-512/224 | 223 | 1643 (ARMv8.2 crypto) | **7.4×** | – |
| SHA-512/256 | 229 | 1638 (ARMv8.2 crypto) | **7.2×** | – |
| BobJenkins  | 817 | 3400 (A64 asm) | **4.2×** | – |
| FNV-1a 32   | 465 | 949 (A64 asm) | **2.0×** | – |
| FNV-1a 64   | 332 | 965 (A64 asm) | **2.9×** | – |

#### Windows: Intel Celeron J4105 (Goldmont Plus: SHA-NI, no AVX)

| Algorithm | Win64 System.Hash | Win64 FastHash | × | Win32 System.Hash | Win32 FastHash | × |
|-----------|------------------:|---------------:|--:|------------------:|---------------:|--:|
| MD5         | 81  | 446 (x86 asm) | **5.5×** | 74  | 448 (x86 asm) | **6.0×** |
| SHA-1       | 75  | 1251 (SHA-NI) | **16.8×** | 79  | 1234 (SHA-NI) | **15.6×** |
| SHA-224     | 48  | 527 (SHA-NI) | **11.0×** | 50  | 543 (SHA-NI) | **10.8×** |
| SHA-256     | 48  | 538 (SHA-NI) | **11.2×** | 51  | 544 (SHA-NI) | **10.8×** |
| SHA-384     | 78  | 185 (x86 asm) | **2.4×** | 21  | 110 (x86 asm) | **5.2×** |
| SHA-512     | 78  | 185 (x86 asm) | **2.4×** | 21  | 110 (x86 asm) | **5.2×** |
| SHA-512/224 | 78  | 184 (x86 asm) | **2.4×** | 21  | 110 (x86 asm) | **5.2×** |
| SHA-512/256 | 78  | 183 (x86 asm) | **2.4×** | 21  | 110 (x86 asm) | **5.2×** |
| BobJenkins  | 355 | 1275 (x86 asm) | **3.6×** | 348 | 1260 (x86 asm) | **3.6×** |
| FNV-1a 32   | 534 | 549 (x86 asm) | 1.0× | 541 | 534 (x86 asm) | 1.0× |
| FNV-1a 64   | 369 | 368 (x86 asm) | 1.0× | 124 | 373 (x86 asm) | **3.0×** |

Indy (native Pascal, no OpenSSL DLLs): MD5 124/128 and SHA-1 73/89 MB/s
(Win64/Win32).

#### Windows: Intel i7-10750H (AVX2, no SHA-NI)

| Algorithm | Win64 System.Hash | Win64 FastHash | × | Win32 System.Hash | Win32 FastHash | × |
|-----------|------------------:|---------------:|--:|------------------:|---------------:|--:|
| MD5         | 90  | 481 (x86 asm) | **5.4×** | 90  | 539 (x86 asm) | **6.0×** |
| SHA-1       | 100 | 399 (AVX2) | **4.0×** | 135 | 515 (AVX2) | **3.8×** |
| SHA-224     | 57  | 262 (AVX2) | **4.6×** | 83  | 201 (AVX2) | **2.4×** |
| SHA-256     | 66  | 239 (AVX2) | **3.6×** | 74  | 182 (AVX2) | **2.4×** |
| SHA-384     | 100 | 308 (AVX2) | **3.1×** | 28  | 117 (AVX2) | **4.2×** |
| SHA-512     | 106 | 312 (AVX2) | **2.9×** | 25  | 182 (AVX2) | **7.2×** |
| SHA-512/224 | 135 | 431 (AVX2) | **3.2×** | 34  | 216 (AVX2) | **6.4×** |
| SHA-512/256 | 146 | 356 (AVX2) | **2.4×** | 31  | 148 (AVX2) | **4.8×** |
| BobJenkins  | 407 | 1158 (x86 asm) | **2.8×** | 402 | 1353 (x86 asm) | **3.4×** |
| FNV-1a 32   | 483 | 524 (x86 asm) | 1.1× | 514 | 484 (x86 asm) | 0.9× |
| FNV-1a 64   | 376 | 431 (x86 asm) | 1.1× | 190 | 349 (x86 asm) | **1.8×** |

Indy (native Pascal): MD5 118/125 and SHA-1 71/119 MB/s (Win64/Win32).

#### Small messages

The table shows 64-byte messages, each hashed with
`Create`/`Update`/`HashAsBytes`, in MB/s for System.Hash → FastHash.
Per-call overhead dominates at this size.

| Algorithm | M4 macOS | Celeron Win64 | i7 Win64 |
|-----------|---------:|--------------:|---------:|
| MD5     | 46 → 343 | 31 → 151 | 36 → 157 |
| SHA-1   | 63 → 470 | 39 → 204 | 59 → 122 |
| SHA-256 | 65 → 415 | 23 → 131 | 34 → 77 |
| SHA-512 | 96 → 243 | 35 → 56 | 32 → 64 |
| BobJenkins | 559 → 1621 | 236 → 444 | 238 → 370 |

#### Hashing a 1 GB file

This test hashes the same 1 GB file with each library's file API: System.Hash's and FastHash's
`GetHashBytesFromFile`, and Indy's `HashStream` over a `TBufferedFileStream` (1 MB buffer). Indy has no
file API of its own. The file is read once beforehand so that every run sees the same OS cache state.
Figures are MB/s, with the speedup over System.Hash in brackets; each column comes from one run.

| Algorithm | M4 macOS System.Hash | M4 FastHash | M4 Indy (OpenSSL) | i7 Win64 System.Hash | i7 Win64 FastHash | i7 Win64 Indy (native) | i7 Win32 System.Hash | i7 Win32 FastHash | i7 Win32 Indy (native) |
|-----------|----:|----:|----:|----:|----:|----:|----:|----:|----:|
| MD5         | 108 | **795** (7.3×) | 736 (6.8×) | 50 | **276** (5.5×) | 129 (2.6×) | 74 | **236** (3.2×) | 109 (1.5×) |
| SHA-1       | 112 | **2492** (22×) | 1042 (9.3×) | 81 | **356** (4.4×) | 92 (1.1×) | 81 | **300** (3.7×) | 111 (1.4×) |
| SHA-224     | 140 | **2493** (18×) | 2457 (18×) | 58 | **223** (3.9×) | – | 61 | **184** (3.0×) | – |
| SHA-256     | 139 | **2473** (18×) | 2418 (17×) | 55 | **215** (3.9×) | – | 59 | **169** (2.9×) | – |
| SHA-384     | 212 | **1494** (7.0×) | 798 (3.8×) | 83 | **289** (3.5×) | – | 29 | **144** (5.0×) | – |
| SHA-512     | 212 | **1485** (7.0×) | 799 (3.8×) | 80 | **278** (3.5×) | – | 28 | **149** (5.3×) | – |
| SHA-512/224 | 212 | **1484** (7.0×) | – | 84 | **291** (3.5×) | – | 20 | **102** (5.0×) | – |
| SHA-512/256 | 212 | **1484** (7.0×) | – | 84 | **289** (3.5×) | – | 19 | **107** (5.6×) | – |

On the Celeron J4105 (Win64), FastHash was 5.5× System.Hash for MD5 and 2.4× for the SHA-512 family. Its
SHA-NI paths were 13× for SHA-1 and 9–10× for SHA-224/256. Indy's native code was 2.1× for MD5 and 1.2× for
SHA-1. The Celeron throttled during that run (System.Hash MD5 fell from about 70 MB/s to 17 MB/s), so only
its ratios are reported.

- **From a file, FastHash loses little.** On the M4, SHA-1 drops from about 2.9 GB/s on an in-memory
  buffer to 2.5 GB/s from the file.
- **Indy needs a buffered stream.** On a plain `TFileStream` its `HashStream` read the file in small
  pieces, each an OS call, and ran at about 10 MB/s.
- **With the system OpenSSL on macOS, Indy is close to FastHash for SHA-224/256** (within 2–3%) and for
  MD5 (8%). FastHash still runs SHA-1 at 2.4× and SHA-512 at 1.9× OpenSSL's speed.

#### ARM64: hand-written assembly vs C

This compares the raw block functions in MB/s on a 1 MB buffer, best of
15. The assembly is the version used.

| Kernel | A64 asm | C (clang -O3) |
|--------|--------:|--------------:|
| MD5 | **890** | 676 |
| SHA-1 scalar | **1353** | 1131 |
| SHA-1 crypto | **3222** | 2744 |
| SHA-256 scalar | **575** | 489 |
| SHA-256 crypto | **2961** | 2650 |
| SHA-512 scalar | **909** | 793 |
| SHA-512 crypto | 1780 | 1670–1810 (tie) |
| BobJenkins | 3360–3620 | 3380–3640 (tie) |
| FNV-1a 32 / 64 | ≈1000–1050 | ≈1000–1050 (tie) |

The first SHA-512 crypto asm lost to clang by about 8%. Clang hoisted the
message-schedule instructions so they overlap the round chain, and putting
them first in each step in the generator closed the gap.

#### Notes on the numbers

- **The i7 laptop throttles.** It runs at about 2.2 GHz on the Balanced
  plan with background load, so its absolute MB/s moved by up to 30%
  between runs. Measured back to back, AVX2 beat Scalar for every
  algorithm on both platforms. The Celeron and M4 runs are steady
  (best ≈ median). The Celeron's first runs were throttled to about a
  quarter of these numbers, System.Hash included; the ratios were the same.
- **System.Hash is slow at 64-bit arithmetic on Win32.** That is why its
  SHA-384/512 run at a quarter of its Win64 speed there, and why FastHash's
  speedup is larger on Win32.
- **FNV-1a** is a strict serial xor→multiply chain. On x86 the compiler's
  loop is already at that limit (1.0×, within noise), except Win32
  FNV-1a 64, where the RTL calls a 64-bit multiply helper for every byte.
  Delphi's ARM64 code is slower, so the A64 asm gains 2–3× there.
- **Delphi's own Pascal SHA code is slow on ARM64.** System.Hash runs at
  about 110–230 MB/s there, so the asm and crypto paths matter most on
  ARM64.

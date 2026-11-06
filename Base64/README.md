# TBase64EncodingPolyFill — assembly base64 with the RTL's interface

A self-contained, drop-in replacement for Delphi's built-in
`System.NetEncoding.TBase64Encoding` that performs the byte⇄base64 transform in
hand-written assembly. It descends from `TObject` (not from
`System.NetEncoding`), so it works as a genuine *polyfill* where the RTL class is
unavailable, and can be benchmarked head-to-head against it.

| Platform | Code paths |
|----------|------------|
| Win32, Win64 | Pascal, scalar asm, AVX2 (selected at runtime) |
| macOS ARM64, iOS, Android ARM64 | Pascal, scalar, NEON (always available) |
| macOS x64, Linux | Pascal |

## Files

| File | Purpose |
|------|---------|
| `Base64EncodingPolyFill.pas` | The standalone `TBase64EncodingPolyFill` class + all asm cores (scalar/AVX2 encode & decode, SIMD wrap, single-pass fused MIME encoders). Self-contained, no RTL dependency. |
| `Base64EncodingFast.pas`     | `TBase64EncodingFast` — a subclass of the RTL `TBase64Encoding` (type-compatible with `TNetEncoding`) that delegates to the fast asm. Use when you need RTL compatibility. |
| `Base64Encoding.inc`         | Platform switches: `BASE64_X86ASM` (Windows) and `BASE64_ARM64` (macOS/iOS/Android ARM64). |
| `Arm\base64_arm64.S`         | Hand-written AArch64 assembly. |
| `Arm\base64_arm64.c`         | AArch64 C versions (intrinsics for NEON). |
| `Arm\base64_*_arm64.o`       | The clang-built objects the Delphi ARM64 targets link (macOS, iOS, iOS simulator, Android). Checked in. |
| `Arm\build_arm64.sh`         | Builds those objects: Apple objects with clang on a Mac (over ssh), the Android one with RAD Studio's NDK. `selftest` also runs `Arm\selftest.c` on the Mac. |
| `Tests\PolyFillTestRunner.pas` | Correctness (vs `System.NetEncoding`) + benchmark harness, run for every implementation. |
| `Tests\PolyFillTest32.dpr`   | Win32 console test/benchmark project. |
| `Tests\PolyFillTest64.dpr`   | Console test/benchmark project for Win64 and the macOS, iOS and Android targets. |
| `build.cmd`                  | Builds both Windows platforms (`dcc32`/`dcc64`) into `Win32\Release` and `Win64\Release`. |
| `arm64.sh`                   | Cross-builds on Windows for macOS ARM64, macOS x64, the iOS simulator, iOS devices and Android ARM64. `test` and `bench` run on the Mac and in the iOS simulator. |

On the ARM64 targets, add `Arm\` to the search path so the linker finds the
object. Building needs only Delphi: the objects are checked in. Re-run
`Arm\build_arm64.sh` only if you change the kernels.

## Public interface

Mirrors the public surface `TBase64Encoding` inherits from `TNetEncoding`,
plus the same three constructors:

```delphi
constructor Create;                                    // 76-char MIME lines, CRLF, '=' padded  (== TNetEncoding.Base64)
constructor Create(CharsPerLine: Integer);             // CharsPerLine = 0 => no line breaks    (== TNetEncoding.Base64String)
constructor Create(CharsPerLine: Integer; LineSeparator: string);

function Encode(const Input: array of Byte): TBytes;            overload;
function Encode(const Input: string): string;                  overload;   // UTF-8 in
function Encode(const Input, Output: TStream): Integer;        overload;
function Decode(const Input: array of Byte): TBytes;           overload;
function Decode(const Input: string): string;                  overload;
function Decode(const Input, Output: TStream): Integer;        overload;
function EncodeBytesToString(const Input: array of Byte): string;   overload;
function EncodeBytesToString(const Input: Pointer; Size: Integer): string; overload;
function DecodeStringToBytes(const Input: string): TBytes;
```

Output is **byte-for-byte identical** to `TBase64Encoding` for every input size,
every `CharsPerLine`, and every method (verified by the harness, below). Decode
tolerates embedded whitespace (space/tab/CR/LF) exactly like the RTL, so it
round-trips wrapped output.

```delphi
uses Base64EncodingPolyFill;
var enc := TBase64EncodingPolyFill.Create;        // MIME, like TNetEncoding.Base64
try
  s := enc.EncodeBytesToString(myBytes);
  b := enc.DecodeStringToBytes(s);
finally
  enc.Free;
end;
```

## Two classes

- **`TBase64EncodingPolyFill`** (descends from `TObject`) — the standalone
  polyfill. Mirrors `TBase64Encoding`'s public surface but has **no dependency**
  on `System.NetEncoding`, so it works on compilers/targets that lack the RTL
  class. Not assignment-compatible with `TNetEncoding`.

- **`TBase64EncodingFast`** (descends from `System.NetEncoding.TBase64Encoding`)
  — a true RTL drop-in: assignment-compatible with `TNetEncoding` /
  `TBase64Encoding`, so it can be passed to any API expecting those. It overrides
  the RTL's virtual `Do*` primitives and forwards them to an internal
  `TBase64EncodingPolyFill` (same `CharsPerLine` / `LineSeparator`), so it gets
  the same asm speed and the same byte-identical output.

```delphi
uses System.NetEncoding, Base64EncodingFast;
var enc: TNetEncoding;
enc := TBase64EncodingFast.Create;                // 76-char MIME, like TNetEncoding.Base64
try
  s := enc.EncodeBytesToString(myBytes);          // fast asm, via the RTL interface
finally
  enc.Free;
end;
```

## Implementation

- **Scalar integer asm** (`EncodeRawScalar`, `EncodeFusedScalar`) for Win32
  (inline x86) and Win64 (x64) — always available. Scalar decode is Pascal
  (`DecodeCleanQuanta`, `ScalarStretch`).
- **AVX2 turbo** (`EncodeRawAVX2`, `DecodeAVX2Checked`, Muła/Lemire `vpshufb`
  technique) — used when `PolyFillHasAVX2` (runtime CPUID + XGETBV check),
  with the scalar asm as the fallback and for the final 1–3 byte tail.
- **Line wrapping** matches `TBase64Encoding` exactly: a line holds
  `CharsPerLine div 4` quanta; a separator follows every full 3-byte group that
  lands on a boundary (so a full final group on a boundary gets a *trailing*
  separator), and the final padded group never does. The wrapped (MIME) encode
  uses a **single-pass fused encoder** (`MimeEncodeFused`): AVX2 produces
  base64 for the chunks that fit inside a line and writes the separator inline, so
  there is no scratch buffer and no second copy. (For a 1- or 2-byte separator
  and a line width ≥ 4 chars — i.e. every standard case. Exotic separators fall
  back to encode-then-SIMD-wrap.) No-wrap output is encoded straight into the
  result with no extra copy.
- **Decode** is also single-pass — no separate validating pre-scan.
  `DecodeAVX2Checked` decodes consecutive *clean* 32-char blocks, validating each
  inline with a Lemire/Aqrit `LutLo & LutHi` check. At a dirty block it finishes
  the line 16 chars at a time, keeping the quanta before the bad byte, then skips
  CR and LF and carries on, so wrapped input stays in the kernel from one line to
  the next. It returns at anything else (space, tab, `=`, an invalid byte, a break
  inside a quantum) or with fewer than 16 chars left. A Pascal driver then
  handles that stretch (skips whitespace, decodes complete quanta, the padded
  final group) and hands back at the next quantum boundary.

### ARM64 (external object: hand-written assembly and C)

Delphi's ARM64 compilers have no inline assembler, so, as in FastHash, the
AArch64 code is built with clang into one object per platform and declared with
`external Base64ArmObj name '...'`. Each kernel is written twice, as assembly
and as C, and both are registered, tested and benchmarked.

- **Encode** loads 48 bytes with `ld3`, which deinterleaves them. It then forms
  the four 6-bit fields with `ushr`/`sli`, maps them through the 64-byte alphabet
  with a four-register `tbl`, and stores with `st4`.
- **Decode** loads 64 chars with `ld4` and uses the same nibble lookups as the
  AVX2 path, validating a block before doing any translation. A 128-entry
  `tbl`+`tbx` lookup was also tried: it was slower (16.5 vs 18.5 GB/s in the
  kernel) and was dropped.
- **Wrapped decode** stays in the kernel from one line to the next. The chars
  after the last whole block go 16 at a time. When a load holds a bad byte, the
  quanta before it are kept and CR or LF are skipped, then the kernel carries on.
  Pascal only sees the last few chars of the input, and anything else that is
  dirty (space, tab, `=`, invalid bytes, or a break inside a quantum).
- **MIME encode** runs the 48-byte blocks and then the scalar loop for each line,
  with the separator written inline.

NEON is part of the ARMv8-A baseline, so there is no feature probe. Lists run in
order of preference, and the benchmark decides, kernel by kernel:

- The bound implementation, `NEON`, is the asm encoders with the C decoder. The
  asm wins 76-char encode by about 15%. C wins 76-char decode by about 20%, even
  after porting clang's validate-first ordering, so the two are combined.
  `NEON asm` and `NEON C` stay registered so both twins keep being tested.
- At the scalar level C beats the assembly by 3–8%. Scalar only runs if you ask
  for it with `Base64SetMaxLevel`.

**Why the line breaks are in the kernel.** Delphi's ARM64 compiler keeps every
local on the stack and reloads it for each use. Profiling showed a two-byte
whitespace loop in `DecodeBuffer` taking 57% of wrapped decode, more than twice
the NEON work on the whole line. So once-per-line work on ARM64 belongs in the
object, not in Pascal.

### Choosing an implementation

`Base64SetMaxLevel`, `Base64SelectImplementation`, `Base64ActiveLevel`,
`Base64ActiveImplementation` and `Base64Implementations` work like FastHash's
level control. The tests and the benchmark use them to exercise every path. Do
not call the two setters while other threads are encoding.

## Build & run

```
build.cmd
Win32\Release\PolyFillTest32.exe            # 16 MB generated buffer (default)
Win64\Release\PolyFillTest64.exe 32         # 32 MB generated buffer
Win64\Release\PolyFillTest64.exe C:\big.bin # encode/decode an existing file
PolyFillTest64.exe --nobench  # checks only
```

The other platforms are cross-built on Windows and run on the Mac:

```
./arm64.sh build              # all five targets
./arm64.sh test               # macOS ARM64, iOS simulator, macOS x64
./arm64.sh bench osx 32       # checks and benchmark, 32 MB buffer
Arm/build_arm64.sh selftest   # rebuild the objects and test the kernels directly
```

iOS device and Android builds are link checks only, as there is no device here.

The harness runs 1650 correctness checks **for each implementation**
(`EncodeBytesToString`, `Encode`/`Decode` for bytes/string/stream,
`DecodeStringToBytes`, UTF-8 strings, whitespace-tolerant decode, and
`CharsPerLine` ∈ {4,5,7,8,11,12,76}) against `System.NetEncoding`. It also
decodes text with a bad byte, whitespace or `=` placed at every position, and
compares the outcome with the Pascal path, because the hand-over from a SIMD
block to the scalar loop must work wherever the dirty byte lands. It then
compares every implementation side by side and benchmarks encode (MIME +
no-breaks) and decode against the RTL. The exit code is 1 if any check fails.

On Windows the harness also decodes text placed hard against a no-access page,
so reading one byte past the end faults. `Arm\selftest.c` covers the same risk on
ARM64 by checking the chars consumed.

## Measured: Apple M4 (macOS 26, NEON)

Against the RTL on a 32 MB buffer:

| Operation | PolyFill | Speedup vs `TNetEncoding` |
|-----------|---------:|--------------------------:|
| Encode, 76-char MIME   | ≈14.7 GB/s | ~32× |
| Encode, no line breaks | ≈23.9 GB/s | ~50× |
| Decode                 | ≈12.5 GB/s | ~37× |

Every implementation on a 1 MB buffer, in MB/s (each run takes the best of 15;
figures are the median of 5 runs):

| Implementation | Encode | Encode 76 | Decode | Decode 76 |
|----------------|-------:|----------:|-------:|----------:|
| Pascal   |  1538 |  1387 |   909 |  653 |
| C        |  3997 |  3682 |   903 |  663 |
| A64 asm  |  3791 |  3606 |   918 |  651 |
| **NEON** | **21882** | **14749** | **12674** | **7153** |
| NEON asm | 22272 | 14663 | 12987 | 5928 |
| NEON C   | 22321 | 12422 | 12674 | 6993 |

Figures are megabytes of binary data, so a decode column counts output bytes.
Wrapped decode was 1.4 GB/s when each line ended in Pascal. Scalar-level decode
is the same Pascal loop, which is why those rows match.

macOS x64 has no assembler path. The Pascal code, under Rosetta 2 on the same
machine, is about 4× faster than the RTL for encode and 2.8× for decode.

## Measured (i7-10750H, 32 MB, AVX2 present)

| Operation | Win32 | Win64 |
|-----------|------:|------:|
| Encode, 76-char MIME      | ~8.4× (≈2.2 GB/s) | ~10.6× (≈2.2 GB/s) |
| Encode, no line breaks    | ~8.8× (≈2.6 GB/s) | ~12.9× (≈2.9 GB/s) |
| Decode                    | ~8.8× (≈2.4 GB/s) | ~12.8× (≈2.9 GB/s) |

(Median of 6 runs. Speedup vs the corresponding `TNetEncoding` method; all
outputs verified byte-identical to the RTL. This laptop varies a lot from run to
run: the same exe has measured anywhere from 1 to 2.6 GB/s on plain decode.)

Every implementation on a 1 MB buffer, in MB/s (each run takes the best of 15;
figures are the median of 6 runs):

| Implementation | Win32 Encode | Encode 76 | Decode | Decode 76 | Win64 Encode | Encode 76 | Decode | Decode 76 |
|----------------|-------------:|----------:|-------:|----------:|-------------:|----------:|-------:|----------:|
| Pascal       |  812 |  742 |  640 |  552 |  614 |  537 |  615 |  533 |
| x86 asm      |  850 |  760 |  664 |  540 |  707 |  719 |  636 |  550 |
| **AVX2 asm** | **1791** | **1296** | **1977** | **1430** | **1462** | **1134** | **1454** | **1146** |

**Wrapped decode.** Skipping line breaks in the kernel instead of in Pascal
raised 76-char decode by about 30% on Win64 and 50% on Win32. Those figures come
from alternating the old and new exes 8 times each, because comparing runs from
different moments is meaningless here. Medians, in MB/s:

| | Before | After |
|---|-------:|------:|
| Win32 | ~960 | ~1455 |
| Win64 | ~1120 | ~1465 |

Scalar decode is Pascal, as on ARM64, so those rows match the Pascal row.

### MIME encode: how the line-break strategy was chosen (4-way)

The harness benchmarks four ways to produce 76-char-CRLF base64. Speedups are
vs `TNetEncoding.Base64`; all four are byte-identical.

| Approach | 64 MB (bandwidth-bound) | 256 KB (cache-resident, compute-bound) |
|----------|------------------------:|---------------------------------------:|
| RTL `TNetEncoding.Base64`               | 1.0× | 1.0× |
| V1 two-pass: AVX2 encode + SIMD wrap    | ~5.4× | ~10–14× |
| V2 fused **scalar** (100% asm, one pass)| ~3–4× | ~4–5× |
| V3 fused **AVX2** (one pass)            | ~4.5–6× | ~9.5–14× |

Takeaways:
- The fully-fused **AVX2** encoder (V3) is the fastest overall and is what the
  class uses for the MIME path. It avoids the scratch buffer entirely by writing
  the separators inline as it encodes.
- The two-pass approach (V1) is surprisingly close to V3: the SIMD copy-with-gaps
  is cheap, and V1 runs AVX2 at full width whereas V3 has a small scalar
  remainder per line (3 of every 19 quanta for 76-char lines). They trade places
  within run-to-run noise, especially when bandwidth-bound.
- The fully-asm **scalar** fused encoder (V2) is the slowest of the three but
  still ~3–5× the RTL — a good portable baseline where SIMD isn't available.

## A note on the RTL `Encode` bug (non-multiple-of-4 line widths)

While testing the `Encode(array of Byte): TBytes` path the harness uncovered a
genuine defect in `System.NetEncoding`: for `CharsPerLine` values that are **not
a multiple of 4** (e.g. 5, 7, 11), `TBase64Encoding.Encode`/`EncodeBytesToString`
under-allocate the output buffer. `EstimateEncodeLength` assumes lines of
`CharsPerLine` characters, but the encoder actually breaks every
`CharsPerLine div 4` quanta (a multiple of 4 chars), so it produces more
separators than estimated and the result is truncated/zero-padded. This polyfill
produces the **correct** output for every `CharsPerLine`; the harness therefore
compares the bytes path to the RTL only for multiples of 4 (where the RTL is
correct) and otherwise validates the payload by round-trip and by stripping the
breaks. All standard widths (76, 64, …) are multiples of 4 and match the RTL
exactly.

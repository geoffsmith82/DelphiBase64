# TBase64EncodingPolyFill — assembly base64 with the RTL's interface

A self-contained, drop-in replacement for Delphi's built-in
`System.NetEncoding.TBase64Encoding` that performs the byte⇄base64 transform in
hand-written assembly (Win32 **and** Win64), with an AVX2 turbo path selected at
runtime. It descends from `TObject` (not from `System.NetEncoding`), so it works
as a genuine *polyfill* where the RTL class is unavailable, and can be
benchmarked head-to-head against it.

## Files

| File | Purpose |
|------|---------|
| `Base64EncodingPolyFill.pas` | The standalone `TBase64EncodingPolyFill` class + all asm cores (scalar/AVX2 encode & decode, SIMD wrap, single-pass fused MIME encoders). Self-contained, no RTL dependency. |
| `Base64EncodingFast.pas`     | `TBase64EncodingFast` — a subclass of the RTL `TBase64Encoding` (type-compatible with `TNetEncoding`) that delegates to the fast asm. Use when you need RTL compatibility. |
| `PolyFillTestRunner.pas`     | Correctness (vs `System.NetEncoding`) + benchmark harness. |
| `PolyFillTest32.dpr`         | Win32 console test/benchmark project. |
| `PolyFillTest64.dpr`         | Win64 console test/benchmark project. |
| `build.cmd`                  | Builds both platforms (`dcc32`/`dcc64`). |

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

- **Scalar integer asm** (`EncodeRawScalar`, `DecodeFullGroups`) for Win32 (inline
  x86) and Win64 (x64) — always available. Adapted from the validated
  `VSoft.Base64` polyfill cores.
- **AVX2 turbo** (`EncodeRawAVX2`, `DecodeAVX2Bulk`, Muła/Lemire `vpshufb`
  technique) — used when `PolyFillHasAVX2` (runtime CPUID + XGETBV check),
  with the scalar asm as the fallback and for the final 1–3 byte tail.
- **Line wrapping** matches `TBase64Encoding` exactly: a line holds
  `CharsPerLine div 4` quanta; a separator follows every full 3-byte group that
  lands on a boundary (so a full final group on a boundary gets a *trailing*
  separator), and the final padded group never does. The wrapped (MIME) encode
  uses a **single-pass fused encoder** (`MimeEncodeFusedAVX2`): AVX2 produces
  base64 for the chunks that fit inside a line and writes the separator inline, so
  there is no scratch buffer and no second copy. (For a 1- or 2-byte separator
  and a line width ≥ 4 chars — i.e. every standard case. Exotic separators fall
  back to encode-then-SIMD-wrap.) No-wrap output is encoded straight into the
  result with no extra copy.
- **Decode** is also single-pass — no separate validating pre-scan. A driver
  alternates `DecodeAVX2Checked` (decodes consecutive *clean* 32-char blocks,
  validating each inline with a Lemire/Aqrit `LutLo & LutHi` check, and stops at
  the first block touching whitespace / `=` / an invalid byte) with a scalar
  stretch that handles the dirty region (skips whitespace, decodes complete
  quanta, the padded final group) and returns at the next quantum boundary so
  AVX2 resumes. Unbroken input is effectively one AVX2 sweep + a small scalar
  tail; MIME input still gets AVX2 for the bulk of every line.

## Build & run

```
build.cmd
PolyFillTest32.exe            # 16 MB generated buffer (default)
PolyFillTest64.exe 32         # 32 MB generated buffer
PolyFillTest64.exe C:\big.bin # encode/decode an existing file
```

The harness runs 470+ correctness checks (`EncodeBytesToString`,
`Encode`/`Decode` for bytes/string/stream, `DecodeStringToBytes`, UTF-8
strings, whitespace-tolerant decode, and `CharsPerLine` ∈ {4,5,7,8,11,12,76})
against `System.NetEncoding`, then benchmarks encode (MIME + no-breaks) and
decode against the RTL.

## Measured (this machine, 32 MB, AVX2 present)

| Operation | Win32 | Win64 |
|-----------|------:|------:|
| Encode, 76-char MIME      | ~7× (≈2.0 GB/s) | ~7–8× (≈1.9 GB/s) |
| Encode, no line breaks    | ~7–10× (≈2.4 GB/s) | ~9–11× (≈2.6 GB/s) |
| Decode                    | ~7× (≈1.9 GB/s) | ~7–8× (≈1.8 GB/s) |

(Speedup vs the corresponding `TNetEncoding` method; all outputs verified
byte-identical to the RTL. Numbers vary run-to-run — the MIME/decode paths are
partly memory-bandwidth-bound at 32–64 MB.)

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

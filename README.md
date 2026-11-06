# DelphiBase64: fast assembly versions of Delphi's encoding and hashing RTL

Two independent Delphi libraries. Each replaces a part of the RTL with
hand-written assembly, keeps the same API and gives byte-identical results.
Neither depends on the other, so you can use just the one you need.

| | [Base64](Base64/README.md) | [Hash](Hash/README.md) |
|---|---|---|
| **Replaces** | `System.NetEncoding.TBase64Encoding` | `System.Hash` (MD5, SHA-1, SHA-2, Bob Jenkins, FNV-1a) |
| **Main classes** | `TBase64EncodingPolyFill`, `TBase64EncodingFast` | `THashMD5Fast`, `THashSHA1Fast`, `THashSHA2Fast`, ... |
| **Platforms** | Win32, Win64, macOS, iOS, Android | Win32, Win64, macOS, iOS, Android |
| **Code paths** | Scalar, AVX2, NEON | Scalar, AVX2+BMI2, SHA-NI, ARMv8 crypto |
| **Tests** | Checks against `System.NetEncoding`, built into the test program | DUnitX suite, cross-checked against `System.Hash` |
| **Benchmark** | Built into the test program | `Hash\Bench\FastHashBench.dpr` |

## Layout

```
Base64\            Base64 library
  Arm\             AArch64 sources and objects
  Tests\           Test and benchmark programs
  build.cmd        Builds Base64 for Win32 and Win64
  arm64.sh         Cross-builds and runs the macOS, iOS and Android targets
  README.md        API, implementation notes and results
Hash\              FastHash library
  Asm\  Arm\       Generated x86/x64 asm, AArch64 sources and objects
  Tools\           Perl generators for the asm
  Tests\  Bench\   DUnitX tests and the benchmark
  build.cmd        Builds Hash for Win32 and Win64
  arm64.sh         Cross-builds and runs the macOS, iOS and Android targets
  README.md        API, implementation notes and results
build.cmd          Builds both libraries
```

## Using a library

Add the `Base64` or `Hash` folder to your project's search path (plus its `Arm`
folder on the ARM64 targets), then:

```delphi
uses Base64EncodingPolyFill;   // or Base64EncodingFast for a TNetEncoding descendant

Encoder := TBase64EncodingPolyFill.Create;
Text := Encoder.EncodeBytesToString(Bytes);
```

```delphi
uses FastHash;

Digest := THashSHA2Fast.GetHashString('abc');
```

## Building

`build.cmd` builds the tests and benchmarks of both libraries for Win32 and
Win64. Output goes to `Win32\Release` and `Win64\Release` inside each library's
folder. Run `Base64\build.cmd` or `Hash\build.cmd` to build just one. Each
library's `arm64.sh` cross-builds and runs the other platforms.

# FastHash: assembly versions of the System.Hash algorithms

Hand-written x86/x64 assembly implementations of every hash in Delphi's
`System.Hash`. They have the same public API and give byte-identical results:

| System.Hash       | FastHash              | Asm code paths |
|-------------------|-----------------------|----------------|
| `THashMD5`        | `THashMD5Fast`        | Scalar |
| `THashSHA1`       | `THashSHA1Fast`       | Scalar, AVX2+BMI2, SHA-NI |
| `THashSHA2` (SHA224, SHA256) | `THashSHA2Fast` | Scalar, AVX2+BMI2, SHA-NI |
| `THashSHA2` (SHA384, SHA512, SHA512_224, SHA512_256) | `THashSHA2Fast` | Scalar (SSE2 schedule), AVX2+BMI2 |
| `THashBobJenkins` | `THashBobJenkinsFast` | Scalar |
| `THashFNV1a32`    | `THashFNV1a32Fast`    | Scalar |
| `THashFNV1a64`    | `THashFNV1a64Fast`    | Scalar |

Every algorithm also has a portable Pascal implementation. That is the
fallback on non-x86 platforms, and the tests use it as a reference. The code
path is chosen at start-up from CPUID/XGETBV, and every path is built for
both Win32 and Win64.

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

## Files

| Path | Purpose |
|------|---------|
| `FastHash.pas` | The public records (`THash*Fast`), level control (`FastHashSetMaxLevel`, `FastHashActiveLevel`). |
| `FastHash.CPU.pas` | CPU/OS feature detection, the `TFastHashLevel` enum, aligned constant blocks. |
| `FastHash.MD5.pas`, `.SHA1.pas`, `.SHA256.pas`, `.SHA512.pas`, `.NonCrypto.pas` | Per-algorithm block functions: Pascal reference, asm cores, dispatch. |
| `Asm\*.x86.inc`, `Asm\*.x64.inc` | The generated asm (checked in). |
| `Tools\gen_*.pl` | Perl generators for the unrolled asm (Perl ships with Git for Windows). Run from this folder, e.g. `perl Tools\gen_sha256.pl`. |
| `Tests\FastHashTests.dpr` | DUnitX test project. |
| `Bench\FastHashBench.dpr` | Benchmark against System.Hash and Indy. |
| `build.cmd` | Builds the tests and the benchmark for Win32 and Win64 into `Win32\Release` and `Win64\Release`. |

The SHA and MD5 cores are fully unrolled. Writing several thousand lines of
asm by hand would be error-prone, so they come from small Perl scripts that
emit Delphi `asm` blocks. Building needs only Delphi; edit the generators and
re-run them only if you change the asm.

## API notes

- The records mirror the RTL method for method, including all overloads,
  default parameters, `GetHMAC`/`GetHMACAsBytes`, stream and file hashing,
  `GetBlockSize`/`GetHashSize`, and the BobJenkins/FNV `Reset(seed)`,
  `GetHashValue`, `HashAsInteger` and `RawByteString` overloads.
- RTL behaviour that is reproduced on purpose:
  - `Update(string)` hashes UTF-8 for MD5/SHA, but the raw UTF-16 bytes
    for BobJenkins/FNV-1a.
  - `THashBobJenkinsFast.Update` re-hashes each chunk seeded with the
    previous value, so it is not a streaming hash.
  - `HashAsString` is lower-case hex for MD5/SHA and upper-case
    (`IntToHex`) for BobJenkins/FNV-1a.
  - The digest can be read repeatedly. `Update` after the digest has been
    read raises `EFastHashException` (the RTL raises `EHashException`).
- The unit does not use `System.Hash`, so it also works where that unit is
  unavailable.
- `FastHashSetMaxLevel(fhlScalar)` (or `fhlPascal`, `fhlAVX2`) lowers the
  fastest path each algorithm may use. It exists for testing and
  benchmarking, and is not thread-safe.

## Implementation

All asm functions process a run of whole blocks:
`Compress(State, Data, Blocks)`. Pascal code does the buffering and
padding, and hands each `Update`'s complete blocks to the asm in one call.

- **MD5:** unrolled integer rounds. The G step uses the disjoint-bits form
  `(b and d) + (c and not d)`, which shortens the critical path. MD5 is one
  long dependency chain, so SIMD cannot help.
- **SHA-1 / SHA-256 Scalar:** unrolled integer rounds with a 16-word
  circular message schedule. Maj is computed from the previous round's
  `a xor b`. Win32 has only seven usable registers, so SHA-256 keeps `a`
  and `e` in registers and the other six variables in a stack ring whose
  slot names rotate with the round number; no data moves between rounds.
- **AVX2 (SHA-1, SHA-256, SHA-512):** the message schedule (W+K) for two
  blocks is computed together in ymm registers, with block A in the low
  128-bit lane and block B in the high lane. The schedule for A is
  interleaved with A's rounds, and block B's rounds then read
  already-computed W+K. The rounds use BMI1/BMI2 (`rorx`, `andn`), and
  Ch is added before Σ1 to keep the `e` chain short.
- **SHA-NI (SHA-1, SHA-256):** the Intel SHA extensions
  (`sha1rnds4`/`sha1nexte`/`sha1msg1/2`, `sha256rnds2`/`sha256msg1/2`).
  They are used on Intel Goldmont and newer Atom/Celeron/Pentium cores,
  Ice Lake and later Core CPUs, and AMD Zen.
- **SHA-512 Scalar:** an SSE2 schedule (two words per xmm), then 64-bit
  integer rounds on Win64. Win32 runs the rounds in the 64-bit lanes of
  xmm registers instead of `add`/`adc` pairs; with AVX2 they use VEX
  encodings.
- **BobJenkins / FNV-1a:** unrolled, register-only loops. FNV-1a is a
  strict xor→multiply chain per byte, so on Win64 and for FNV-1a 32 it is
  latency-bound, and the asm is no faster than the compiler's loop. On
  Win32, FNV-1a 64 replaces the RTL's per-byte call to the 64-bit multiply
  helper with three instructions, because the prime is 2^40 + 0x1B3.
- Win64 asm uses `.PUSHNV`/`.SAVENV` and stack locals, so exceptions
  unwind correctly (checked with a deliberate access violation). Legacy-SSE
  constants live in 64-byte aligned blocks; the VEX code uses named 32-byte
  constant rows.

## Tests

`Tests\FastHashTests.exe`, built by `build.cmd`, is a DUnitX console
runner with 96 tests. Each algorithm test runs once per code level
(`Pascal`, `Scalar`, `AVX2`, `SHANI`):

- **Known-answer vectors:** RFC 1321 (MD5) and FIPS 180 for every
  SHA-1/SHA-2 variant (`""`, `"abc"`, the 448- and 896-bit messages,
  10^6 × `'a'`), each fed as one Update and in pieces. HMAC vectors come
  from RFC 2202 (MD5, SHA-1) and RFC 4231 (SHA-224/256/384/512). Also
  lookup3.c's self-test values and the FNV-1a reference values.
- **Byte-for-byte comparison with System.Hash:**
  - every length from 0 to 300, sparser lengths up to about 4.5 KB, and
    1 MB + 13;
  - random-sized pieces;
  - a 300-byte message split into two Updates at every point;
  - HMAC over a grid of key and data lengths;
  - BobJenkins/FNV-1a for every length 0..300 at four alignments, with
    seeds and chained Updates.
- **API surface:** Unicode strings (including a surrogate pair), streams
  (starting from the current position) and files, every HMAC overload,
  sizes, repeated digest reads, `Reset`, `Update` after the digest, and
  `Update(TBytes, Length)`.

A level the CPU lacks, or that an algorithm doesn't implement, ends with
`Assert.Pass('SKIPPED: ...')`, because DUnitX has no runtime ignore. The
runner then prints which levels actually ran, for example:

```
Code paths exercised (tests per algorithm @ level):
  SHA-256 @ AVX2: ran                                                       6
  SHA-256 @ SHANI: skipped (this CPU lacks SHANI)                           6
```

Results: all 96 tests pass on Win32 and Win64 on an i7-10750H
(Pascal/Scalar/AVX2 paths) and on a Celeron J4105, which has SHA-NI but no
AVX (Pascal/Scalar/SHA-NI paths). Together the two machines cover every
path on both platforms.

## Benchmark

```
Win64\Release\FastHashBench.exe          16 MB buffer (default)
Win64\Release\FastHashBench.exe 64       64 MB buffer
```

For each algorithm the benchmark first checks that all contenders produce
the same digest. It then measures three things for every contender: the
large buffer (best and median), 1 KB messages, and 64-byte messages. Each
message is hashed with `Create`/`Update`/`HashAsBytes`, so per-call
overhead shows up. The contenders are:

- System.Hash;
- every FastHash level the CPU supports;
- Indy: `TIdHashMessageDigest5` and `TIdHashSHA1` always (native code, or
  OpenSSL when it can be loaded). `TIdHashSHA224/256/384/512` exist only
  through OpenSSL 1.0.x (`libeay32.dll`/`ssleay32.dll`), so they show as
  `n/a` without those DLLs. Indy has no SHA-512/224, SHA-512/256,
  BobJenkins or FNV-1a.

Indy hashers are created once and reused. With `IdSSLOpenSSL` linked but
no OpenSSL DLLs present, constructing an Indy hash object costs about 4 ms
because it retries loading the DLLs, which would otherwise swamp the
per-message numbers.

### Results

Speedups below are vs `System.Hash` on a 16 MB buffer (best of several
runs), using the fastest path each CPU supports. Each column gives the
speedup, with the path name and absolute MB/s where shown.

| Algorithm | i7-10750H Win64 | i7-10750H Win32 | Celeron J4105 Win64 | Celeron J4105 Win32 |
|-----------|----------------:|----------------:|--------------------:|--------------------:|
| MD5         | 7.0× (Scalar, 592 MB/s) | 5.7× | 5.8× (Scalar, 113 MB/s) | 6.2× |
| SHA-1       | 6.1× (AVX2, 673 MB/s)   | 3.9× | **17.8×** (SHA-NI, 328 MB/s) | **16.0×** |
| SHA-224     | 3.3× (AVX2)             | 3.1× | **11.6×** (SHA-NI, 138 MB/s) | **11.0×** |
| SHA-256     | 3.6× (AVX2, 307 MB/s)   | 3.6× | **11.6×** (SHA-NI, 138 MB/s) | **11.0×** |
| SHA-384     | 3.7× (AVX2, 468 MB/s)   | 6.7× | 2.4× (Scalar, 46 MB/s) | 5.3× |
| SHA-512     | 3.0× (AVX2, 404 MB/s)   | 5–7× | 2.4× (Scalar, 46 MB/s) | 5.2× |
| SHA-512/224 | 3.2× (AVX2)             | 5.7× | 2.4× | 5.0× |
| SHA-512/256 | 3.9× (AVX2)             | 5.6× | 2.5× | 5.2× |
| BobJenkins  | 4.4× (2.1 GB/s)         | 2.5–3.4× | 3.7× | 3.7× |
| FNV-1a 32   | 1.0×                    | 1.0–1.1× | 1.0× | 1.0× |
| FNV-1a 64   | 1.0×                    | **2.4–3.1×** | 1.0× | **3.1×** |

Per-message overhead is lower too. For 64-byte messages hashed with
Create/Update/HashAsBytes, the speedups are about 2–5× for MD5/SHA, and
up to 5.8× with SHA-NI.

Indy, measured without OpenSSL DLLs (native Pascal):
- `TIdHashMessageDigest5`: 1.5–2.3× System.Hash.
- `TIdHashSHA1`: about 1.0×.

So FastHash is roughly 3× Indy's MD5, about 6× Indy's SHA-1 with AVX2,
and about 17× with SHA-NI. Indy's SHA-2 needs OpenSSL, so it was `n/a`
on both machines.

Notes on the numbers:
- **The i7 laptop throttles.** It runs the Balanced power plan at about
  2.2 GHz with background load, so its absolute MB/s moved by up to 30%
  between runs, and whichever path ran later sometimes looked slower.
  Measured back to back under identical conditions, AVX2 was faster than
  Scalar for every algorithm on both platforms. On a cache-resident
  256 KB buffer, Win64 was:
  - SHA-1: Scalar 477, AVX2 727 MB/s;
  - SHA-256: Scalar 263, AVX2 340 MB/s;
  - SHA-512: Scalar 317, AVX2 508 MB/s.
  The Celeron runs (quiet machine, best ≈ median) are the steadier
  reference.
- **Win32 SHA-512 family:** the RTL is slow on Win32 because 64-bit
  arithmetic in Delphi's 32-bit code generator is poor, so the speedup is
  larger there.
- **FNV-1a:** the hash is a strict serial xor→multiply chain, so nothing
  beats the compiler's loop except Win32 FNV-1a 64, where the RTL calls a
  64-bit multiply helper for every byte.
- **The Celeron (Goldmont Plus)** has SHA-NI but no AVX. SHA-1 and
  SHA-256 use SHA-NI there, and SHA-512 uses the SSE2 scalar path.

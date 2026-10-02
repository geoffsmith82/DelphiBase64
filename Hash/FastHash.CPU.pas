unit FastHash.CPU;

{
  ============================================================================
  FastHash.CPU - runtime CPU feature detection and code-path levels
  ============================================================================

  Every hash in FastHash has up to four kinds of implementation ("levels"):

    fhlPascal  portable Pascal reference (any CPU, any platform)
    fhlScalar  integer assembly: x86/x64 (Windows) or AArch64 (macOS, iOS,
               Android)
    fhlSIMD    x86: AVX2 vectorised message schedule + BMI1/BMI2 rounds
    fhlCrypto  dedicated hash instructions: Intel SHA extensions (SHA-1,
               SHA-256) or the ARMv8 Cryptographic Extension (SHA-1,
               SHA-256, and SHA-512 where the CPU has ARMv8.2-SHA512)

  At unit initialisation each algorithm binds the best level the CPU and OS
  support. FastHashSetMaxLevel (FastHash.pas) can lower that ceiling, which
  the tests and the benchmark use to exercise every path.

  x86/x64 assembly is Delphi inline asm, so it is only built for Windows
  (Delphi's macOS/Linux x64 compilers have no inline assembler; those
  targets use Pascal). The AArch64 code lives in Arm\fasthash_arm64.S and
  Arm\fasthash_arm64.c, compiled by clang into one object per platform
  (Arm\build_arm64.sh) that the Delphi ARM64 targets link.
  ============================================================================
}

interface

{$I FastHash.inc}

type
  TFastHashLevel = (fhlPascal, fhlScalar, fhlSIMD, fhlCrypto);
  TFastHashLevels = set of TFastHashLevel;

  /// <summary>A block function: compresses Blocks whole blocks of Data into State.</summary>
  TFastHashBlockProc = procedure(State: Pointer; Data: PByte; Blocks: NativeUInt);

  /// <summary>One implementation of a block function, as listed by the
  /// XxxImplementations functions of the algorithm units. Several may share a
  /// level (e.g. the hand-written assembly and the C version on ARM64).</summary>
  TFastHashBlockImpl = record
    Name: string;
    Level: TFastHashLevel;
    Proc: TFastHashBlockProc;
  end;

const
  // the level names used by earlier versions
  fhlAVX2 = fhlSIMD;
  fhlSHANI = fhlCrypto;

{$IFDEF FASTHASH_ARM64}
  /// <summary>The clang-built object holding the AArch64 kernels for this platform.</summary>
  {$IF defined(ANDROID)}
  FastHashArmObj = 'fasthash_android_arm64.o';
  {$ELSEIF defined(IOSSIMULATOR)}
  FastHashArmObj = 'fasthash_iossim_arm64.o';
  {$ELSEIF defined(IOS)}
  FastHashArmObj = 'fasthash_ios_arm64.o';
  {$ELSE}
  FastHashArmObj = 'fasthash_macos_arm64.o';
  {$ENDIF}
{$ENDIF}

var
  CPUHasSSE2: Boolean;
  CPUHasSSSE3: Boolean;
  CPUHasSSE41: Boolean;
  CPUHasAVX: Boolean;
  CPUHasAVX2: Boolean;
  CPUHasBMI1: Boolean;
  CPUHasBMI2: Boolean;
  /// <summary>x86: Intel SHA extensions. ARM64: FEAT_SHA1 and FEAT_SHA256.</summary>
  CPUHasSHA: Boolean;
  /// <summary>ARM64: FEAT_SHA512 (ARMv8.2 SHA512H/SHA512H2/SHA512SU0/SHA512SU1).</summary>
  CPUHasSHA512: Boolean;
  /// <summary>The OS saves the YMM registers on context switch (XCR0 bits 1 and 2).</summary>
  OSHasYMM: Boolean;

/// <summary>The levels this CPU/OS can run. fhlPascal is always present.
/// An algorithm may still not implement a level (FastHashActiveLevel tells).</summary>
function FastHashSupportedLevels: TFastHashLevels;
/// <summary>The levels this build has code for, whatever the CPU: all four on
/// Windows x86/x64; Pascal, Scalar and Crypto on ARM64; Pascal elsewhere.</summary>
function FastHashPlatformLevels: TFastHashLevels;
/// <summary>The platform's name for a level: 'Pascal', 'Scalar', then 'AVX2'
/// and 'SHA-NI' on x86, or 'NEON' and 'ARMv8-CE' on ARM64.</summary>
function FastHashLevelName(Level: TFastHashLevel): string;
/// <summary>Parses a level name, case-insensitive: the generic names
/// ('Pascal', 'Scalar', 'SIMD', 'Crypto') or any platform name
/// ('AVX2', 'SHANI', 'SHA-NI', 'NEON', 'ARMv8-CE', 'CE').</summary>
function FastHashLevelFromName(const Name: string): TFastHashLevel;
/// <summary>A short description of the detected features, e.g. 'SSE2 SSSE3 AVX2 BMI2'.</summary>
function FastHashCPUFeatures: string;
/// <summary>Copies Size bytes of constants to a 64-byte aligned block that lives
/// until the program ends. The asm cores read their tables from such blocks
/// because legacy-SSE memory operands must be 16-byte aligned.</summary>
function FastHashAlignedConst(const Src; Size: Integer): Pointer;
/// <summary>Builds a TFastHashBlockImpl.</summary>
function FastHashImpl(const Name: string; Level: TFastHashLevel; Proc: TFastHashBlockProc): TFastHashBlockImpl;
/// <summary>Picks the implementation to use: the first one in Impls (which lists
/// them in order of preference) at the highest level not above MaxLevel.
/// Impls always contains a Pascal entry, so this never fails.</summary>
function FastHashSelect(const Impls: TArray<TFastHashBlockImpl>; MaxLevel: TFastHashLevel): TFastHashBlockImpl;

implementation

uses
  System.SysUtils;

{$IFDEF FASTHASH_X86ASM}
type
  TCPUIDRegs = record
    EAX, EBX, ECX, EDX: Cardinal;
  end;

procedure GetCPUID(Leaf, SubLeaf: Cardinal; var R: TCPUIDRegs);
asm
{$IFDEF CPUX64}
    // ecx = Leaf, edx = SubLeaf, r8 = @R
    mov   r9, rbx
    mov   eax, ecx
    mov   ecx, edx
    cpuid
    mov   [r8], eax
    mov   [r8 + 4], ebx
    mov   [r8 + 8], ecx
    mov   [r8 + 12], edx
    mov   rbx, r9
{$ELSE}
    // eax = Leaf, edx = SubLeaf, ecx = @R
    push  ebx
    push  edi
    mov   edi, ecx
    mov   ecx, edx
    cpuid
    mov   [edi], eax
    mov   [edi + 4], ebx
    mov   [edi + 8], ecx
    mov   [edi + 12], edx
    pop   edi
    pop   ebx
{$ENDIF}
end;

// Low 32 bits of XCR0. Only called when CPUID reports OSXSAVE.
function GetXCR0Low: Cardinal;
asm
    xor   ecx, ecx
    db    $0F, $01, $D0       // xgetbv
end;

procedure DetectCPU;
var
  R: TCPUIDRegs;
  MaxLeaf: Cardinal;
  HasOSXSAVE: Boolean;
begin
  GetCPUID(0, 0, R);
  MaxLeaf := R.EAX;
  if MaxLeaf < 1 then
    Exit;

  GetCPUID(1, 0, R);
  CPUHasSSE2  := (R.EDX and (1 shl 26)) <> 0;
  CPUHasSSSE3 := (R.ECX and (1 shl 9)) <> 0;
  CPUHasSSE41 := (R.ECX and (1 shl 19)) <> 0;
  HasOSXSAVE  := (R.ECX and (1 shl 27)) <> 0;
  CPUHasAVX   := (R.ECX and (1 shl 28)) <> 0;

  OSHasYMM := HasOSXSAVE and ((GetXCR0Low and 6) = 6);

  if MaxLeaf >= 7 then
  begin
    GetCPUID(7, 0, R);
    CPUHasBMI1 := (R.EBX and (1 shl 3)) <> 0;
    CPUHasAVX2 := (R.EBX and (1 shl 5)) <> 0;
    CPUHasBMI2 := (R.EBX and (1 shl 8)) <> 0;
    CPUHasSHA  := (R.EBX and (1 shl 29)) <> 0;
  end;
end;
{$ENDIF}

{$IFDEF FASTHASH_ARM64}
// sysctlbyname on Apple, getauxval(AT_HWCAP) on Android; see fasthash_arm64.c
function fh_arm64_features: Cardinal; external FastHashArmObj name 'fh_arm64_features';

procedure DetectCPU;
var
  F: Cardinal;
begin
  F := fh_arm64_features;
  CPUHasSHA := (F and 3) = 3;           // FEAT_SHA1 and FEAT_SHA256
  CPUHasSHA512 := (F and 4) <> 0;
end;
{$ENDIF}

function FastHashSupportedLevels: TFastHashLevels;
begin
  Result := [fhlPascal];
{$IFDEF FASTHASH_X86ASM}
  if CPUHasSSE2 then
    Include(Result, fhlScalar);
  if CPUHasSSE2 and CPUHasAVX and CPUHasAVX2 and CPUHasBMI1 and CPUHasBMI2 and OSHasYMM then
    Include(Result, fhlSIMD);
  if CPUHasSSE2 and CPUHasSSSE3 and CPUHasSSE41 and CPUHasSHA then
    Include(Result, fhlCrypto);
{$ENDIF}
{$IFDEF FASTHASH_ARM64}
  Include(Result, fhlScalar);
  if CPUHasSHA or CPUHasSHA512 then
    Include(Result, fhlCrypto);
{$ENDIF}
end;

function FastHashPlatformLevels: TFastHashLevels;
begin
{$IF defined(FASTHASH_X86ASM)}
  Result := [fhlPascal, fhlScalar, fhlSIMD, fhlCrypto];
{$ELSEIF defined(FASTHASH_ARM64)}
  Result := [fhlPascal, fhlScalar, fhlCrypto];
{$ELSE}
  Result := [fhlPascal];
{$ENDIF}
end;

function FastHashLevelName(Level: TFastHashLevel): string;
const
{$IFDEF CPUARM64}
  Names: array[TFastHashLevel] of string = ('Pascal', 'Scalar', 'NEON', 'ARMv8-CE');
{$ELSE}
  Names: array[TFastHashLevel] of string = ('Pascal', 'Scalar', 'AVX2', 'SHA-NI');
{$ENDIF}
begin
  Result := Names[Level];
end;

function FastHashLevelFromName(const Name: string): TFastHashLevel;
const
  Aliases: array[0..11] of record S: string; L: TFastHashLevel end = (
    (S: 'Pascal'; L: fhlPascal), (S: 'Scalar'; L: fhlScalar),
    (S: 'SIMD'; L: fhlSIMD), (S: 'AVX2'; L: fhlSIMD), (S: 'NEON'; L: fhlSIMD),
    (S: 'Crypto'; L: fhlCrypto), (S: 'SHANI'; L: fhlCrypto), (S: 'SHA-NI'; L: fhlCrypto),
    (S: 'ARMv8-CE'; L: fhlCrypto), (S: 'CE'; L: fhlCrypto), (S: 'ARMCE'; L: fhlCrypto),
    (S: 'HW'; L: fhlCrypto));
var
  I: Integer;
begin
  for I := Low(Aliases) to High(Aliases) do
    if SameText(Name, Aliases[I].S) then
      Exit(Aliases[I].L);
  raise EArgumentException.CreateFmt('Unknown FastHash level "%s"', [Name]);
end;

function FastHashCPUFeatures: string;

  procedure Add(Has: Boolean; const S: string);
  begin
    if Has then
      Result := Result + S + ' ';
  end;

begin
  Result := '';
{$IFDEF CPUARM64}
  Add(True, 'NEON');
  Add(CPUHasSHA, 'SHA1 SHA256');
  Add(CPUHasSHA512, 'SHA512');
{$ELSE}
  Add(CPUHasSSE2, 'SSE2');
  Add(CPUHasSSSE3, 'SSSE3');
  Add(CPUHasSSE41, 'SSE4.1');
  Add(CPUHasAVX, 'AVX');
  Add(CPUHasAVX2, 'AVX2');
  Add(CPUHasBMI1, 'BMI1');
  Add(CPUHasBMI2, 'BMI2');
  Add(CPUHasSHA, 'SHA');
  Add(OSHasYMM, 'OS-YMM');
{$ENDIF}
  Result := Trim(Result);
  if Result = '' then
    Result := '(none detected)';
end;

var
  ConstBlocks: array of Pointer;

function FastHashAlignedConst(const Src; Size: Integer): Pointer;
var
  Raw: Pointer;
begin
  GetMem(Raw, Size + 64);
  SetLength(ConstBlocks, Length(ConstBlocks) + 1);
  ConstBlocks[High(ConstBlocks)] := Raw;
  Result := Pointer((NativeUInt(Raw) + 63) and not NativeUInt(63));
  Move(Src, Result^, Size);
end;

procedure FreeConstBlocks;
var
  P: Pointer;
begin
  for P in ConstBlocks do
    FreeMem(P);
  ConstBlocks := nil;
end;

function FastHashImpl(const Name: string; Level: TFastHashLevel; Proc: TFastHashBlockProc): TFastHashBlockImpl;
begin
  Result.Name := Name;
  Result.Level := Level;
  Result.Proc := Proc;
end;

function FastHashSelect(const Impls: TArray<TFastHashBlockImpl>; MaxLevel: TFastHashLevel): TFastHashBlockImpl;
var
  L: TFastHashLevel;
  I: Integer;
begin
  for L := MaxLevel downto Low(TFastHashLevel) do
    for I := 0 to High(Impls) do
      if Impls[I].Level = L then
        Exit(Impls[I]);
  raise EArgumentException.Create('FastHashSelect: no implementation available');
end;

initialization
{$IF defined(FASTHASH_X86ASM) or defined(FASTHASH_ARM64)}
  DetectCPU;
{$ENDIF}

finalization
  FreeConstBlocks;

end.

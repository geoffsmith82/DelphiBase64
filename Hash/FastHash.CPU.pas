unit FastHash.CPU;

{
  ============================================================================
  FastHash.CPU - runtime CPU feature detection and code-path levels
  ============================================================================

  Every hash in FastHash has up to four implementations ("levels"):

    fhlPascal  portable Pascal reference (any CPU, any platform)
    fhlScalar  hand-written x86/x64 integer asm (needs SSE2, which every x64
               CPU and every Win32 CPU Delphi still targets has)
    fhlAVX2    AVX2 vectorised message schedule + BMI1/BMI2 rounds
    fhlSHANI   Intel SHA extensions (SHA-1 and SHA-256 only)

  At unit initialisation each algorithm binds the highest level the CPU and
  OS support. FastHashSetMaxLevel (in FastHash.pas) can lower that ceiling,
  which the tests and the benchmark use to exercise every path.
  ============================================================================
}

interface

type
  TFastHashLevel = (fhlPascal, fhlScalar, fhlAVX2, fhlSHANI);
  TFastHashLevels = set of TFastHashLevel;

var
  CPUHasSSE2: Boolean;
  CPUHasSSSE3: Boolean;
  CPUHasSSE41: Boolean;
  CPUHasAVX: Boolean;
  CPUHasAVX2: Boolean;
  CPUHasBMI1: Boolean;
  CPUHasBMI2: Boolean;
  CPUHasSHA: Boolean;
  /// <summary>The OS saves the YMM registers on context switch (XCR0 bits 1 and 2).</summary>
  OSHasYMM: Boolean;

/// <summary>The levels this CPU/OS can run. fhlPascal is always present.</summary>
function FastHashSupportedLevels: TFastHashLevels;
function FastHashLevelName(Level: TFastHashLevel): string;
/// <summary>Parses a level name ('Pascal', 'Scalar', 'AVX2', 'SHANI'), case-insensitive.</summary>
function FastHashLevelFromName(const Name: string): TFastHashLevel;
/// <summary>A short description of the detected features, e.g. 'SSE2 SSSE3 AVX2 BMI2'.</summary>
function FastHashCPUFeatures: string;
/// <summary>Copies Size bytes of constants to a 64-byte aligned block that lives
/// until the program ends. The asm cores read their tables from such blocks
/// because legacy-SSE memory operands must be 16-byte aligned.</summary>
function FastHashAlignedConst(const Src; Size: Integer): Pointer;

implementation

uses
  System.SysUtils;

{$IF defined(CPUX86) or defined(CPUX64)}
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

function FastHashSupportedLevels: TFastHashLevels;
begin
  Result := [fhlPascal];
{$IF defined(CPUX86) or defined(CPUX64)}
  if CPUHasSSE2 then
    Include(Result, fhlScalar);
  if CPUHasSSE2 and CPUHasAVX and CPUHasAVX2 and CPUHasBMI1 and CPUHasBMI2 and OSHasYMM then
    Include(Result, fhlAVX2);
  if CPUHasSSE2 and CPUHasSSSE3 and CPUHasSSE41 and CPUHasSHA then
    Include(Result, fhlSHANI);
{$ENDIF}
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

function FastHashLevelName(Level: TFastHashLevel): string;
const
  Names: array[TFastHashLevel] of string = ('Pascal', 'Scalar', 'AVX2', 'SHANI');
begin
  Result := Names[Level];
end;

function FastHashLevelFromName(const Name: string): TFastHashLevel;
var
  L: TFastHashLevel;
begin
  for L := Low(TFastHashLevel) to High(TFastHashLevel) do
    if SameText(Name, FastHashLevelName(L)) then
      Exit(L);
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
  Add(CPUHasSSE2, 'SSE2');
  Add(CPUHasSSSE3, 'SSSE3');
  Add(CPUHasSSE41, 'SSE4.1');
  Add(CPUHasAVX, 'AVX');
  Add(CPUHasAVX2, 'AVX2');
  Add(CPUHasBMI1, 'BMI1');
  Add(CPUHasBMI2, 'BMI2');
  Add(CPUHasSHA, 'SHA');
  Add(OSHasYMM, 'OS-YMM');
  Result := Trim(Result);
end;

initialization
{$IF defined(CPUX86) or defined(CPUX64)}
  DetectCPU;
{$ENDIF}

finalization
  FreeConstBlocks;

end.

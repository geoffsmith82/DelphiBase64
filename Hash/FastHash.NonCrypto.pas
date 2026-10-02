unit FastHash.NonCrypto;

{
  Non-cryptographic hashes from System.Hash: Bob Jenkins' lookup3
  "hashlittle", FNV-1a 32-bit and FNV-1a 64-bit. Each has a Pascal reference
  and hand-written assembly: x86/x64 (Windows) and AArch64, plus a C version
  on AArch64 (Armasthash_arm64.c); each function uses whichever of its
  implementations benchmarked fastest.

  All three are a single serial dependency chain (FNV-1a is xor-then-multiply
  per byte), so there is nothing for SIMD to parallelise. The asm wins come
  from unrolling, keeping everything in registers, and - for FNV-1a 64 on
  Win32 - replacing the RTL's per-byte call to the 64-bit multiply helper
  with a three-instruction multiply by the sparse FNV prime (2^40 + $1B3).
}

interface

{$I FastHash.inc}

uses
  FastHash.CPU;

type
  TBobJenkinsProc = function(Data: Pointer; Len: Integer; InitVal: Integer): Integer;
  TFNV1a32Proc = function(Data: Pointer; Len: Cardinal; Seed: Cardinal): Cardinal;
  TFNV1a64Proc = function(Data: Pointer; Len: Cardinal; Seed: UInt64): UInt64;

  /// <summary>One implementation of one of the functions (see TFastHashBlockImpl).</summary>
  TNonCryptoImpl<T> = record
    Name: string;
    Level: TFastHashLevel;
    Proc: T;
    class function Make(const AName: string; ALevel: TFastHashLevel; AProc: T): TNonCryptoImpl<T>; static;
  end;

var
  /// <summary>lookup3 hashlittle, identical to THashBobJenkins.HashLittle.</summary>
  BobJenkinsHashLittle: TBobJenkinsProc;
  FNV1a32Hash: TFNV1a32Proc;
  FNV1a64Hash: TFNV1a64Proc;

function BobJenkinsHashLittlePascal(Data: Pointer; Len: Integer; InitVal: Integer): Integer;
function FNV1a32HashPascal(Data: Pointer; Len: Cardinal; Seed: Cardinal): Cardinal;
function FNV1a64HashPascal(Data: Pointer; Len: Cardinal; Seed: UInt64): UInt64;

function NonCryptoSetMaxLevel(MaxLevel: TFastHashLevel): TFastHashLevel;
function NonCryptoActiveLevel: TFastHashLevel;
/// <summary>Names of the implementations in use, e.g. 'BobJenkins: A64 asm, FNV-1a 32: C, ...'.</summary>
function NonCryptoActiveImplementation: string;

/// <summary>Every implementation this CPU can run, Pascal first, in order of
/// preference within each level.</summary>
function BobJenkinsImplementations: TArray<TNonCryptoImpl<TBobJenkinsProc>>;
function FNV1a32Implementations: TArray<TNonCryptoImpl<TFNV1a32Proc>>;
function FNV1a64Implementations: TArray<TNonCryptoImpl<TFNV1a64Proc>>;

implementation

{$Q-}{$R-}

type
  TNonCryptoSelect<T> = record
    /// <summary>The first implementation at the highest level not above MaxLevel.</summary>
    class function Select(const Impls: TArray<TNonCryptoImpl<T>>; MaxLevel: TFastHashLevel): TNonCryptoImpl<T>; static;
  end;

var
  ActiveLevel: TFastHashLevel;
  ActiveNames: string;

{ ---------------------------------------------------------------------------
  Pascal references
  --------------------------------------------------------------------------- }

{$POINTERMATH ON}
function BobJenkinsHashLittlePascal(Data: Pointer; Len: Integer; InitVal: Integer): Integer;

  function Rot(x, k: Cardinal): Cardinal; inline;
  begin
    Result := (x shl k) or (x shr (32 - k));
  end;

var
  P: PByte;
  a, b, c: Cardinal;
  Tail: array[0..11] of Byte;
begin
  a := Cardinal($DEADBEEF) + Cardinal(Len) + Cardinal(InitVal);
  b := a;
  c := a;
  if Len = 0 then
    Exit(Integer(c));
  P := Data;
  if Len > 0 then
  begin
    while Len > 12 do
    begin
      Inc(a, PCardinal(P)[0]);
      Inc(b, PCardinal(P)[1]);
      Inc(c, PCardinal(P)[2]);
      Dec(a, c); a := a xor Rot(c, 4); Inc(c, b);
      Dec(b, a); b := b xor Rot(a, 6); Inc(a, c);
      Dec(c, b); c := c xor Rot(b, 8); Inc(b, a);
      Dec(a, c); a := a xor Rot(c, 16); Inc(c, b);
      Dec(b, a); b := b xor Rot(a, 19); Inc(a, c);
      Dec(c, b); c := c xor Rot(b, 4); Inc(b, a);
      Dec(Len, 12);
      Inc(P, 12);
    end;
    // the final 1..12 bytes, zero-padded, little-endian
    FillChar(Tail, SizeOf(Tail), 0);
    Move(P^, Tail, Len);
    Inc(a, PCardinal(@Tail)[0]);
    Inc(b, PCardinal(@Tail)[1]);
    Inc(c, PCardinal(@Tail)[2]);
  end;
  c := c xor b; Dec(c, Rot(b, 14));
  a := a xor c; Dec(a, Rot(c, 11));
  b := b xor a; Dec(b, Rot(a, 25));
  c := c xor b; Dec(c, Rot(b, 16));
  a := a xor c; Dec(a, Rot(c, 4));
  b := b xor a; Dec(b, Rot(a, 14));
  c := c xor b; Dec(c, Rot(b, 24));
  Result := Integer(c);
end;
{$POINTERMATH OFF}

function FNV1a32HashPascal(Data: Pointer; Len: Cardinal; Seed: Cardinal): Cardinal;
var
  P, PEnd: PByte;
begin
  Result := Seed;
  P := Data;
  PEnd := P + Len;
  while P < PEnd do
  begin
    Result := (Result xor P^) * $01000193;
    Inc(P);
  end;
end;

function FNV1a64HashPascal(Data: Pointer; Len: Cardinal; Seed: UInt64): UInt64;
var
  P, PEnd: PByte;
begin
  Result := Seed;
  P := Data;
  PEnd := P + Len;
  while P < PEnd do
  begin
    Result := (Result xor P^) * UInt64($00000100000001B3);
    Inc(P);
  end;
end;

{ ---------------------------------------------------------------------------
  asm
  --------------------------------------------------------------------------- }

{$IF defined(FASTHASH_X86ASM) and defined(CPUX64)}

function BobJenkinsHashLittleAsm(Data: Pointer; Len: Integer; InitVal: Integer): Integer;
var
  Tail: array[0..1] of UInt64;
asm
    // rcx = Data, edx = Len, r8d = InitVal; a = eax, b = r9d, c = r10d, t = r11d
    mov   eax, $DEADBEEF
    add   eax, edx
    add   eax, r8d
    mov   r9d, eax
    mov   r10d, eax
    test  edx, edx
    jz    @retc
    js    @final                  // negative length: no data, just the final mix
    cmp   edx, 12
    jle   @tail
@loop:
    add   eax, [rcx]
    add   r9d, [rcx + 4]
    add   r10d, [rcx + 8]
    // mix(a, b, c)
    sub   eax, r10d
    mov   r11d, r10d
    rol   r11d, 4
    xor   eax, r11d
    add   r10d, r9d
    sub   r9d, eax
    mov   r11d, eax
    rol   r11d, 6
    xor   r9d, r11d
    add   eax, r10d
    sub   r10d, r9d
    mov   r11d, r9d
    rol   r11d, 8
    xor   r10d, r11d
    add   r9d, eax
    sub   eax, r10d
    mov   r11d, r10d
    rol   r11d, 16
    xor   eax, r11d
    add   r10d, r9d
    sub   r9d, eax
    mov   r11d, eax
    rol   r11d, 19
    xor   r9d, r11d
    add   eax, r10d
    sub   r10d, r9d
    mov   r11d, r9d
    rol   r11d, 4
    xor   r10d, r11d
    add   r9d, eax
    add   rcx, 12
    sub   edx, 12
    cmp   edx, 12
    jg    @loop
@tail:
    // 1..12 bytes remain
    cmp   edx, 12
    je    @add
    lea   r8, Tail
    mov   qword ptr [r8], 0
    mov   qword ptr [r8 + 8], 0
@copy:
    movzx r11d, byte ptr [rcx]
    mov   [r8], r11b
    inc   rcx
    inc   r8
    dec   edx
    jnz   @copy
    lea   rcx, Tail
@add:
    add   eax, [rcx]
    add   r9d, [rcx + 4]
    add   r10d, [rcx + 8]
@final:
    xor   r10d, r9d
    mov   r11d, r9d
    rol   r11d, 14
    sub   r10d, r11d
    xor   eax, r10d
    mov   r11d, r10d
    rol   r11d, 11
    sub   eax, r11d
    xor   r9d, eax
    mov   r11d, eax
    rol   r11d, 25
    sub   r9d, r11d
    xor   r10d, r9d
    mov   r11d, r9d
    rol   r11d, 16
    sub   r10d, r11d
    xor   eax, r10d
    mov   r11d, r10d
    rol   r11d, 4
    sub   eax, r11d
    xor   r9d, eax
    mov   r11d, eax
    rol   r11d, 14
    sub   r9d, r11d
    xor   r10d, r9d
    mov   r11d, r9d
    rol   r11d, 24
    sub   r10d, r11d
@retc:
    mov   eax, r10d
end;

function FNV1a32HashAsm(Data: Pointer; Len: Cardinal; Seed: Cardinal): Cardinal;
asm
    // rcx = Data, edx = Len, r8d = Seed. Bytes are zero-extended and xor'ed
    // into the full register (partial-register writes stall Atom-class cores).
    mov   eax, r8d
    mov   r9d, edx
    and   r9d, 3                  // trailing bytes
    shr   edx, 2                  // groups of four
    jz    @bytes
@quad:
    movzx r8d, byte ptr [rcx]
    movzx r10d, byte ptr [rcx + 1]
    xor   eax, r8d
    imul  eax, eax, $01000193
    movzx r8d, byte ptr [rcx + 2]
    xor   eax, r10d
    imul  eax, eax, $01000193
    movzx r10d, byte ptr [rcx + 3]
    xor   eax, r8d
    imul  eax, eax, $01000193
    xor   eax, r10d
    imul  eax, eax, $01000193
    add   rcx, 4
    dec   edx
    jnz   @quad
@bytes:
    test  r9d, r9d
    jz    @done
@byte:
    movzx r8d, byte ptr [rcx]
    xor   eax, r8d
    imul  eax, eax, $01000193
    inc   rcx
    dec   r9d
    jnz   @byte
@done:
end;

function FNV1a64HashAsm(Data: Pointer; Len: Cardinal; Seed: UInt64): UInt64;
asm
    // rcx = Data, edx = Len, r8 = Seed
    mov   rax, r8
    mov   r11, $00000100000001B3
    mov   r9d, edx
    and   r9d, 3
    shr   edx, 2
    jz    @bytes
@quad:
    movzx r8d, byte ptr [rcx]
    movzx r10d, byte ptr [rcx + 1]
    xor   rax, r8
    imul  rax, r11
    movzx r8d, byte ptr [rcx + 2]
    xor   rax, r10
    imul  rax, r11
    movzx r10d, byte ptr [rcx + 3]
    xor   rax, r8
    imul  rax, r11
    xor   rax, r10
    imul  rax, r11
    add   rcx, 4
    dec   edx
    jnz   @quad
@bytes:
    test  r9d, r9d
    jz    @done
@byte:
    movzx r8d, byte ptr [rcx]
    xor   rax, r8
    imul  rax, r11
    inc   rcx
    dec   r9d
    jnz   @byte
@done:
end;

{$ELSEIF defined(FASTHASH_X86ASM)}

function BobJenkinsHashLittleAsm(Data: Pointer; Len: Integer; InitVal: Integer): Integer;
asm
    // eax = Data, edx = Len, ecx = InitVal; a = eax, b = ebx, c = ecx, t = edi, p = esi
    push  ebx
    push  esi
    push  edi
    sub   esp, 16                 // tail buffer
    mov   esi, eax
    mov   eax, $DEADBEEF
    add   eax, edx
    add   eax, ecx
    mov   ebx, eax
    mov   ecx, eax
    test  edx, edx
    jz    @retc
    js    @final
    cmp   edx, 12
    jle   @tail
@loop:
    add   eax, [esi]
    add   ebx, [esi + 4]
    add   ecx, [esi + 8]
    sub   eax, ecx
    mov   edi, ecx
    rol   edi, 4
    xor   eax, edi
    add   ecx, ebx
    sub   ebx, eax
    mov   edi, eax
    rol   edi, 6
    xor   ebx, edi
    add   eax, ecx
    sub   ecx, ebx
    mov   edi, ebx
    rol   edi, 8
    xor   ecx, edi
    add   ebx, eax
    sub   eax, ecx
    mov   edi, ecx
    rol   edi, 16
    xor   eax, edi
    add   ecx, ebx
    sub   ebx, eax
    mov   edi, eax
    rol   edi, 19
    xor   ebx, edi
    add   eax, ecx
    sub   ecx, ebx
    mov   edi, ebx
    rol   edi, 4
    xor   ecx, edi
    add   ebx, eax
    add   esi, 12
    sub   edx, 12
    cmp   edx, 12
    jg    @loop
@tail:
    cmp   edx, 12
    je    @add
    mov   edi, esp
    mov   dword ptr [edi], 0
    mov   dword ptr [edi + 4], 0
    mov   dword ptr [edi + 8], 0
@copy:
    push  eax
    movzx eax, byte ptr [esi]
    mov   [edi], al
    pop   eax
    inc   esi
    inc   edi
    dec   edx
    jnz   @copy
    mov   esi, esp
@add:
    add   eax, [esi]
    add   ebx, [esi + 4]
    add   ecx, [esi + 8]
@final:
    xor   ecx, ebx
    mov   edi, ebx
    rol   edi, 14
    sub   ecx, edi
    xor   eax, ecx
    mov   edi, ecx
    rol   edi, 11
    sub   eax, edi
    xor   ebx, eax
    mov   edi, eax
    rol   edi, 25
    sub   ebx, edi
    xor   ecx, ebx
    mov   edi, ebx
    rol   edi, 16
    sub   ecx, edi
    xor   eax, ecx
    mov   edi, ecx
    rol   edi, 4
    sub   eax, edi
    xor   ebx, eax
    mov   edi, eax
    rol   edi, 14
    sub   ebx, edi
    xor   ecx, ebx
    mov   edi, ebx
    rol   edi, 24
    sub   ecx, edi
@retc:
    mov   eax, ecx
    add   esp, 16
    pop   edi
    pop   esi
    pop   ebx
end;

function FNV1a32HashAsm(Data: Pointer; Len: Cardinal; Seed: Cardinal): Cardinal;
asm
    // eax = Data, edx = Len, ecx = Seed. Bytes are zero-extended and xor'ed
    // into the full register (partial-register writes stall Atom-class cores).
    push  ebx
    push  esi
    push  edi
    mov   esi, eax
    mov   eax, ecx
    mov   ecx, edx
    and   ecx, 3
    shr   edx, 2
    jz    @bytes
@quad:
    movzx ebx, byte ptr [esi]
    movzx edi, byte ptr [esi + 1]
    xor   eax, ebx
    imul  eax, eax, $01000193
    movzx ebx, byte ptr [esi + 2]
    xor   eax, edi
    imul  eax, eax, $01000193
    movzx edi, byte ptr [esi + 3]
    xor   eax, ebx
    imul  eax, eax, $01000193
    xor   eax, edi
    imul  eax, eax, $01000193
    add   esi, 4
    dec   edx
    jnz   @quad
@bytes:
    test  ecx, ecx
    jz    @done
@byte:
    movzx ebx, byte ptr [esi]
    xor   eax, ebx
    imul  eax, eax, $01000193
    inc   esi
    dec   ecx
    jnz   @byte
@done:
    pop   edi
    pop   esi
    pop   ebx
end;

// h * (2^40 + $1B3) on a 32-bit CPU: lo' = low32(lo * $1B3),
// hi' = hi * $1B3 + high32(lo * $1B3) + (lo shl 8).
function FNV1a64HashAsm(Data: Pointer; Len: Cardinal; Seed: UInt64): UInt64;
asm
    // eax = Data, edx = Len, Seed on the stack
    push  ebx
    push  esi
    push  edi
    mov   esi, eax
    mov   ecx, edx                // ecx = bytes left
    mov   ebx, dword ptr [Seed]   // lo
    mov   edi, dword ptr [Seed + 4] // hi
    test  ecx, ecx
    jz    @done
    add   ecx, esi                // ecx = end
@byte:
    movzx eax, byte ptr [esi]
    xor   ebx, eax
    mov   eax, $1B3
    mul   ebx
    imul  edi, edi, $1B3
    shl   ebx, 8
    add   edi, ebx
    add   edi, edx
    mov   ebx, eax
    inc   esi
    cmp   esi, ecx
    jb    @byte
@done:
    mov   eax, ebx
    mov   edx, edi
    pop   edi
    pop   esi
    pop   ebx
end;

{$ENDIF}

{$IFDEF FASTHASH_ARM64}
function fh_bobjenkins_asm(Data: Pointer; Len: Integer; InitVal: Integer): Integer; external FastHashArmObj name 'fh_bobjenkins_asm';
function fh_bobjenkins_c(Data: Pointer; Len: Integer; InitVal: Integer): Integer; external FastHashArmObj name 'fh_bobjenkins_c';
function fh_fnv1a32_asm(Data: Pointer; Len: Cardinal; Seed: Cardinal): Cardinal; external FastHashArmObj name 'fh_fnv1a32_asm';
function fh_fnv1a32_c(Data: Pointer; Len: Cardinal; Seed: Cardinal): Cardinal; external FastHashArmObj name 'fh_fnv1a32_c';
function fh_fnv1a64_asm(Data: Pointer; Len: Cardinal; Seed: UInt64): UInt64; external FastHashArmObj name 'fh_fnv1a64_asm';
function fh_fnv1a64_c(Data: Pointer; Len: Cardinal; Seed: UInt64): UInt64; external FastHashArmObj name 'fh_fnv1a64_c';
{$ENDIF}

class function TNonCryptoImpl<T>.Make(const AName: string; ALevel: TFastHashLevel; AProc: T): TNonCryptoImpl<T>;
begin
  Result.Name := AName;
  Result.Level := ALevel;
  Result.Proc := AProc;
end;

// In order of preference within each level (see the README's benchmark notes).

function BobJenkinsImplementations: TArray<TNonCryptoImpl<TBobJenkinsProc>>;
begin
  Result := [TNonCryptoImpl<TBobJenkinsProc>.Make('Pascal', fhlPascal, BobJenkinsHashLittlePascal)];
{$IFDEF FASTHASH_X86ASM}
  if fhlScalar in FastHashSupportedLevels then
    Result := Result + [TNonCryptoImpl<TBobJenkinsProc>.Make('x86 asm', fhlScalar, BobJenkinsHashLittleAsm)];
{$ENDIF}
{$IFDEF FASTHASH_ARM64}
  Result := Result + [TNonCryptoImpl<TBobJenkinsProc>.Make('A64 asm', fhlScalar, fh_bobjenkins_asm),
                      TNonCryptoImpl<TBobJenkinsProc>.Make('C', fhlScalar, fh_bobjenkins_c)];
{$ENDIF}
end;

function FNV1a32Implementations: TArray<TNonCryptoImpl<TFNV1a32Proc>>;
begin
  Result := [TNonCryptoImpl<TFNV1a32Proc>.Make('Pascal', fhlPascal, FNV1a32HashPascal)];
{$IFDEF FASTHASH_X86ASM}
  if fhlScalar in FastHashSupportedLevels then
    Result := Result + [TNonCryptoImpl<TFNV1a32Proc>.Make('x86 asm', fhlScalar, FNV1a32HashAsm)];
{$ENDIF}
{$IFDEF FASTHASH_ARM64}
  Result := Result + [TNonCryptoImpl<TFNV1a32Proc>.Make('A64 asm', fhlScalar, fh_fnv1a32_asm),
                      TNonCryptoImpl<TFNV1a32Proc>.Make('C', fhlScalar, fh_fnv1a32_c)];
{$ENDIF}
end;

function FNV1a64Implementations: TArray<TNonCryptoImpl<TFNV1a64Proc>>;
begin
  Result := [TNonCryptoImpl<TFNV1a64Proc>.Make('Pascal', fhlPascal, FNV1a64HashPascal)];
{$IFDEF FASTHASH_X86ASM}
  if fhlScalar in FastHashSupportedLevels then
    Result := Result + [TNonCryptoImpl<TFNV1a64Proc>.Make('x86 asm', fhlScalar, FNV1a64HashAsm)];
{$ENDIF}
{$IFDEF FASTHASH_ARM64}
  Result := Result + [TNonCryptoImpl<TFNV1a64Proc>.Make('A64 asm', fhlScalar, fh_fnv1a64_asm),
                      TNonCryptoImpl<TFNV1a64Proc>.Make('C', fhlScalar, fh_fnv1a64_c)];
{$ENDIF}
end;

class function TNonCryptoSelect<T>.Select(const Impls: TArray<TNonCryptoImpl<T>>; MaxLevel: TFastHashLevel): TNonCryptoImpl<T>;
var
  L: TFastHashLevel;
  I: Integer;
begin
  for L := MaxLevel downto Low(TFastHashLevel) do
    for I := 0 to High(Impls) do
      if Impls[I].Level = L then
        Exit(Impls[I]);
  Result := Impls[0];
end;

function NonCryptoSetMaxLevel(MaxLevel: TFastHashLevel): TFastHashLevel;
var
  BJ: TNonCryptoImpl<TBobJenkinsProc>;
  F32: TNonCryptoImpl<TFNV1a32Proc>;
  F64: TNonCryptoImpl<TFNV1a64Proc>;
begin
  BJ := TNonCryptoSelect<TBobJenkinsProc>.Select(BobJenkinsImplementations, MaxLevel);
  F32 := TNonCryptoSelect<TFNV1a32Proc>.Select(FNV1a32Implementations, MaxLevel);
  F64 := TNonCryptoSelect<TFNV1a64Proc>.Select(FNV1a64Implementations, MaxLevel);
  BobJenkinsHashLittle := BJ.Proc;
  FNV1a32Hash := F32.Proc;
  FNV1a64Hash := F64.Proc;
  // the three always reach the same level: each has Pascal and Scalar versions
  ActiveLevel := BJ.Level;
  ActiveNames := 'BobJenkins: ' + BJ.Name + ', FNV-1a 32: ' + F32.Name + ', FNV-1a 64: ' + F64.Name;
  Result := ActiveLevel;
end;

function NonCryptoActiveLevel: TFastHashLevel;
begin
  Result := ActiveLevel;
end;

function NonCryptoActiveImplementation: string;
begin
  Result := ActiveNames;
end;

initialization
  NonCryptoSetMaxLevel(High(TFastHashLevel));

end.

unit Base64EncodingPolyFill;

{
  ============================================================================
  TBase64EncodingPolyFill
  ============================================================================

  A self-contained, drop-in replacement for Delphi's built-in
  System.NetEncoding.TBase64Encoding. It exposes the SAME public interface
  (constructors + the Encode/Decode/EncodeBytesToString/DecodeStringToBytes
  methods inherited by TBase64Encoding from TNetEncoding) but performs the
  byte<->base64 transform in hand-written assembly:

    - baseline integer x86/x64 assembly (Win32 + Win64), always available;
    - an AVX2 "turbo" path (encode and decode) selected at runtime via CPUID,
      with the scalar assembly used as the fallback.

  Because it descends from TObject (not from System.NetEncoding), it can be
  used as a polyfill on platforms / compilers where the RTL class is missing,
  and it can be benchmarked head-to-head against the RTL class.

  Output is byte-for-byte identical to TBase64Encoding:
    - Create               -> 76-char MIME lines, CRLF, '=' padded
                              (== TNetEncoding.Base64)
    - Create(0)            -> no line breaks, '=' padded
                              (== TNetEncoding.Base64String)
    - Create(N) / Create(N, Sep) -> N-char lines with the given separator.

  Line wrapping matches TBase64Encoding exactly: a line holds (CharsPerLine
  div 4) full 4-char quanta; a separator follows every full 3-byte group that
  lands on a line boundary (so a full final group on a boundary gets a
  TRAILING separator); the final padded group never gets a trailing separator.

  Scalar cores adapted from the validated VSoft.Base64 polyfill; AVX2 cores
  adapted from the validated Base64AVX2 unit (Mula/Lemire technique).
  ============================================================================
}

interface

uses
  System.Classes,
  System.SysUtils;

type
  TBase64EncodingPolyFill = class
  private
    FCharsPerLine: Integer;
    FLineSeparator: string;
  public
    /// <summary>Default: 76-char MIME lines, CRLF separator, '=' padding
    /// (matches TNetEncoding.Base64).</summary>
    constructor Create; overload; virtual;
    /// <summary>CharsPerLine = 0 disables line breaks (matches
    /// TNetEncoding.Base64String). Separator defaults to CRLF.</summary>
    constructor Create(CharsPerLine: Integer); overload; virtual;
    constructor Create(CharsPerLine: Integer; LineSeparator: string); overload; virtual;

    { ---- public surface mirroring TNetEncoding / TBase64Encoding ---- }

    function Encode(const Input: array of Byte): TBytes; overload;
    function Encode(const Input: string): string; overload;
    function Encode(const Input, Output: TStream): Integer; overload;

    function Decode(const Input: array of Byte): TBytes; overload;
    function Decode(const Input: string): string; overload;
    function Decode(const Input, Output: TStream): Integer; overload;

    function EncodeBytesToString(const Input: array of Byte): string; overload;
    function EncodeBytesToString(const Input: Pointer; Size: Integer): string; overload;

    function DecodeStringToBytes(const Input: string): TBytes;
  end;

/// <summary>True when the running CPU/OS supports the AVX2 turbo path.</summary>
function PolyFillHasAVX2: Boolean;

{ Single-pass fused encode+separator encoders (used by the class for the MIME
  path; also exposed for benchmarking the line-break strategies). lineQuanta =
  CharsPerLine div 4; sep is the 1- or 2-byte separator. Src may be nil when
  Len = 0. Output is byte-identical to TBase64Encoding. }
function MimeEncodeFusedScalar(Src: PByte; Len: NativeInt; lineQuanta: Integer; const sep: TBytes): TBytes;
function MimeEncodeFusedAVX2(Src: PByte; Len: NativeInt; lineQuanta: Integer; const sep: TBytes): TBytes;

implementation

uses
  System.Math;

const
  // Standard base64 alphabet as ANSI bytes (for the byte-oriented cores).
  B64EncTable: array[0..63] of AnsiChar =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

  // ASCII value -> 6-bit value; 255 = invalid; '=' maps to 0 (caller handles padding).
  Base64DecodeTable: array[0..255] of Byte = (
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255, // 0-15
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255, // 16-31
    255,255,255,255,255,255,255,255,255,255,255, 62,255,255,255, 63, // 32-47 (+,/)
     52, 53, 54, 55, 56, 57, 58, 59, 60, 61,255,255,255,  0,255,255, // 48-63 (0-9,=)
    255,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, // 64-79 (A-O)
     15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,255,255,255,255,255, // 80-95 (P-Z)
    255, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, // 96-111 (a-o)
     41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,255,255,255,255,255, // 112-127 (p-z)
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255
  );

  // ---- AVX2 encode constants (Mula/Lemire) ----
  PermIdx: array[0..7] of Cardinal = (0, 1, 2, 3, 3, 4, 5, 6);
  ReshuffleMask: array[0..31] of Byte = (
    1, 0, 2, 1, 4, 3, 5, 4, 7, 6, 8, 7, 10, 9, 11, 10,
    1, 0, 2, 1, 4, 3, 5, 4, 7, 6, 8, 7, 10, 9, 11, 10);
  C_0fc0fc00: array[0..7] of Cardinal =
    ($0fc0fc00, $0fc0fc00, $0fc0fc00, $0fc0fc00, $0fc0fc00, $0fc0fc00, $0fc0fc00, $0fc0fc00);
  C_04000040: array[0..7] of Cardinal =
    ($04000040, $04000040, $04000040, $04000040, $04000040, $04000040, $04000040, $04000040);
  C_003f03f0: array[0..7] of Cardinal =
    ($003f03f0, $003f03f0, $003f03f0, $003f03f0, $003f03f0, $003f03f0, $003f03f0, $003f03f0);
  C_01000010: array[0..7] of Cardinal =
    ($01000010, $01000010, $01000010, $01000010, $01000010, $01000010, $01000010, $01000010);
  C_51: array[0..31] of Byte = (
    51,51,51,51,51,51,51,51,51,51,51,51,51,51,51,51,
    51,51,51,51,51,51,51,51,51,51,51,51,51,51,51,51);
  C_26: array[0..31] of Byte = (
    26,26,26,26,26,26,26,26,26,26,26,26,26,26,26,26,
    26,26,26,26,26,26,26,26,26,26,26,26,26,26,26,26);
  C_13: array[0..31] of Byte = (
    13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,
    13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13);
  ShiftLUT: array[0..31] of Byte = (
    71, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 237, 240, 65, 0, 0,
    71, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 237, 240, 65, 0, 0);

  // ---- AVX2 decode constants (Mula/Lemire) ----
  Mask2F: array[0..31] of Byte = (
    $2F,$2F,$2F,$2F,$2F,$2F,$2F,$2F,$2F,$2F,$2F,$2F,$2F,$2F,$2F,$2F,
    $2F,$2F,$2F,$2F,$2F,$2F,$2F,$2F,$2F,$2F,$2F,$2F,$2F,$2F,$2F,$2F);
  LutRoll: array[0..31] of ShortInt = (
      0,  16,  19,   4, -65, -65, -71, -71,  0, 0, 0, 0, 0, 0, 0, 0,
      0,  16,  19,   4, -65, -65, -71, -71,  0, 0, 0, 0, 0, 0, 0, 0);
  C_01400140: array[0..7] of Cardinal =
    ($01400140, $01400140, $01400140, $01400140, $01400140, $01400140, $01400140, $01400140);
  C_00011000: array[0..7] of Cardinal =
    ($00011000, $00011000, $00011000, $00011000, $00011000, $00011000, $00011000, $00011000);
  DecShuffle: array[0..31] of Byte = (
    2, 1, 0, 6, 5, 4, 10, 9, 8, 14, 13, 12, $FF, $FF, $FF, $FF,
    2, 1, 0, 6, 5, 4, 10, 9, 8, 14, 13, 12, $FF, $FF, $FF, $FF);
  PermStore: array[0..7] of Cardinal = (0, 1, 2, 4, 5, 6, 7, 7);

  // ---- AVX2 decode VALIDITY check (Lemire/Aqrit): a byte is a valid base64
  // alphabet char iff (LutLo[lo_nibble] and LutHi[hi_nibble]) = 0. Whitespace,
  // '=', and any non-alphabet byte give a non-zero result. ----
  C_Mask0F: array[0..31] of Byte = (
    $0F,$0F,$0F,$0F,$0F,$0F,$0F,$0F,$0F,$0F,$0F,$0F,$0F,$0F,$0F,$0F,
    $0F,$0F,$0F,$0F,$0F,$0F,$0F,$0F,$0F,$0F,$0F,$0F,$0F,$0F,$0F,$0F);
  LutLo: array[0..31] of Byte = (
    $15,$11,$11,$11,$11,$11,$11,$11,$11,$11,$13,$1A,$1B,$1B,$1B,$1A,
    $15,$11,$11,$11,$11,$11,$11,$11,$11,$11,$13,$1A,$1B,$1B,$1B,$1A);
  LutHi: array[0..31] of Byte = (
    $10,$10,$01,$02,$04,$08,$04,$08,$10,$10,$10,$10,$10,$10,$10,$10,
    $10,$10,$01,$02,$04,$08,$04,$08,$10,$10,$10,$10,$10,$10,$10,$10);

{ ============================================================================
  CPU feature detection
  ============================================================================ }

function CheckAVX2: Boolean; assembler;
{$IFDEF CPUX64}
asm
    push rbx
    mov  eax, 1
    xor  ecx, ecx
    cpuid
    and  ecx, $18000000        // OSXSAVE (27) + AVX (28)
    cmp  ecx, $18000000
    jne  @no
    xor  ecx, ecx
    db   $0F, $01, $D0         // xgetbv -> EDX:EAX = XCR0
    and  eax, 6                // XMM + YMM state enabled
    cmp  eax, 6
    jne  @no
    mov  eax, 7
    xor  ecx, ecx
    cpuid
    test ebx, $20             // AVX2 (leaf 7, EBX bit 5)
    jz   @no
    mov  al, 1
    jmp  @done
  @no:
    xor  al, al
  @done:
    pop  rbx
end;
{$ENDIF}
{$IFDEF CPUX86}
asm
    push ebx
    mov  eax, 1
    xor  ecx, ecx
    cpuid
    and  ecx, $18000000
    cmp  ecx, $18000000
    jne  @no
    xor  ecx, ecx
    db   $0F, $01, $D0         // xgetbv
    and  eax, 6
    cmp  eax, 6
    jne  @no
    mov  eax, 7
    xor  ecx, ecx
    cpuid
    test ebx, $20
    jz   @no
    mov  al, 1
    jmp  @done
  @no:
    xor  al, al
  @done:
    pop  ebx
end;
{$ENDIF}

var
  _avx2: Integer = -1;

function PolyFillHasAVX2: Boolean;
begin
  if _avx2 < 0 then
    _avx2 := Ord(CheckAVX2);
  Result := _avx2 = 1;
end;

{ ============================================================================
  Scalar assembly cores (always available)
  ============================================================================ }

{$IFDEF WIN32}
// Encode Len bytes at Src to ASCII base64 (no line breaks) at Dst; returns
// chars written. Reads the final 1-3 bytes individually so it never reads
// past the input buffer.
function EncodeRawScalar(Src: PByte; Len: NativeInt; Dst: PByte): NativeInt; assembler;
asm
    // EAX=Src, EDX=Len, ECX=Dst
    push esi
    push edi
    push ebx
    mov  esi, eax
    mov  edi, ecx
    mov  ebx, ecx                   // Dst start
    mov  ecx, edx                   // remaining
  @loop:
    cmp  ecx, 4
    jl   @tail
    mov  eax, [esi]
    bswap eax
    shr  eax, 8
    mov  edx, eax
    shr  eax, 18
    mov  al, byte ptr [B64EncTable + eax]
    mov  [edi], al
    mov  eax, edx
    shr  eax, 12
    and  eax, $3F
    mov  al, byte ptr [B64EncTable + eax]
    mov  [edi+1], al
    mov  eax, edx
    shr  eax, 6
    and  eax, $3F
    mov  al, byte ptr [B64EncTable + eax]
    mov  [edi+2], al
    mov  eax, edx
    and  eax, $3F
    mov  al, byte ptr [B64EncTable + eax]
    mov  [edi+3], al
    add  edi, 4
    add  esi, 3
    sub  ecx, 3
    jmp  @loop
  @tail:
    test ecx, ecx
    jz   @done
    movzx eax, byte ptr [esi]
    shl  eax, 16
    cmp  ecx, 1
    je   @emit
    movzx edx, byte ptr [esi+1]
    shl  edx, 8
    or   eax, edx
    cmp  ecx, 2
    je   @emit
    movzx edx, byte ptr [esi+2]
    or   eax, edx
  @emit:
    mov  edx, eax
    shr  eax, 18
    mov  al, byte ptr [B64EncTable + eax]
    mov  [edi], al
    inc  edi
    mov  eax, edx
    shr  eax, 12
    and  eax, $3F
    mov  al, byte ptr [B64EncTable + eax]
    mov  [edi], al
    inc  edi
    cmp  ecx, 1
    je   @pad2
    mov  eax, edx
    shr  eax, 6
    and  eax, $3F
    mov  al, byte ptr [B64EncTable + eax]
    mov  [edi], al
    inc  edi
    cmp  ecx, 2
    je   @pad1
    mov  eax, edx
    and  eax, $3F
    mov  al, byte ptr [B64EncTable + eax]
    mov  [edi], al
    inc  edi
    jmp  @done
  @pad1:
    mov  byte ptr [edi], '='
    inc  edi
    jmp  @done
  @pad2:
    mov  word ptr [edi], '=' * 256 + '='
    add  edi, 2
  @done:
    mov  eax, edi
    sub  eax, ebx
    pop  ebx
    pop  edi
    pop  esi
end;

{$ENDIF WIN32}

{$IFDEF WIN64}
function EncodeRawScalar(Src: PByte; Len: NativeInt; Dst: PByte): NativeInt; assembler;
asm
    // rcx=Src, rdx=Len, r8=Dst
    push rsi
    push rdi
    push rbx
    mov  rsi, rcx
    mov  rcx, rdx
    mov  rdi, r8
    mov  r10, r8                    // Dst start
    lea  rbx, B64EncTable
  @loop:
    cmp  rcx, 4
    jl   @tail
    mov  eax, [rsi]
    bswap eax
    shr  eax, 8
    mov  edx, eax
    shr  eax, 18
    mov  al, [rbx + rax]
    mov  [rdi], al
    mov  eax, edx
    shr  eax, 12
    and  eax, $3F
    mov  al, [rbx + rax]
    mov  [rdi+1], al
    mov  eax, edx
    shr  eax, 6
    and  eax, $3F
    mov  al, [rbx + rax]
    mov  [rdi+2], al
    mov  eax, edx
    and  eax, $3F
    mov  al, [rbx + rax]
    mov  [rdi+3], al
    add  rdi, 4
    add  rsi, 3
    sub  rcx, 3
    jmp  @loop
  @tail:
    test rcx, rcx
    jz   @done
    movzx eax, byte ptr [rsi]
    shl  eax, 16
    cmp  rcx, 1
    je   @emit
    movzx edx, byte ptr [rsi+1]
    shl  edx, 8
    or   eax, edx
    cmp  rcx, 2
    je   @emit
    movzx edx, byte ptr [rsi+2]
    or   eax, edx
  @emit:
    mov  edx, eax
    shr  eax, 18
    mov  al, [rbx + rax]
    mov  [rdi], al
    inc  rdi
    mov  eax, edx
    shr  eax, 12
    and  eax, $3F
    mov  al, [rbx + rax]
    mov  [rdi], al
    inc  rdi
    cmp  rcx, 1
    je   @pad2
    mov  eax, edx
    shr  eax, 6
    and  eax, $3F
    mov  al, [rbx + rax]
    mov  [rdi], al
    inc  rdi
    cmp  rcx, 2
    je   @pad1
    mov  eax, edx
    and  eax, $3F
    mov  al, [rbx + rax]
    mov  [rdi], al
    inc  rdi
    jmp  @done
  @pad1:
    mov  byte ptr [rdi], '='
    inc  rdi
    jmp  @done
  @pad2:
    mov  word ptr [rdi], '=' * 256 + '='
    add  rdi, 2
  @done:
    mov  rax, rdi
    sub  rax, r10
    pop  rbx
    pop  rdi
    pop  rsi
end;

{$ENDIF WIN64}

{ ============================================================================
  AVX2 turbo cores (used when PolyFillHasAVX2). Both produce output byte-
  identical to the scalar cores for the bulk; tails are finished by scalar.
  ============================================================================ }

{$IFDEF WIN64}
function EncodeRawAVX2(Src: PByte; Len: NativeInt; Dst: PByte): NativeInt; assembler;
asm
    // rcx=Src, rdx=Len, r8=Dst
    push rsi
    push rdi
    push rbx
    mov  rsi, rcx
    mov  rcx, rdx
    mov  rdi, r8
    mov  r10, r8                    // Dst start
    cmp  rcx, 32                    // need 32 readable bytes per iteration
    jl   @rest
  @avx2:
    vmovdqu   ymm0, [rsi]
    vmovdqu   ymm1, [PermIdx]
    vpermd    ymm0, ymm1, ymm0
    vpshufb   ymm0, ymm0, [ReshuffleMask]
    vpand     ymm1, ymm0, [C_0fc0fc00]
    vpmulhuw  ymm1, ymm1, [C_04000040]
    vpand     ymm2, ymm0, [C_003f03f0]
    vpmullw   ymm2, ymm2, [C_01000010]
    vpor      ymm0, ymm1, ymm2
    vpsubusb  ymm1, ymm0, [C_51]
    vmovdqu   ymm2, [C_26]
    vpcmpgtb  ymm2, ymm2, ymm0
    vpand     ymm2, ymm2, [C_13]
    vpor      ymm1, ymm1, ymm2
    vmovdqu   ymm3, [ShiftLUT]
    vpshufb   ymm1, ymm3, ymm1
    vpaddb    ymm0, ymm1, ymm0
    vmovdqu   [rdi], ymm0
    add  rsi, 24
    add  rdi, 32
    sub  rcx, 24
    cmp  rcx, 32
    jge  @avx2
    vzeroupper
  @rest:
    // scalar finish: EncodeRawScalar(Src=rsi, Len=rcx, Dst=rdi)
    mov  rbx, rdi
    sub  rbx, r10                   // bytes already produced
    mov  r8, rdi
    mov  rdx, rcx
    mov  rcx, rsi
    sub  rsp, 32
    call EncodeRawScalar
    add  rsp, 32
    add  rax, rbx
    pop  rbx
    pop  rdi
    pop  rsi
end;

// Single-pass validating decode: decode consecutive CLEAN 32-char blocks (every
// byte a base64 alphabet char) via AVX2, writing 24 bytes each (+ up to 8 bytes
// slop, trimmed by the caller). Stops at the first block that contains any
// whitespace / '=' / invalid byte, or when fewer than 32 chars remain. Returns
// the number of input chars consumed (a multiple of 32).
function DecodeAVX2Checked(Src: PByte; NumChars: NativeInt; Dst: PByte): NativeInt; assembler;
asm
    // rcx=Src, rdx=NumChars, r8=Dst
    push rsi
    push rdi
    mov  rsi, rcx
    mov  rcx, rdx
    mov  rdi, r8
    mov  r10, rsi              // Src start
  @loop:
    cmp  rcx, 32
    jl   @done
    vmovdqu    ymm0, [rsi]            // input (kept for the transform)
    // ---- validity check: (LutLo[lo] and LutHi[hi]) must be 0 for every byte ----
    vpand      ymm1, ymm0, [C_Mask0F]
    vmovdqu    ymm2, [LutLo]
    vpshufb    ymm1, ymm2, ymm1
    vpsrld     ymm2, ymm0, 4
    vpand      ymm2, ymm2, [C_Mask0F]
    vmovdqu    ymm3, [LutHi]
    vpshufb    ymm2, ymm3, ymm2
    vpand      ymm1, ymm1, ymm2
    vptest     ymm1, ymm1
    jnz        @done                  // dirty block -> stop (do not consume it)
    // ---- transform (roll method) ----
    vpsrld     ymm1, ymm0, 4
    vpand      ymm1, ymm1, [Mask2F]
    vpcmpeqb   ymm3, ymm0, [Mask2F]
    vpaddb     ymm3, ymm3, ymm1
    vmovdqu    ymm4, [LutRoll]
    vpshufb    ymm3, ymm4, ymm3
    vpaddb     ymm0, ymm0, ymm3
    vpmaddubsw ymm0, ymm0, [C_01400140]
    vpmaddwd   ymm0, ymm0, [C_00011000]
    vpshufb    ymm0, ymm0, [DecShuffle]
    vmovdqu    ymm5, [PermStore]
    vpermd     ymm0, ymm5, ymm0
    vmovdqu    [rdi], ymm0
    add  rsi, 32
    add  rdi, 24
    sub  rcx, 32
    jmp  @loop
  @done:
    vzeroupper
    mov  rax, rsi
    sub  rax, r10              // chars consumed
    pop  rdi
    pop  rsi
end;
{$ENDIF WIN64}

{$IFDEF WIN32}
function EncodeRawAVX2(Src: PByte; Len: NativeInt; Dst: PByte): NativeInt; assembler;
asm
    // EAX=Src, EDX=Len, ECX=Dst
    push esi
    push edi
    push ebx
    mov  esi, eax
    mov  edi, ecx
    mov  ebx, ecx                   // Dst start
    mov  ecx, edx                   // remaining
    cmp  ecx, 32
    jl   @rest
  @avx2:
    vmovdqu   ymm0, [esi]
    vmovdqu   ymm1, [PermIdx]
    vpermd    ymm0, ymm1, ymm0
    vpshufb   ymm0, ymm0, [ReshuffleMask]
    vpand     ymm1, ymm0, [C_0fc0fc00]
    vpmulhuw  ymm1, ymm1, [C_04000040]
    vpand     ymm2, ymm0, [C_003f03f0]
    vpmullw   ymm2, ymm2, [C_01000010]
    vpor      ymm0, ymm1, ymm2
    vpsubusb  ymm1, ymm0, [C_51]
    vmovdqu   ymm2, [C_26]
    vpcmpgtb  ymm2, ymm2, ymm0
    vpand     ymm2, ymm2, [C_13]
    vpor      ymm1, ymm1, ymm2
    vmovdqu   ymm3, [ShiftLUT]
    vpshufb   ymm1, ymm3, ymm1
    vpaddb    ymm0, ymm1, ymm0
    vmovdqu   [edi], ymm0
    add  esi, 24
    add  edi, 32
    sub  ecx, 24
    cmp  ecx, 32
    jge  @avx2
    vzeroupper
  @rest:
    // scalar finish: EncodeRawScalar(Src=esi, Len=ecx, Dst=edi); preserves esi/edi/ebx
    mov  eax, esi
    mov  edx, ecx
    mov  ecx, edi
    call EncodeRawScalar
    mov  edx, edi
    sub  edx, ebx                   // bytes already produced
    add  eax, edx
    pop  ebx
    pop  edi
    pop  esi
end;

function DecodeAVX2Checked(Src: PByte; NumChars: NativeInt; Dst: PByte): NativeInt; assembler;
asm
    // EAX=Src, EDX=NumChars, ECX=Dst
    push esi
    push edi
    push ebx
    mov  esi, eax
    mov  edi, ecx
    mov  ebx, esi              // Src start
    mov  ecx, edx
  @loop:
    cmp  ecx, 32
    jl   @done
    vmovdqu    ymm0, [esi]
    vpand      ymm1, ymm0, [C_Mask0F]
    vmovdqu    ymm2, [LutLo]
    vpshufb    ymm1, ymm2, ymm1
    vpsrld     ymm2, ymm0, 4
    vpand      ymm2, ymm2, [C_Mask0F]
    vmovdqu    ymm3, [LutHi]
    vpshufb    ymm2, ymm3, ymm2
    vpand      ymm1, ymm1, ymm2
    vptest     ymm1, ymm1
    jnz        @done
    vpsrld     ymm1, ymm0, 4
    vpand      ymm1, ymm1, [Mask2F]
    vpcmpeqb   ymm3, ymm0, [Mask2F]
    vpaddb     ymm3, ymm3, ymm1
    vmovdqu    ymm4, [LutRoll]
    vpshufb    ymm3, ymm4, ymm3
    vpaddb     ymm0, ymm0, ymm3
    vpmaddubsw ymm0, ymm0, [C_01400140]
    vpmaddwd   ymm0, ymm0, [C_00011000]
    vpshufb    ymm0, ymm0, [DecShuffle]
    vmovdqu    ymm5, [PermStore]
    vpermd     ymm0, ymm5, ymm0
    vmovdqu    [edi], ymm0
    add  esi, 32
    add  edi, 24
    sub  ecx, 32
    jmp  @loop
  @done:
    vzeroupper
    mov  eax, esi
    sub  eax, ebx              // chars consumed
    pop  ebx
    pop  edi
    pop  esi
end;
{$ENDIF WIN32}

{ ============================================================================
  Raw encode dispatcher (AVX2 if available, else scalar)
  ============================================================================ }

// Dst must hold at least ((Len+2) div 3)*4 + 32 bytes (the +32 covers the
// AVX2 path's 32-byte stores). Returns the exact number of base64 chars.
function EncodeRaw(Src: PByte; Len: NativeInt; Dst: PByte): NativeInt;
begin
  if PolyFillHasAVX2 then
    Result := EncodeRawAVX2(Src, Len, Dst)
  else
    Result := EncodeRawScalar(Src, Len, Dst);
end;

{ ============================================================================
  Line-wrapping helpers (match TBase64Encoding byte-for-byte)
  ============================================================================ }

// Compute how many line separators get inserted for numInputBytes of input at
// the given line width.
function CountBreaks(numInputBytes, charsPerLine: Integer): Integer;
var
  quantaPerLine, fullGroups: Integer;
begin
  if charsPerLine <= 0 then
    Exit(0);
  quantaPerLine := charsPerLine div 4;
  if quantaPerLine < 1 then
    quantaPerLine := 1;
  fullGroups := numInputBytes div 3;
  Result := fullGroups div quantaPerLine;
end;

// Widen the raw ASCII base64 to a UTF-16 string, inserting line breaks.
function WidenAndWrap(raw: PByte; rawLen, numInputBytes, charsPerLine: Integer;
  const lineBreak: string): string;
var
  lineLen, quantaPerLine, lbLen, fullGroups, numBreaks, wi, gi, k, col: Integer;
  hasPartial: Boolean;
  rp: PByte;
begin
  if rawLen = 0 then
    Exit('');

  if charsPerLine <= 0 then
  begin
    SetLength(Result, rawLen);
    rp := raw;
    for k := 1 to rawLen do
    begin
      Result[k] := Char(rp^);
      Inc(rp);
    end;
    Exit;
  end;

  lineLen := (charsPerLine div 4) * 4;
  if lineLen < 4 then
    lineLen := 4;
  quantaPerLine := lineLen div 4;
  lbLen := Length(lineBreak);
  fullGroups := numInputBytes div 3;
  hasPartial := (numInputBytes mod 3) <> 0;
  numBreaks := fullGroups div quantaPerLine;
  SetLength(Result, rawLen + numBreaks * lbLen);

  rp := raw;
  wi := 1;
  col := 0;
  for gi := 1 to fullGroups do
  begin
    for k := 0 to 3 do
    begin
      Result[wi] := Char(rp^);
      Inc(rp);
      Inc(wi);
    end;
    Inc(col, 4);
    if col = lineLen then
    begin
      for k := 1 to lbLen do
      begin
        Result[wi] := lineBreak[k];
        Inc(wi);
      end;
      col := 0;
    end;
  end;
  if hasPartial then
    for k := 0 to 3 do
    begin
      Result[wi] := Char(rp^);
      Inc(rp);
      Inc(wi);
    end;
end;

// Same wrapping, but emitting bytes with a byte separator (for the TBytes /
// stream encode paths). lineSep holds the separator as bytes (UTF-8 of CRLF).
function WrapRawToBytes(raw: PByte; rawLen, numInputBytes, charsPerLine: Integer;
  const lineSep: TBytes): TBytes;
var
  lineLen, quantaPerLine, lbLen, fullGroups, numBreaks, gi, k: Integer;
  rp, dp: PByte;
begin
  if rawLen = 0 then
    Exit(nil);

  if charsPerLine <= 0 then
  begin
    SetLength(Result, rawLen);
    Move(raw^, Result[0], rawLen);
    Exit;
  end;

  lineLen := (charsPerLine div 4) * 4;
  if lineLen < 4 then
    lineLen := 4;
  quantaPerLine := lineLen div 4;
  lbLen := Length(lineSep);
  fullGroups := numInputBytes div 3;
  numBreaks := fullGroups div quantaPerLine;
  SetLength(Result, rawLen + numBreaks * lbLen);

  // Copy whole lines with Move (much faster than the per-char loop). Each of
  // the numBreaks lines is exactly lineLen raw chars followed by the separator;
  // whatever raw chars remain after the last break are copied without a
  // trailing separator. This reproduces TBase64Encoding's wrapping (including
  // the trailing separator when the final full group lands on a boundary).
  rp := raw;
  dp := PByte(@Result[0]);
  for gi := 1 to numBreaks do
  begin
    Move(rp^, dp^, lineLen);
    Inc(rp, lineLen);
    Inc(dp, lineLen);
    if lbLen > 0 then
    begin
      Move(lineSep[0], dp^, lbLen);
      Inc(dp, lbLen);
    end;
  end;
  k := rawLen - numBreaks * lineLen;        // remaining raw chars (no trailing sep)
  if k > 0 then
    Move(rp^, dp^, k);
end;

{ ----- AVX2 fast wrap -----

  The slow part of wrapping a large buffer is not the byte movement itself
  (that is memory-bound) but the ~one-Move-per-line call overhead. WrapCopyLines
  copies every line's worth of raw chars to its final, strided destination in a
  single tight SIMD pass (one routine call total), leaving gaps for the
  separators; the (tiny) separators are then written in Pascal with cheap PWord
  stores. The 32-byte SIMD copies over-read/over-write up to 31 bytes past each
  line, which is why both the source (rawBuf) and destination (Result) are
  allocated with >=32 bytes of slack. Correctness invariant: lines are copied in
  ascending address order and later copies start beyond earlier lines' real
  bytes, so each line's real bytes are written last by its own copy; the final
  tail copy (done after all lines) overwrites any over-copy into the tail
  region, and the separator writes overwrite the gap bytes. }

type
  TWrapLines = record
    Src, Dst: PByte;
    LineLen, StrideDst, NumBreaks, TailLen: NativeInt;
  end;

{$IFDEF WIN64}
procedure WrapCopyLines(const Info: TWrapLines); assembler;
asm
    // rcx = ^TWrapLines
    push rsi
    push rdi
    push rbx
    mov  rbx, rcx
    mov  rsi, [rbx]          // Src
    mov  rdi, [rbx+8]        // Dst
    mov  r8,  [rbx+16]       // LineLen
    mov  r9,  [rbx+24]       // StrideDst
    mov  r11, [rbx+32]       // NumBreaks
  @lineloop:
    test r11, r11
    jz   @tail
    xor  rax, rax
  @cp:
    vmovdqu ymm0, [rsi+rax]
    vmovdqu [rdi+rax], ymm0
    add  rax, 32
    cmp  rax, r8
    jl   @cp
    add  rsi, r8            // Src += LineLen
    add  rdi, r9            // Dst += StrideDst
    dec  r11
    jmp  @lineloop
  @tail:
    mov  rax, [rbx+40]      // TailLen
    test rax, rax
    jz   @done
    xor  rdx, rdx
  @cpt:
    vmovdqu ymm0, [rsi+rdx]
    vmovdqu [rdi+rdx], ymm0
    add  rdx, 32
    cmp  rdx, rax
    jl   @cpt
  @done:
    vzeroupper
    pop  rbx
    pop  rdi
    pop  rsi
end;
{$ENDIF WIN64}

{$IFDEF WIN32}
procedure WrapCopyLines(const Info: TWrapLines); assembler;
asm
    // eax = ^TWrapLines
    push esi
    push edi
    push ebx
    mov  ebx, eax
    mov  esi, [ebx]          // Src
    mov  edi, [ebx+4]        // Dst
    mov  ecx, [ebx+16]       // NumBreaks
  @lineloop:
    test ecx, ecx
    jz   @tail
    mov  eax, [ebx+8]        // LineLen
    xor  edx, edx
  @cp:
    vmovdqu ymm0, [esi+edx]
    vmovdqu [edi+edx], ymm0
    add  edx, 32
    cmp  edx, eax
    jl   @cp
    add  esi, [ebx+8]        // Src += LineLen
    add  edi, [ebx+12]       // Dst += StrideDst
    dec  ecx
    jmp  @lineloop
  @tail:
    mov  eax, [ebx+20]       // TailLen
    test eax, eax
    jz   @done
    xor  edx, edx
  @cpt:
    vmovdqu ymm0, [esi+edx]
    vmovdqu [edi+edx], ymm0
    add  edx, 32
    cmp  edx, eax
    jl   @cpt
  @done:
    vzeroupper
    pop  ebx
    pop  edi
    pop  esi
end;
{$ENDIF WIN32}

// AVX2 wrap: one SIMD pass for the line bodies + cheap PWord separator stores.
// Produces output byte-identical to WrapRawToBytes. Requires PolyFillHasAVX2.
function WrapRawFast(raw: PByte; rawLen, numInputBytes, charsPerLine: Integer;
  const lineSep: TBytes): TBytes;
var
  lineLen, quantaPerLine, lbLen, fullGroups: Integer;
  numBreaks, strideDst, tailLen, W, i: NativeInt;
  info: TWrapLines;
  dst: PByte;
  sepW: Word;
begin
  if rawLen = 0 then
    Exit(nil);

  if charsPerLine <= 0 then
  begin
    SetLength(Result, rawLen + 32);
    info.Src := raw; info.Dst := PByte(@Result[0]);
    info.LineLen := 0; info.StrideDst := 0; info.NumBreaks := 0;
    info.TailLen := rawLen;
    WrapCopyLines(info);
    SetLength(Result, rawLen);
    Exit;
  end;

  lineLen := (charsPerLine div 4) * 4;
  if lineLen < 4 then
    lineLen := 4;
  quantaPerLine := lineLen div 4;
  lbLen := Length(lineSep);
  fullGroups := numInputBytes div 3;
  numBreaks := fullGroups div quantaPerLine;
  strideDst := lineLen + lbLen;
  tailLen := rawLen - numBreaks * lineLen;
  W := rawLen + numBreaks * lbLen;

  SetLength(Result, W + 32);          // +32 slack for the SIMD over-write
  dst := PByte(@Result[0]);
  info.Src := raw;
  info.Dst := dst;
  info.LineLen := lineLen;
  info.StrideDst := strideDst;
  info.NumBreaks := numBreaks;
  info.TailLen := tailLen;
  WrapCopyLines(info);

  // Fill the separators into the gaps (cheap: usually a 2-byte CRLF).
  if lbLen = 2 then
  begin
    sepW := PWord(@lineSep[0])^;
    for i := 0 to numBreaks - 1 do
      PWord(dst + i * strideDst + lineLen)^ := sepW;
  end
  else if lbLen = 1 then
  begin
    for i := 0 to numBreaks - 1 do
      (dst + i * strideDst + lineLen)^ := lineSep[0];
  end
  else if lbLen > 0 then
  begin
    for i := 0 to numBreaks - 1 do
      Move(lineSep[0], (dst + i * strideDst + lineLen)^, lbLen);
  end;

  SetLength(Result, W);
end;

{ ============================================================================
  Decode core — single pass, whitespace/padding tolerant.

  No separate validating pre-scan. The driver alternates between:
    * DecodeAVX2Checked: decodes consecutive CLEAN 32-char blocks (validating
      each inline) and stops at the first block touching whitespace / '=' /
      invalid; and
    * ScalarStretch: a scalar pass that handles one "dirty" stretch (skips
      whitespace, decodes complete quanta, handles the padded final group) and
      returns at the next quantum boundary so AVX2 can resume.

  For unbroken base64 (the common case + the benchmark) this is effectively a
  single AVX2 sweep plus one small scalar tail. For MIME (CRLF every 76 chars)
  AVX2 still does the bulk of every line; only the few chars around each break
  go scalar.
  ============================================================================ }

function IsB64Ws(b: Byte): Boolean; inline;
begin
  Result := (b = Ord(' ')) or (b = 9) or (b = 10) or (b = 13);
end;

{ Decode from Src (Len bytes) starting on a quantum boundary. Skips whitespace,
  decodes complete 4-char quanta, and the final padded group on '='. Returns
  early (AtEnd=False) once it reaches a quantum boundary followed by whitespace
  (so the caller can resume the AVX2 fast path), having first consumed that run
  of whitespace. Sets AtEnd=True on '=' or end of input. Raises on invalid. }
procedure ScalarStretch(Src: PByte; Len: NativeInt; Dst: PByte;
  out Consumed, Written: NativeInt; out AtEnd: Boolean);
var
  i, o: NativeInt;
  acc: Cardinal;
  nb: Integer;
  b, v: Byte;
begin
  i := 0; o := 0; acc := 0; nb := 0;
  while i < Len do
  begin
    b := Src[i];
    if IsB64Ws(b) then
    begin
      if nb = 0 then
      begin
        // on a quantum boundary: swallow the whole whitespace run, then hand
        // back to the caller (AVX2) for the next clean stretch.
        repeat Inc(i) until (i >= Len) or (not IsB64Ws(Src[i]));
        Consumed := i; Written := o; AtEnd := i >= Len;
        Exit;
      end;
      Inc(i);                 // stray whitespace mid-quantum: skip and continue
      Continue;
    end;
    if b = Ord('=') then
    begin
      // final (padded) group: nb is 18 (3 chars -> 2 bytes) or 12 (2 -> 1 byte)
      if nb = 18 then
      begin
        Dst[o] := Byte(acc shr 10); Dst[o + 1] := Byte(acc shr 2); Inc(o, 2);
      end
      else if nb = 12 then
      begin
        Dst[o] := Byte(acc shr 4); Inc(o);
      end;
      Consumed := Len; Written := o; AtEnd := True;
      Exit;
    end;
    v := Base64DecodeTable[b];
    if v = 255 then
      raise EConvertError.CreateFmt('Invalid Base64 character $%2.2x', [b]);
    acc := (acc shl 6) or v; Inc(nb, 6); Inc(i);
    if nb = 24 then
    begin
      Dst[o] := Byte(acc shr 16); Dst[o + 1] := Byte(acc shr 8); Dst[o + 2] := Byte(acc);
      Inc(o, 3); nb := 0; acc := 0;
    end;
  end;
  // end of input without '=' padding
  if nb = 18 then
  begin
    Dst[o] := Byte(acc shr 10); Dst[o + 1] := Byte(acc shr 2); Inc(o, 2);
  end
  else if nb = 12 then
  begin
    Dst[o] := Byte(acc shr 4); Inc(o);
  end;
  Consumed := i; Written := o; AtEnd := True;
end;

// Decode a buffer of base64 ASCII (Src/SrcLen), tolerating embedded whitespace,
// exactly like TBase64Encoding. Single pass.
function DecodeBuffer(Src: PByte; SrcLen: NativeInt): TBytes;
var
  pos, written, estimate, cons, wr: NativeInt;
  atEnd: Boolean;
  dst: PByte;
begin
  if SrcLen <= 0 then
    Exit(nil);

  // (SrcLen div 4)*3 is an upper bound on the output (whitespace only shrinks
  // it); +48 slack covers AVX2's 8-byte store overshoot and the scalar tail.
  estimate := (SrcLen div 4) * 3 + 48;
  SetLength(Result, estimate);
  dst := PByte(@Result[0]);

  pos := 0; written := 0;
  while pos < SrcLen do
  begin
    if PolyFillHasAVX2 and (SrcLen - pos >= 32) then
    begin
      cons := DecodeAVX2Checked(Src + pos, SrcLen - pos, dst + written);
      Inc(pos, cons);
      Inc(written, (cons div 4) * 3);
      if pos >= SrcLen then
        Break;
    end;
    // dirty / tail stretch (also the whole input on non-AVX2 CPUs)
    ScalarStretch(Src + pos, SrcLen - pos, dst + written, cons, wr, atEnd);
    Inc(pos, cons);
    Inc(written, wr);
    if atEnd or (cons = 0) then
      Break;
  end;

  SetLength(Result, written);
end;

{ ============================================================================
  Fused single-pass encode + line separator (no scratch buffer)

  These read the input once and write base64 with the separator inserted inline,
  directly into the output. Compared with encode-into-scratch then SIMD-copy-with-
  gaps, this halves the wrapped-output memory traffic.

    EncodeFusedScalar - 100% scalar integer asm (portable baseline).
    EncodeFusedAVX2   - AVX2 for the 24-byte chunks that fit inside a line,
                        scalar for the line's remaining quanta, separator inline;
                        the final (partial) line is encoded scalar with padding.

  Both reproduce TBase64Encoding's wrapping exactly (a separator after every full
  line, incl. a trailing separator when the last full group lands on a boundary;
  the final padded group never gets one) and reuse the unit's B64EncTable and
  AVX2 constants. lineQuanta = CharsPerLine div 4 (line = lineQuanta*3 bytes).
  ============================================================================ }

type
  // Field offsets relied on by the asm:
  //   Win64: Src0 Dst8 Sep16 Len24 LineQuanta32 SepLen40 LineBytes48 QCount56
  //   Win32: Src0 Dst4 Sep8 Len12 LineQuanta16 SepLen20 LineBytes24 QCount28
  TFusedInfo = record
    Src, Dst, Sep: PByte;
    Len, LineQuanta, SepLen, LineBytes: NativeInt;
    QCount: NativeInt;   // scratch: quanta left in the current line
  end;

{$IFDEF WIN64}
procedure EncodeFusedScalar(var Info: TFusedInfo); assembler;
asm
    push rsi
    push rdi
    push rbx
    push r12
    push r13
    mov  r11, rcx           // Info ptr
    mov  rsi, [r11]         // Src
    mov  rdi, [r11+8]       // Dst
    mov  rcx, [r11+24]      // Len (remaining)
    mov  r12, [r11+32]      // LineQuanta
    lea  rbx, [B64EncTable]
    mov  r13, r12           // quanta left in line
  @loop:
    cmp  rcx, 4
    jl   @tail
    mov  eax, [rsi]
    bswap eax
    shr  eax, 8
    mov  edx, eax
    shr  eax, 18
    mov  al, [rbx+rax]
    mov  [rdi], al
    mov  eax, edx
    shr  eax, 12
    and  eax, 03Fh
    mov  al, [rbx+rax]
    mov  [rdi+1], al
    mov  eax, edx
    shr  eax, 6
    and  eax, 03Fh
    mov  al, [rbx+rax]
    mov  [rdi+2], al
    mov  eax, edx
    and  eax, 03Fh
    mov  al, [rbx+rax]
    mov  [rdi+3], al
    add  rdi, 4
    add  rsi, 3
    sub  rcx, 3
    dec  r13
    jnz  @loop
    mov  r10, [r11+16]
    cmp  qword ptr [r11+40], 2
    jne  @sep1
    mov  ax, [r10]
    mov  [rdi], ax
    add  rdi, 2
    jmp  @sepd
  @sep1:
    mov  al, [r10]
    mov  [rdi], al
    inc  rdi
  @sepd:
    mov  r13, r12
    jmp  @loop
  @tail:
    test rcx, rcx
    jz   @done
    movzx eax, byte ptr [rsi]
    shl  eax, 16
    cmp  rcx, 1
    je   @temit
    movzx edx, byte ptr [rsi+1]
    shl  edx, 8
    or   eax, edx
    cmp  rcx, 2
    je   @temit
    movzx edx, byte ptr [rsi+2]
    or   eax, edx
  @temit:
    mov  edx, eax
    shr  eax, 18
    mov  al, [rbx+rax]
    mov  [rdi], al
    inc  rdi
    mov  eax, edx
    shr  eax, 12
    and  eax, 03Fh
    mov  al, [rbx+rax]
    mov  [rdi], al
    inc  rdi
    cmp  rcx, 1
    je   @tp2
    mov  eax, edx
    shr  eax, 6
    and  eax, 03Fh
    mov  al, [rbx+rax]
    mov  [rdi], al
    inc  rdi
    cmp  rcx, 2
    je   @tp1
    mov  eax, edx
    and  eax, 03Fh
    mov  al, [rbx+rax]
    mov  [rdi], al
    inc  rdi
    dec  r13
    jnz  @done
    mov  r10, [r11+16]
    cmp  qword ptr [r11+40], 2
    jne  @tsep1
    mov  ax, [r10]
    mov  [rdi], ax
    add  rdi, 2
    jmp  @done
  @tsep1:
    mov  al, [r10]
    mov  [rdi], al
    inc  rdi
    jmp  @done
  @tp1:
    mov  byte ptr [rdi], '='
    inc  rdi
    jmp  @done
  @tp2:
    mov  word ptr [rdi], '=' * 256 + '='
    add  rdi, 2
  @done:
    pop  r13
    pop  r12
    pop  rbx
    pop  rdi
    pop  rsi
end;
{$ENDIF WIN64}

{$IFDEF WIN32}
procedure EncodeFusedScalar(var Info: TFusedInfo); assembler;
asm
    push esi
    push edi
    push ebx
    mov  ebx, eax           // Info
    mov  esi, [ebx]         // Src
    mov  edi, [ebx+4]       // Dst
    mov  ecx, [ebx+12]      // Len
    mov  eax, [ebx+16]      // LineQuanta
    mov  [ebx+28], eax      // QCount
  @loop:
    cmp  ecx, 4
    jl   @tail
    mov  eax, [esi]
    bswap eax
    shr  eax, 8
    mov  edx, eax
    shr  eax, 18
    mov  al, byte ptr [B64EncTable+eax]
    mov  [edi], al
    mov  eax, edx
    shr  eax, 12
    and  eax, 03Fh
    mov  al, byte ptr [B64EncTable+eax]
    mov  [edi+1], al
    mov  eax, edx
    shr  eax, 6
    and  eax, 03Fh
    mov  al, byte ptr [B64EncTable+eax]
    mov  [edi+2], al
    mov  eax, edx
    and  eax, 03Fh
    mov  al, byte ptr [B64EncTable+eax]
    mov  [edi+3], al
    add  edi, 4
    add  esi, 3
    sub  ecx, 3
    dec  dword ptr [ebx+28]
    jnz  @loop
    mov  eax, [ebx+8]       // Sep
    cmp  dword ptr [ebx+20], 2
    jne  @sep1
    mov  dx, [eax]
    mov  [edi], dx
    add  edi, 2
    jmp  @sepd
  @sep1:
    mov  dl, [eax]
    mov  [edi], dl
    inc  edi
  @sepd:
    mov  eax, [ebx+16]
    mov  [ebx+28], eax
    jmp  @loop
  @tail:
    test ecx, ecx
    jz   @done
    movzx eax, byte ptr [esi]
    shl  eax, 16
    cmp  ecx, 1
    je   @temit
    movzx edx, byte ptr [esi+1]
    shl  edx, 8
    or   eax, edx
    cmp  ecx, 2
    je   @temit
    movzx edx, byte ptr [esi+2]
    or   eax, edx
  @temit:
    mov  edx, eax
    shr  eax, 18
    mov  al, byte ptr [B64EncTable+eax]
    mov  [edi], al
    inc  edi
    mov  eax, edx
    shr  eax, 12
    and  eax, 03Fh
    mov  al, byte ptr [B64EncTable+eax]
    mov  [edi], al
    inc  edi
    cmp  ecx, 1
    je   @tp2
    mov  eax, edx
    shr  eax, 6
    and  eax, 03Fh
    mov  al, byte ptr [B64EncTable+eax]
    mov  [edi], al
    inc  edi
    cmp  ecx, 2
    je   @tp1
    mov  eax, edx
    and  eax, 03Fh
    mov  al, byte ptr [B64EncTable+eax]
    mov  [edi], al
    inc  edi
    dec  dword ptr [ebx+28]
    jnz  @done
    mov  eax, [ebx+8]
    cmp  dword ptr [ebx+20], 2
    jne  @tsep1
    mov  dx, [eax]
    mov  [edi], dx
    add  edi, 2
    jmp  @done
  @tsep1:
    mov  dl, [eax]
    mov  [edi], dl
    inc  edi
    jmp  @done
  @tp1:
    mov  byte ptr [edi], '='
    inc  edi
    jmp  @done
  @tp2:
    mov  word ptr [edi], '=' * 256 + '='
    add  edi, 2
  @done:
    pop  ebx
    pop  edi
    pop  esi
end;
{$ENDIF WIN32}

{$IFDEF WIN64}
procedure EncodeFusedAVX2(var Info: TFusedInfo); assembler;
asm
    push rsi
    push rdi
    push rbx
    push r12
    push r13
    mov  r11, rcx
    mov  rsi, [r11]         // Src
    mov  rdi, [r11+8]       // Dst
    mov  rcx, [r11+24]      // Len
    mov  r12, [r11+32]      // LineQuanta
    mov  r8,  [r11+48]      // LineBytes
    lea  rbx, [B64EncTable]
  @fullline:
    cmp  rcx, r8
    jl   @lastseg
    mov  r13, r12           // quanta this line
  @avx:
    cmp  r13, 11            // need >=33 input bytes left in line for a safe 32-byte load
    jl   @linesc
    vmovdqu   ymm0, [rsi]
    vmovdqu   ymm1, [PermIdx]
    vpermd    ymm0, ymm1, ymm0
    vpshufb   ymm0, ymm0, [ReshuffleMask]
    vpand     ymm1, ymm0, [C_0fc0fc00]
    vpmulhuw  ymm1, ymm1, [C_04000040]
    vpand     ymm2, ymm0, [C_003f03f0]
    vpmullw   ymm2, ymm2, [C_01000010]
    vpor      ymm0, ymm1, ymm2
    vpsubusb  ymm1, ymm0, [C_51]
    vmovdqu   ymm2, [C_26]
    vpcmpgtb  ymm2, ymm2, ymm0
    vpand     ymm2, ymm2, [C_13]
    vpor      ymm1, ymm1, ymm2
    vmovdqu   ymm3, [ShiftLUT]
    vpshufb   ymm1, ymm3, ymm1
    vpaddb    ymm0, ymm1, ymm0
    vmovdqu   [rdi], ymm0
    add  rsi, 24
    add  rdi, 32
    sub  r13, 8
    jmp  @avx
  @linesc:
    test r13, r13
    jz   @linesep
    movzx eax, byte ptr [rsi]
    shl  eax, 16
    movzx edx, byte ptr [rsi+1]
    shl  edx, 8
    or   eax, edx
    movzx edx, byte ptr [rsi+2]
    or   eax, edx
    mov  edx, eax
    shr  eax, 18
    mov  al, [rbx+rax]
    mov  [rdi], al
    mov  eax, edx
    shr  eax, 12
    and  eax, 03Fh
    mov  al, [rbx+rax]
    mov  [rdi+1], al
    mov  eax, edx
    shr  eax, 6
    and  eax, 03Fh
    mov  al, [rbx+rax]
    mov  [rdi+2], al
    mov  eax, edx
    and  eax, 03Fh
    mov  al, [rbx+rax]
    mov  [rdi+3], al
    add  rsi, 3
    add  rdi, 4
    dec  r13
    jmp  @linesc
  @linesep:
    sub  rcx, r8
    mov  r10, [r11+16]
    cmp  qword ptr [r11+40], 2
    jne  @ls1
    mov  ax, [r10]
    mov  [rdi], ax
    add  rdi, 2
    jmp  @fullline
  @ls1:
    mov  al, [r10]
    mov  [rdi], al
    inc  rdi
    jmp  @fullline
  @lastseg:
  @lsloop:
    cmp  rcx, 3
    jl   @lstail
    movzx eax, byte ptr [rsi]
    shl  eax, 16
    movzx edx, byte ptr [rsi+1]
    shl  edx, 8
    or   eax, edx
    movzx edx, byte ptr [rsi+2]
    or   eax, edx
    mov  edx, eax
    shr  eax, 18
    mov  al, [rbx+rax]
    mov  [rdi], al
    mov  eax, edx
    shr  eax, 12
    and  eax, 03Fh
    mov  al, [rbx+rax]
    mov  [rdi+1], al
    mov  eax, edx
    shr  eax, 6
    and  eax, 03Fh
    mov  al, [rbx+rax]
    mov  [rdi+2], al
    mov  eax, edx
    and  eax, 03Fh
    mov  al, [rbx+rax]
    mov  [rdi+3], al
    add  rsi, 3
    add  rdi, 4
    sub  rcx, 3
    jmp  @lsloop
  @lstail:
    test rcx, rcx
    jz   @done
    movzx eax, byte ptr [rsi]
    shl  eax, 16
    cmp  rcx, 1
    je   @lsemit
    movzx edx, byte ptr [rsi+1]
    shl  edx, 8
    or   eax, edx
  @lsemit:
    mov  edx, eax
    shr  eax, 18
    mov  al, [rbx+rax]
    mov  [rdi], al
    inc  rdi
    mov  eax, edx
    shr  eax, 12
    and  eax, 03Fh
    mov  al, [rbx+rax]
    mov  [rdi], al
    inc  rdi
    cmp  rcx, 1
    je   @lsp2
    mov  eax, edx
    shr  eax, 6
    and  eax, 03Fh
    mov  al, [rbx+rax]
    mov  [rdi], al
    inc  rdi
    mov  byte ptr [rdi], '='
    inc  rdi
    jmp  @done
  @lsp2:
    mov  word ptr [rdi], '=' * 256 + '='
    add  rdi, 2
  @done:
    vzeroupper
    pop  r13
    pop  r12
    pop  rbx
    pop  rdi
    pop  rsi
end;
{$ENDIF WIN64}

{$IFDEF WIN32}
procedure EncodeFusedAVX2(var Info: TFusedInfo); assembler;
asm
    push esi
    push edi
    push ebx
    mov  ebx, eax
    mov  esi, [ebx]
    mov  edi, [ebx+4]
    mov  ecx, [ebx+12]
  @fullline:
    mov  eax, [ebx+24]      // LineBytes
    cmp  ecx, eax
    jl   @lastseg
    mov  eax, [ebx+16]      // LineQuanta
    mov  [ebx+28], eax      // QCount
  @avx:
    cmp  dword ptr [ebx+28], 11
    jl   @linesc
    vmovdqu   ymm0, [esi]
    vmovdqu   ymm1, [PermIdx]
    vpermd    ymm0, ymm1, ymm0
    vpshufb   ymm0, ymm0, [ReshuffleMask]
    vpand     ymm1, ymm0, [C_0fc0fc00]
    vpmulhuw  ymm1, ymm1, [C_04000040]
    vpand     ymm2, ymm0, [C_003f03f0]
    vpmullw   ymm2, ymm2, [C_01000010]
    vpor      ymm0, ymm1, ymm2
    vpsubusb  ymm1, ymm0, [C_51]
    vmovdqu   ymm2, [C_26]
    vpcmpgtb  ymm2, ymm2, ymm0
    vpand     ymm2, ymm2, [C_13]
    vpor      ymm1, ymm1, ymm2
    vmovdqu   ymm3, [ShiftLUT]
    vpshufb   ymm1, ymm3, ymm1
    vpaddb    ymm0, ymm1, ymm0
    vmovdqu   [edi], ymm0
    add  esi, 24
    add  edi, 32
    sub  dword ptr [ebx+28], 8
    jmp  @avx
  @linesc:
    cmp  dword ptr [ebx+28], 0
    jle  @linesep
    movzx eax, byte ptr [esi]
    shl  eax, 16
    movzx edx, byte ptr [esi+1]
    shl  edx, 8
    or   eax, edx
    movzx edx, byte ptr [esi+2]
    or   eax, edx
    mov  edx, eax
    shr  eax, 18
    mov  al, byte ptr [B64EncTable+eax]
    mov  [edi], al
    mov  eax, edx
    shr  eax, 12
    and  eax, 03Fh
    mov  al, byte ptr [B64EncTable+eax]
    mov  [edi+1], al
    mov  eax, edx
    shr  eax, 6
    and  eax, 03Fh
    mov  al, byte ptr [B64EncTable+eax]
    mov  [edi+2], al
    mov  eax, edx
    and  eax, 03Fh
    mov  al, byte ptr [B64EncTable+eax]
    mov  [edi+3], al
    add  esi, 3
    add  edi, 4
    dec  dword ptr [ebx+28]
    jmp  @linesc
  @linesep:
    sub  ecx, [ebx+24]
    mov  eax, [ebx+8]
    cmp  dword ptr [ebx+20], 2
    jne  @ls1
    mov  dx, [eax]
    mov  [edi], dx
    add  edi, 2
    jmp  @fullline
  @ls1:
    mov  dl, [eax]
    mov  [edi], dl
    inc  edi
    jmp  @fullline
  @lastseg:
  @lsloop:
    cmp  ecx, 3
    jl   @lstail
    movzx eax, byte ptr [esi]
    shl  eax, 16
    movzx edx, byte ptr [esi+1]
    shl  edx, 8
    or   eax, edx
    movzx edx, byte ptr [esi+2]
    or   eax, edx
    mov  edx, eax
    shr  eax, 18
    mov  al, byte ptr [B64EncTable+eax]
    mov  [edi], al
    mov  eax, edx
    shr  eax, 12
    and  eax, 03Fh
    mov  al, byte ptr [B64EncTable+eax]
    mov  [edi+1], al
    mov  eax, edx
    shr  eax, 6
    and  eax, 03Fh
    mov  al, byte ptr [B64EncTable+eax]
    mov  [edi+2], al
    mov  eax, edx
    and  eax, 03Fh
    mov  al, byte ptr [B64EncTable+eax]
    mov  [edi+3], al
    add  esi, 3
    add  edi, 4
    sub  ecx, 3
    jmp  @lsloop
  @lstail:
    test ecx, ecx
    jz   @done
    movzx eax, byte ptr [esi]
    shl  eax, 16
    cmp  ecx, 1
    je   @lsemit
    movzx edx, byte ptr [esi+1]
    shl  edx, 8
    or   eax, edx
  @lsemit:
    mov  edx, eax
    shr  eax, 18
    mov  al, byte ptr [B64EncTable+eax]
    mov  [edi], al
    inc  edi
    mov  eax, edx
    shr  eax, 12
    and  eax, 03Fh
    mov  al, byte ptr [B64EncTable+eax]
    mov  [edi], al
    inc  edi
    cmp  ecx, 1
    je   @lsp2
    mov  eax, edx
    shr  eax, 6
    and  eax, 03Fh
    mov  al, byte ptr [B64EncTable+eax]
    mov  [edi], al
    inc  edi
    mov  byte ptr [edi], '='
    inc  edi
    jmp  @done
  @lsp2:
    mov  word ptr [edi], '=' * 256 + '='
    add  edi, 2
  @done:
    vzeroupper
    pop  ebx
    pop  edi
    pop  esi
end;
{$ENDIF WIN32}

function FusedBuildInfo(Src: PByte; Len: NativeInt; lineQuanta: Integer;
  const sep: TBytes; out W: NativeInt): TFusedInfo;
var
  rawLen, fullGroups, numBreaks: NativeInt;
begin
  rawLen := ((Len + 2) div 3) * 4;
  fullGroups := Len div 3;
  numBreaks := fullGroups div lineQuanta;
  W := rawLen + numBreaks * Length(sep);
  Result.Src := Src;
  Result.Dst := nil;
  if Length(sep) > 0 then
    Result.Sep := @sep[0]
  else
    Result.Sep := nil;
  Result.Len := Len;
  Result.LineQuanta := lineQuanta;
  Result.SepLen := Length(sep);
  Result.LineBytes := NativeInt(lineQuanta) * 3;
  Result.QCount := 0;
end;

function MimeEncodeFusedScalar(Src: PByte; Len: NativeInt; lineQuanta: Integer; const sep: TBytes): TBytes;
var
  W: NativeInt;
  info: TFusedInfo;
begin
  if Len <= 0 then
    Exit(nil);
  info := FusedBuildInfo(Src, Len, lineQuanta, sep, W);
  SetLength(Result, W + 64);
  info.Dst := @Result[0];
  EncodeFusedScalar(info);
  SetLength(Result, W);
end;

function MimeEncodeFusedAVX2(Src: PByte; Len: NativeInt; lineQuanta: Integer; const sep: TBytes): TBytes;
var
  W: NativeInt;
  info: TFusedInfo;
begin
  if Len <= 0 then
    Exit(nil);
  if not PolyFillHasAVX2 then
    Exit(MimeEncodeFusedScalar(Src, Len, lineQuanta, sep));
  info := FusedBuildInfo(Src, Len, lineQuanta, sep, W);
  SetLength(Result, W + 64);
  info.Dst := @Result[0];
  EncodeFusedAVX2(info);
  SetLength(Result, W);
end;

{ ============================================================================
  TBase64EncodingPolyFill
  ============================================================================ }

constructor TBase64EncodingPolyFill.Create;
begin
  Create(76, #13#10);
end;

constructor TBase64EncodingPolyFill.Create(CharsPerLine: Integer);
begin
  Create(CharsPerLine, #13#10);
end;

constructor TBase64EncodingPolyFill.Create(CharsPerLine: Integer; LineSeparator: string);
begin
  inherited Create;
  FCharsPerLine := CharsPerLine;
  FLineSeparator := LineSeparator;
end;

function TBase64EncodingPolyFill.EncodeBytesToString(const Input: Pointer; Size: Integer): string;
var
  rawBuf: TBytes;
  rawLen: NativeInt;
begin
  if Size <= 0 then
    Exit('');
  SetLength(rawBuf, ((NativeInt(Size) + 2) div 3) * 4 + 32);
  rawLen := EncodeRaw(PByte(Input), Size, @rawBuf[0]);
  Result := WidenAndWrap(@rawBuf[0], rawLen, Size, FCharsPerLine, FLineSeparator);
end;

function TBase64EncodingPolyFill.EncodeBytesToString(const Input: array of Byte): string;
begin
  if Length(Input) = 0 then
    Result := ''
  else
    Result := EncodeBytesToString(@Input[0], Length(Input));
end;

function TBase64EncodingPolyFill.Encode(const Input: array of Byte): TBytes;
var
  rawBuf, lineSep: TBytes;
  rawLen, n: NativeInt;
begin
  n := Length(Input);
  if n = 0 then
    Exit(nil);

  if FCharsPerLine <= 0 then
  begin
    // No wrapping: encode straight into the result (no scratch-buffer copy).
    SetLength(Result, ((n + 2) div 3) * 4 + 32);   // +32 slack for AVX2 stores
    rawLen := EncodeRaw(@Input[0], n, @Result[0]);
    SetLength(Result, rawLen);
    Exit;
  end;

  lineSep := TEncoding.UTF8.GetBytes(FLineSeparator);

  // Fastest path: single-pass fused encode+separator (no scratch buffer). Usable
  // for a 1- or 2-byte separator and a line width of at least one quantum.
  if (FCharsPerLine >= 4) and (Length(lineSep) in [1, 2]) then
    Exit(MimeEncodeFusedAVX2(@Input[0], n, FCharsPerLine div 4, lineSep));

  // Fallback for exotic separators / sub-quantum widths: encode then wrap.
  SetLength(rawBuf, ((n + 2) div 3) * 4 + 64);
  rawLen := EncodeRaw(@Input[0], n, @rawBuf[0]);
  if PolyFillHasAVX2 then
    Result := WrapRawFast(@rawBuf[0], rawLen, n, FCharsPerLine, lineSep)
  else
    Result := WrapRawToBytes(@rawBuf[0], rawLen, n, FCharsPerLine, lineSep);
end;

function TBase64EncodingPolyFill.Encode(const Input: string): string;
begin
  Result := EncodeBytesToString(TEncoding.UTF8.GetBytes(Input));
end;

function TBase64EncodingPolyFill.Encode(const Input, Output: TStream): Integer;
var
  inBuf, outBuf: TBytes;
  n: NativeInt;
begin
  n := Input.Size - Input.Position;
  if n <= 0 then
    Exit(0);
  SetLength(inBuf, n);
  Input.ReadBuffer(inBuf[0], n);
  outBuf := Encode(inBuf);
  Result := Length(outBuf);
  if Result > 0 then
    Output.WriteBuffer(outBuf[0], Result);
end;

function TBase64EncodingPolyFill.Decode(const Input: array of Byte): TBytes;
begin
  if Length(Input) = 0 then
    Result := nil
  else
    Result := DecodeBuffer(@Input[0], Length(Input));
end;

function TBase64EncodingPolyFill.DecodeStringToBytes(const Input: string): TBytes;
var
  ansi: TBytes;
  i, n: Integer;
begin
  n := Length(Input);
  if n = 0 then
    Exit(nil);
  // The base64 alphabet is ASCII; narrow the UTF-16 chars to bytes.
  SetLength(ansi, n);
  for i := 0 to n - 1 do
    ansi[i] := Byte(Input[i + 1]);
  Result := DecodeBuffer(@ansi[0], n);
end;

function TBase64EncodingPolyFill.Decode(const Input: string): string;
begin
  Result := TEncoding.UTF8.GetString(DecodeStringToBytes(Input));
end;

function TBase64EncodingPolyFill.Decode(const Input, Output: TStream): Integer;
var
  inBuf, outBuf: TBytes;
  n: NativeInt;
begin
  n := Input.Size - Input.Position;
  if n <= 0 then
    Exit(0);
  SetLength(inBuf, n);
  Input.ReadBuffer(inBuf[0], n);
  outBuf := Decode(inBuf);
  Result := Length(outBuf);
  if Result > 0 then
    Output.WriteBuffer(outBuf[0], Result);
end;

end.

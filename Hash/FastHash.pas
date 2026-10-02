unit FastHash;

{
  ============================================================================
  FastHash - assembly-accelerated versions of the System.Hash algorithms
  ============================================================================

  Drop-in counterparts of the System.Hash records with the same public
  methods, the same overloads and byte-identical results:

    System.Hash        FastHash
    -----------        --------
    THashMD5           THashMD5Fast
    THashSHA1          THashSHA1Fast
    THashSHA2          THashSHA2Fast     (SHA224, SHA256, SHA384, SHA512,
                                          SHA512_224, SHA512_256)
    THashBobJenkins    THashBobJenkinsFast
    THashFNV1a32       THashFNV1a32Fast
    THashFNV1a64       THashFNV1a64Fast

  The block functions are hand-written assembly with runtime dispatch (see
  FastHash.CPU):
    - Windows x86/x64: integer asm, AVX2+BMI2 message schedules for
      SHA-1/SHA-256/SHA-512, and the Intel SHA extensions for SHA-1/SHA-256;
    - ARM64 (macOS, iOS, Android): AArch64 asm and C versions, using the ARMv8
      Cryptographic Extension for SHA-1, SHA-256 and SHA-512 when present.
  Other platforms use the Pascal reference implementations.

  The unit does not use System.Hash. Behaviour mirrored from it on purpose:
    - Update(string) hashes UTF-8 for MD5/SHA-1/SHA-2 but the raw UTF-16
      bytes for BobJenkins/FNV-1a;
    - THashBobJenkinsFast.Update re-runs the whole hash seeded with the
      previous value (it is not a streaming hash), exactly like the RTL;
    - HashAsString is lower-case hex for MD5/SHA, upper-case
      (IntToHex) for BobJenkins/FNV-1a;
    - Update after the digest has been read raises (EFastHashException
      here, EHashException in the RTL).

  Usage:
    uses FastHash;
    s := THashSHA2Fast.GetHashString('abc');                 // SHA-256
    h := THashSHA1Fast.Create;  h.Update(Buf, Len);  d := h.HashAsBytes;
  ============================================================================
}

interface

uses
  System.Classes,
  System.SysUtils,
  FastHash.CPU;

type
  EFastHashException = class(Exception);

  TFastHashLevel = FastHash.CPU.TFastHashLevel;
  TFastHashAlgorithm = (fhaMD5, fhaSHA1, fhaSHA256, fhaSHA512, fhaNonCrypto);

const
  fhlPascal = FastHash.CPU.fhlPascal;
  fhlScalar = FastHash.CPU.fhlScalar;
  fhlSIMD   = FastHash.CPU.fhlSIMD;
  fhlCrypto = FastHash.CPU.fhlCrypto;
  fhlAVX2   = FastHash.CPU.fhlAVX2;
  fhlSHANI  = FastHash.CPU.fhlSHANI;

type
  /// <summary>MD5, interface-compatible with System.Hash.THashMD5.</summary>
  THashMD5Fast = record
  private
    FState: array[0..3] of Cardinal;
    FBuffer: array[0..63] of Byte;
    FLength: UInt64;
    FIndex: Cardinal;
    FFinalized: Boolean;
    procedure UpdateBuffer(Data: PByte; Len: Cardinal);
    procedure Finalize;
    function GetDigest: TBytes;
  public
    class function Create: THashMD5Fast; static; inline;
    procedure Reset;
    procedure Update(const AData; ALength: Cardinal); overload;
    procedure Update(const AData: TBytes; ALength: Cardinal = 0); overload; inline;
    procedure Update(const Input: string); overload; inline;
    function GetBlockSize: Integer; inline;
    function GetHashSize: Integer; inline;
    function HashAsBytes: TBytes; inline;
    function HashAsString: string; inline;
    class function GetHashBytes(const AData: string): TBytes; overload; static;
    class function GetHashString(const AString: string): string; overload; static; inline;
    class function GetHashBytes(const AStream: TStream): TBytes; overload; static;
    class function GetHashString(const AStream: TStream): string; overload; static; inline;
    class function GetHashBytesFromFile(const AFileName: TFileName): TBytes; static;
    class function GetHashStringFromFile(const AFileName: TFileName): string; static; inline;
    class function GetHMAC(const AData, AKey: string): string; static; inline;
    class function GetHMACAsBytes(const AData, AKey: string): TBytes; overload; static;
    class function GetHMACAsBytes(const AData: string; const AKey: TBytes): TBytes; overload; static;
    class function GetHMACAsBytes(const AData: TBytes; const AKey: string): TBytes; overload; static;
    class function GetHMACAsBytes(const AData, AKey: TBytes): TBytes; overload; static;
  end;

  /// <summary>SHA-1, interface-compatible with System.Hash.THashSHA1.</summary>
  THashSHA1Fast = record
  private
    FState: array[0..4] of Cardinal;
    FBuffer: array[0..63] of Byte;
    FLength: UInt64;
    FIndex: Cardinal;
    FFinalized: Boolean;
    procedure UpdateBuffer(Data: PByte; Len: Cardinal);
    procedure Finalize;
    function GetDigest: TBytes;
  public
    class function Create: THashSHA1Fast; static; inline;
    procedure Reset;
    procedure Update(const AData; ALength: Cardinal); overload;
    procedure Update(const AData: TBytes; ALength: Cardinal = 0); overload; inline;
    procedure Update(const Input: string); overload; inline;
    function GetBlockSize: Integer; inline;
    function GetHashSize: Integer; inline;
    function HashAsBytes: TBytes; inline;
    function HashAsString: string; inline;
    class function GetHashBytes(const AData: string): TBytes; overload; static;
    class function GetHashString(const AString: string): string; overload; static; inline;
    class function GetHashBytes(const AStream: TStream): TBytes; overload; static;
    class function GetHashString(const AStream: TStream): string; overload; static; inline;
    class function GetHashBytesFromFile(const AFileName: TFileName): TBytes; static;
    class function GetHashStringFromFile(const AFileName: TFileName): string; static; inline;
    class function GetHMAC(const AData, AKey: string): string; static; inline;
    class function GetHMACAsBytes(const AData, AKey: string): TBytes; overload; static;
    class function GetHMACAsBytes(const AData: string; const AKey: TBytes): TBytes; overload; static;
    class function GetHMACAsBytes(const AData: TBytes; const AKey: string): TBytes; overload; static;
    class function GetHMACAsBytes(const AData, AKey: TBytes): TBytes; overload; static;
  end;

  /// <summary>SHA-2 family, interface-compatible with System.Hash.THashSHA2.</summary>
  THashSHA2Fast = record
  public type
    TSHA2Version = (SHA224, SHA256, SHA384, SHA512, SHA512_224, SHA512_256);
  private
    FBuffer: array[0..127] of Byte;
    FLength: UInt64;
    FIndex: Cardinal;
    FFinalized: Boolean;
    FVersion: TSHA2Version;
    procedure Initialize(AVersion: TSHA2Version);
    procedure UpdateBuffer(Data: PByte; Len: Cardinal);
    procedure Finalize;
    function GetDigest: TBytes;
  public
    class function Create(AHashVersion: TSHA2Version = TSHA2Version.SHA256): THashSHA2Fast; static; inline;
    procedure Reset; inline;
    procedure Update(const AData; ALength: Cardinal); overload;
    procedure Update(const AData: TBytes; ALength: Cardinal = 0); overload; inline;
    procedure Update(const Input: string); overload; inline;
    function GetBlockSize: Integer; inline;
    function GetHashSize: Integer; inline;
    function HashAsBytes: TBytes; inline;
    function HashAsString: string; inline;
    class function GetHashBytes(const AData: string; AHashVersion: TSHA2Version = TSHA2Version.SHA256): TBytes; overload; static;
    class function GetHashString(const AString: string; AHashVersion: TSHA2Version = TSHA2Version.SHA256): string; overload; static; inline;
    class function GetHashBytes(const AStream: TStream; AHashVersion: TSHA2Version = TSHA2Version.SHA256): TBytes; overload; static;
    class function GetHashString(const AStream: TStream; AHashVersion: TSHA2Version = TSHA2Version.SHA256): string; overload; static; inline;
    class function GetHashBytesFromFile(const AFileName: TFileName; AHashVersion: TSHA2Version = TSHA2Version.SHA256): TBytes; static;
    class function GetHashStringFromFile(const AFileName: TFileName; AHashVersion: TSHA2Version = TSHA2Version.SHA256): string; static; inline;
    class function GetHMAC(const AData, AKey: string; AHashVersion: TSHA2Version = TSHA2Version.SHA256): string; static; inline;
    class function GetHMACAsBytes(const AData, AKey: string; AHashVersion: TSHA2Version = TSHA2Version.SHA256): TBytes; overload; static;
    class function GetHMACAsBytes(const AData: string; const AKey: TBytes; AHashVersion: TSHA2Version = TSHA2Version.SHA256): TBytes; overload; static;
    class function GetHMACAsBytes(const AData: TBytes; const AKey: string; AHashVersion: TSHA2Version = TSHA2Version.SHA256): TBytes; overload; static;
    class function GetHMACAsBytes(const AData, AKey: TBytes; AHashVersion: TSHA2Version = TSHA2Version.SHA256): TBytes; overload; static;
  private
    case Integer of
      0: (FState32: array[0..7] of Cardinal);
      1: (FState64: array[0..7] of UInt64);
  end;

  /// <summary>Bob Jenkins lookup3, interface-compatible with System.Hash.THashBobJenkins.</summary>
  THashBobJenkinsFast = record
  private
    FHash: Integer;
    function GetDigest: TBytes;
  public
    class function Create: THashBobJenkinsFast; static;
    procedure Reset(AInitialValue: Integer = 0);
    procedure Update(const AData; ALength: Cardinal); overload;
    procedure Update(const AData: TBytes; ALength: Cardinal = 0); overload;
    procedure Update(const Input: string); overload;
    function HashAsBytes: TBytes;
    function HashAsInteger: Integer;
    function HashAsString: string;
    class function GetHashBytes(const AData: string): TBytes; static;
    class function GetHashString(const AString: string): string; static;
    class function GetHashValue(const AData: string): Integer; overload; static;
    class function GetHashValue(const AData; ALength: Integer; AInitialValue: Integer = 0): Integer; overload; static;
  end;

  /// <summary>FNV-1a 32-bit, interface-compatible with System.Hash.THashFNV1a32.</summary>
  THashFNV1a32Fast = record
  public const
    FNV_PRIME = $01000193;
    FNV_SEED  = $811C9DC5;
  private
    FHash: Cardinal;
    function GetDigest: TBytes;
  public
    class function Create: THashFNV1a32Fast; static;
    procedure Reset(AInitialValue: Cardinal = FNV_SEED);
    procedure Update(const AData; ALength: Cardinal); overload;
    procedure Update(const AData: TBytes; ALength: Cardinal = 0); overload;
    procedure Update(const Input: string); overload;
    function HashAsBytes: TBytes;
    function HashAsInteger: Integer;
    function HashAsString: string;
    class function GetHashBytes(const AData: string): TBytes; static;
    class function GetHashString(const AString: string): string; overload; static;
    class function GetHashString(const AString: RawByteString): string; overload; static;
    class function GetHashValue(const AData: string): Integer; overload; static;
    class function GetHashValue(const AData: RawByteString): Integer; overload; static;
    class function GetHashValue(const AData; ALength: Cardinal; AInitialValue: Cardinal = FNV_SEED): Integer; overload; static;
  end;

  /// <summary>FNV-1a 64-bit, interface-compatible with System.Hash.THashFNV1a64.</summary>
  THashFNV1a64Fast = record
  public const
    FNV_PRIME = $00000100000001B3;
    FNV_SEED  = $CBF29CE484222325;
  private
    FHash: UInt64;
    function GetDigest: TBytes;
  public
    class function Create: THashFNV1a64Fast; static;
    procedure Reset(AInitialValue: UInt64 = FNV_SEED);
    procedure Update(const AData; ALength: Cardinal); overload;
    procedure Update(const AData: TBytes; ALength: Cardinal = 0); overload;
    procedure Update(const Input: string); overload;
    function HashAsBytes: TBytes;
    function HashAsInteger: Int64;
    function HashAsString: string;
    class function GetHashBytes(const AData: string): TBytes; static;
    class function GetHashString(const AString: string): string; overload; static;
    class function GetHashString(const AString: RawByteString): string; overload; static;
    class function GetHashValue(const AData: string): Int64; overload; static;
    class function GetHashValue(const AData: RawByteString): Int64; overload; static;
    class function GetHashValue(const AData; ALength: Cardinal; AInitialValue: UInt64 = FNV_SEED): Int64; overload; static;
  end;

/// <summary>Lowers (or raises back) the fastest code path every algorithm may
/// use. Each algorithm picks the best level it implements that is at or below
/// MaxLevel and supported by this CPU. Not thread-safe: call it before
/// hashing starts (the tests and the benchmark use it to pin a path).</summary>
procedure FastHashSetMaxLevel(MaxLevel: TFastHashLevel);
/// <summary>The code path an algorithm is currently using.</summary>
function FastHashActiveLevel(Algorithm: TFastHashAlgorithm): TFastHashLevel;
/// <summary>The implementation an algorithm is currently using, e.g. 'CE asm'.</summary>
function FastHashActiveImplementation(Algorithm: TFastHashAlgorithm): string;
/// <summary>Lower-case hex, like System.Hash.THash.DigestAsString.</summary>
function FastHashDigestAsString(const ADigest: TBytes): string;

implementation

uses
  FastHash.MD5,
  FastHash.SHA1,
  FastHash.SHA256,
  FastHash.SHA512,
  FastHash.NonCrypto;

{$Q-}{$R-}

const
  SCannotUpdateMD5 = 'MD5: Cannot update a finalized hash';
  SCannotUpdateSHA1 = 'SHA1: Cannot update a finalized hash';
  SCannotUpdateSHA2 = 'SHA2: Cannot update a finalized hash';
  StreamBufferSize = 64 * 1024;

type
  TCompressProc = procedure(State: Pointer; Data: PByte; Blocks: NativeUInt);

{ ---------------------------------------------------------------------------
  Shared helpers
  --------------------------------------------------------------------------- }

procedure FastHashSetMaxLevel(MaxLevel: TFastHashLevel);
begin
  MD5SetMaxLevel(MaxLevel);
  SHA1SetMaxLevel(MaxLevel);
  SHA256SetMaxLevel(MaxLevel);
  SHA512SetMaxLevel(MaxLevel);
  NonCryptoSetMaxLevel(MaxLevel);
end;

function FastHashActiveLevel(Algorithm: TFastHashAlgorithm): TFastHashLevel;
begin
  case Algorithm of
    fhaMD5: Result := MD5ActiveLevel;
    fhaSHA1: Result := SHA1ActiveLevel;
    fhaSHA256: Result := SHA256ActiveLevel;
    fhaSHA512: Result := SHA512ActiveLevel;
  else
    Result := NonCryptoActiveLevel;
  end;
end;

function FastHashActiveImplementation(Algorithm: TFastHashAlgorithm): string;
begin
  case Algorithm of
    fhaMD5: Result := MD5ActiveImplementation;
    fhaSHA1: Result := SHA1ActiveImplementation;
    fhaSHA256: Result := SHA256ActiveImplementation;
    fhaSHA512: Result := SHA512ActiveImplementation;
  else
    Result := NonCryptoActiveImplementation;
  end;
end;

function FastHashDigestAsString(const ADigest: TBytes): string;
const
  XD: array[0..15] of Char = '0123456789abcdef';
var
  I: Integer;
  PC: PChar;
begin
  SetLength(Result, Length(ADigest) * 2);
  PC := Pointer(Result);
  for I := 0 to High(ADigest) do
  begin
    PC[0] := XD[ADigest[I] shr 4];
    PC[1] := XD[ADigest[I] and $0F];
    Inc(PC, 2);
  end;
end;

// Buffers partial blocks and hands every complete block run to Compress in
// one call, so the asm sees the bulk of each Update as a single multi-block call.
procedure BufferedUpdate(Compress: TCompressProc; State, Buffer: PByte; var Index: Cardinal;
  BlockSize: Cardinal; Data: PByte; Len: Cardinal);
var
  N, Blocks: Cardinal;
begin
  if Len = 0 then
    Exit;
  if Index > 0 then
  begin
    N := BlockSize - Index;
    if N > Len then
      N := Len;
    Move(Data^, Buffer[Index], N);
    Inc(Index, N);
    Inc(Data, N);
    Dec(Len, N);
    if Index < BlockSize then
      Exit;
    Compress(State, Buffer, 1);
    Index := 0;
  end;
  Blocks := Len div BlockSize;
  if Blocks > 0 then
  begin
    Compress(State, Data, Blocks);
    Inc(Data, Blocks * BlockSize);
    Dec(Len, Blocks * BlockSize);
  end;
  if Len > 0 then
  begin
    Move(Data^, Buffer[0], Len);
    Index := Len;
  end;
end;

// Appends $80, zero padding and the 64-bit message bit length (big- or
// little-endian) in the last 8 bytes, then compresses the final block(s).
// For 128-byte blocks the upper 64 bits of the 128-bit length are zero.
procedure PadAndCompress(Compress: TCompressProc; State, Buffer: PByte; Index: Cardinal;
  BlockSize: Cardinal; ByteLength: UInt64; BigEndian: Boolean);
var
  LenField: Cardinal;
  Bits: UInt64;
  I: Integer;
begin
  if BlockSize = 128 then
    LenField := 16
  else
    LenField := 8;
  Buffer[Index] := $80;
  Inc(Index);
  if Index > BlockSize - LenField then
  begin
    FillChar(Buffer[Index], BlockSize - Index, 0);
    Compress(State, Buffer, 1);
    Index := 0;
  end;
  FillChar(Buffer[Index], BlockSize - 8 - Index, 0);
  Bits := ByteLength shl 3;
  for I := 0 to 7 do
    if BigEndian then
      Buffer[BlockSize - 1 - Cardinal(I)] := Byte(Bits shr (8 * I))
    else
      Buffer[BlockSize - 8 + Cardinal(I)] := Byte(Bits shr (8 * I));
  Compress(State, Buffer, 1);
end;

function BigEndianWords32(const Words; Count, Bytes: Integer): TBytes;
var
  P: PCardinal;
  I: Integer;
  W: Cardinal;
  Full: TBytes;
begin
  SetLength(Full, Count * 4);
  P := @Words;
  for I := 0 to Count - 1 do
  begin
    W := P^;
    Full[4 * I] := Byte(W shr 24);
    Full[4 * I + 1] := Byte(W shr 16);
    Full[4 * I + 2] := Byte(W shr 8);
    Full[4 * I + 3] := Byte(W);
    Inc(P);
  end;
  Result := Copy(Full, 0, Bytes);
end;

function BigEndianWords64(const Words; Bytes: Integer): TBytes;
var
  P: PUInt64;
  I, J: Integer;
  W: UInt64;
  Full: TBytes;
begin
  SetLength(Full, 64);
  P := @Words;
  for I := 0 to 7 do
  begin
    W := P^;
    for J := 0 to 7 do
      Full[8 * I + J] := Byte(W shr (56 - 8 * J));
    Inc(P);
  end;
  Result := Copy(Full, 0, Bytes);
end;

// Key block for HMAC: the key (hashed first if longer than a block), zero
// padded to BlockSize, xor'ed with Pad.
function HMACKeyBlock(const Key: TBytes; BlockSize: Integer; Pad: Byte): TBytes;
var
  I: Integer;
begin
  SetLength(Result, BlockSize);
  for I := 0 to BlockSize - 1 do
    if I < Length(Key) then
      Result[I] := Key[I] xor Pad
    else
      Result[I] := Pad;
end;

procedure StreamHash(const AStream: TStream; const Feed: TProc<PByte, Integer>);
var
  Buf: TBytes;
  N: Integer;
begin
  SetLength(Buf, StreamBufferSize);
  repeat
    N := AStream.Read(Buf[0], StreamBufferSize);
    if N <= 0 then
      Break;
    Feed(@Buf[0], N);
  until False;
end;

function ReadFileHash(const AFileName: TFileName; const Hasher: TFunc<TStream, TBytes>): TBytes;
var
  LFile: TFileStream;
begin
  LFile := TFileStream.Create(AFileName, fmShareDenyNone or fmOpenRead);
  try
    Result := Hasher(LFile);
  finally
    LFile.Free;
  end;
end;

{ ---------------------------------------------------------------------------
  THashMD5Fast
  --------------------------------------------------------------------------- }

class function THashMD5Fast.Create: THashMD5Fast;
begin
  Result.Reset;
end;

procedure THashMD5Fast.Reset;
begin
  FState[0] := $67452301;
  FState[1] := $EFCDAB89;
  FState[2] := $98BADCFE;
  FState[3] := $10325476;
  FLength := 0;
  FIndex := 0;
  FFinalized := False;
end;

procedure THashMD5Fast.UpdateBuffer(Data: PByte; Len: Cardinal);
begin
  if FFinalized then
    raise EFastHashException.Create(SCannotUpdateMD5);
  Inc(FLength, Len);
  BufferedUpdate(MD5Compress, @FState, @FBuffer, FIndex, 64, Data, Len);
end;

procedure THashMD5Fast.Update(const AData; ALength: Cardinal);
begin
  UpdateBuffer(@AData, ALength);
end;

procedure THashMD5Fast.Update(const AData: TBytes; ALength: Cardinal);
begin
  if ALength = 0 then
    ALength := Length(AData);
  UpdateBuffer(PByte(AData), ALength);
end;

procedure THashMD5Fast.Update(const Input: string);
begin
  Update(TEncoding.UTF8.GetBytes(Input));
end;

procedure THashMD5Fast.Finalize;
begin
  PadAndCompress(MD5Compress, @FState, @FBuffer, FIndex, 64, FLength, False);
  FFinalized := True;
end;

function THashMD5Fast.GetDigest: TBytes;
begin
  if not FFinalized then
    Finalize;
  SetLength(Result, 16);
  Move(FState, Result[0], 16);
end;

function THashMD5Fast.GetBlockSize: Integer;
begin
  Result := 64;
end;

function THashMD5Fast.GetHashSize: Integer;
begin
  Result := 16;
end;

function THashMD5Fast.HashAsBytes: TBytes;
begin
  Result := GetDigest;
end;

function THashMD5Fast.HashAsString: string;
begin
  Result := FastHashDigestAsString(GetDigest);
end;

class function THashMD5Fast.GetHashBytes(const AData: string): TBytes;
var
  H: THashMD5Fast;
begin
  H := THashMD5Fast.Create;
  H.Update(AData);
  Result := H.GetDigest;
end;

class function THashMD5Fast.GetHashString(const AString: string): string;
begin
  Result := FastHashDigestAsString(GetHashBytes(AString));
end;

class function THashMD5Fast.GetHashBytes(const AStream: TStream): TBytes;
var
  H: THashMD5Fast;
begin
  H := THashMD5Fast.Create;
  StreamHash(AStream, procedure(P: PByte; N: Integer) begin H.UpdateBuffer(P, N); end);
  Result := H.GetDigest;
end;

class function THashMD5Fast.GetHashString(const AStream: TStream): string;
begin
  Result := FastHashDigestAsString(GetHashBytes(AStream));
end;

class function THashMD5Fast.GetHashBytesFromFile(const AFileName: TFileName): TBytes;
begin
  Result := ReadFileHash(AFileName, function(S: TStream): TBytes begin Result := GetHashBytes(S); end);
end;

class function THashMD5Fast.GetHashStringFromFile(const AFileName: TFileName): string;
begin
  Result := FastHashDigestAsString(GetHashBytesFromFile(AFileName));
end;

class function THashMD5Fast.GetHMAC(const AData, AKey: string): string;
begin
  Result := FastHashDigestAsString(GetHMACAsBytes(AData, AKey));
end;

class function THashMD5Fast.GetHMACAsBytes(const AData, AKey: string): TBytes;
begin
  Result := GetHMACAsBytes(TEncoding.UTF8.GetBytes(AData), TEncoding.UTF8.GetBytes(AKey));
end;

class function THashMD5Fast.GetHMACAsBytes(const AData: string; const AKey: TBytes): TBytes;
begin
  Result := GetHMACAsBytes(TEncoding.UTF8.GetBytes(AData), AKey);
end;

class function THashMD5Fast.GetHMACAsBytes(const AData: TBytes; const AKey: string): TBytes;
begin
  Result := GetHMACAsBytes(AData, TEncoding.UTF8.GetBytes(AKey));
end;

class function THashMD5Fast.GetHMACAsBytes(const AData, AKey: TBytes): TBytes;
var
  H: THashMD5Fast;
  Key, Inner: TBytes;
begin
  Key := AKey;
  if Length(Key) > 64 then
  begin
    H := THashMD5Fast.Create;
    H.Update(Key);
    Key := H.GetDigest;
  end;
  H := THashMD5Fast.Create;
  H.Update(HMACKeyBlock(Key, 64, $36));
  H.Update(AData);
  Inner := H.GetDigest;
  H := THashMD5Fast.Create;
  H.Update(HMACKeyBlock(Key, 64, $5C));
  H.Update(Inner);
  Result := H.GetDigest;
end;

{ ---------------------------------------------------------------------------
  THashSHA1Fast
  --------------------------------------------------------------------------- }

class function THashSHA1Fast.Create: THashSHA1Fast;
begin
  Result.Reset;
end;

procedure THashSHA1Fast.Reset;
begin
  FState[0] := $67452301;
  FState[1] := $EFCDAB89;
  FState[2] := $98BADCFE;
  FState[3] := $10325476;
  FState[4] := $C3D2E1F0;
  FLength := 0;
  FIndex := 0;
  FFinalized := False;
end;

procedure THashSHA1Fast.UpdateBuffer(Data: PByte; Len: Cardinal);
begin
  if FFinalized then
    raise EFastHashException.Create(SCannotUpdateSHA1);
  Inc(FLength, Len);
  BufferedUpdate(SHA1Compress, @FState, @FBuffer, FIndex, 64, Data, Len);
end;

procedure THashSHA1Fast.Update(const AData; ALength: Cardinal);
begin
  UpdateBuffer(@AData, ALength);
end;

procedure THashSHA1Fast.Update(const AData: TBytes; ALength: Cardinal);
begin
  if ALength = 0 then
    ALength := Length(AData);
  UpdateBuffer(PByte(AData), ALength);
end;

procedure THashSHA1Fast.Update(const Input: string);
begin
  Update(TEncoding.UTF8.GetBytes(Input));
end;

procedure THashSHA1Fast.Finalize;
begin
  if FFinalized then
    raise EFastHashException.Create(SCannotUpdateSHA1);
  PadAndCompress(SHA1Compress, @FState, @FBuffer, FIndex, 64, FLength, True);
  FFinalized := True;
end;

function THashSHA1Fast.GetDigest: TBytes;
begin
  if not FFinalized then
    Finalize;
  Result := BigEndianWords32(FState, 5, 20);
end;

function THashSHA1Fast.GetBlockSize: Integer;
begin
  Result := 64;
end;

function THashSHA1Fast.GetHashSize: Integer;
begin
  Result := 20;
end;

function THashSHA1Fast.HashAsBytes: TBytes;
begin
  Result := GetDigest;
end;

function THashSHA1Fast.HashAsString: string;
begin
  Result := FastHashDigestAsString(GetDigest);
end;

class function THashSHA1Fast.GetHashBytes(const AData: string): TBytes;
var
  H: THashSHA1Fast;
begin
  H := THashSHA1Fast.Create;
  H.Update(AData);
  Result := H.GetDigest;
end;

class function THashSHA1Fast.GetHashString(const AString: string): string;
begin
  Result := FastHashDigestAsString(GetHashBytes(AString));
end;

class function THashSHA1Fast.GetHashBytes(const AStream: TStream): TBytes;
var
  H: THashSHA1Fast;
begin
  H := THashSHA1Fast.Create;
  StreamHash(AStream, procedure(P: PByte; N: Integer) begin H.UpdateBuffer(P, N); end);
  Result := H.GetDigest;
end;

class function THashSHA1Fast.GetHashString(const AStream: TStream): string;
begin
  Result := FastHashDigestAsString(GetHashBytes(AStream));
end;

class function THashSHA1Fast.GetHashBytesFromFile(const AFileName: TFileName): TBytes;
begin
  Result := ReadFileHash(AFileName, function(S: TStream): TBytes begin Result := GetHashBytes(S); end);
end;

class function THashSHA1Fast.GetHashStringFromFile(const AFileName: TFileName): string;
begin
  Result := FastHashDigestAsString(GetHashBytesFromFile(AFileName));
end;

class function THashSHA1Fast.GetHMAC(const AData, AKey: string): string;
begin
  Result := FastHashDigestAsString(GetHMACAsBytes(AData, AKey));
end;

class function THashSHA1Fast.GetHMACAsBytes(const AData, AKey: string): TBytes;
begin
  Result := GetHMACAsBytes(TEncoding.UTF8.GetBytes(AData), TEncoding.UTF8.GetBytes(AKey));
end;

class function THashSHA1Fast.GetHMACAsBytes(const AData: string; const AKey: TBytes): TBytes;
begin
  Result := GetHMACAsBytes(TEncoding.UTF8.GetBytes(AData), AKey);
end;

class function THashSHA1Fast.GetHMACAsBytes(const AData: TBytes; const AKey: string): TBytes;
begin
  Result := GetHMACAsBytes(AData, TEncoding.UTF8.GetBytes(AKey));
end;

class function THashSHA1Fast.GetHMACAsBytes(const AData, AKey: TBytes): TBytes;
var
  H: THashSHA1Fast;
  Key, Inner: TBytes;
begin
  Key := AKey;
  if Length(Key) > 64 then
  begin
    H := THashSHA1Fast.Create;
    H.Update(Key);
    Key := H.GetDigest;
  end;
  H := THashSHA1Fast.Create;
  H.Update(HMACKeyBlock(Key, 64, $36));
  H.Update(AData);
  Inner := H.GetDigest;
  H := THashSHA1Fast.Create;
  H.Update(HMACKeyBlock(Key, 64, $5C));
  H.Update(Inner);
  Result := H.GetDigest;
end;

{ ---------------------------------------------------------------------------
  THashSHA2Fast
  --------------------------------------------------------------------------- }

class function THashSHA2Fast.Create(AHashVersion: TSHA2Version): THashSHA2Fast;
begin
  Result.Initialize(AHashVersion);
end;

procedure THashSHA2Fast.Initialize(AVersion: TSHA2Version);
const
  IV224: array[0..7] of Cardinal = (
    $c1059ed8, $367cd507, $3070dd17, $f70e5939, $ffc00b31, $68581511, $64f98fa7, $befa4fa4);
  IV256: array[0..7] of Cardinal = (
    $6a09e667, $bb67ae85, $3c6ef372, $a54ff53a, $510e527f, $9b05688c, $1f83d9ab, $5be0cd19);
  IV384: array[0..7] of UInt64 = (
    $cbbb9d5dc1059ed8, $629a292a367cd507, $9159015a3070dd17, $152fecd8f70e5939,
    $67332667ffc00b31, $8eb44a8768581511, $db0c2e0d64f98fa7, $47b5481dbefa4fa4);
  IV512: array[0..7] of UInt64 = (
    $6a09e667f3bcc908, $bb67ae8584caa73b, $3c6ef372fe94f82b, $a54ff53a5f1d36f1,
    $510e527fade682d1, $9b05688c2b3e6c1f, $1f83d9abfb41bd6b, $5be0cd19137e2179);
  IV512_224: array[0..7] of UInt64 = (
    $8C3D37C819544DA2, $73E1996689DCD4D6, $1DFAB7AE32FF9C82, $679DD514582F9FCF,
    $0F6D2B697BD44DA8, $77E36F7304C48942, $3F9D85A86A1D36C8, $1112E6AD91D692A1);
  IV512_256: array[0..7] of UInt64 = (
    $22312194FC2BF72C, $9F555FA3C84C64C2, $2393B86B6F53B151, $963877195940EABD,
    $96283EE2A88EFFE3, $BE5E1E2553863992, $2B0199FC2C85B8AA, $0EB72DDC81C52CA2);
begin
  FVersion := AVersion;
  FLength := 0;
  FIndex := 0;
  FFinalized := False;
  case AVersion of
    TSHA2Version.SHA224: Move(IV224, FState32, SizeOf(IV224));
    TSHA2Version.SHA256: Move(IV256, FState32, SizeOf(IV256));
    TSHA2Version.SHA384: Move(IV384, FState64, SizeOf(IV384));
    TSHA2Version.SHA512: Move(IV512, FState64, SizeOf(IV512));
    TSHA2Version.SHA512_224: Move(IV512_224, FState64, SizeOf(IV512_224));
    TSHA2Version.SHA512_256: Move(IV512_256, FState64, SizeOf(IV512_256));
  end;
end;

procedure THashSHA2Fast.Reset;
begin
  Initialize(FVersion);
end;

procedure THashSHA2Fast.UpdateBuffer(Data: PByte; Len: Cardinal);
begin
  if FFinalized then
    raise EFastHashException.Create(SCannotUpdateSHA2);
  Inc(FLength, Len);
  if FVersion in [TSHA2Version.SHA224, TSHA2Version.SHA256] then
    BufferedUpdate(SHA256Compress, @FState32, @FBuffer, FIndex, 64, Data, Len)
  else
    BufferedUpdate(SHA512Compress, @FState64, @FBuffer, FIndex, 128, Data, Len);
end;

procedure THashSHA2Fast.Update(const AData; ALength: Cardinal);
begin
  UpdateBuffer(@AData, ALength);
end;

procedure THashSHA2Fast.Update(const AData: TBytes; ALength: Cardinal);
begin
  if ALength = 0 then
    ALength := Length(AData);
  UpdateBuffer(PByte(AData), ALength);
end;

procedure THashSHA2Fast.Update(const Input: string);
begin
  Update(TEncoding.UTF8.GetBytes(Input));
end;

procedure THashSHA2Fast.Finalize;
begin
  if FFinalized then
    raise EFastHashException.Create(SCannotUpdateSHA2);
  if FVersion in [TSHA2Version.SHA224, TSHA2Version.SHA256] then
    PadAndCompress(SHA256Compress, @FState32, @FBuffer, FIndex, 64, FLength, True)
  else
    PadAndCompress(SHA512Compress, @FState64, @FBuffer, FIndex, 128, FLength, True);
  FFinalized := True;
end;

function THashSHA2Fast.GetDigest: TBytes;
begin
  if not FFinalized then
    Finalize;
  if FVersion in [TSHA2Version.SHA224, TSHA2Version.SHA256] then
    Result := BigEndianWords32(FState32, 8, GetHashSize)
  else
    Result := BigEndianWords64(FState64, GetHashSize);
end;

function THashSHA2Fast.GetBlockSize: Integer;
begin
  if FVersion in [TSHA2Version.SHA224, TSHA2Version.SHA256] then
    Result := 64
  else
    Result := 128;
end;

function THashSHA2Fast.GetHashSize: Integer;
begin
  case FVersion of
    TSHA2Version.SHA224: Result := 28;
    TSHA2Version.SHA256: Result := 32;
    TSHA2Version.SHA384: Result := 48;
    TSHA2Version.SHA512: Result := 64;
    TSHA2Version.SHA512_224: Result := 28;
  else
    Result := 32;   // SHA512_256
  end;
end;

function THashSHA2Fast.HashAsBytes: TBytes;
begin
  Result := GetDigest;
end;

function THashSHA2Fast.HashAsString: string;
begin
  Result := FastHashDigestAsString(GetDigest);
end;

class function THashSHA2Fast.GetHashBytes(const AData: string; AHashVersion: TSHA2Version): TBytes;
var
  H: THashSHA2Fast;
begin
  H := THashSHA2Fast.Create(AHashVersion);
  H.Update(AData);
  Result := H.GetDigest;
end;

class function THashSHA2Fast.GetHashString(const AString: string; AHashVersion: TSHA2Version): string;
begin
  Result := FastHashDigestAsString(GetHashBytes(AString, AHashVersion));
end;

class function THashSHA2Fast.GetHashBytes(const AStream: TStream; AHashVersion: TSHA2Version): TBytes;
var
  H: THashSHA2Fast;
begin
  H := THashSHA2Fast.Create(AHashVersion);
  StreamHash(AStream, procedure(P: PByte; N: Integer) begin H.UpdateBuffer(P, N); end);
  Result := H.GetDigest;
end;

class function THashSHA2Fast.GetHashString(const AStream: TStream; AHashVersion: TSHA2Version): string;
begin
  Result := FastHashDigestAsString(GetHashBytes(AStream, AHashVersion));
end;

class function THashSHA2Fast.GetHashBytesFromFile(const AFileName: TFileName; AHashVersion: TSHA2Version): TBytes;
begin
  Result := ReadFileHash(AFileName,
    function(S: TStream): TBytes begin Result := GetHashBytes(S, AHashVersion); end);
end;

class function THashSHA2Fast.GetHashStringFromFile(const AFileName: TFileName; AHashVersion: TSHA2Version): string;
begin
  Result := FastHashDigestAsString(GetHashBytesFromFile(AFileName, AHashVersion));
end;

class function THashSHA2Fast.GetHMAC(const AData, AKey: string; AHashVersion: TSHA2Version): string;
begin
  Result := FastHashDigestAsString(GetHMACAsBytes(AData, AKey, AHashVersion));
end;

class function THashSHA2Fast.GetHMACAsBytes(const AData, AKey: string; AHashVersion: TSHA2Version): TBytes;
begin
  Result := GetHMACAsBytes(TEncoding.UTF8.GetBytes(AData), TEncoding.UTF8.GetBytes(AKey), AHashVersion);
end;

class function THashSHA2Fast.GetHMACAsBytes(const AData: string; const AKey: TBytes; AHashVersion: TSHA2Version): TBytes;
begin
  Result := GetHMACAsBytes(TEncoding.UTF8.GetBytes(AData), AKey, AHashVersion);
end;

class function THashSHA2Fast.GetHMACAsBytes(const AData: TBytes; const AKey: string; AHashVersion: TSHA2Version): TBytes;
begin
  Result := GetHMACAsBytes(AData, TEncoding.UTF8.GetBytes(AKey), AHashVersion);
end;

class function THashSHA2Fast.GetHMACAsBytes(const AData, AKey: TBytes; AHashVersion: TSHA2Version): TBytes;
var
  H: THashSHA2Fast;
  Key, Inner: TBytes;
  BlockSize: Integer;
begin
  H := THashSHA2Fast.Create(AHashVersion);
  BlockSize := H.GetBlockSize;
  Key := AKey;
  if Length(Key) > BlockSize then
  begin
    H.Update(Key);
    Key := H.GetDigest;
  end;
  H := THashSHA2Fast.Create(AHashVersion);
  H.Update(HMACKeyBlock(Key, BlockSize, $36));
  H.Update(AData);
  Inner := H.GetDigest;
  H := THashSHA2Fast.Create(AHashVersion);
  H.Update(HMACKeyBlock(Key, BlockSize, $5C));
  H.Update(Inner);
  Result := H.GetDigest;
end;

{ ---------------------------------------------------------------------------
  THashBobJenkinsFast
  --------------------------------------------------------------------------- }

class function THashBobJenkinsFast.Create: THashBobJenkinsFast;
begin
  Result.FHash := 0;
end;

procedure THashBobJenkinsFast.Reset(AInitialValue: Integer);
begin
  FHash := AInitialValue;
end;

procedure THashBobJenkinsFast.Update(const AData; ALength: Cardinal);
begin
  FHash := BobJenkinsHashLittle(@AData, Integer(ALength), FHash);
end;

procedure THashBobJenkinsFast.Update(const AData: TBytes; ALength: Cardinal);
begin
  if ALength = 0 then
    ALength := Length(AData);
  FHash := BobJenkinsHashLittle(PByte(AData), Integer(ALength), FHash);
end;

procedure THashBobJenkinsFast.Update(const Input: string);
begin
  FHash := BobJenkinsHashLittle(Pointer(Input), Length(Input) * SizeOf(Char), FHash);
end;

function THashBobJenkinsFast.GetDigest: TBytes;
var
  H: Cardinal;
begin
  H := Cardinal(FHash);
  SetLength(Result, 4);
  Result[0] := Byte(H shr 24);
  Result[1] := Byte(H shr 16);
  Result[2] := Byte(H shr 8);
  Result[3] := Byte(H);
end;

function THashBobJenkinsFast.HashAsBytes: TBytes;
begin
  Result := GetDigest;
end;

function THashBobJenkinsFast.HashAsInteger: Integer;
begin
  Result := FHash;
end;

function THashBobJenkinsFast.HashAsString: string;
begin
  Result := IntToHex(FHash, 8);
end;

class function THashBobJenkinsFast.GetHashBytes(const AData: string): TBytes;
var
  H: THashBobJenkinsFast;
begin
  H.FHash := GetHashValue(AData);
  Result := H.GetDigest;
end;

class function THashBobJenkinsFast.GetHashString(const AString: string): string;
begin
  Result := IntToHex(GetHashValue(AString), 8);
end;

class function THashBobJenkinsFast.GetHashValue(const AData: string): Integer;
begin
  Result := BobJenkinsHashLittle(Pointer(AData), Length(AData) * SizeOf(Char), 0);
end;

class function THashBobJenkinsFast.GetHashValue(const AData; ALength: Integer; AInitialValue: Integer): Integer;
begin
  Result := BobJenkinsHashLittle(@AData, ALength, AInitialValue);
end;

{ ---------------------------------------------------------------------------
  THashFNV1a32Fast
  --------------------------------------------------------------------------- }

class function THashFNV1a32Fast.Create: THashFNV1a32Fast;
begin
  Result.FHash := FNV_SEED;
end;

procedure THashFNV1a32Fast.Reset(AInitialValue: Cardinal);
begin
  FHash := AInitialValue;
end;

procedure THashFNV1a32Fast.Update(const AData; ALength: Cardinal);
begin
  FHash := FNV1a32Hash(@AData, ALength, FHash);
end;

procedure THashFNV1a32Fast.Update(const AData: TBytes; ALength: Cardinal);
begin
  if ALength = 0 then
    ALength := Length(AData);
  FHash := FNV1a32Hash(PByte(AData), ALength, FHash);
end;

procedure THashFNV1a32Fast.Update(const Input: string);
begin
  FHash := FNV1a32Hash(Pointer(Input), Length(Input) * SizeOf(Char), FHash);
end;

function THashFNV1a32Fast.GetDigest: TBytes;
begin
  SetLength(Result, 4);
  PCardinal(@Result[0])^ := FHash;
end;

function THashFNV1a32Fast.HashAsBytes: TBytes;
begin
  Result := GetDigest;
end;

function THashFNV1a32Fast.HashAsInteger: Integer;
begin
  Result := Integer(FHash);
end;

function THashFNV1a32Fast.HashAsString: string;
begin
  Result := IntToHex(FHash, 8);
end;

class function THashFNV1a32Fast.GetHashBytes(const AData: string): TBytes;
begin
  SetLength(Result, 4);
  PCardinal(@Result[0])^ := FNV1a32Hash(Pointer(AData), Length(AData) * SizeOf(Char), FNV_SEED);
end;

class function THashFNV1a32Fast.GetHashString(const AString: string): string;
begin
  Result := IntToHex(GetHashValue(AString), 8);
end;

class function THashFNV1a32Fast.GetHashString(const AString: RawByteString): string;
begin
  Result := IntToHex(GetHashValue(AString), 8);
end;

class function THashFNV1a32Fast.GetHashValue(const AData: string): Integer;
begin
  Result := Integer(FNV1a32Hash(Pointer(AData), Length(AData) * SizeOf(Char), FNV_SEED));
end;

class function THashFNV1a32Fast.GetHashValue(const AData: RawByteString): Integer;
begin
  Result := Integer(FNV1a32Hash(Pointer(AData), Length(AData), FNV_SEED));
end;

class function THashFNV1a32Fast.GetHashValue(const AData; ALength: Cardinal; AInitialValue: Cardinal): Integer;
begin
  Result := Integer(FNV1a32Hash(@AData, ALength, AInitialValue));
end;

{ ---------------------------------------------------------------------------
  THashFNV1a64Fast
  --------------------------------------------------------------------------- }

class function THashFNV1a64Fast.Create: THashFNV1a64Fast;
begin
  Result.FHash := FNV_SEED;
end;

procedure THashFNV1a64Fast.Reset(AInitialValue: UInt64);
begin
  FHash := AInitialValue;
end;

procedure THashFNV1a64Fast.Update(const AData; ALength: Cardinal);
begin
  FHash := FNV1a64Hash(@AData, ALength, FHash);
end;

procedure THashFNV1a64Fast.Update(const AData: TBytes; ALength: Cardinal);
begin
  if ALength = 0 then
    ALength := Length(AData);
  FHash := FNV1a64Hash(PByte(AData), ALength, FHash);
end;

procedure THashFNV1a64Fast.Update(const Input: string);
begin
  FHash := FNV1a64Hash(Pointer(Input), Length(Input) * SizeOf(Char), FHash);
end;

function THashFNV1a64Fast.GetDigest: TBytes;
begin
  SetLength(Result, 8);
  PUInt64(@Result[0])^ := FHash;
end;

function THashFNV1a64Fast.HashAsBytes: TBytes;
begin
  Result := GetDigest;
end;

function THashFNV1a64Fast.HashAsInteger: Int64;
begin
  Result := Int64(FHash);
end;

function THashFNV1a64Fast.HashAsString: string;
begin
  Result := IntToHex(FHash, 16);
end;

class function THashFNV1a64Fast.GetHashBytes(const AData: string): TBytes;
begin
  SetLength(Result, 8);
  PUInt64(@Result[0])^ := FNV1a64Hash(Pointer(AData), Length(AData) * SizeOf(Char), FNV_SEED);
end;

class function THashFNV1a64Fast.GetHashString(const AString: string): string;
begin
  Result := IntToHex(GetHashValue(AString), 16);
end;

class function THashFNV1a64Fast.GetHashString(const AString: RawByteString): string;
begin
  Result := IntToHex(GetHashValue(AString), 16);
end;

class function THashFNV1a64Fast.GetHashValue(const AData: string): Int64;
begin
  Result := Int64(FNV1a64Hash(Pointer(AData), Length(AData) * SizeOf(Char), FNV_SEED));
end;

class function THashFNV1a64Fast.GetHashValue(const AData: RawByteString): Int64;
begin
  Result := Int64(FNV1a64Hash(Pointer(AData), Length(AData), FNV_SEED));
end;

class function THashFNV1a64Fast.GetHashValue(const AData; ALength: Cardinal; AInitialValue: UInt64): Int64;
begin
  Result := Int64(FNV1a64Hash(@AData, ALength, AInitialValue));
end;

end.

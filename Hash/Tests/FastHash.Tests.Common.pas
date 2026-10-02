unit FastHash.Tests.Common;

{
  Shared helpers for the FastHash DUnitX tests.

  Most tests are parameterised by a code-path level name ('Pascal', 'Scalar',
  'AVX2', 'SHANI'). UseLevel pins every algorithm to that level; if the
  algorithm under test has no implementation at that level, or the CPU lacks
  it, the test is recorded as skipped and ends via Assert.Pass with a
  'SKIPPED' message. DUnitX has no runtime "ignore", so the runner prints the
  skip summary (SkipReport) after the run to make the coverage explicit.
}

interface

uses
  System.SysUtils,
  System.Generics.Collections,
  FastHash;

/// <summary>Pins all algorithms to LevelName. Calls Assert.Pass (ending the
/// test) when Algorithm cannot run at exactly that level here.</summary>
procedure UseLevel(const LevelName: string; Algorithm: TFastHashAlgorithm);
/// <summary>Restores the fastest available level for every algorithm.</summary>
procedure RestoreLevels;

function TestData(Size: Integer; Seed: Cardinal = $12345678): TBytes;
function HexToBytes(const Hex: string): TBytes;
function BytesToHex(const B: TBytes): string;
function RepeatByte(Value: Byte; Count: Integer): TBytes;
function AsciiBytes(const S: string): TBytes;

/// <summary>One line per algorithm/level: how many tests ran or were skipped and why.</summary>
function SkipReport: string;
/// <summary>Adds one to a line of the coverage report.</summary>
procedure CountCoverage(const Key: string);

type
  THashKind = (hkMD5, hkSHA1, hkSHA224, hkSHA256, hkSHA384, hkSHA512, hkSHA512_224, hkSHA512_256);

  /// <summary>Incremental hashing behind one interface, so tests can loop over kinds.</summary>
  IIncHash = interface
    procedure Update(P: PByte; N: Integer);
    function Final: TBytes;
  end;

const
  HashKindNames: array[THashKind] of string =
    ('MD5', 'SHA-1', 'SHA-224', 'SHA-256', 'SHA-384', 'SHA-512', 'SHA-512/224', 'SHA-512/256');

function KindAlgorithm(K: THashKind): TFastHashAlgorithm;
function NewFastHasher(K: THashKind): IIncHash;
function FastDigest(K: THashKind; const Data: TBytes): TBytes;
function RTLDigest(K: THashKind; const Data: TBytes): TBytes;
function FastHMAC(K: THashKind; const Data, Key: TBytes): TBytes;
function RTLHMAC(K: THashKind; const Data, Key: TBytes): TBytes;

implementation

uses
  System.Hash,
  DUnitX.TestFramework,
  FastHash.CPU;

const
  AlgoNames: array[TFastHashAlgorithm] of string = ('MD5', 'SHA-1', 'SHA-256', 'SHA-512', 'NonCrypto');

var
  Counts: TDictionary<string, Integer>;

procedure Count(const Key: string);
var
  N: Integer;
begin
  if not Counts.TryGetValue(Key, N) then
    N := 0;
  Counts.AddOrSetValue(Key, N + 1);
end;

procedure CountCoverage(const Key: string);
begin
  Count(Key);
end;

procedure UseLevel(const LevelName: string; Algorithm: TFastHashAlgorithm);
var
  Level: TFastHashLevel;
  Why: string;
begin
  Level := FastHashLevelFromName(LevelName);
  FastHashSetMaxLevel(Level);
  if FastHashActiveLevel(Algorithm) = Level then
  begin
    Count(Format('%s @ %s: ran', [AlgoNames[Algorithm], FastHashLevelName(Level)]));
    Exit;
  end;
  if not (Level in FastHashPlatformLevels) then
    Why := Format('no %s code on this platform', [FastHashLevelName(Level)])
  else if Level in FastHashSupportedLevels then
    Why := Format('%s has no %s implementation', [AlgoNames[Algorithm], FastHashLevelName(Level)])
  else
    Why := Format('this CPU lacks %s', [FastHashLevelName(Level)]);
  Count(Format('%s @ %s: skipped (%s)', [AlgoNames[Algorithm], FastHashLevelName(Level), Why]));
  RestoreLevels;
  Assert.Pass('SKIPPED: ' + Why);
end;

procedure RestoreLevels;
begin
  FastHashSetMaxLevel(High(TFastHashLevel));
end;

function TestData(Size: Integer; Seed: Cardinal): TBytes;
var
  I: Integer;
begin
  SetLength(Result, Size);
  for I := 0 to Size - 1 do
  begin
    Seed := Seed * 1103515245 + 12345;
    Result[I] := Byte(Seed shr 16);
  end;
end;

function HexToBytes(const Hex: string): TBytes;
var
  I: Integer;
begin
  SetLength(Result, Length(Hex) div 2);
  for I := 0 to High(Result) do
    Result[I] := StrToInt('$' + Copy(Hex, 2 * I + 1, 2));
end;

function BytesToHex(const B: TBytes): string;
begin
  Result := FastHashDigestAsString(B);
end;

function RepeatByte(Value: Byte; Count: Integer): TBytes;
begin
  SetLength(Result, Count);
  if Count > 0 then
    FillChar(Result[0], Count, Value);
end;

function AsciiBytes(const S: string): TBytes;
begin
  Result := TEncoding.ASCII.GetBytes(S);
end;

function SkipReport: string;
var
  Keys: TArray<string>;
  K: string;
begin
  Keys := Counts.Keys.ToArray;
  TArray.Sort<string>(Keys);
  Result := '';
  for K in Keys do
    Result := Result + Format('  %-70s %4d', [K, Counts[K]]) + sLineBreak;
end;

{ ---- hash kinds ---- }

type
  TMD5Inc = class(TInterfacedObject, IIncHash)
    H: THashMD5Fast;
    procedure Update(P: PByte; N: Integer);
    function Final: TBytes;
  end;

  TSHA1Inc = class(TInterfacedObject, IIncHash)
    H: THashSHA1Fast;
    procedure Update(P: PByte; N: Integer);
    function Final: TBytes;
  end;

  TSHA2Inc = class(TInterfacedObject, IIncHash)
    H: THashSHA2Fast;
    procedure Update(P: PByte; N: Integer);
    function Final: TBytes;
  end;

procedure TMD5Inc.Update(P: PByte; N: Integer);
begin
  H.Update(P^, N);
end;

function TMD5Inc.Final: TBytes;
begin
  Result := H.HashAsBytes;
end;

procedure TSHA1Inc.Update(P: PByte; N: Integer);
begin
  H.Update(P^, N);
end;

function TSHA1Inc.Final: TBytes;
begin
  Result := H.HashAsBytes;
end;

procedure TSHA2Inc.Update(P: PByte; N: Integer);
begin
  H.Update(P^, N);
end;

function TSHA2Inc.Final: TBytes;
begin
  Result := H.HashAsBytes;
end;

function FastVersion(K: THashKind): THashSHA2Fast.TSHA2Version;
begin
  case K of
    hkSHA224: Result := THashSHA2Fast.TSHA2Version.SHA224;
    hkSHA256: Result := THashSHA2Fast.TSHA2Version.SHA256;
    hkSHA384: Result := THashSHA2Fast.TSHA2Version.SHA384;
    hkSHA512: Result := THashSHA2Fast.TSHA2Version.SHA512;
    hkSHA512_224: Result := THashSHA2Fast.TSHA2Version.SHA512_224;
  else
    Result := THashSHA2Fast.TSHA2Version.SHA512_256;
  end;
end;

function RTLVersion(K: THashKind): THashSHA2.TSHA2Version;
begin
  Result := THashSHA2.TSHA2Version(Ord(FastVersion(K)));
end;

function KindAlgorithm(K: THashKind): TFastHashAlgorithm;
begin
  case K of
    hkMD5: Result := fhaMD5;
    hkSHA1: Result := fhaSHA1;
    hkSHA224, hkSHA256: Result := fhaSHA256;
  else
    Result := fhaSHA512;
  end;
end;

function NewFastHasher(K: THashKind): IIncHash;
var
  M: TMD5Inc;
  S1: TSHA1Inc;
  S2: TSHA2Inc;
begin
  case K of
    hkMD5:
      begin
        M := TMD5Inc.Create;
        M.H := THashMD5Fast.Create;
        Result := M;
      end;
    hkSHA1:
      begin
        S1 := TSHA1Inc.Create;
        S1.H := THashSHA1Fast.Create;
        Result := S1;
      end;
  else
    S2 := TSHA2Inc.Create;
    S2.H := THashSHA2Fast.Create(FastVersion(K));
    Result := S2;
  end;
end;

function FastDigest(K: THashKind; const Data: TBytes): TBytes;
var
  H: IIncHash;
begin
  H := NewFastHasher(K);
  H.Update(PByte(Data), Length(Data));
  Result := H.Final;
end;

function RTLDigest(K: THashKind; const Data: TBytes): TBytes;
var
  M: THashMD5;
  S1: THashSHA1;
  S2: THashSHA2;
begin
  case K of
    hkMD5:
      begin
        M := THashMD5.Create;
        M.Update(Data);
        Result := M.HashAsBytes;
      end;
    hkSHA1:
      begin
        S1 := THashSHA1.Create;
        S1.Update(Data);
        Result := S1.HashAsBytes;
      end;
  else
    S2 := THashSHA2.Create(RTLVersion(K));
    S2.Update(Data);
    Result := S2.HashAsBytes;
  end;
end;

function FastHMAC(K: THashKind; const Data, Key: TBytes): TBytes;
begin
  case K of
    hkMD5: Result := THashMD5Fast.GetHMACAsBytes(Data, Key);
    hkSHA1: Result := THashSHA1Fast.GetHMACAsBytes(Data, Key);
  else
    Result := THashSHA2Fast.GetHMACAsBytes(Data, Key, FastVersion(K));
  end;
end;

function RTLHMAC(K: THashKind; const Data, Key: TBytes): TBytes;
begin
  case K of
    hkMD5: Result := THashMD5.GetHMACAsBytes(Data, Key);
    hkSHA1: Result := THashSHA1.GetHMACAsBytes(Data, Key);
  else
    Result := THashSHA2.GetHMACAsBytes(Data, Key, RTLVersion(K));
  end;
end;

initialization
  Counts := TDictionary<string, Integer>.Create;

finalization
  Counts.Free;

end.

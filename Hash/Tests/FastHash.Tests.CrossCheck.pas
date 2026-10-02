unit FastHash.Tests.CrossCheck;

{
  Byte-for-byte comparison against System.Hash, at every code-path level:
    - every message length 0..300, then sparser lengths up to ~4.5 KB (odd
      and even block counts for the two-block AVX2 paths) and 1 MB + 13;
    - the same messages fed in random-sized pieces;
    - a 300-byte message split into two Updates at every possible point
      (covers the buffering around the 55/56/63/64/111/112/127/128 edges);
    - BobJenkins / FNV-1a for every length 0..300 at four alignments with
      varying seeds, and chained Update calls.
}

interface

uses
  DUnitX.TestFramework,
  FastHash.Tests.Common;

type
  [TestFixture]
  TCrossCheckTests = class
  private
    procedure CrossCheck(K: THashKind);
  public
    [TearDown] procedure TearDown;

    [Test]
    [TestCase('Pascal', 'Pascal')] [TestCase('Scalar', 'Scalar')] [TestCase('SIMD', 'SIMD')] [TestCase('Crypto', 'Crypto')]
    procedure MD5MatchesRTL(const Level: string);
    [Test]
    [TestCase('Pascal', 'Pascal')] [TestCase('Scalar', 'Scalar')] [TestCase('SIMD', 'SIMD')] [TestCase('Crypto', 'Crypto')]
    procedure SHA1MatchesRTL(const Level: string);
    [Test]
    [TestCase('Pascal', 'Pascal')] [TestCase('Scalar', 'Scalar')] [TestCase('SIMD', 'SIMD')] [TestCase('Crypto', 'Crypto')]
    procedure SHA224And256MatchRTL(const Level: string);
    [Test]
    [TestCase('Pascal', 'Pascal')] [TestCase('Scalar', 'Scalar')] [TestCase('SIMD', 'SIMD')] [TestCase('Crypto', 'Crypto')]
    procedure SHA384And512FamilyMatchRTL(const Level: string);
    [Test]
    [TestCase('Pascal', 'Pascal')] [TestCase('Scalar', 'Scalar')] [TestCase('SIMD', 'SIMD')] [TestCase('Crypto', 'Crypto')]
    procedure HMACMatchesRTL(const Level: string);
    [Test]
    [TestCase('Pascal', 'Pascal')] [TestCase('Scalar', 'Scalar')]
    procedure NonCryptoMatchesRTL(const Level: string);
  end;

implementation

uses
  System.SysUtils,
  System.Hash,
  FastHash;

function Lengths: TArray<Integer>;
var
  L: Integer;
begin
  Result := nil;
  for L := 0 to 300 do
    Result := Result + [L];
  L := 301;
  while L < 4500 do
  begin
    Result := Result + [L];
    Inc(L, 61);
  end;
  Result := Result + [1048576 + 13];
end;

{ TCrossCheckTests }

procedure TCrossCheckTests.TearDown;
begin
  RestoreLevels;
end;

procedure TCrossCheckTests.CrossCheck(K: THashKind);
var
  Data, Expected: TBytes;
  L, Pos, Piece, Split: Integer;
  H: IIncHash;
  Rnd: Cardinal;
begin
  Data := TestData(1048576 + 13, Ord(K) + 1);

  // one Update per message
  for L in Lengths do
  begin
    Expected := RTLDigest(K, Copy(Data, 0, L));
    Assert.AreEqual(BytesToHex(Expected), BytesToHex(FastDigest(K, Copy(Data, 0, L))),
      Format('%s, %d bytes, one Update', [HashKindNames[K], L]));
  end;

  // random-sized pieces (1..300 bytes) over a 20 KB message
  Rnd := 777 + Cardinal(Ord(K));
  for L in [1000, 8191, 20000] do
  begin
    Expected := RTLDigest(K, Copy(Data, 0, L));
    H := NewFastHasher(K);
    Pos := 0;
    while Pos < L do
    begin
      Rnd := Rnd * 1103515245 + 12345;
      Piece := 1 + Integer((Rnd shr 16) mod 300);
      if Piece > L - Pos then
        Piece := L - Pos;
      H.Update(@Data[Pos], Piece);
      Inc(Pos, Piece);
    end;
    Assert.AreEqual(BytesToHex(Expected), BytesToHex(H.Final),
      Format('%s, %d bytes, random pieces', [HashKindNames[K], L]));
  end;

  // two Updates, split at every point of a 300-byte message
  Expected := RTLDigest(K, Copy(Data, 0, 300));
  for Split := 0 to 300 do
  begin
    H := NewFastHasher(K);
    H.Update(@Data[0], Split);
    H.Update(@Data[Split], 300 - Split);
    Assert.AreEqual(BytesToHex(Expected), BytesToHex(H.Final),
      Format('%s, 300 bytes split at %d', [HashKindNames[K], Split]));
  end;
end;

procedure TCrossCheckTests.MD5MatchesRTL(const Level: string);
begin
  UseLevel(Level, fhaMD5);
  CrossCheck(hkMD5);
end;

procedure TCrossCheckTests.SHA1MatchesRTL(const Level: string);
begin
  UseLevel(Level, fhaSHA1);
  CrossCheck(hkSHA1);
end;

procedure TCrossCheckTests.SHA224And256MatchRTL(const Level: string);
begin
  UseLevel(Level, fhaSHA256);
  CrossCheck(hkSHA224);
  CrossCheck(hkSHA256);
end;

procedure TCrossCheckTests.SHA384And512FamilyMatchRTL(const Level: string);
begin
  UseLevel(Level, fhaSHA512);
  CrossCheck(hkSHA384);
  CrossCheck(hkSHA512);
  CrossCheck(hkSHA512_224);
  CrossCheck(hkSHA512_256);
end;

procedure TCrossCheckTests.HMACMatchesRTL(const Level: string);
const
  KeyLens: array[0..8] of Integer = (0, 1, 20, 63, 64, 65, 127, 128, 200);
  DataLens: array[0..5] of Integer = (0, 1, 55, 64, 129, 1000);
var
  K: THashKind;
  KL, DL: Integer;
  Key, Data: TBytes;
begin
  // the level pins every algorithm; HMAC exercises whichever paths exist there
  UseLevel(Level, fhaSHA256);
  for K := Low(THashKind) to High(THashKind) do
    for KL in KeyLens do
      for DL in DataLens do
      begin
        Key := TestData(KL, KL + 1);
        Data := TestData(DL, DL + 1000);
        Assert.AreEqual(BytesToHex(RTLHMAC(K, Data, Key)), BytesToHex(FastHMAC(K, Data, Key)),
          Format('HMAC-%s key %d data %d', [HashKindNames[K], KL, DL]));
      end;
end;

procedure TCrossCheckTests.NonCryptoMatchesRTL(const Level: string);
var
  Data: TBytes;
  L, Off: Integer;
  Seed: Integer;
  BJ: THashBobJenkinsFast;
  BJR: THashBobJenkins;
  F32: THashFNV1a32Fast;
  F32R: THashFNV1a32;
  F64: THashFNV1a64Fast;
  F64R: THashFNV1a64;
begin
  UseLevel(Level, fhaNonCrypto);
  Data := TestData(400, 99);
  for Off := 0 to 3 do
    for L := 0 to 300 do
    begin
      Seed := L * 7919 - 12345;
      Assert.AreEqual(THashBobJenkins.GetHashValue(Data[Off], L, Seed),
        THashBobJenkinsFast.GetHashValue(Data[Off], L, Seed), Format('BobJenkins len %d off %d', [L, Off]));
      Assert.AreEqual(THashFNV1a32.GetHashValue(Data[Off], L, Cardinal(Seed)),
        THashFNV1a32Fast.GetHashValue(Data[Off], L, Cardinal(Seed)), Format('FNV1a32 len %d off %d', [L, Off]));
      Assert.AreEqual(THashFNV1a64.GetHashValue(Data[Off], L, UInt64(Seed) * 31),
        THashFNV1a64Fast.GetHashValue(Data[Off], L, UInt64(Seed) * 31), Format('FNV1a64 len %d off %d', [L, Off]));
    end;

  // chained Updates (BobJenkins re-seeds with the previous value, like the RTL)
  BJ := THashBobJenkinsFast.Create;
  BJR := THashBobJenkins.Create;
  F32 := THashFNV1a32Fast.Create;
  F32R := THashFNV1a32.Create;
  F64 := THashFNV1a64Fast.Create;
  F64R := THashFNV1a64.Create;
  for L := 0 to 40 do
  begin
    BJ.Update(Data[L], L);
    BJR.Update(Data[L], L);
    F32.Update(Data[L], L);
    F32R.Update(Data[L], L);
    F64.Update(Data[L], L);
    F64R.Update(Data[L], L);
    Assert.AreEqual(BJR.HashAsInteger, BJ.HashAsInteger, Format('BobJenkins chained %d', [L]));
    Assert.AreEqual(F32R.HashAsInteger, F32.HashAsInteger, Format('FNV1a32 chained %d', [L]));
    Assert.AreEqual(F64R.HashAsInteger, F64.HashAsInteger, Format('FNV1a64 chained %d', [L]));
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(TCrossCheckTests);

end.

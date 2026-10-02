unit FastHash.Tests.API;

{
  The public surface of the FastHash records against their System.Hash
  counterparts: string (UTF-8 / UTF-16) overloads, stream and file
  overloads, HMAC string/bytes overload combinations, sizes, Reset,
  finalisation, and the BobJenkins / FNV-1a seed and RawByteString
  overloads. Runs at the default (fastest) level.
}

interface

uses
  DUnitX.TestFramework;

type
  [TestFixture]
  TAPITests = class
  public
    [Test] procedure StringOverloadsMatchRTL;
    [Test] procedure StreamOverloadsMatchRTL;
    [Test] procedure FileOverloadsMatchRTL;
    [Test] procedure HMACOverloadsMatchRTL;
    [Test] procedure SizesMatchRTL;
    [Test] procedure DigestCanBeReadRepeatedly;
    [Test] procedure UpdateAfterDigestRaises;
    [Test] procedure ResetStartsAgain;
    [Test] procedure UpdateBytesWithLength;
    [Test] procedure BobJenkinsSurfaceMatchesRTL;
    [Test] procedure FNV1a32SurfaceMatchesRTL;
    [Test] procedure FNV1a64SurfaceMatchesRTL;
  end;

implementation

uses
  System.SysUtils,
  System.Classes,
  System.IOUtils,
  System.Hash,
  FastHash,
  FastHash.Tests.Common;

const
  Texts: array[0..5] of string = ('', 'a', 'abc', 'The quick brown fox jumps over the lazy dog',
    'h'#$E9'llo w'#$F6'rld '#$20AC' '#$D83D#$DE00' '#$4E2D#$6587,   // accents, euro, emoji (surrogate pair), CJK
    'x');

function AllTexts: TArray<string>;
var
  S: string;
begin
  Result := nil;
  for S in Texts do
    Result := Result + [S];
  Result := Result + [StringOfChar('Z', 5000) + Texts[4]];
end;

function SHA2Versions: TArray<THashSHA2.TSHA2Version>;
var
  V: THashSHA2.TSHA2Version;
begin
  Result := nil;
  for V := Low(V) to High(V) do
    Result := Result + [V];
end;

function FV(V: THashSHA2.TSHA2Version): THashSHA2Fast.TSHA2Version;
begin
  Result := THashSHA2Fast.TSHA2Version(Ord(V));
end;

{ TAPITests }

procedure TAPITests.StringOverloadsMatchRTL;
var
  S: string;
  V: THashSHA2.TSHA2Version;
  M: THashMD5Fast;
  S1: THashSHA1Fast;
  S2: THashSHA2Fast;
  RM: THashMD5;
  RS1: THashSHA1;
  RS2: THashSHA2;
begin
  for S in AllTexts do
  begin
    Assert.AreEqual(THashMD5.GetHashString(S), THashMD5Fast.GetHashString(S), 'MD5 ' + S);
    Assert.AreEqual(BytesToHex(THashMD5.GetHashBytes(S)), BytesToHex(THashMD5Fast.GetHashBytes(S)), 'MD5 bytes');
    Assert.AreEqual(THashSHA1.GetHashString(S), THashSHA1Fast.GetHashString(S), 'SHA1 ' + S);
    Assert.AreEqual(BytesToHex(THashSHA1.GetHashBytes(S)), BytesToHex(THashSHA1Fast.GetHashBytes(S)), 'SHA1 bytes');
    for V in SHA2Versions do
    begin
      Assert.AreEqual(THashSHA2.GetHashString(S, V), THashSHA2Fast.GetHashString(S, FV(V)), 'SHA2 ' + S);
      Assert.AreEqual(BytesToHex(THashSHA2.GetHashBytes(S, V)), BytesToHex(THashSHA2Fast.GetHashBytes(S, FV(V))), 'SHA2 bytes');
    end;
    // instance Update(string), twice, then HashAsString
    M := THashMD5Fast.Create; M.Update(S); M.Update(S);
    RM := THashMD5.Create; RM.Update(S); RM.Update(S);
    Assert.AreEqual(RM.HashAsString, M.HashAsString, 'MD5 Update(string) x2');
    S1 := THashSHA1Fast.Create; S1.Update(S); S1.Update(S);
    RS1 := THashSHA1.Create; RS1.Update(S); RS1.Update(S);
    Assert.AreEqual(RS1.HashAsString, S1.HashAsString, 'SHA1 Update(string) x2');
    for V in SHA2Versions do
    begin
      S2 := THashSHA2Fast.Create(FV(V)); S2.Update(S); S2.Update(S);
      RS2 := THashSHA2.Create(V); RS2.Update(S); RS2.Update(S);
      Assert.AreEqual(RS2.HashAsString, S2.HashAsString, 'SHA2 Update(string) x2');
    end;
  end;
  // default version is SHA-256
  Assert.AreEqual(THashSHA2.GetHashString('abc'), THashSHA2Fast.GetHashString('abc'), 'default version');
end;

procedure TAPITests.StreamOverloadsMatchRTL;
var
  Data: TBytes;
  Stream: TBytesStream;
  V: THashSHA2.TSHA2Version;
  Expected: string;
  L: Integer;
begin
  for L in [0, 1, 4095, 4096, 65535, 65536, 65537, 300000] do
  begin
    Data := TestData(L, L);
    Stream := TBytesStream.Create(Data);
    try
      Expected := THashMD5.GetHashString(Stream);
      Stream.Position := 0;
      Assert.AreEqual(Expected, THashMD5Fast.GetHashString(Stream), 'MD5 stream');
      Stream.Position := 0;
      Expected := THashSHA1.GetHashString(Stream);
      Stream.Position := 0;
      Assert.AreEqual(Expected, THashSHA1Fast.GetHashString(Stream), 'SHA1 stream');
      for V in SHA2Versions do
      begin
        Stream.Position := 0;
        Expected := THashSHA2.GetHashString(Stream, V);
        Stream.Position := 0;
        Assert.AreEqual(Expected, THashSHA2Fast.GetHashString(Stream, FV(V)), 'SHA2 stream');
        Stream.Position := 0;
        Expected := BytesToHex(THashSHA2.GetHashBytes(Stream, V));
        Stream.Position := 0;
        Assert.AreEqual(Expected, BytesToHex(THashSHA2Fast.GetHashBytes(Stream, FV(V))), 'SHA2 stream bytes');
      end;
      // hashing starts at the current position, like the RTL
      if L > 10 then
      begin
        Stream.Position := 10;
        Expected := THashSHA1.GetHashString(Stream);
        Stream.Position := 10;
        Assert.AreEqual(Expected, THashSHA1Fast.GetHashString(Stream), 'SHA1 stream from position 10');
      end;
    finally
      Stream.Free;
    end;
  end;
end;

procedure TAPITests.FileOverloadsMatchRTL;
var
  FileName: string;
  V: THashSHA2.TSHA2Version;
begin
  FileName := TPath.Combine(TPath.GetTempPath, 'FastHashTest_' + IntToStr(Random(MaxInt)) + '.bin');
  TFile.WriteAllBytes(FileName, TestData(123457, 5));
  try
    Assert.AreEqual(THashMD5.GetHashStringFromFile(FileName), THashMD5Fast.GetHashStringFromFile(FileName), 'MD5 file');
    Assert.AreEqual(BytesToHex(THashMD5.GetHashBytesFromFile(FileName)), BytesToHex(THashMD5Fast.GetHashBytesFromFile(FileName)), 'MD5 file bytes');
    Assert.AreEqual(THashSHA1.GetHashStringFromFile(FileName), THashSHA1Fast.GetHashStringFromFile(FileName), 'SHA1 file');
    for V in SHA2Versions do
      Assert.AreEqual(THashSHA2.GetHashStringFromFile(FileName, V), THashSHA2Fast.GetHashStringFromFile(FileName, FV(V)), 'SHA2 file');
    Assert.AreEqual(THashSHA2.GetHashStringFromFile(FileName), THashSHA2Fast.GetHashStringFromFile(FileName), 'SHA2 file default');
  finally
    TFile.Delete(FileName);
  end;
end;

procedure TAPITests.HMACOverloadsMatchRTL;
const
  Keys: array[0..3] of string = ('', 'key', 'k'#$E9'y '#$20AC, 'a much longer key that is well over sixty-four bytes long, to force hashing it first, yes');
var
  D, K: string;
  V: THashSHA2.TSHA2Version;
  DB, KB: TBytes;
begin
  for D in Texts do
    for K in Keys do
    begin
      DB := TEncoding.UTF8.GetBytes(D);
      KB := TEncoding.UTF8.GetBytes(K);
      Assert.AreEqual(THashMD5.GetHMAC(D, K), THashMD5Fast.GetHMAC(D, K), 'MD5 HMAC');
      Assert.AreEqual(BytesToHex(THashMD5.GetHMACAsBytes(D, KB)), BytesToHex(THashMD5Fast.GetHMACAsBytes(D, KB)), 'MD5 HMAC s/b');
      Assert.AreEqual(BytesToHex(THashMD5.GetHMACAsBytes(DB, K)), BytesToHex(THashMD5Fast.GetHMACAsBytes(DB, K)), 'MD5 HMAC b/s');
      Assert.AreEqual(THashSHA1.GetHMAC(D, K), THashSHA1Fast.GetHMAC(D, K), 'SHA1 HMAC');
      Assert.AreEqual(BytesToHex(THashSHA1.GetHMACAsBytes(D, KB)), BytesToHex(THashSHA1Fast.GetHMACAsBytes(D, KB)), 'SHA1 HMAC s/b');
      Assert.AreEqual(BytesToHex(THashSHA1.GetHMACAsBytes(DB, K)), BytesToHex(THashSHA1Fast.GetHMACAsBytes(DB, K)), 'SHA1 HMAC b/s');
      for V in SHA2Versions do
      begin
        Assert.AreEqual(THashSHA2.GetHMAC(D, K, V), THashSHA2Fast.GetHMAC(D, K, FV(V)), 'SHA2 HMAC');
        Assert.AreEqual(BytesToHex(THashSHA2.GetHMACAsBytes(D, KB, V)), BytesToHex(THashSHA2Fast.GetHMACAsBytes(D, KB, FV(V))), 'SHA2 HMAC s/b');
        Assert.AreEqual(BytesToHex(THashSHA2.GetHMACAsBytes(DB, K, V)), BytesToHex(THashSHA2Fast.GetHMACAsBytes(DB, K, FV(V))), 'SHA2 HMAC b/s');
        Assert.AreEqual(BytesToHex(THashSHA2.GetHMACAsBytes(DB, KB, V)), BytesToHex(THashSHA2Fast.GetHMACAsBytes(DB, KB, FV(V))), 'SHA2 HMAC b/b');
      end;
    end;
end;

procedure TAPITests.SizesMatchRTL;
var
  V: THashSHA2.TSHA2Version;
begin
  Assert.AreEqual(THashMD5.Create.GetBlockSize, THashMD5Fast.Create.GetBlockSize, 'MD5 block');
  Assert.AreEqual(THashMD5.Create.GetHashSize, THashMD5Fast.Create.GetHashSize, 'MD5 hash');
  Assert.AreEqual(THashSHA1.Create.GetBlockSize, THashSHA1Fast.Create.GetBlockSize, 'SHA1 block');
  Assert.AreEqual(THashSHA1.Create.GetHashSize, THashSHA1Fast.Create.GetHashSize, 'SHA1 hash');
  for V in SHA2Versions do
  begin
    Assert.AreEqual(THashSHA2.Create(V).GetBlockSize, THashSHA2Fast.Create(FV(V)).GetBlockSize, 'SHA2 block');
    Assert.AreEqual(THashSHA2.Create(V).GetHashSize, THashSHA2Fast.Create(FV(V)).GetHashSize, 'SHA2 hash');
    Assert.AreEqual(THashSHA2.Create(V).GetHashSize, Integer(Length(THashSHA2Fast.Create(FV(V)).HashAsBytes)), 'SHA2 digest length');
  end;
end;

procedure TAPITests.DigestCanBeReadRepeatedly;
var
  M: THashMD5Fast;
  S1: THashSHA1Fast;
  S2: THashSHA2Fast;
  First: string;
begin
  M := THashMD5Fast.Create;
  M.Update('abc');
  First := M.HashAsString;
  Assert.AreEqual(First, M.HashAsString, 'MD5 second read');
  Assert.AreEqual(First, BytesToHex(M.HashAsBytes), 'MD5 bytes read');
  S1 := THashSHA1Fast.Create;
  S1.Update('abc');
  First := S1.HashAsString;
  Assert.AreEqual(First, S1.HashAsString, 'SHA1 second read');
  S2 := THashSHA2Fast.Create(THashSHA2Fast.TSHA2Version.SHA384);
  S2.Update('abc');
  First := S2.HashAsString;
  Assert.AreEqual(First, S2.HashAsString, 'SHA384 second read');
end;

procedure TAPITests.UpdateAfterDigestRaises;
var
  M: THashMD5Fast;
  S1: THashSHA1Fast;
  S2: THashSHA2Fast;
begin
  M := THashMD5Fast.Create;
  M.HashAsBytes;
  try
    M.Update('x');
    Assert.Fail('MD5: Update after the digest did not raise');
  except
    on EFastHashException do ;
  end;
  S1 := THashSHA1Fast.Create;
  S1.HashAsBytes;
  try
    S1.Update('x');
    Assert.Fail('SHA1: Update after the digest did not raise');
  except
    on EFastHashException do ;
  end;
  S2 := THashSHA2Fast.Create;
  S2.HashAsBytes;
  try
    S2.Update('x');
    Assert.Fail('SHA2: Update after the digest did not raise');
  except
    on EFastHashException do ;
  end;
end;

procedure TAPITests.ResetStartsAgain;
var
  M: THashMD5Fast;
  S1: THashSHA1Fast;
  S2: THashSHA2Fast;
begin
  M := THashMD5Fast.Create;
  M.Update('garbage');
  M.HashAsBytes;
  M.Reset;
  M.Update('abc');
  Assert.AreEqual(THashMD5.GetHashString('abc'), M.HashAsString, 'MD5');
  S1 := THashSHA1Fast.Create;
  S1.Update('garbage');
  S1.Reset;
  S1.Update('abc');
  Assert.AreEqual(THashSHA1.GetHashString('abc'), S1.HashAsString, 'SHA1');
  S2 := THashSHA2Fast.Create(THashSHA2Fast.TSHA2Version.SHA512_224);
  S2.Update('garbage');
  S2.HashAsBytes;
  S2.Reset;   // keeps the version
  S2.Update('abc');
  Assert.AreEqual(THashSHA2.GetHashString('abc', THashSHA2.TSHA2Version.SHA512_224), S2.HashAsString, 'SHA512_224');
end;

procedure TAPITests.UpdateBytesWithLength;
var
  Data: TBytes;
  M: THashMD5Fast;
  RM: THashMD5;
  S2: THashSHA2Fast;
  RS2: THashSHA2;
begin
  Data := TestData(500);
  M := THashMD5Fast.Create;
  M.Update(Data, 123);
  M.Update(Data);      // ALength = 0 means the whole array
  RM := THashMD5.Create;
  RM.Update(Data, 123);
  RM.Update(Data);
  Assert.AreEqual(RM.HashAsString, M.HashAsString, 'MD5');
  S2 := THashSHA2Fast.Create;
  S2.Update(Data, 77);
  S2.Update(Data[100], 300);
  RS2 := THashSHA2.Create;
  RS2.Update(Data, 77);
  RS2.Update(Data[100], 300);
  Assert.AreEqual(RS2.HashAsString, S2.HashAsString, 'SHA256');
end;

procedure TAPITests.BobJenkinsSurfaceMatchesRTL;
var
  S: string;
  H: THashBobJenkinsFast;
  R: THashBobJenkins;
  Data: TBytes;
begin
  for S in AllTexts do
  begin
    Assert.AreEqual(THashBobJenkins.GetHashValue(S), THashBobJenkinsFast.GetHashValue(S), 'GetHashValue');
    Assert.AreEqual(THashBobJenkins.GetHashString(S), THashBobJenkinsFast.GetHashString(S), 'GetHashString');
    Assert.AreEqual(BytesToHex(THashBobJenkins.GetHashBytes(S)), BytesToHex(THashBobJenkinsFast.GetHashBytes(S)), 'GetHashBytes');
    H := THashBobJenkinsFast.Create;
    R := THashBobJenkins.Create;
    H.Update(S);
    R.Update(S);
    Assert.AreEqual(R.HashAsInteger, H.HashAsInteger, 'Update(string)');
    Assert.AreEqual(R.HashAsString, H.HashAsString, 'HashAsString');
    Assert.AreEqual(BytesToHex(R.HashAsBytes), BytesToHex(H.HashAsBytes), 'HashAsBytes');
  end;
  Data := TestData(77);
  H.Reset(12345);
  R.Reset(12345);
  H.Update(Data);
  R.Update(Data);
  H.Update(Data, 10);
  R.Update(Data, 10);
  Assert.AreEqual(R.HashAsInteger, H.HashAsInteger, 'Reset(seed) + Update(TBytes)');
end;

procedure TAPITests.FNV1a32SurfaceMatchesRTL;
var
  S: string;
  RB: RawByteString;
  H: THashFNV1a32Fast;
  R: THashFNV1a32;
  Data: TBytes;
begin
  for S in AllTexts do
  begin
    Assert.AreEqual(THashFNV1a32.GetHashValue(S), THashFNV1a32Fast.GetHashValue(S), 'GetHashValue');
    Assert.AreEqual(THashFNV1a32.GetHashString(S), THashFNV1a32Fast.GetHashString(S), 'GetHashString');
    Assert.AreEqual(BytesToHex(THashFNV1a32.GetHashBytes(S)), BytesToHex(THashFNV1a32Fast.GetHashBytes(S)), 'GetHashBytes');
    RB := UTF8Encode(S);
    Assert.AreEqual(THashFNV1a32.GetHashValue(RB), THashFNV1a32Fast.GetHashValue(RB), 'GetHashValue(RawByteString)');
    Assert.AreEqual(THashFNV1a32.GetHashString(RB), THashFNV1a32Fast.GetHashString(RB), 'GetHashString(RawByteString)');
    H := THashFNV1a32Fast.Create;
    R := THashFNV1a32.Create;
    H.Update(S);
    R.Update(S);
    Assert.AreEqual(R.HashAsInteger, H.HashAsInteger, 'Update(string)');
    Assert.AreEqual(R.HashAsString, H.HashAsString, 'HashAsString');
    Assert.AreEqual(BytesToHex(R.HashAsBytes), BytesToHex(H.HashAsBytes), 'HashAsBytes');
  end;
  Data := TestData(77);
  H.Reset(12345);
  R.Reset(12345);
  H.Update(Data);
  R.Update(Data);
  Assert.AreEqual(R.HashAsInteger, H.HashAsInteger, 'Reset(seed) + Update(TBytes)');
end;

procedure TAPITests.FNV1a64SurfaceMatchesRTL;
var
  S: string;
  RB: RawByteString;
  H: THashFNV1a64Fast;
  R: THashFNV1a64;
  Data: TBytes;
begin
  for S in AllTexts do
  begin
    Assert.AreEqual(THashFNV1a64.GetHashValue(S), THashFNV1a64Fast.GetHashValue(S), 'GetHashValue');
    Assert.AreEqual(THashFNV1a64.GetHashString(S), THashFNV1a64Fast.GetHashString(S), 'GetHashString');
    Assert.AreEqual(BytesToHex(THashFNV1a64.GetHashBytes(S)), BytesToHex(THashFNV1a64Fast.GetHashBytes(S)), 'GetHashBytes');
    RB := UTF8Encode(S);
    Assert.AreEqual(THashFNV1a64.GetHashValue(RB), THashFNV1a64Fast.GetHashValue(RB), 'GetHashValue(RawByteString)');
    Assert.AreEqual(THashFNV1a64.GetHashString(RB), THashFNV1a64Fast.GetHashString(RB), 'GetHashString(RawByteString)');
    H := THashFNV1a64Fast.Create;
    R := THashFNV1a64.Create;
    H.Update(S);
    R.Update(S);
    Assert.AreEqual(R.HashAsInteger, H.HashAsInteger, 'Update(string)');
    Assert.AreEqual(R.HashAsString, H.HashAsString, 'HashAsString');
    Assert.AreEqual(BytesToHex(R.HashAsBytes), BytesToHex(H.HashAsBytes), 'HashAsBytes');
  end;
  Data := TestData(77);
  H.Reset(UInt64(12345) shl 33);
  R.Reset(UInt64(12345) shl 33);
  H.Update(Data);
  R.Update(Data);
  Assert.AreEqual(R.HashAsInteger, H.HashAsInteger, 'Reset(seed) + Update(TBytes)');
end;

initialization
  TDUnitX.RegisterTestFixture(TAPITests);

end.

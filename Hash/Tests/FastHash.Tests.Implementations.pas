unit FastHash.Tests.Implementations;

{
  Every registered implementation of every block function and non-crypto
  hash - including the variants the dispatcher did not pick (e.g. the C twin
  of an AArch64 assembly kernel) - against the Pascal reference:
    - block functions: 0..40 blocks of random data from random starting
      states (odd and even counts for the two-block AVX2 paths);
    - BobJenkins / FNV-1a: every length 0..300 at four alignments, varied
      seeds.
  The level tests only reach the preferred implementation of each level;
  this fixture keeps the alternates honest so the per-platform choice can be
  changed without fear.
}

interface

uses
  DUnitX.TestFramework;

type
  [TestFixture]
  TImplementationTests = class
  public
    [Test] procedure MD5Implementations;
    [Test] procedure SHA1Implementations;
    [Test] procedure SHA256Implementations;
    [Test] procedure SHA512Implementations;
    [Test] procedure NonCryptoImplementations;
  end;

implementation

uses
  System.SysUtils,
  FastHash.CPU,
  FastHash.MD5,
  FastHash.SHA1,
  FastHash.SHA256,
  FastHash.SHA512,
  FastHash.NonCrypto,
  FastHash.Tests.Common;

procedure CheckBlockImpls(const Alg: string; const Impls: TArray<TFastHashBlockImpl>;
  StateSize, BlockSize: Integer);
var
  Data, Start, Ref, Got: TBytes;
  Impl: TFastHashBlockImpl;
  N, Trial: Integer;
begin
  Data := TestData(41 * BlockSize, 4242);
  Assert.AreEqual('Pascal', Impls[0].Name, Alg + ': the first implementation must be the Pascal reference');
  for Impl in Impls do
  begin
    for Trial := 0 to 2 do
      for N := 0 to 40 do
      begin
        Start := TestData(StateSize, Cardinal(N * 7 + Trial));
        Ref := Copy(Start);
        Got := Copy(Start);
        Impls[0].Proc(@Ref[0], @Data[0], N);
        Impl.Proc(@Got[0], @Data[0], N);
        Assert.AreEqual(BytesToHex(Ref), BytesToHex(Got), Format('%s %s, %d blocks, trial %d', [Alg, Impl.Name, N, Trial]));
      end;
    CountCoverage(Format('%s implementation "%s" (%s): checked', [Alg, Impl.Name, FastHashLevelName(Impl.Level)]));
  end;
end;

{ TImplementationTests }

procedure TImplementationTests.MD5Implementations;
begin
  CheckBlockImpls('MD5', FastHash.MD5.MD5Implementations, 16, 64);
end;

procedure TImplementationTests.SHA1Implementations;
begin
  CheckBlockImpls('SHA-1', FastHash.SHA1.SHA1Implementations, 20, 64);
end;

procedure TImplementationTests.SHA256Implementations;
begin
  CheckBlockImpls('SHA-256', FastHash.SHA256.SHA256Implementations, 32, 64);
end;

procedure TImplementationTests.SHA512Implementations;
begin
  CheckBlockImpls('SHA-512', FastHash.SHA512.SHA512Implementations, 64, 128);
end;

procedure TImplementationTests.NonCryptoImplementations;
var
  Data: TBytes;
  BJ: TArray<TNonCryptoImpl<TBobJenkinsProc>>;
  F32: TArray<TNonCryptoImpl<TFNV1a32Proc>>;
  F64: TArray<TNonCryptoImpl<TFNV1a64Proc>>;
  I, Off, L, Seed: Integer;
begin
  Data := TestData(400, 77);
  BJ := BobJenkinsImplementations;
  F32 := FNV1a32Implementations;
  F64 := FNV1a64Implementations;
  for I := 0 to High(BJ) do
  begin
    for Off := 0 to 3 do
      for L := 0 to 300 do
      begin
        Seed := L * 7919 - 12345;
        Assert.AreEqual(BJ[0].Proc(@Data[Off], L, Seed), BJ[I].Proc(@Data[Off], L, Seed),
          Format('BobJenkins %s len %d off %d', [BJ[I].Name, L, Off]));
      end;
    CountCoverage(Format('BobJenkins implementation "%s" (%s): checked', [BJ[I].Name, FastHashLevelName(BJ[I].Level)]));
  end;
  for I := 0 to High(F32) do
  begin
    for Off := 0 to 3 do
      for L := 0 to 300 do
        Assert.AreEqual(F32[0].Proc(@Data[Off], L, Cardinal(L * 31)), F32[I].Proc(@Data[Off], L, Cardinal(L * 31)),
          Format('FNV-1a 32 %s len %d off %d', [F32[I].Name, L, Off]));
    CountCoverage(Format('FNV-1a 32 implementation "%s" (%s): checked', [F32[I].Name, FastHashLevelName(F32[I].Level)]));
  end;
  for I := 0 to High(F64) do
  begin
    for Off := 0 to 3 do
      for L := 0 to 300 do
        Assert.AreEqual(F64[0].Proc(@Data[Off], L, UInt64(L) * 1000003), F64[I].Proc(@Data[Off], L, UInt64(L) * 1000003),
          Format('FNV-1a 64 %s len %d off %d', [F64[I].Name, L, Off]));
    CountCoverage(Format('FNV-1a 64 implementation "%s" (%s): checked', [F64[I].Name, FastHashLevelName(F64[I].Level)]));
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(TImplementationTests);

end.

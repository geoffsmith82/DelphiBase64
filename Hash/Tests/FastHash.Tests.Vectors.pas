unit FastHash.Tests.Vectors;

{
  Known-answer tests from the standards, run at every code-path level:
    - MD5: RFC 1321 test suite
    - SHA-1 / SHA-2: FIPS 180 examples ("", "abc", the 448- and 896-bit
      messages, one million 'a')
    - HMAC: RFC 2202 (MD5, SHA-1) and RFC 4231 (SHA-224/256/384/512)
    - lookup3 hashlittle (Bob Jenkins' lookup3.c driver) and FNV-1a
      (the reference vectors for "", "a", "foobar")
}

interface

uses
  DUnitX.TestFramework,
  FastHash.Tests.Common;

type
  [TestFixture]
  TVectorTests = class
  private
    procedure CheckDigests(K: THashKind; const Expected: array of string);
    procedure CheckHMACs(K: THashKind; const Expected: array of string);
  public
    [TearDown] procedure TearDown;

    [Test]
    [TestCase('Pascal', 'Pascal')] [TestCase('Scalar', 'Scalar')] [TestCase('SIMD', 'SIMD')] [TestCase('Crypto', 'Crypto')]
    procedure MD5(const Level: string);
    [Test]
    [TestCase('Pascal', 'Pascal')] [TestCase('Scalar', 'Scalar')] [TestCase('SIMD', 'SIMD')] [TestCase('Crypto', 'Crypto')]
    procedure SHA1(const Level: string);
    [Test]
    [TestCase('Pascal', 'Pascal')] [TestCase('Scalar', 'Scalar')] [TestCase('SIMD', 'SIMD')] [TestCase('Crypto', 'Crypto')]
    procedure SHA224(const Level: string);
    [Test]
    [TestCase('Pascal', 'Pascal')] [TestCase('Scalar', 'Scalar')] [TestCase('SIMD', 'SIMD')] [TestCase('Crypto', 'Crypto')]
    procedure SHA256(const Level: string);
    [Test]
    [TestCase('Pascal', 'Pascal')] [TestCase('Scalar', 'Scalar')] [TestCase('SIMD', 'SIMD')] [TestCase('Crypto', 'Crypto')]
    procedure SHA384(const Level: string);
    [Test]
    [TestCase('Pascal', 'Pascal')] [TestCase('Scalar', 'Scalar')] [TestCase('SIMD', 'SIMD')] [TestCase('Crypto', 'Crypto')]
    procedure SHA512(const Level: string);
    [Test]
    [TestCase('Pascal', 'Pascal')] [TestCase('Scalar', 'Scalar')] [TestCase('SIMD', 'SIMD')] [TestCase('Crypto', 'Crypto')]
    procedure SHA512_224(const Level: string);
    [Test]
    [TestCase('Pascal', 'Pascal')] [TestCase('Scalar', 'Scalar')] [TestCase('SIMD', 'SIMD')] [TestCase('Crypto', 'Crypto')]
    procedure SHA512_256(const Level: string);

    [Test]
    [TestCase('Pascal', 'Pascal')] [TestCase('Scalar', 'Scalar')] [TestCase('SIMD', 'SIMD')] [TestCase('Crypto', 'Crypto')]
    procedure HMAC_MD5(const Level: string);
    [Test]
    [TestCase('Pascal', 'Pascal')] [TestCase('Scalar', 'Scalar')] [TestCase('SIMD', 'SIMD')] [TestCase('Crypto', 'Crypto')]
    procedure HMAC_SHA1(const Level: string);
    [Test]
    [TestCase('Pascal', 'Pascal')] [TestCase('Scalar', 'Scalar')] [TestCase('SIMD', 'SIMD')] [TestCase('Crypto', 'Crypto')]
    procedure HMAC_SHA224(const Level: string);
    [Test]
    [TestCase('Pascal', 'Pascal')] [TestCase('Scalar', 'Scalar')] [TestCase('SIMD', 'SIMD')] [TestCase('Crypto', 'Crypto')]
    procedure HMAC_SHA256(const Level: string);
    [Test]
    [TestCase('Pascal', 'Pascal')] [TestCase('Scalar', 'Scalar')] [TestCase('SIMD', 'SIMD')] [TestCase('Crypto', 'Crypto')]
    procedure HMAC_SHA384(const Level: string);
    [Test]
    [TestCase('Pascal', 'Pascal')] [TestCase('Scalar', 'Scalar')] [TestCase('SIMD', 'SIMD')] [TestCase('Crypto', 'Crypto')]
    procedure HMAC_SHA512(const Level: string);

    [Test]
    [TestCase('Pascal', 'Pascal')] [TestCase('Scalar', 'Scalar')]
    procedure BobJenkinsLookup3(const Level: string);
    [Test]
    [TestCase('Pascal', 'Pascal')] [TestCase('Scalar', 'Scalar')]
    procedure FNV1a32(const Level: string);
    [Test]
    [TestCase('Pascal', 'Pascal')] [TestCase('Scalar', 'Scalar')]
    procedure FNV1a64(const Level: string);
  end;

implementation

uses
  System.SysUtils,
  FastHash;

const
  // FIPS 180 example messages; index 4 is one million 'a' (built at runtime)
  Msg448 = 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq';
  Msg896 = 'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu';

function Message(Index: Integer): TBytes;
begin
  case Index of
    0: Result := nil;
    1: Result := AsciiBytes('abc');
    2: Result := AsciiBytes(Msg448);
    3: Result := AsciiBytes(Msg896);
  else
    Result := RepeatByte(Ord('a'), 1000000);
  end;
end;

// RFC 2202 / RFC 4231 cases used here: 1, 2, 3 and the "larger than block size
// key" case. SmallKey is the key length of cases 1 and 3 (16 for MD5, 20
// otherwise); BigKey that of the last case (80 for RFC 2202, 131 for RFC 4231).
procedure HMACCase(Index, SmallKey, BigKey: Integer; out Key, Data: TBytes);
begin
  case Index of
    0:
      begin
        Key := RepeatByte($0B, SmallKey);
        Data := AsciiBytes('Hi There');
      end;
    1:
      begin
        Key := AsciiBytes('Jefe');
        Data := AsciiBytes('what do ya want for nothing?');
      end;
    2:
      begin
        Key := RepeatByte($AA, SmallKey);
        Data := RepeatByte($DD, 50);
      end;
  else
    Key := RepeatByte($AA, BigKey);
    Data := AsciiBytes('Test Using Larger Than Block-Size Key - Hash Key First');
  end;
end;

{ TVectorTests }

procedure TVectorTests.TearDown;
begin
  RestoreLevels;
end;

procedure TVectorTests.CheckDigests(K: THashKind; const Expected: array of string);
var
  I, J: Integer;
  Msg: TBytes;
  H: IIncHash;
begin
  for I := 0 to High(Expected) do
  begin
    if Expected[I] = '' then
      Continue;
    Msg := Message(I);
    Assert.AreEqual(Expected[I], BytesToHex(FastDigest(K, Msg)),
      Format('%s message #%d (one Update)', [HashKindNames[K], I]));
    // the same message fed in 1000-byte pieces (or byte by byte when short)
    H := NewFastHasher(K);
    if Length(Msg) > 1000 then
    begin
      J := 0;
      while J < Length(Msg) do
      begin
        H.Update(@Msg[J], 1000);
        Inc(J, 1000);
      end;
    end
    else
      for J := 0 to High(Msg) do
        H.Update(@Msg[J], 1);
    Assert.AreEqual(Expected[I], BytesToHex(H.Final),
      Format('%s message #%d (pieces)', [HashKindNames[K], I]));
  end;
end;

procedure TVectorTests.CheckHMACs(K: THashKind; const Expected: array of string);
var
  I, SmallKey, BigKey: Integer;
  Key, Data: TBytes;
begin
  if K = hkMD5 then
    SmallKey := 16
  else
    SmallKey := 20;
  if K in [hkMD5, hkSHA1] then
    BigKey := 80
  else
    BigKey := 131;
  for I := 0 to High(Expected) do
  begin
    HMACCase(I, SmallKey, BigKey, Key, Data);
    Assert.AreEqual(Expected[I], BytesToHex(FastHMAC(K, Data, Key)),
      Format('HMAC-%s case #%d', [HashKindNames[K], I]));
  end;
end;

procedure TVectorTests.MD5(const Level: string);
const
  Suite: array[0..6] of string = ('', 'a', 'abc', 'message digest', 'abcdefghijklmnopqrstuvwxyz',
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
    '12345678901234567890123456789012345678901234567890123456789012345678901234567890');
  SuiteMD5: array[0..6] of string = (
    'd41d8cd98f00b204e9800998ecf8427e', '0cc175b9c0f1b6a831c399e269772661',
    '900150983cd24fb0d6963f7d28e17f72', 'f96b697d7cb7938d525a2f31aaf161d0',
    'c3fcd3d76192e4007dfb496cca67e13b', 'd174ab98d277d9f5a5611c2c9f419d9f',
    '57edf4a22be3c955ac49da2e2107b67a');
var
  I: Integer;
begin
  UseLevel(Level, fhaMD5);
  for I := 0 to High(Suite) do
    Assert.AreEqual(SuiteMD5[I], THashMD5Fast.GetHashString(Suite[I]), 'RFC 1321 "' + Suite[I] + '"');
  CheckDigests(hkMD5, ['d41d8cd98f00b204e9800998ecf8427e', '900150983cd24fb0d6963f7d28e17f72',
    '8215ef0796a20bcaaae116d3876c664a', '', '7707d6ae4e027c70eea2a935c2296f21']);
end;

procedure TVectorTests.SHA1(const Level: string);
begin
  UseLevel(Level, fhaSHA1);
  CheckDigests(hkSHA1, ['da39a3ee5e6b4b0d3255bfef95601890afd80709',
    'a9993e364706816aba3e25717850c26c9cd0d89d', '84983e441c3bd26ebaae4aa1f95129e5e54670f1',
    'a49b2446a02c645bf419f995b67091253a04a259', '34aa973cd4c4daa4f61eeb2bdbad27316534016f']);
end;

procedure TVectorTests.SHA224(const Level: string);
begin
  UseLevel(Level, fhaSHA256);
  CheckDigests(hkSHA224, ['d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f',
    '23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7',
    '75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525',
    'c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3',
    '20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67']);
end;

procedure TVectorTests.SHA256(const Level: string);
begin
  UseLevel(Level, fhaSHA256);
  CheckDigests(hkSHA256, ['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1',
    'cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1',
    'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0']);
end;

procedure TVectorTests.SHA384(const Level: string);
begin
  UseLevel(Level, fhaSHA512);
  CheckDigests(hkSHA384, [
    '38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b',
    'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7',
    '3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b',
    '09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039',
    '9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985']);
end;

procedure TVectorTests.SHA512(const Level: string);
begin
  UseLevel(Level, fhaSHA512);
  CheckDigests(hkSHA512, [
    'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e',
    'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f',
    '204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445',
    '8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909',
    'e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b']);
end;

procedure TVectorTests.SHA512_224(const Level: string);
begin
  UseLevel(Level, fhaSHA512);
  CheckDigests(hkSHA512_224, ['6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4',
    '4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa', '',
    '23fec5bb94d60b23308192640b0c453335d664734fe40e7268674af9']);
end;

procedure TVectorTests.SHA512_256(const Level: string);
begin
  UseLevel(Level, fhaSHA512);
  CheckDigests(hkSHA512_256, ['c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a',
    '53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23', '',
    '3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a']);
end;

procedure TVectorTests.HMAC_MD5(const Level: string);
begin
  UseLevel(Level, fhaMD5);
  CheckHMACs(hkMD5, ['9294727a3638bb1c13f48ef8158bfc9d', '750c783e6ab0b503eaa86e310a5db738',
    '56be34521d144c88dbb8c733f0e8b3f6', '6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd']);
end;

procedure TVectorTests.HMAC_SHA1(const Level: string);
begin
  UseLevel(Level, fhaSHA1);
  CheckHMACs(hkSHA1, ['b617318655057264e28bc0b6fb378c8ef146be00', 'effcdf6ae5eb2fa2d27416d5f184df9c259a7c79',
    '125d7342b9ac11cd91a39af48aa17b4f63f175d3', 'aa4ae5e15272d00e95705637ce8a3b55ed402112']);
end;

procedure TVectorTests.HMAC_SHA224(const Level: string);
begin
  UseLevel(Level, fhaSHA256);
  CheckHMACs(hkSHA224, ['896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22',
    'a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44',
    '7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea',
    '95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e']);
end;

procedure TVectorTests.HMAC_SHA256(const Level: string);
begin
  UseLevel(Level, fhaSHA256);
  CheckHMACs(hkSHA256, ['b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7',
    '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
    '773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe',
    '60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54']);
end;

procedure TVectorTests.HMAC_SHA384(const Level: string);
begin
  UseLevel(Level, fhaSHA512);
  CheckHMACs(hkSHA384, [
    'afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6',
    'af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649',
    '88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27',
    '4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952']);
end;

procedure TVectorTests.HMAC_SHA512(const Level: string);
begin
  UseLevel(Level, fhaSHA512);
  CheckHMACs(hkSHA512, [
    '87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854',
    '164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737',
    'fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb',
    '80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598']);
end;

procedure TVectorTests.BobJenkinsLookup3(const Level: string);
const
  FourScore: RawByteString = 'Four score and seven years ago';
begin
  UseLevel(Level, fhaNonCrypto);
  // from the self-test driver in Bob Jenkins' lookup3.c
  Assert.AreEqual(Integer($DEADBEEF), THashBobJenkinsFast.GetHashValue(PAnsiChar('')^, 0, 0), 'empty');
  Assert.AreEqual(Integer($17770551), THashBobJenkinsFast.GetHashValue(FourScore[1], 30, 0), 'Four score, 0');
  Assert.AreEqual(Integer($CD628161), THashBobJenkinsFast.GetHashValue(FourScore[1], 30, 1), 'Four score, 1');
end;

procedure TVectorTests.FNV1a32(const Level: string);
begin
  UseLevel(Level, fhaNonCrypto);
  Assert.AreEqual(Integer($811C9DC5), THashFNV1a32Fast.GetHashValue(RawByteString('')), 'empty');
  Assert.AreEqual(Integer($E40C292C), THashFNV1a32Fast.GetHashValue(RawByteString('a')), 'a');
  Assert.AreEqual(Integer($BF9CF968), THashFNV1a32Fast.GetHashValue(RawByteString('foobar')), 'foobar');
end;

procedure TVectorTests.FNV1a64(const Level: string);
begin
  UseLevel(Level, fhaNonCrypto);
  Assert.AreEqual(Int64($CBF29CE484222325), THashFNV1a64Fast.GetHashValue(RawByteString('')), 'empty');
  Assert.AreEqual(Int64($AF63DC4C8601EC8C), THashFNV1a64Fast.GetHashValue(RawByteString('a')), 'a');
  Assert.AreEqual(Int64($85944171F73967E8), THashFNV1a64Fast.GetHashValue(RawByteString('foobar')), 'foobar');
end;

initialization
  TDUnitX.RegisterTestFixture(TVectorTests);

end.

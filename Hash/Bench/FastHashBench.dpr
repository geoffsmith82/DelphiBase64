program FastHashBench;

{
  Throughput benchmark: FastHash (every code path the CPU supports) vs
  System.Hash vs Indy.

    FastHashBench.exe            16 MB buffer
    FastHashBench.exe 64         64 MB buffer

  For each algorithm it first checks that every contender produces the same
  digest, then times:
    - one large buffer (best and median of several runs, MB/s);
    - 1 KB and 64-byte messages, each hashed with Create/Update/HashAsBytes,
      to show per-message overhead.
  Speedups are relative to System.Hash.

  Indy: TIdHashMessageDigest5 and TIdHashSHA1 always run (native Pascal, or
  OpenSSL when it can be loaded). TIdHashSHA224/256/384/512 only exist
  through OpenSSL 1.0.x (libeay32.dll/ssleay32.dll); they are shown as n/a
  when those DLLs cannot be loaded. Indy has no SHA-512/224, SHA-512/256,
  BobJenkins or FNV-1a.
}

{$APPTYPE CONSOLE}

uses
  System.SysUtils,
  System.Classes,
  System.Diagnostics,
  System.Math,
  System.Generics.Collections,
  System.Generics.Defaults,
  System.Hash,
  IdGlobal,
  IdHash,
  IdHashMessageDigest,
  IdHashSHA,
  IdSSLOpenSSL,
  FastHash.CPU in '..\FastHash.CPU.pas',
  FastHash.MD5 in '..\FastHash.MD5.pas',
  FastHash.SHA1 in '..\FastHash.SHA1.pas',
  FastHash.SHA256 in '..\FastHash.SHA256.pas',
  FastHash.SHA512 in '..\FastHash.SHA512.pas',
  FastHash.NonCrypto in '..\FastHash.NonCrypto.pas',
  FastHash in '..\FastHash.pas';

type
  THashFn = TFunc<PByte, Integer, TBytes>;
  TIdHashIntFClass = class of TIdHashIntF;

  TContender = record
    Name: string;
    IsFast: Boolean;          // FastHash: pin Level first
    Level: TFastHashLevel;
    Fn: THashFn;              // nil = not available (Why says why)
    Why: string;
  end;

  TAlgo = record
    Name: string;
    FastAlgo: TFastHashAlgorithm;
    Contenders: TArray<TContender>;
  end;

  TResult = record
    BestMBs, MedianMBs: Double;
    KBMBs, SmallMBs, SmallNs: Double;
  end;

const
  MsgSizeKB = 1024;
  MsgSizeSmall = 64;

var
  BufferMB: Integer = 16;
  Data: TBytes;
  IndyOpenSSL: Boolean;

{ ---------- helpers ---------- }

function ToIdBytes(P: PByte; N: Integer): TIdBytes;
begin
  SetLength(Result, N);
  if N > 0 then
    Move(P^, Result[0], N);
end;

function FromIdBytes(const B: TIdBytes): TBytes;
begin
  SetLength(Result, Length(B));
  if Length(B) > 0 then
    Move(B[0], Result[0], Length(B));
end;

function Int32Bytes(V: Cardinal): TBytes;
begin
  SetLength(Result, 4);
  PCardinal(@Result[0])^ := V;
end;

function Int64Bytes(V: UInt64): TBytes;
begin
  SetLength(Result, 8);
  PUInt64(@Result[0])^ := V;
end;

function Contender(const Name: string; const Fn: THashFn): TContender;
begin
  Result.Name := Name;
  Result.IsFast := False;
  Result.Level := fhlPascal;
  Result.Fn := Fn;
  Result.Why := '';
end;

function Unavailable(const Name, Why: string): TContender;
begin
  Result := Contender(Name, nil);
  Result.Why := Why;
end;

// One FastHash contender per level that this algorithm implements and the CPU supports.
function FastContenders(Algo: TFastHashAlgorithm; const Fn: THashFn): TArray<TContender>;
var
  L: TFastHashLevel;
  C: TContender;
begin
  Result := nil;
  for L := Low(TFastHashLevel) to High(TFastHashLevel) do
  begin
    if not (L in FastHashSupportedLevels) then
      Continue;
    FastHashSetMaxLevel(L);
    if FastHashActiveLevel(Algo) <> L then
      Continue;
    C := Contender('FastHash ' + FastHashLevelName(L), Fn);
    C.IsFast := True;
    C.Level := L;
    Result := Result + [C];
  end;
  FastHashSetMaxLevel(High(TFastHashLevel));
end;

// One reusable Indy hasher per class. Indy objects are meant to be reused, and
// with IdSSLOpenSSL linked but no OpenSSL DLLs, constructing one costs ~4 ms
// (it retries the DLL load), which would swamp the per-message timings.
var
  IndyHashers: TObjectDictionary<TIdHashClass, TIdHash>;

function IndyHash(HashClass: TIdHashClass; P: PByte; N: Integer): TBytes;
var
  H: TIdHash;
begin
  if not IndyHashers.TryGetValue(HashClass, H) then
  begin
    H := HashClass.Create;
    IndyHashers.Add(HashClass, H);
  end;
  Result := FromIdBytes(H.HashBytes(ToIdBytes(P, N)));
end;

function IndyName(HashClass: TIdHashClass): string;
begin
  // TIdHashIntF descendants (MD5, SHA-1, SHA-2) use OpenSSL whenever it is loaded
  if IndyOpenSSL and HashClass.InheritsFrom(TIdHashIntF) and TIdHashIntFClass(HashClass).IsIntfAvailable then
    Result := 'Indy (OpenSSL)'
  else
    Result := 'Indy (native)';
end;

{ ---------- the algorithm table ---------- }

function SHA2Algo(const Name: string; V: THashSHA2.TSHA2Version; FastAlgo: TFastHashAlgorithm;
  IndyClass: TIdHashClass): TAlgo;
var
  FV: THashSHA2Fast.TSHA2Version;
begin
  FV := THashSHA2Fast.TSHA2Version(Ord(V));
  Result.Name := Name;
  Result.FastAlgo := FastAlgo;
  Result.Contenders := [Contender('System.Hash',
    function(P: PByte; N: Integer): TBytes
    var H: THashSHA2;
    begin
      H := THashSHA2.Create(V); H.Update(P^, N); Result := H.HashAsBytes;
    end)];
  Result.Contenders := Result.Contenders + FastContenders(FastAlgo,
    function(P: PByte; N: Integer): TBytes
    var H: THashSHA2Fast;
    begin
      H := THashSHA2Fast.Create(FV); H.Update(P^, N); Result := H.HashAsBytes;
    end);
  if IndyClass = nil then
    Result.Contenders := Result.Contenders + [Unavailable('Indy', 'not in Indy')]
  else if not IndyClass.IsAvailable then
    Result.Contenders := Result.Contenders + [Unavailable('Indy (OpenSSL)', 'needs OpenSSL 1.0.x DLLs')]
  else
    Result.Contenders := Result.Contenders + [Contender(IndyName(IndyClass),
      function(P: PByte; N: Integer): TBytes begin Result := IndyHash(IndyClass, P, N); end)];
end;

function BuildAlgos: TArray<TAlgo>;
var
  A: TAlgo;
begin
  Result := nil;

  A.Name := 'MD5';
  A.FastAlgo := fhaMD5;
  A.Contenders := [Contender('System.Hash',
    function(P: PByte; N: Integer): TBytes
    var H: THashMD5;
    begin
      H := THashMD5.Create; H.Update(P^, N); Result := H.HashAsBytes;
    end)];
  A.Contenders := A.Contenders + FastContenders(fhaMD5,
    function(P: PByte; N: Integer): TBytes
    var H: THashMD5Fast;
    begin
      H := THashMD5Fast.Create; H.Update(P^, N); Result := H.HashAsBytes;
    end);
  A.Contenders := A.Contenders + [Contender(IndyName(TIdHashMessageDigest5),
    function(P: PByte; N: Integer): TBytes begin Result := IndyHash(TIdHashMessageDigest5, P, N); end)];
  Result := Result + [A];

  A.Name := 'SHA-1';
  A.FastAlgo := fhaSHA1;
  A.Contenders := [Contender('System.Hash',
    function(P: PByte; N: Integer): TBytes
    var H: THashSHA1;
    begin
      H := THashSHA1.Create; H.Update(P^, N); Result := H.HashAsBytes;
    end)];
  A.Contenders := A.Contenders + FastContenders(fhaSHA1,
    function(P: PByte; N: Integer): TBytes
    var H: THashSHA1Fast;
    begin
      H := THashSHA1Fast.Create; H.Update(P^, N); Result := H.HashAsBytes;
    end);
  A.Contenders := A.Contenders + [Contender(IndyName(TIdHashSHA1),
    function(P: PByte; N: Integer): TBytes begin Result := IndyHash(TIdHashSHA1, P, N); end)];
  Result := Result + [A];

  Result := Result + [SHA2Algo('SHA-224', THashSHA2.TSHA2Version.SHA224, fhaSHA256, TIdHashSHA224)];
  Result := Result + [SHA2Algo('SHA-256', THashSHA2.TSHA2Version.SHA256, fhaSHA256, TIdHashSHA256)];
  Result := Result + [SHA2Algo('SHA-384', THashSHA2.TSHA2Version.SHA384, fhaSHA512, TIdHashSHA384)];
  Result := Result + [SHA2Algo('SHA-512', THashSHA2.TSHA2Version.SHA512, fhaSHA512, TIdHashSHA512)];
  Result := Result + [SHA2Algo('SHA-512/224', THashSHA2.TSHA2Version.SHA512_224, fhaSHA512, nil)];
  Result := Result + [SHA2Algo('SHA-512/256', THashSHA2.TSHA2Version.SHA512_256, fhaSHA512, nil)];

  A.Name := 'BobJenkins';
  A.FastAlgo := fhaNonCrypto;
  A.Contenders := [Contender('System.Hash',
    function(P: PByte; N: Integer): TBytes
    begin
      Result := Int32Bytes(Cardinal(THashBobJenkins.GetHashValue(P^, N, 0)));
    end)];
  A.Contenders := A.Contenders + FastContenders(fhaNonCrypto,
    function(P: PByte; N: Integer): TBytes
    begin
      Result := Int32Bytes(Cardinal(THashBobJenkinsFast.GetHashValue(P^, N, 0)));
    end);
  Result := Result + [A];

  A.Name := 'FNV-1a 32';
  A.FastAlgo := fhaNonCrypto;
  A.Contenders := [Contender('System.Hash',
    function(P: PByte; N: Integer): TBytes
    begin
      Result := Int32Bytes(Cardinal(THashFNV1a32.GetHashValue(P^, N)));
    end)];
  A.Contenders := A.Contenders + FastContenders(fhaNonCrypto,
    function(P: PByte; N: Integer): TBytes
    begin
      Result := Int32Bytes(Cardinal(THashFNV1a32Fast.GetHashValue(P^, N)));
    end);
  Result := Result + [A];

  A.Name := 'FNV-1a 64';
  A.FastAlgo := fhaNonCrypto;
  A.Contenders := [Contender('System.Hash',
    function(P: PByte; N: Integer): TBytes
    begin
      Result := Int64Bytes(UInt64(THashFNV1a64.GetHashValue(P^, N)));
    end)];
  A.Contenders := A.Contenders + FastContenders(fhaNonCrypto,
    function(P: PByte; N: Integer): TBytes
    begin
      Result := Int64Bytes(UInt64(THashFNV1a64Fast.GetHashValue(P^, N)));
    end);
  Result := Result + [A];
end;

{ ---------- timing ---------- }

function MBs(Bytes: Int64; Ms: Double): Double;
begin
  if Ms <= 0 then
    Exit(0);
  Result := (Bytes / (1024 * 1024)) / (Ms / 1000);
end;

// Hashes Size-byte messages (walking through the buffer) for about TargetMs
// and returns the throughput in MB/s and the time per message in ns.
procedure TimeMessages(const Fn: THashFn; Size: Integer; out Rate, NsPerMsg: Double);
const
  TargetMs = 300;
  Batch = 64;
var
  SW: TStopwatch;
  I, Off, Span: Integer;
  Count: Int64;
  Ms: Double;
begin
  Span := Length(Data) - Size;
  Off := 0;
  Count := 0;
  SW := TStopwatch.StartNew;
  repeat
    for I := 1 to Batch do
    begin
      Fn(@Data[Off], Size);
      Inc(Off, Size);
      if Off > Span then
        Off := 0;
    end;
    Inc(Count, Batch);
    Ms := SW.Elapsed.TotalMilliseconds;
  until Ms >= TargetMs;
  Rate := MBs(Count * Size, Ms);
  NsPerMsg := Ms * 1E6 / Count;
end;

function Measure(const C: TContender): TResult;
var
  Times: TArray<Double>;
  Total: Double;
  SW: TStopwatch;
  Rate1, Ns1, Rate2, Ns2: Double;
begin
  // large buffer: at least 2 runs, then until about 1 s has been spent (max 7)
  Times := nil;
  Total := 0;
  repeat
    SW := TStopwatch.StartNew;
    C.Fn(@Data[0], Length(Data));
    Times := Times + [SW.Elapsed.TotalMilliseconds];
    Total := Total + Times[High(Times)];
  until ((Length(Times) >= 2) and (Total >= 1000)) or (Length(Times) >= 7);
  TArray.Sort<Double>(Times);
  Result.BestMBs := MBs(Length(Data), Times[0]);
  Result.MedianMBs := MBs(Length(Data), Times[Length(Times) div 2]);

  // messages: best of two time-boxed passes
  TimeMessages(C.Fn, MsgSizeKB, Rate1, Ns1);
  TimeMessages(C.Fn, MsgSizeKB, Rate2, Ns2);
  Result.KBMBs := Max(Rate1, Rate2);
  TimeMessages(C.Fn, MsgSizeSmall, Rate1, Ns1);
  TimeMessages(C.Fn, MsgSizeSmall, Rate2, Ns2);
  Result.SmallMBs := Max(Rate1, Rate2);
  Result.SmallNs := Min(Ns1, Ns2);
end;

function Ratio(Value, Base: Double): string;
begin
  if (Base <= 0) or (Value <= 0) then
    Result := '-'
  else
    Result := Format('%.2fx', [Value / Base]);
end;

procedure RunAlgo(const A: TAlgo);
var
  C: TContender;
  Ref, D: TBytes;
  R, Base: TResult;
  First, AllMatch: Boolean;
  Mismatch: string;
begin
  Writeln;
  Writeln(A.Name);

  // all contenders must agree before anything is timed
  Ref := nil;
  AllMatch := True;
  Mismatch := '';
  for C in A.Contenders do
  begin
    if not Assigned(C.Fn) then
      Continue;
    if C.IsFast then
      FastHashSetMaxLevel(C.Level);
    D := C.Fn(@Data[0], Length(Data));
    if Ref = nil then
      Ref := D
    else if (Length(D) <> Length(Ref)) or not CompareMem(@D[0], @Ref[0], Length(D)) then
    begin
      AllMatch := False;
      Mismatch := Mismatch + ' ' + C.Name;
    end;
  end;
  FastHashSetMaxLevel(High(TFastHashLevel));
  if AllMatch then
    Writeln('  digest check: all contenders agree (', FastHashDigestAsString(Ref).Substring(0, 16), '...)')
  else
    Writeln('  digest check: MISMATCH in', Mismatch);

  Writeln(Format('  %-20s %11s %8s %8s | %10s %8s | %10s %8s %8s',
    ['', Format('%d MB best', [BufferMB]), 'median', 'x RTL', '1 KB MB/s', 'x RTL', '64 B MB/s', 'ns/msg', 'x RTL']));
  First := True;
  for C in A.Contenders do
  begin
    if not Assigned(C.Fn) then
    begin
      Writeln(Format('  %-20s %11s   (%s)', [C.Name, 'n/a', C.Why]));
      Flush(Output);
      Continue;
    end;
    if C.IsFast then
      FastHashSetMaxLevel(C.Level);
    R := Measure(C);
    FastHashSetMaxLevel(High(TFastHashLevel));
    if First then
    begin
      Base := R;
      First := False;
    end;
    Writeln(Format('  %-20s %11.1f %8.1f %8s | %10.1f %8s | %10.1f %8.0f %8s',
      [C.Name, R.BestMBs, R.MedianMBs, Ratio(R.BestMBs, Base.BestMBs),
       R.KBMBs, Ratio(R.KBMBs, Base.KBMBs),
       R.SmallMBs, R.SmallNs, Ratio(R.SmallMBs, Base.SmallMBs)]));
    Flush(Output);
  end;
end;

var
  A: TAlgo;
  I: Integer;
  Seed: UInt32;
  L: TFastHashLevel;
  Levels: string;
begin
  try
    if ParamCount >= 1 then
      BufferMB := StrToIntDef(ParamStr(1), BufferMB);
    SetLength(Data, BufferMB * 1024 * 1024);
    Seed := $12345678;
    for I := 0 to High(Data) do
    begin
      Seed := Seed * 1103515245 + 12345;
      Data[I] := Byte(Seed shr 16);
    end;

    IndyHashers := TObjectDictionary<TIdHashClass, TIdHash>.Create([doOwnsValues]);
    try
      IndyOpenSSL := LoadOpenSSLLibrary;
    except
      IndyOpenSSL := False;
    end;

    Levels := '';
    for L := Low(TFastHashLevel) to High(TFastHashLevel) do
      if L in FastHashSupportedLevels then
        Levels := Levels + FastHashLevelName(L) + ' ';
    Writeln(Format('FastHash benchmark (%d-bit), %d MB buffer', [SizeOf(Pointer) * 8, BufferMB]));
    Writeln('CPU features : ', FastHashCPUFeatures);
    Writeln('Levels       : ', Trim(Levels));
    if IndyOpenSSL then
      Writeln('Indy OpenSSL : loaded')
    else
      Writeln('Indy OpenSSL : not available (Indy SHA-2 shown as n/a; Indy MD5/SHA-1 use native code)');
    Writeln('MB/s = 2^20 bytes per second; "x RTL" = speed relative to System.Hash.');

    for A in BuildAlgos do
      RunAlgo(A);
  except
    on E: Exception do
    begin
      Writeln(ErrOutput, E.ClassName, ': ', E.Message);
      ExitCode := 2;
    end;
  end;
end.

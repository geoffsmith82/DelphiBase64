unit PolyFillTestRunner;

{
  Correctness + benchmark harness for TBase64EncodingPolyFill.

  Validates that every public method produces output byte-identical to the
  RTL's System.NetEncoding classes, then benchmarks the assembly-backed
  polyfill against the RTL encoder/decoder on a large buffer.

  Reference mapping:
    PolyFill.Create        (76-char, CRLF)  ==  TNetEncoding.Base64
    PolyFill.Create(0)     (no breaks)      ==  TNetEncoding.Base64String
    PolyFill.Create(N[,S])                  ==  TBase64Encoding.Create(N[,S])

  Usage:  PolyFillTestNN.exe [file | megabytes]
}

interface

procedure RunTests;

implementation

uses
  System.SysUtils,
  System.Classes,
  System.IOUtils,
  System.Diagnostics,
  System.Math,
  System.NetEncoding,
  Base64EncodingPolyFill,
  Base64EncodingFast;

const
  DEFAULT_MB  = 16;
  BENCH_ITERS = 7;

var
  TestsRun: Integer = 0;
  TestsPassed: Integer = 0;

{ ---------- helpers ---------- }

function GenerateData(SizeBytes: NativeInt): TBytes;
var
  i: NativeInt;
  seed: UInt32;
begin
  SetLength(Result, SizeBytes);
  seed := $12345678;
  for i := 0 to SizeBytes - 1 do
  begin
    seed := seed * 1103515245 + 12345;
    Result[i] := Byte(seed shr 16);
  end;
end;

function BytesEqual(const A, B: TBytes): Boolean;
begin
  Result := Length(A) = Length(B);
  if Result and (Length(A) > 0) then
    Result := CompareMem(@A[0], @B[0], Length(A));
end;

function StripCRLFBytes(const A: TBytes): TBytes;
var
  i, n: Integer;
begin
  SetLength(Result, Length(A));
  n := 0;
  for i := 0 to High(A) do
    if (A[i] <> 13) and (A[i] <> 10) then
    begin
      Result[n] := A[i];
      Inc(n);
    end;
  SetLength(Result, n);
end;

function Vis(const S: string): string;
begin
  Result := StringReplace(S, #13, '\r', [rfReplaceAll]);
  Result := StringReplace(Result, #10, '\n', [rfReplaceAll]);
end;

procedure Check(const Name: string; Passed: Boolean; const Detail: string = '');
begin
  Inc(TestsRun);
  if Passed then
  begin
    Inc(TestsPassed);
    Writeln(Format('  [PASS] %s', [Name]));
  end
  else
  begin
    Writeln(Format('  [FAIL] %s', [Name]));
    if Detail <> '' then
      Writeln('         ' + Detail);
  end;
end;

function FirstBytesDiff(const A, B: TBytes): string;
var
  i, n: Integer;
begin
  n := Min(Length(A), Length(B));
  for i := 0 to n - 1 do
    if A[i] <> B[i] then
      Exit(Format('len got=%d exp=%d; first diff @%d: got=%d exp=%d',
        [Length(A), Length(B), i, A[i], B[i]]));
  Result := Format('len got=%d exp=%d (prefix equal)', [Length(A), Length(B)]);
end;

function FirstStrDiff(const A, B: string): string;
var
  i, n: Integer;
begin
  if A = B then Exit('(identical)');
  n := Min(Length(A), Length(B));
  for i := 1 to n do
    if A[i] <> B[i] then
      Exit(Format('diff @%d: got "%s" exp "%s"',
        [i, Vis(Copy(A, i, 16)), Vis(Copy(B, i, 16))]));
  Result := Format('length: got %d exp %d', [Length(A), Length(B)]);
end;

{ ---------- correctness ---------- }

procedure TestCorrectness;
const
  Sizes: array[0..20] of Integer =
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 53, 54, 55, 56, 57, 58, 71, 72, 200, 1000, 65537, 100000);
  CPs: array[0..6] of Integer = (4, 5, 7, 8, 11, 12, 76);
var
  si, ci, sz: Integer;
  data, encBytes, refBytes, dec, refDec: TBytes;
  pf76, pf0, pfN: TBase64EncodingPolyFill;
  netN: TBase64Encoding;
  encStr, refStr, wrapped: string;
begin
  Writeln(Format('AVX2 turbo path available on this CPU: %s',
    [BoolToStr(PolyFillHasAVX2, True)]));
  Writeln('');
  Writeln('Correctness vs System.NetEncoding:');

  pf76 := TBase64EncodingPolyFill.Create;      // == TNetEncoding.Base64 (76, CRLF)
  pf0  := TBase64EncodingPolyFill.Create(0);   // == TNetEncoding.Base64String
  try
    for si := Low(Sizes) to High(Sizes) do
    begin
      sz := Sizes[si];
      data := GenerateData(sz);

      // 1) EncodeBytesToString, 76-char MIME, vs TNetEncoding.Base64
      encStr := pf76.EncodeBytesToString(data);
      refStr := TNetEncoding.Base64.EncodeBytesToString(data);
      Check(Format('EncBytesToString(76) sz=%d', [sz]), encStr = refStr,
        FirstStrDiff(encStr, refStr));

      // 2) EncodeBytesToString, no breaks, vs TNetEncoding.Base64String
      encStr := pf0.EncodeBytesToString(data);
      refStr := TNetEncoding.Base64String.EncodeBytesToString(data);
      Check(Format('EncBytesToString(0)  sz=%d', [sz]), encStr = refStr,
        FirstStrDiff(encStr, refStr));

      // 3) Encode(bytes): TBytes, 76-char, vs TNetEncoding.Base64.Encode
      encBytes := pf76.Encode(data);
      refBytes := TNetEncoding.Base64.Encode(data);
      Check(Format('Encode(bytes,76)     sz=%d', [sz]), BytesEqual(encBytes, refBytes),
        Format('len got=%d exp=%d', [Length(encBytes), Length(refBytes)]));

      // 4) DecodeStringToBytes round-trips and matches the RTL
      dec := pf0.DecodeStringToBytes(refStr);
      Check(Format('DecStrToBytes rt     sz=%d', [sz]), BytesEqual(dec, data));
      if refStr <> '' then
      begin
        refDec := TNetEncoding.Base64String.DecodeStringToBytes(refStr);
        Check(Format('DecStrToBytes vs net sz=%d', [sz]), BytesEqual(dec, refDec));
      end;

      // 5) Decode tolerates CRLF line breaks (decode the 76-wrapped form)
      wrapped := pf76.EncodeBytesToString(data);
      dec := pf76.DecodeStringToBytes(wrapped);
      Check(Format('Decode wrapped rt    sz=%d', [sz]), BytesEqual(dec, data));

      // 6) Various CharsPerLine vs TBase64Encoding.Create(N)
      for ci := Low(CPs) to High(CPs) do
      begin
        pfN  := TBase64EncodingPolyFill.Create(CPs[ci]);
        netN := TBase64Encoding.Create(CPs[ci]);
        try
          encStr := pfN.EncodeBytesToString(data);
          refStr := netN.EncodeBytesToString(data);
          Check(Format('Enc cp=%d sz=%d', [CPs[ci], sz]), encStr = refStr,
            FirstStrDiff(encStr, refStr));
          // Encode(bytes): TBytes exercises the WrapRawFast SIMD wrap path.
          encBytes := pfN.Encode(data);
          // Payload correctness (RTL-independent): stripping the line breaks
          // must yield the unbroken encoding, and the bytes must round-trip.
          Check(Format('EncBytes payload cp=%d sz=%d', [CPs[ci], sz]),
            BytesEqual(StripCRLFBytes(encBytes), pf0.Encode(data)),
            FirstBytesDiff(StripCRLFBytes(encBytes), pf0.Encode(data)));
          Check(Format('EncBytes rt cp=%d sz=%d', [CPs[ci], sz]),
            BytesEqual(pfN.Decode(encBytes), data));
          // vs the RTL only where the RTL is correct. The RTL's Encode(bytes)
          // under-allocates and corrupts the output for CharsPerLine values
          // that are not multiples of 4 (EstimateEncodeLength assumes lines of
          // CharsPerLine chars, but it actually wraps every CharsPerLine div 4
          // quanta = a multiple of 4 chars). Our output is correct regardless.
          if (CPs[ci] mod 4) = 0 then
          begin
            refBytes := netN.Encode(data);
            Check(Format('EncBytes vs RTL cp=%d sz=%d', [CPs[ci], sz]),
              BytesEqual(encBytes, refBytes), FirstBytesDiff(encBytes, refBytes));
          end;
          Check(Format('Dec cp=%d sz=%d', [CPs[ci], sz]),
            BytesEqual(pfN.DecodeStringToBytes(encStr), data));
        finally
          pfN.Free;
          netN.Free;
        end;
      end;
    end;

    // 7) Encode(string)/Decode(string) UTF-8 semantics vs TNetEncoding.Base64
    for var s in ['', 'Hello, World!', 'Caf'#$E9' na'#$EF've r'#$E9'sum'#$E9,
                  'mixed '#$2603' snowman & '#$1F600] do
    begin
      encStr := pf76.Encode(s);
      refStr := TNetEncoding.Base64.Encode(s);
      Check(Format('Encode(string) "%s"', [Vis(Copy(s, 1, 12))]), encStr = refStr,
        FirstStrDiff(encStr, refStr));
      Check(Format('Decode(string) rt "%s"', [Vis(Copy(s, 1, 12))]),
        pf76.Decode(encStr) = s);
    end;

    // 8) Stream encode/decode vs RTL stream encode
    for si := Low(Sizes) to High(Sizes) do
    begin
      sz := Sizes[si];
      data := GenerateData(sz);
      var src := TBytesStream.Create(data);
      var dstPF := TBytesStream.Create;
      var dstNet := TBytesStream.Create;
      try
        src.Position := 0;
        pf76.Encode(src, dstPF);
        src.Position := 0;
        TNetEncoding.Base64.Encode(src, dstNet);
        Check(Format('Stream encode sz=%d', [sz]),
          BytesEqual(dstPF.Bytes, dstNet.Bytes) and (dstPF.Size = dstNet.Size),
          Format('len got=%d exp=%d', [dstPF.Size, dstNet.Size]));

        // round-trip decode of the stream-encoded bytes
        dstPF.Position := 0;
        var dstDec := TBytesStream.Create;
        try
          pf76.Decode(dstPF, dstDec);
          Check(Format('Stream decode rt sz=%d', [sz]),
            (dstDec.Size = sz) and BytesEqual(Copy(dstDec.Bytes, 0, sz), data));
        finally
          dstDec.Free;
        end;
      finally
        src.Free;
        dstPF.Free;
        dstNet.Free;
      end;
    end;
  finally
    pf76.Free;
    pf0.Free;
  end;
  Writeln('');
end;

{ ----- RTL-descendant (TBase64EncodingFast) correctness ----- }

procedure TestRTLDescendant;
const
  Sizes: array[0..12] of Integer = (0, 1, 2, 3, 5, 53, 57, 200, 1000, 4096, 65537, 100000, 100001);
  CPs: array[0..3] of Integer = (0, 64, 72, 76);  // 0 = no breaks; rest multiples of 4
var
  si, ci, sz: Integer;
  data, encB, refB, dec: TBytes;
  encS, refS: string;
  fast: TNetEncoding;          // hold it via the RTL base type to prove compatibility
  rtl: TBase64Encoding;
begin
  Writeln('RTL-descendant TBase64EncodingFast vs TBase64Encoding (same params):');
  for si := Low(Sizes) to High(Sizes) do
  begin
    sz := Sizes[si];
    data := GenerateData(sz);
    for ci := Low(CPs) to High(CPs) do
    begin
      // Construct via the RTL constructor signature; reference via the RTL class.
      if CPs[ci] = 0 then
      begin
        // CharsPerLine 0 => no breaks (use the single-arg ctor)
        fast := TBase64EncodingFast.Create(0);
        rtl := TBase64Encoding.Create(0);
      end
      else
      begin
        fast := TBase64EncodingFast.Create(CPs[ci], #13#10);
        rtl := TBase64Encoding.Create(CPs[ci], #13#10);
      end;
      try
        // EncodeBytesToString through the TNetEncoding base reference
        encS := fast.EncodeBytesToString(data);
        refS := rtl.EncodeBytesToString(data);
        Check(Format('Fast.EncBytesToString cp=%d sz=%d', [CPs[ci], sz]),
          encS = refS, FirstStrDiff(encS, refS));

        // Encode(bytes): TBytes
        encB := fast.Encode(data);
        refB := rtl.Encode(data);
        Check(Format('Fast.Encode(bytes) cp=%d sz=%d', [CPs[ci], sz]),
          BytesEqual(encB, refB), FirstBytesDiff(encB, refB));

        // Decode round-trip (decode our own encoding) and vs RTL decode
        dec := fast.DecodeStringToBytes(encS);
        Check(Format('Fast.DecStrToBytes rt cp=%d sz=%d', [CPs[ci], sz]),
          BytesEqual(dec, data));
        if encS <> '' then
          Check(Format('Fast.Decode vs RTL cp=%d sz=%d', [CPs[ci], sz]),
            BytesEqual(dec, rtl.DecodeStringToBytes(encS)));
      finally
        fast.Free;
        rtl.Free;
      end;
    end;
  end;

  // Encode/Decode(string) (UTF-8) through the base reference, default ctor.
  fast := TBase64EncodingFast.Create;     // parameterless -> 76-char MIME
  try
    for var s in ['', 'Hello, World!', 'Caf'#$E9' na'#$EF've', 'snow '#$2603' man'] do
    begin
      encS := fast.Encode(s);
      Check(Format('Fast.Encode(string) "%s"', [Vis(Copy(s, 1, 10))]),
        encS = TNetEncoding.Base64.Encode(s), FirstStrDiff(encS, TNetEncoding.Base64.Encode(s)));
      Check(Format('Fast.Decode(string) rt "%s"', [Vis(Copy(s, 1, 10))]),
        fast.Decode(encS) = s);
    end;
  finally
    fast.Free;
  end;
  Writeln('');
end;

{ ----- fused encoders correctness ----- }

procedure TestFused;
const
  Sizes: array[0..18] of Integer =
    (0, 1, 2, 3, 24, 47, 48, 56, 57, 58, 113, 114, 115, 200, 1000, 4096, 65537, 100000, 100001);
  CPs: array[0..6] of Integer = (4, 5, 7, 8, 11, 64, 76);  // incl. non-multiples of 4

  // Validate one (lineQuanta, sep) combination with RTL-independent oracles.
  procedure CheckCombo(const data, sep: TBytes; cp: Integer; const tag: string;
    pf0: TBase64EncodingPolyFill);
  var
    fS, fA, nobreak: TBytes;
    lq: Integer;
  begin
    lq := cp div 4;
    fS := MimeEncodeFusedScalar(PByte(data), Length(data), lq, sep);
    fA := MimeEncodeFusedAVX2(PByte(data), Length(data), lq, sep);
    // 1) the two independent asm implementations must agree
    Check(Format('fused scalar==avx2 %s', [tag]), BytesEqual(fS, fA),
      FirstBytesDiff(fS, fA));
    // 2) stripping the separators must yield the unbroken encoding (payload OK)
    nobreak := pf0.Encode(data);
    Check(Format('fused payload %s', [tag]),
      BytesEqual(StripCRLFBytes(fA), nobreak), FirstBytesDiff(StripCRLFBytes(fA), nobreak));
    // 3) must round-trip back to the input
    Check(Format('fused round-trip %s', [tag]), BytesEqual(pf0.Decode(fA), data));
  end;

var
  si, ci, sz: Integer;
  data, ref, fA: TBytes;
  netN: TBase64Encoding;
  pf0: TBase64EncodingPolyFill;
  crlf, lf: TBytes;
begin
  Writeln('Fused encoders (single-pass): scalar vs avx2, payload, round-trip, RTL:');
  crlf := TBytes.Create(13, 10);
  lf := TBytes.Create(10);
  pf0 := TBase64EncodingPolyFill.Create(0);   // unbroken reference for payload/decode
  try
    for si := Low(Sizes) to High(Sizes) do
    begin
      sz := Sizes[si];
      data := GenerateData(sz);
      for ci := Low(CPs) to High(CPs) do
      begin
        CheckCombo(data, crlf, CPs[ci], Format('CRLF cp=%d sz=%d', [CPs[ci], sz]), pf0);
        // 4) for multiples of 4 the RTL is correct -> compare directly
        if (CPs[ci] mod 4) = 0 then
        begin
          netN := TBase64Encoding.Create(CPs[ci]);
          try
            ref := netN.Encode(data);
          finally
            netN.Free;
          end;
          fA := MimeEncodeFusedAVX2(PByte(data), Length(data), CPs[ci] div 4, crlf);
          Check(Format('fused-avx2 vs RTL cp=%d sz=%d', [CPs[ci], sz]),
            BytesEqual(fA, ref), FirstBytesDiff(fA, ref));
        end;
      end;
      // 1-byte separator (LF)
      CheckCombo(data, lf, 76, Format('LF cp=76 sz=%d', [sz]), pf0);
    end;
  finally
    pf0.Free;
  end;
  Writeln('');
end;

{ ---------- benchmark ---------- }

procedure Benchmark(const FileName: string);
var
  data, decoded, refDec: TBytes;
  refMime, refNoBreak: TBytes;
  bytes: NativeInt;
  mb: Double;
  sw: TStopwatch;
  i: Integer;
  pf76, pf0: TBase64EncodingPolyFill;
  encBest, mimeBest, encNbBest, nbBest, decBest, decRefBest, t: Int64;
  pfMime, pfNb: TBytes;
  okMime, okNb, okDec: Boolean;
begin
  Writeln('Large-buffer benchmark:');
  Writeln('  File: ' + FileName);
  data := TFile.ReadAllBytes(FileName);
  bytes := Length(data);
  mb := bytes / (1024 * 1024);
  Writeln(Format('  Size: %d bytes (%.2f MB), %d iterations', [bytes, mb, BENCH_ITERS]));
  Writeln('');

  pf76 := TBase64EncodingPolyFill.Create;
  pf0  := TBase64EncodingPolyFill.Create(0);
  try
    encBest := High(Int64); mimeBest := High(Int64);
    encNbBest := High(Int64); nbBest := High(Int64);
    decBest := High(Int64); decRefBest := High(Int64);

    // ENCODE, 76-char MIME
    for i := 1 to BENCH_ITERS do
    begin
      sw := TStopwatch.StartNew; pfMime := pf76.Encode(data); sw.Stop;
      t := sw.ElapsedTicks; if t < encBest then encBest := t;
    end;
    for i := 1 to BENCH_ITERS do
    begin
      sw := TStopwatch.StartNew; refMime := TNetEncoding.Base64.Encode(data); sw.Stop;
      t := sw.ElapsedTicks; if t < mimeBest then mimeBest := t;
    end;

    // ENCODE, no breaks
    for i := 1 to BENCH_ITERS do
    begin
      sw := TStopwatch.StartNew; pfNb := pf0.Encode(data); sw.Stop;
      t := sw.ElapsedTicks; if t < encNbBest then encNbBest := t;
    end;
    for i := 1 to BENCH_ITERS do
    begin
      sw := TStopwatch.StartNew; refNoBreak := TNetEncoding.Base64String.Encode(data); sw.Stop;
      t := sw.ElapsedTicks; if t < nbBest then nbBest := t;
    end;

    okMime := BytesEqual(pfMime, refMime);
    okNb   := BytesEqual(pfNb, refNoBreak);

    // DECODE (refNoBreak holds the unbroken base64 bytes)
    for i := 1 to BENCH_ITERS do
    begin
      sw := TStopwatch.StartNew; decoded := pf0.Decode(refNoBreak); sw.Stop;
      t := sw.ElapsedTicks; if t < decBest then decBest := t;
    end;
    for i := 1 to BENCH_ITERS do
    begin
      sw := TStopwatch.StartNew; refDec := TNetEncoding.Base64String.Decode(refNoBreak); sw.Stop;
      t := sw.ElapsedTicks; if t < decRefBest then decRefBest := t;
    end;
    okDec := BytesEqual(decoded, data) and BytesEqual(decoded, refDec);

    Writeln('  Encode (76-char MIME):');
    Writeln(Format('    PolyFill (asm)            : %8.2f ms   %8.2f MB/s',
      [encBest / TStopwatch.Frequency * 1000, mb / (encBest / TStopwatch.Frequency)]));
    Writeln(Format('    TNetEncoding.Base64       : %8.2f ms   %8.2f MB/s',
      [mimeBest / TStopwatch.Frequency * 1000, mb / (mimeBest / TStopwatch.Frequency)]));
    Writeln(Format('    speedup                   : %.2fx', [mimeBest / encBest]));
    Writeln('');
    Writeln('  Encode (no breaks):');
    Writeln(Format('    PolyFill (asm)            : %8.2f ms   %8.2f MB/s',
      [encNbBest / TStopwatch.Frequency * 1000, mb / (encNbBest / TStopwatch.Frequency)]));
    Writeln(Format('    TNetEncoding.Base64String : %8.2f ms   %8.2f MB/s',
      [nbBest / TStopwatch.Frequency * 1000, mb / (nbBest / TStopwatch.Frequency)]));
    Writeln(Format('    speedup                   : %.2fx', [nbBest / encNbBest]));
    Writeln('');
    Writeln('  Decode:');
    Writeln(Format('    PolyFill (asm)            : %8.2f ms   %8.2f MB/s',
      [decBest / TStopwatch.Frequency * 1000, mb / (decBest / TStopwatch.Frequency)]));
    Writeln(Format('    TNetEncoding.Base64String : %8.2f ms   %8.2f MB/s',
      [decRefBest / TStopwatch.Frequency * 1000, mb / (decRefBest / TStopwatch.Frequency)]));
    Writeln(Format('    speedup                   : %.2fx', [decRefBest / decBest]));
    Writeln('');
    Writeln(Format('  Large-buffer output correct: enc-mime=%s  enc-nobreak=%s  decode=%s',
      [BoolToStr(okMime, True), BoolToStr(okNb, True), BoolToStr(okDec, True)]));
    Check('benchmark enc-mime correct', okMime);
    Check('benchmark enc-nobreak correct', okNb);
    Check('benchmark decode correct', okDec);
  finally
    pf76.Free;
    pf0.Free;
  end;
  Writeln('');
end;

{ ---------- 76-char MIME: 4-way comparison ---------- }

procedure MimeFourWay(const data: TBytes; iters: Integer; verifyVsRtl: Boolean);
var
  crlf, rtl, v1, v2, v3: TBytes;
  pf76: TBase64EncodingPolyFill;
  bytes: NativeInt;
  mb: Double;
  sw: TStopwatch;
  i: Integer;
  bRtl, bV1, bV2, bV3: Int64;

  procedure Row(const Name: string; best: Int64);
  begin
    Writeln(Format('    %-28s: %9.3f ms   %8.2f MB/s   %6.2fx',
      [Name, best / TStopwatch.Frequency * 1000,
       (mb * iters) / (best / TStopwatch.Frequency), bRtl / best]));
  end;

begin
  bytes := Length(data);
  mb := bytes / (1024 * 1024);
  crlf := TBytes.Create(13, 10);
  pf76 := TBase64EncodingPolyFill.Create;
  try
    // time the whole batch of `iters` calls (better signal for small buffers)
    sw := TStopwatch.StartNew;
    for i := 1 to iters do rtl := TNetEncoding.Base64.Encode(data);
    sw.Stop; bRtl := sw.ElapsedTicks;
    sw := TStopwatch.StartNew;
    for i := 1 to iters do v1 := pf76.Encode(data);
    sw.Stop; bV1 := sw.ElapsedTicks;
    sw := TStopwatch.StartNew;
    for i := 1 to iters do v2 := MimeEncodeFusedScalar(PByte(data), bytes, 19, crlf);
    sw.Stop; bV2 := sw.ElapsedTicks;
    sw := TStopwatch.StartNew;
    for i := 1 to iters do v3 := MimeEncodeFusedAVX2(PByte(data), bytes, 19, crlf);
    sw.Stop; bV3 := sw.ElapsedTicks;

    Writeln(Format('  Size: %d bytes (%.3f MB) x %d iterations  (speedup vs RTL)',
      [bytes, mb, iters]));
    Row('TNetEncoding.Base64 (RTL)', bRtl);
    Row('V1 two-pass (AVX2+SIMD copy)', bV1);
    Row('V2 fused scalar (all asm)', bV2);
    Row('V3 fused AVX2', bV3);
    if verifyVsRtl then
    begin
      Check('MIME 4-way: V1 == RTL', BytesEqual(v1, rtl), FirstBytesDiff(v1, rtl));
      Check('MIME 4-way: V2 == RTL', BytesEqual(v2, rtl), FirstBytesDiff(v2, rtl));
      Check('MIME 4-way: V3 == RTL', BytesEqual(v3, rtl), FirstBytesDiff(v3, rtl));
    end;
  finally
    pf76.Free;
  end;
  Writeln('');
end;

procedure BenchmarkMime(const FileName: string);
var
  data, small: TBytes;
begin
  Writeln('76-char MIME encode — 4-way comparison:');
  data := TFile.ReadAllBytes(FileName);

  // Large buffer: realistic, but partly memory-bandwidth-bound (input+output
  // exceed cache), so V1 and V3 converge toward the same throughput.
  Writeln('  [large buffer — bandwidth-bound]');
  MimeFourWay(data, BENCH_ITERS, True);

  // Small, cache-resident buffer: compute-bound, so the fused path's lower
  // memory traffic shows as a clear win over the two-pass approach.
  Writeln('  [256 KB cache-resident — compute-bound]');
  small := Copy(data, 0, Min(Length(data), 256 * 1024));
  MimeFourWay(small, 4000, True);
end;

{ ---------- entry point ---------- }

procedure RunTests;
var
  fileArg, tempFile: string;
  mbArg: Integer;
  generated: Boolean;
begin
{$IFDEF WIN32}
  Writeln('=== TBase64EncodingPolyFill test harness  [Win32 / x86 asm] ===');
{$ENDIF}
{$IFDEF WIN64}
  Writeln('=== TBase64EncodingPolyFill test harness  [Win64 / x64 asm] ===');
{$ENDIF}
  Writeln('');

  TestCorrectness;
  TestFused;
  TestRTLDescendant;

  tempFile := '';
  generated := False;
  fileArg := '';
  if ParamCount >= 1 then
    fileArg := ParamStr(1);

  if (fileArg <> '') and TFile.Exists(fileArg) then
    tempFile := fileArg
  else
  begin
    mbArg := DEFAULT_MB;
    if (fileArg <> '') and (StrToIntDef(fileArg, -1) > 0) then
      mbArg := StrToInt(fileArg);
    tempFile := TPath.Combine(TPath.GetTempPath, Format('pf_base64_%dMB.bin', [mbArg]));
    Writeln(Format('Generating %d MB test file: %s', [mbArg, tempFile]));
    TFile.WriteAllBytes(tempFile, GenerateData(Int64(mbArg) * 1024 * 1024));
    generated := True;
    Writeln('');
  end;

  try
    Benchmark(tempFile);
    BenchmarkMime(tempFile);
  finally
    if generated and TFile.Exists(tempFile) then
      TFile.Delete(tempFile);
  end;

  Writeln('================================================');
  Writeln(Format('Summary: %d/%d checks passed.', [TestsPassed, TestsRun]));
  if TestsPassed = TestsRun then
    Writeln('RESULT: ALL CHECKS PASSED')
  else
    Writeln('RESULT: FAILURES PRESENT');
  Writeln('================================================');
end;

end.

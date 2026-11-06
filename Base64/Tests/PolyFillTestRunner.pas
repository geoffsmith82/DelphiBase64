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

  Every check runs once per implementation (Pascal, x86 asm, AVX2 asm on
  Windows; Pascal, C, A64 asm, NEON, NEON asm, NEON C on ARM64).

  Usage:  PolyFillTestNN.exe [file | megabytes | --nobench]
}

interface

procedure RunTests;

implementation

uses
{$IFDEF MSWINDOWS}
  Winapi.Windows,
{$ENDIF}
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
  QuietPass: Boolean = False;   // while looping over implementations

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
    if not QuietPass then
      Writeln(Format('  [PASS] %s', [Name]));
  end
  else
  begin
    Writeln(Format('  [FAIL] %s [%s]', [Name, Base64ActiveImplementation]));
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
    fA := MimeEncodeFused(PByte(data), Length(data), lq, sep);
    // 1) this implementation must agree with the platform's scalar code
    Check(Format('fused scalar==active %s', [tag]), BytesEqual(fS, fA),
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
          fA := MimeEncodeFused(PByte(data), Length(data), CPs[ci] div 4, crlf);
          Check(Format('fused vs RTL cp=%d sz=%d', [CPs[ci], sz]),
            BytesEqual(fA, ref), FirstBytesDiff(fA, ref));
        end;
      end;
      // 1-byte separator (LF)
      CheckCombo(data, lf, 76, Format('LF cp=76 sz=%d', [sz]), pf0);
    end;
  finally
    pf0.Free;
  end;
end;

{ ---------- decode edge cases ---------- }

// The outcome of a decode: the bytes, or the exception text.
function DecodeOutcome(pf: TBase64EncodingPolyFill; const Input: TBytes): TBytes;
begin
  try
    Result := pf.Decode(Input);
  except
    on E: EConvertError do
      Result := TEncoding.UTF8.GetBytes('raised: ' + E.Message);
  end;
end;

{$IFDEF MSWINDOWS}
// Decodes text placed hard against a no-access page, so that reading one byte
// past the end is an access violation. On ARM64 Arm\selftest.c covers this by
// checking the chars consumed; on Windows that count is not visible from here.
procedure TestDecodeBounds;
const
  PageSize = 4096;
var
  buf, p: PByte;
  old: Cardinal;
  pf: TBase64EncodingPolyFill;
  n, k: Integer;
  enc: TBytes;
  faults: Integer;

  procedure DecodeAtEnd(const Text: TBytes);
  begin
    p := buf + PageSize - Length(Text);
    Move(Text[0], p^, Length(Text));
    try
      pf.Decode(Slice(PByteArray(p)^, Length(Text)));
    except
      on EAccessViolation do
        Inc(faults);
      on EConvertError do
        ;
    end;
  end;

begin
  buf := VirtualAlloc(nil, PageSize * 2, MEM_RESERVE or MEM_COMMIT, PAGE_READWRITE);
  if buf = nil then RaiseLastOSError;
  if not VirtualProtect(buf + PageSize, PageSize, PAGE_NOACCESS, old) then RaiseLastOSError;
  pf := TBase64EncodingPolyFill.Create(0);
  try
    faults := 0;
    // clean text of every length
    for n := 1 to 300 do
      DecodeAtEnd(pf.Encode(GenerateData(n)));
    // text ending in a run of line breaks, of every length
    for n := 1 to 12 do
      for k := 1 to 40 do
      begin
        enc := pf.Encode(GenerateData(n * 12));
        SetLength(enc, Length(enc) + k);
        FillChar(enc[Length(enc) - k], k, 10);
        DecodeAtEnd(enc);
      end;
    Check('decode never reads past the end', faults = 0, Format('%d faults', [faults]));
  finally
    pf.Free;
    VirtualFree(buf, 0, MEM_RELEASE);
  end;
end;
{$ENDIF}

// SIMD decoders stop at the first dirty block and hand over to the scalar loop,
// so that hand-over must work wherever the dirty byte lands. Replaces every
// position of the encoded text with bytes on and around the edges of the
// alphabet, and inserts whitespace and '=' at every position, then compares the
// outcome with the Pascal path. Also round-trips every line width.
procedure TestDecodeEdges;
const
  Sizes: array[0..9] of Integer = (30, 45, 47, 48, 49, 63, 96, 100, 144, 200);
  Bytes: array[0..24] of Byte = (0, 9, 10, 13, 32, 33, 43, 45, 47, 48, 57, 58, 61,
    64, 65, 90, 91, 96, 97, 122, 123, 127, 128, $AF, $FF);
  Inserts: array[0..4] of Byte = (9, 10, 13, 32, 61);
var
  pf: TBase64EncodingPolyFill;
  impl: string;
  mismatches, si, pos, k, cp: Integer;
  firstBad: string;
  data, enc, mut, ins: TBytes;
  netN: TBase64Encoding;

  procedure Compare(const Input: TBytes; const Tag: string);
  var
    got, want: TBytes;
  begin
    got := DecodeOutcome(pf, Input);
    Base64SelectImplementation('Pascal');
    want := DecodeOutcome(pf, Input);
    Base64SelectImplementation(impl);
    if not BytesEqual(got, want) then
    begin
      if mismatches = 0 then
        firstBad := Tag + ': ' + FirstBytesDiff(got, want);
      Inc(mismatches);
    end;
  end;

begin
  impl := Base64ActiveImplementation;
  pf := TBase64EncodingPolyFill.Create(0);
  try
    for si := Low(Sizes) to High(Sizes) do
    begin
      data := GenerateData(Sizes[si]);
      enc := pf.Encode(data);
      mismatches := 0;
      firstBad := '';
      for pos := 0 to High(enc) do
      begin
        for k := Low(Bytes) to High(Bytes) do
        begin
          mut := Copy(enc);
          mut[pos] := Bytes[k];
          Compare(mut, Format('replace pos=%d byte=%d', [pos, Bytes[k]]));
        end;
        for k := Low(Inserts) to High(Inserts) do
        begin
          SetLength(ins, Length(enc) + 1);
          Move(enc[0], ins[0], pos);
          ins[pos] := Inserts[k];
          Move(enc[pos], ins[pos + 1], Length(enc) - pos);
          Compare(ins, Format('insert pos=%d byte=%d', [pos, Inserts[k]]));
        end;
      end;
      Check(Format('decode edges size=%d', [Sizes[si]]), mismatches = 0,
        Format('%d mismatches, first: %s', [mismatches, firstBad]));
    end;

    data := GenerateData(1000);
    for cp := 1 to 50 do
    begin
      netN := TBase64Encoding.Create(cp * 4);
      try
        Check(Format('decode wrapped cp=%d', [cp * 4]),
          BytesEqual(pf.Decode(netN.Encode(data)), data));
      finally
        netN.Free;
      end;
    end;
  finally
    pf.Free;
  end;
end;

{ ---------- every implementation side by side ---------- }

procedure BenchmarkImplementations;
const
  Size = 1024 * 1024;
  Rounds = 15;
var
  data, mime, plain: TBytes;
  name: string;
  pf76, pf0: TBase64EncodingPolyFill;

  function Best(const Fn: TProc): Double;
  var
    r: Integer;
    sw: TStopwatch;
    t: Double;
  begin
    Result := 1E30;
    for r := 1 to Rounds do
    begin
      sw := TStopwatch.StartNew;
      Fn();
      sw.Stop;
      t := sw.ElapsedTicks / TStopwatch.Frequency;
      if t < Result then
        Result := t;
    end;
  end;

begin
  Writeln(Format('Implementations, MB/s on a 1 MB buffer, best of %d:', [Rounds]));
  Writeln(Format('  %-10s %10s %10s %10s %10s',
    ['', 'Encode', 'Encode 76', 'Decode', 'Decode 76']));
  data := GenerateData(Size);
  pf76 := TBase64EncodingPolyFill.Create;
  pf0 := TBase64EncodingPolyFill.Create(0);
  try
    mime := pf76.Encode(data);
    plain := pf0.Encode(data);
    for name in Base64Implementations do
    begin
      Base64SelectImplementation(name);
      Writeln(Format('  %-10s %10.0f %10.0f %10.0f %10.0f', [name,
        1 / Best(procedure begin pf0.Encode(data); end),
        1 / Best(procedure begin pf76.Encode(data); end),
        1 / Best(procedure begin pf0.Decode(plain); end),
        1 / Best(procedure begin pf76.Decode(mime); end)]));
    end;
  finally
    pf76.Free;
    pf0.Free;
    Base64SetMaxLevel(High(TBase64Level));
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
    Writeln(Format('    PolyFill                  : %8.2f ms   %8.2f MB/s',
      [encBest / TStopwatch.Frequency * 1000, mb / (encBest / TStopwatch.Frequency)]));
    Writeln(Format('    TNetEncoding.Base64       : %8.2f ms   %8.2f MB/s',
      [mimeBest / TStopwatch.Frequency * 1000, mb / (mimeBest / TStopwatch.Frequency)]));
    Writeln(Format('    speedup                   : %.2fx', [mimeBest / encBest]));
    Writeln('');
    Writeln('  Encode (no breaks):');
    Writeln(Format('    PolyFill                  : %8.2f ms   %8.2f MB/s',
      [encNbBest / TStopwatch.Frequency * 1000, mb / (encNbBest / TStopwatch.Frequency)]));
    Writeln(Format('    TNetEncoding.Base64String : %8.2f ms   %8.2f MB/s',
      [nbBest / TStopwatch.Frequency * 1000, mb / (nbBest / TStopwatch.Frequency)]));
    Writeln(Format('    speedup                   : %.2fx', [nbBest / encNbBest]));
    Writeln('');
    Writeln('  Decode:');
    Writeln(Format('    PolyFill                  : %8.2f ms   %8.2f MB/s',
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
    for i := 1 to iters do v3 := MimeEncodeFused(PByte(data), bytes, 19, crlf);
    sw.Stop; bV3 := sw.ElapsedTicks;

    Writeln(Format('  Size: %d bytes (%.3f MB) x %d iterations  (speedup vs RTL)',
      [bytes, mb, iters]));
    Row('TNetEncoding.Base64 (RTL)', bRtl);
    Row('V1 class Encode', bV1);
    Row('V2 fused scalar', bV2);
    Row('V3 fused ' + Base64ActiveImplementation, bV3);
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

procedure WriteSummary;
begin
  Writeln('================================================');
  Writeln(Format('Summary: %d/%d checks passed.', [TestsPassed, TestsRun]));
  if TestsPassed = TestsRun then
    Writeln('RESULT: ALL CHECKS PASSED')
  else
  begin
    Writeln('RESULT: FAILURES PRESENT');
    ExitCode := 1;
  end;
  Writeln('================================================');
end;

procedure RunTests;
const
  PlatformName =
  {$IF defined(WIN32)} 'Win32'
  {$ELSEIF defined(WIN64)} 'Win64'
  {$ELSEIF defined(IOSSIMULATOR)} 'iOS simulator ARM64'
  {$ELSEIF defined(IOS)} 'iOS ARM64'
  {$ELSEIF defined(ANDROID)} 'Android ARM64'
  {$ELSEIF defined(CPUARM64)} 'macOS ARM64'
  {$ELSEIF defined(MACOS)} 'macOS x64'
  {$ELSE} 'other'
  {$ENDIF};
var
  fileArg, tempFile, name: string;
  mbArg, runBefore, passedBefore: Integer;
  generated: Boolean;
begin
  Writeln('=== TBase64EncodingPolyFill test harness  [' + PlatformName + '] ===');
  Writeln(Format('AVX2: %s   NEON: %s   bound: %s', [BoolToStr(PolyFillHasAVX2, True),
    BoolToStr(PolyFillHasNEON, True), Base64ActiveImplementation]));
  Writeln('');

  // Correctness vs System.NetEncoding, the fused encoders, the RTL descendant
  // and the decode edge cases, for each implementation this CPU can run.
  Writeln('Correctness, per implementation:');
  QuietPass := True;
  for name in Base64Implementations do
  begin
    Base64SelectImplementation(name);
    runBefore := TestsRun;
    passedBefore := TestsPassed;
    TestCorrectness;
    TestFused;
    TestRTLDescendant;
    TestDecodeEdges;
  {$IFDEF MSWINDOWS}
    TestDecodeBounds;
  {$ENDIF}
    Writeln(Format('  %-10s %d/%d checks passed',
      [name, TestsPassed - passedBefore, TestsRun - runBefore]));
  end;
  QuietPass := False;
  Base64SetMaxLevel(High(TBase64Level));
  Writeln('');

  if (ParamCount >= 1) and (ParamStr(1) = '--nobench') then
  begin
    WriteSummary;
    Exit;
  end;

  BenchmarkImplementations;

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

  WriteSummary;
end;

end.

unit Base64EncodingFast;

{
  ============================================================================
  TBase64EncodingFast
  ============================================================================

  A drop-in subclass of System.NetEncoding.TBase64Encoding that replaces the
  RTL's byte<->base64 work with the assembly-backed encoders/decoders from
  Base64EncodingPolyFill, while remaining fully type-compatible with the RTL:

    var enc: TNetEncoding;
    enc := TBase64EncodingFast.Create;          // 76-char MIME, like TNetEncoding.Base64
    s := enc.EncodeBytesToString(myBytes);      // dispatches to the fast asm path

  Because it inherits from TBase64Encoding it can be passed anywhere a
  TNetEncoding / TBase64Encoding is expected (TNetEncoding.Base64 helpers,
  existing APIs, etc.). Use this when you need RTL compatibility; use the
  standalone TBase64EncodingPolyFill when you want a class with no dependency on
  System.NetEncoding (e.g. as a polyfill on compilers that lack it).

  It works by overriding the virtual Do* primitives that TNetEncoding's public
  methods funnel through, and forwarding them to an internal
  TBase64EncodingPolyFill created with the same CharsPerLine / LineSeparator. The
  inherited string/stream overloads route through these overrides automatically.

  Standard alphabet + '=' padding only (that is what TBase64Encoding's public
  constructors configure). Output is byte-identical to TBase64Encoding for every
  standard line width; for line widths that are not a multiple of 4 it produces
  the CORRECT output, where the RTL's own Encode is actually buggy (it
  under-allocates and emits trailing NULs — see the PolyFill README).
  ============================================================================
}

interface

uses
  System.Classes,
  System.SysUtils,
  System.NetEncoding,
  Base64EncodingPolyFill;

type
  TBase64EncodingFast = class(TBase64Encoding)
  private
    FImpl: TBase64EncodingPolyFill;
  protected
    function DoEncode(const Input, Output: TStream): NativeInt; overload; override;
    function DoEncode(const Input: array of Byte): TBytes; overload; override;
    function DoDecode(const Input, Output: TStream): NativeInt; overload; override;
    function DoDecode(const Input: array of Byte): TBytes; overload; override;
    function DoEncodeBytesToString(const Input: Pointer; Size: Integer): string; overload; override;
    function DoDecodeStringToBytes(const Input: string): TBytes; override;
  public
    // Overriding only the (virtual) two-argument constructor is enough: the RTL's
    // parameterless and single-argument constructors both virtual-dispatch to it,
    // so FImpl is created exactly once on every construction path.
    constructor Create(CharsPerLine: Integer; LineSeparator: string); overload; override;
    destructor Destroy; override;
  end;

implementation

constructor TBase64EncodingFast.Create(CharsPerLine: Integer; LineSeparator: string);
begin
  inherited Create(CharsPerLine, LineSeparator);   // sets FCharsPerLine/FLineSeparator/tables
  FImpl := TBase64EncodingPolyFill.Create(CharsPerLine, LineSeparator);
end;

destructor TBase64EncodingFast.Destroy;
begin
  FImpl.Free;
  inherited;
end;

function TBase64EncodingFast.DoEncode(const Input: array of Byte): TBytes;
begin
  Result := FImpl.Encode(Input);
end;

function TBase64EncodingFast.DoEncode(const Input, Output: TStream): NativeInt;
begin
  Result := FImpl.Encode(Input, Output);
end;

function TBase64EncodingFast.DoEncodeBytesToString(const Input: Pointer; Size: Integer): string;
begin
  Result := FImpl.EncodeBytesToString(Input, Size);
end;

function TBase64EncodingFast.DoDecode(const Input: array of Byte): TBytes;
begin
  Result := FImpl.Decode(Input);
end;

function TBase64EncodingFast.DoDecode(const Input, Output: TStream): NativeInt;
begin
  Result := FImpl.Decode(Input, Output);
end;

function TBase64EncodingFast.DoDecodeStringToBytes(const Input: string): TBytes;
begin
  Result := FImpl.DecodeStringToBytes(Input);
end;

end.

program PolyFillTest32;

{$APPTYPE CONSOLE}

uses
  System.SysUtils,
  Base64EncodingPolyFill in 'Base64EncodingPolyFill.pas',
  Base64EncodingFast in 'Base64EncodingFast.pas',
  PolyFillTestRunner in 'PolyFillTestRunner.pas';

begin
  try
    RunTests;
  except
    on E: Exception do
    begin
      Writeln(ErrOutput, E.ClassName, ': ', E.Message);
      ExitCode := 2;
    end;
  end;
end.

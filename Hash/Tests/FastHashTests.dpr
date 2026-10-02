program FastHashTests;

{
  DUnitX console runner for FastHash.

    FastHashTests.exe            run everything
    FastHashTests.exe --help     DUnitX options (filters, XML output, ...)

  Prints the CPU features, then the DUnitX results, then which code-path
  levels actually ran for each algorithm (levels the CPU lacks are reported
  as skipped, not silently passed).
}

{$APPTYPE CONSOLE}
{$STRONGLINKTYPES ON}

uses
  System.SysUtils,
  DUnitX.Loggers.Console,
  DUnitX.Loggers.Xml.NUnit,
  DUnitX.TestFramework,
  FastHash.CPU in '..\FastHash.CPU.pas',
  FastHash.MD5 in '..\FastHash.MD5.pas',
  FastHash.SHA1 in '..\FastHash.SHA1.pas',
  FastHash.SHA256 in '..\FastHash.SHA256.pas',
  FastHash.SHA512 in '..\FastHash.SHA512.pas',
  FastHash.NonCrypto in '..\FastHash.NonCrypto.pas',
  FastHash in '..\FastHash.pas',
  FastHash.Tests.Common in 'FastHash.Tests.Common.pas',
  FastHash.Tests.Vectors in 'FastHash.Tests.Vectors.pas',
  FastHash.Tests.CrossCheck in 'FastHash.Tests.CrossCheck.pas',
  FastHash.Tests.API in 'FastHash.Tests.API.pas';

var
  Runner: ITestRunner;
  Results: IRunResults;
  L: TFastHashLevel;
  Levels: string;
begin
  try
    TDUnitX.CheckCommandLine;
    Levels := '';
    for L := Low(TFastHashLevel) to High(TFastHashLevel) do
      if L in FastHashSupportedLevels then
        Levels := Levels + FastHashLevelName(L) + ' ';
    Writeln(Format('FastHash tests (%d-bit)', [SizeOf(Pointer) * 8]));
    Writeln('CPU features : ', FastHashCPUFeatures);
    Writeln('Levels       : ', Trim(Levels));
    Writeln;

    Runner := TDUnitX.CreateRunner;
    Runner.UseRTTI := True;
    Runner.FailsOnNoAsserts := False;
    if TDUnitX.Options.ConsoleMode <> TDunitXConsoleMode.Off then
      Runner.AddLogger(TDUnitXConsoleLogger.Create(TDUnitX.Options.ConsoleMode = TDunitXConsoleMode.Quiet));
    if TDUnitX.Options.XMLOutputFile <> '' then
      Runner.AddLogger(TDUnitXXMLNUnitFileLogger.Create(TDUnitX.Options.XMLOutputFile));
    Results := Runner.Execute;

    Writeln;
    Writeln('Code paths exercised (tests per algorithm @ level):');
    Write(SkipReport);
    if not Results.AllPassed then
      System.ExitCode := EXIT_ERRORS;
  except
    on E: Exception do
    begin
      Writeln(E.ClassName, ': ', E.Message);
      System.ExitCode := EXIT_ERRORS;
    end;
  end;
end.

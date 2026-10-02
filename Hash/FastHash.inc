// FastHash.inc - platform switches shared by the FastHash units.
//
// FASTHASH_X86ASM  Delphi inline x86/x64 assembly. Windows only: Delphi's
//                  macOS and Linux x64 compilers have no inline assembler.
// FASTHASH_ARM64   AArch64 kernels linked from the clang-built object in Arm\
//                  (macOS, iOS, iOS simulator, Android).
//
// Every other target uses the Pascal implementations.

{$IF (defined(CPUX86) or defined(CPUX64)) and defined(MSWINDOWS)}
  {$DEFINE FASTHASH_X86ASM}
{$ENDIF}
{$IF defined(CPUARM64) and (defined(MACOS) or defined(IOS) or defined(ANDROID))}
  {$DEFINE FASTHASH_ARM64}
{$ENDIF}

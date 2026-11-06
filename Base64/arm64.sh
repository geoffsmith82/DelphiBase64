#!/bin/bash
# Cross-builds the base64 test program for the non-Windows targets on this
# Windows machine, and runs it on the Mac (macOS natively, iOS in the simulator).
#
#   ./arm64.sh build          build OSXARM64, iOSSimARM64, iOSDevice64 and
#                             Android64 (link check only for those two -
#                             there is no device here) and OSX64 (Pascal
#                             paths; runs under Rosetta 2)
#   ./arm64.sh test [target]  run the checks, no benchmark
#                             (osx | iossim | osx64 | all)
#   ./arm64.sh bench [target] [MB]  run the checks and the benchmark
#
# Output: <Platform>/Release/PolyFillTest64 (Android: libPolyFillTest64.so).
# The AArch64 kernels come from the objects in Arm/ (see Arm/build_arm64.sh).
# Needs the 'mac' ssh alias, the imported macOS/iOS SDKs (paserve sdk fetch) and the
# Android NDK that RAD Studio installs.
set -e
export MSYS_NO_PATHCONV=1
cd "$(dirname "$0")"
HERE=$(pwd -W 2>/dev/null || pwd)

BDS="C:/Program Files (x86)/Embarcadero/Studio/37.0"
SDKS="C:/Users/geoff/Documents/Embarcadero/Studio/SDKs"
# 26.1, not 26.5: libiconv.dylib in the imported 26.5 SDK is tapi-tbd text, which ld rejects.
MACSDK=${MACSDK:-$SDKS/MacOSX26.1.sdk}
SIMSDK=${SIMSDK:-$SDKS/iPhoneSimulator26.5.sdk}
IOSSDK=${IOSSDK:-$SDKS/iPhoneOS26.5.sdk}
NDK=${NDK:-"C:/Users/Public/Documents/Embarcadero/Studio/37.0/CatalogRepository/AndroidSDK-37.0.59082.6021/ndk/27.1.12297006/toolchains/llvm/prebuilt/windows-x86_64"}
MAC=${MAC:-mac}
REMOTE=neonwork/base64-run
SIM=${SIM:-"iPhone 16 Pro"}
EXE=PolyFillTest64
PATH="$BDS/bin:$PATH"

build_one() {   # $1 = platform dir, $2 = compiler, rest = compiler options
  local plat=$1 dcc=$2; shift 2
  mkdir -p "$plat/Release"
  echo "=== $plat"
  (cd Tests && "$dcc" -B -Q -E"$HERE/$plat/Release" -N0"$HERE/$plat/Release" -O"$HERE/Arm" "$@" "$EXE.dpr") \
    | grep -v "^Embarcadero\|^Copyright\|^Linker command line" || true
  test "${PIPESTATUS[0]}" = 0
}

build() {
  build_one OSXARM64 dccosxarm64 --syslibroot:"$MACSDK" --libpath:"$BDS/lib/osxarm64/release"
  build_one iOSSimARM64 dcciossimarm64 --syslibroot:"$SIMSDK" --libpath:"$BDS/lib/iossimarm64/release" \
    -O"$BDS/lib/iossimarm64/release"
  build_one iOSDevice64 dcciosarm64 --syslibroot:"$IOSSDK" --libpath:"$BDS/lib/iosDevice64/release" \
    -O"$BDS/lib/iosDevice64/release"
  build_one Android64 dccaarm64 --linker:"$NDK/bin/ld.lld.exe" \
    --libpath:"$BDS/lib/android64/release;$NDK/sysroot/usr/lib/aarch64-linux-android/23;$NDK/sysroot/usr/lib/aarch64-linux-android;$NDK/lib/clang/18/lib/linux" \
    -O"$BDS/lib/android64/release"
  build_one OSX64 dccosx64 --syslibroot:"$MACSDK" --libpath:"$BDS/lib/osx64/release" -O"$BDS/lib/osx64/release"
  ls -la OSXARM64/Release/$EXE iOSSimARM64/Release/$EXE iOSDevice64/Release/$EXE \
         Android64/Release/lib$EXE.so OSX64/Release/$EXE
}

# $1 = target, rest = args
run() {
  local target=$1; shift
  local plat
  case $target in
    osx) plat=OSXARM64 ;; iossim) plat=iOSSimARM64 ;; osx64) plat=OSX64 ;;
    *) echo "unknown target $target"; exit 2 ;;
  esac
  ssh "$MAC" "mkdir -p $REMOTE/$plat"
  scp -q "$plat/Release/$EXE" "$MAC:$REMOTE/$plat/"
  case $target in
    osx)    ssh "$MAC" "cd $REMOTE/$plat && chmod +x $EXE && codesign -s - --force $EXE 2>/dev/null; ./$EXE $* < /dev/null" ;;
    osx64)  ssh "$MAC" "cd $REMOTE/$plat && chmod +x $EXE && codesign -s - --force $EXE 2>/dev/null; arch -x86_64 ./$EXE $* < /dev/null" ;;
    iossim) ssh "$MAC" "cd $REMOTE/$plat && chmod +x $EXE && codesign -s - --force $EXE 2>/dev/null;
              xcrun simctl boot '$SIM' 2>/dev/null || true;
              xcrun simctl spawn '$SIM' \$HOME/$REMOTE/$plat/$EXE $* < /dev/null" ;;
  esac
}

targets() { if [ -z "$1" ] || [ "$1" = all ]; then echo "osx iossim osx64"; else echo "$1"; fi; }

case $1 in
  build) build ;;
  test)  for t in $(targets "$2"); do echo "##### $t"; run "$t" --nobench; done ;;
  bench) for t in $(targets "$2"); do echo "##### $t"; run "$t" "${@:3}"; done ;;
  *) echo "usage: $0 build | test [osx|iossim|osx64|all] | bench [osx|iossim|osx64|all] [MB]"; exit 2 ;;
esac

#!/bin/bash
# Cross-builds the FastHash tests and benchmark for the non-Windows targets on
# this Windows machine, and runs them on the Mac (macOS natively, iOS in the
# simulator).
#
#   ./arm64.sh build          build OSXARM64, iOSSimARM64, iOSDevice64 and
#                             Android64 (link check only for those two -
#                             there is no device here) and OSX64 (Pascal
#                             paths; runs under Rosetta 2)
#   ./arm64.sh test [target]  run FastHashTests   (osx | iossim | osx64 | all)
#   ./arm64.sh bench [target] run FastHashBench
#
# Output: <Platform>/Release/{FastHashTests,FastHashBench} (Android: lib*.so).
# The AArch64 kernels come from the objects in Arm/ (see Arm/build_arm64.sh).
# Needs the 'mac' ssh alias, the imported macOS/iOS SDKs (paserve sdk fetch) and the
# Android NDK that RAD Studio installs.
set -e
export MSYS_NO_PATHCONV=1
cd "$(dirname "$0")"
HERE=$(pwd -W 2>/dev/null || pwd)

BDS="C:/Program Files (x86)/Embarcadero/Studio/37.0"
SDKS="C:/Users/geoff/Documents/Embarcadero/Studio/SDKs"
MACSDK=${MACSDK:-$SDKS/MacOSX26.5.sdk}
SIMSDK=${SIMSDK:-$SDKS/iPhoneSimulator26.5.sdk}
IOSSDK=${IOSSDK:-$SDKS/iPhoneOS26.5.sdk}
NDK=${NDK:-"C:/Users/Public/Documents/Embarcadero/Studio/37.0/CatalogRepository/AndroidSDK-37.0.59082.6021/ndk/27.1.12297006/toolchains/llvm/prebuilt/windows-x86_64"}
MAC=${MAC:-mac}
REMOTE=neonwork/fasthash-run
SIM=${SIM:-"iPhone 16 Pro"}
PATH="$BDS/bin:$PATH"

build_one() {   # $1 = platform dir, $2 = compiler, $3 = project dir, $4 = dpr, rest = compiler options
  local plat=$1 dcc=$2 dir=$3 dpr=$4; shift 4
  mkdir -p "$plat/Release"
  echo "=== $plat: $dpr"
  (cd "$dir" && "$dcc" -B -Q -E"$HERE/$plat/Release" -N0"$HERE/$plat/Release" -O"$HERE/Arm" "$@" "$dpr") \
    | grep -v "^Embarcadero\|^Copyright\|^Linker command line" || true
  test "${PIPESTATUS[0]}" = 0
}

build() {
  for p in Tests:FastHashTests.dpr Bench:FastHashBench.dpr; do
    dir=${p%%:*}; dpr=${p#*:}
    build_one OSXARM64 dccosxarm64 "$dir" "$dpr" --syslibroot:"$MACSDK" --libpath:"$BDS/lib/osxarm64/release"
    build_one iOSSimARM64 dcciossimarm64 "$dir" "$dpr" --syslibroot:"$SIMSDK" --libpath:"$BDS/lib/iossimarm64/release" \
      -O"$BDS/lib/iossimarm64/release"
    build_one iOSDevice64 dcciosarm64 "$dir" "$dpr" --syslibroot:"$IOSSDK" --libpath:"$BDS/lib/iosDevice64/release" \
      -O"$BDS/lib/iosDevice64/release"
    build_one Android64 dccaarm64 "$dir" "$dpr" --linker:"$NDK/bin/ld.lld.exe" \
      --libpath:"$BDS/lib/android64/release;$NDK/sysroot/usr/lib/aarch64-linux-android/23;$NDK/sysroot/usr/lib/aarch64-linux-android;$NDK/lib/clang/18/lib/linux" \
      -O"$BDS/lib/android64/release" -U"$BDS/source/DunitX"
    build_one OSX64 dccosx64 "$dir" "$dpr" --syslibroot:"$MACSDK" --libpath:"$BDS/lib/osx64/release" -O"$BDS/lib/osx64/release"
  done
  ls -la OSXARM64/Release/FastHash{Tests,Bench} iOSSimARM64/Release/FastHash{Tests,Bench} \
         iOSDevice64/Release/FastHash{Tests,Bench} Android64/Release/libFastHash{Tests,Bench}.so OSX64/Release/FastHash{Tests,Bench}
}

# $1 = exe name, $2 = target, rest = args
run() {
  local exe=$1 target=$2; shift 2
  local plat
  case $target in
    osx) plat=OSXARM64 ;; iossim) plat=iOSSimARM64 ;; osx64) plat=OSX64 ;;
    *) echo "unknown target $target"; exit 2 ;;
  esac
  ssh "$MAC" "mkdir -p $REMOTE/$plat"
  scp -q "$plat/Release/$exe" "$MAC:$REMOTE/$plat/"
  case $target in
    osx)    ssh "$MAC" "cd $REMOTE/$plat && chmod +x $exe && codesign -s - --force $exe 2>/dev/null; ./$exe $* < /dev/null" ;;
    osx64)  ssh "$MAC" "cd $REMOTE/$plat && chmod +x $exe && codesign -s - --force $exe 2>/dev/null; arch -x86_64 ./$exe $* < /dev/null" ;;
    iossim) ssh "$MAC" "cd $REMOTE/$plat && chmod +x $exe && codesign -s - --force $exe 2>/dev/null;
              xcrun simctl boot '$SIM' 2>/dev/null || true;
              xcrun simctl spawn '$SIM' \$HOME/$REMOTE/$plat/$exe $* < /dev/null" ;;
  esac
}

targets() { if [ -z "$1" ] || [ "$1" = all ]; then echo "osx iossim osx64"; else echo "$1"; fi; }

case $1 in
  build) build ;;
  test)  for t in $(targets "$2"); do echo "##### $t"; run FastHashTests "$t" --consolemode:quiet --exitbehavior:Continue; done ;;
  bench) for t in $(targets "$2"); do echo "##### $t"; run FastHashBench "$t" "${@:3}"; done ;;
  *) echo "usage: $0 build | test [osx|iossim|osx64|all] | bench [osx|iossim|osx64|all] [MB]"; exit 2 ;;
esac

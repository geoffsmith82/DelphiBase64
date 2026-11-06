#!/bin/bash
# Builds the ARM64 objects that the Delphi ARM64 targets link against:
#
#   base64_macos_arm64.o    macOS ARM64          (clang on the Mac)
#   base64_ios_arm64.o      iOS device ARM64     (clang on the Mac)
#   base64_iossim_arm64.o   iOS simulator ARM64  (clang on the Mac)
#   base64_android_arm64.o  Android ARM64 (ELF)  (the Android NDK's clang on Windows)
#
# Each object is base64_arm64.c (C / intrinsics) + base64_arm64.S (hand-written
# asm) merged with a relocatable link. The objects are checked in, so building
# the Delphi projects does not need this script.
#
#   Arm/build_arm64.sh            build all four objects
#   Arm/build_arm64.sh selftest   also build and run selftest.c on the Mac
#
# Needs: the 'mac' ssh alias (see the global CLAUDE.md) and Delphi's Android NDK.
set -e
cd "$(dirname "$0")"

MAC=${MAC:-mac}
REMOTE=neonwork/base64
NDK=${NDK:-"/c/Users/Public/Documents/Embarcadero/Studio/37.0/CatalogRepository/AndroidSDK-37.0.59082.6021/ndk/27.1.12297006/toolchains/llvm/prebuilt/windows-x86_64/bin"}
CFLAGS="-O3 -ffreestanding -fno-stack-protector -Wall"

ssh "$MAC" "mkdir -p $REMOTE"
scp -q base64_arm64.c base64_arm64.S selftest.c "$MAC:$REMOTE/"
ssh "$MAC" "cd $REMOTE && set -e &&
  for t in macos:arm64-apple-macos11 ios:arm64-apple-ios12.0 iossim:arm64-apple-ios13.0-simulator; do
    n=\${t%%:*}; tr=\${t#*:}
    clang -target \$tr $CFLAGS -c base64_arm64.c -o c_\$n.o
    clang -target \$tr $CFLAGS -c base64_arm64.S -o s_\$n.o
    ld -r c_\$n.o s_\$n.o -o base64_\${n}_arm64.o
    echo \"built base64_\${n}_arm64.o\"
  done" 2>&1 | grep -v "incompatible-sysroot"
scp -q "$MAC:$REMOTE/base64_macos_arm64.o" "$MAC:$REMOTE/base64_ios_arm64.o" "$MAC:$REMOTE/base64_iossim_arm64.o" .

"$NDK/clang.exe" --target=aarch64-linux-android21 $CFLAGS -c base64_arm64.c -o c_android.o
"$NDK/clang.exe" --target=aarch64-linux-android21 $CFLAGS -c base64_arm64.S -o s_android.o
"$NDK/ld.lld.exe" -r c_android.o s_android.o -o base64_android_arm64.o
rm -f c_android.o s_android.o
echo "built base64_android_arm64.o"

if [ "$1" = "selftest" ]; then
  ssh "$MAC" "cd $REMOTE && clang -O3 -arch arm64 selftest.c base64_macos_arm64.o -o selftest && ./selftest"
fi

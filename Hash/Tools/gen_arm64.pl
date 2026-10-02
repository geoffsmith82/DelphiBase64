#!/usr/bin/perl
# Generates Arm\fasthash_arm64.S: hand-written AArch64 assembly twins of the
# C kernels in Arm\fasthash_arm64.c (same names with _asm instead of _c).
#
#   fh_md5_asm         scalar MD5 (bic/orn forms of G and I)
#   fh_sha1_asm        scalar SHA-1, whole 16-word schedule in registers
#   fh_sha256_asm      scalar SHA-256, schedule in registers, sigma terms via
#                      ROR-shifted eor operands
#   fh_sha512_asm      scalar SHA-512, same in 64-bit registers
#   fh_sha1_ce_asm     ARMv8 SHA1C/SHA1P/SHA1M/SHA1H/SHA1SU0/SHA1SU1
#   fh_sha256_ce_asm   ARMv8 SHA256H/SHA256H2/SHA256SU0/SHA256SU1
#   fh_sha512_ce_asm   ARMv8.2 SHA512H/SHA512H2/SHA512SU0/SHA512SU1
#   fh_bobjenkins_asm, fh_fnv1a32_asm, fh_fnv1a64_asm
#
# Block functions: (x0 = state, x1 = data, x2 = blocks). The file is
# preprocessed (.S), so one source serves Mach-O (macOS/iOS, '_' symbol
# prefix) and ELF (Android). x18 is never touched (platform register on
# Apple); x19-x30 and d8-d15 are saved when used.
#
# Run from the Hash folder:  perl Tools\gen_arm64.pl
use strict;
use warnings;
use FindBin;

my $out = "$FindBin::Bin/../Arm/fasthash_arm64.S";
my @o;

my @MD5T = (
  0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
  0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
  0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
  0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
  0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
  0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
  0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
  0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391);
my @K256 = (
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2);
my @K512 = qw(
  428a2f98d728ae22 7137449123ef65cd b5c0fbcfec4d3b2f e9b5dba58189dbbc 3956c25bf348b538 59f111f1b605d019
  923f82a4af194f9b ab1c5ed5da6d8118 d807aa98a3030242 12835b0145706fbe 243185be4ee4b28c 550c7dc3d5ffb4e2
  72be5d74f27b896f 80deb1fe3b1696b1 9bdc06a725c71235 c19bf174cf692694 e49b69c19ef14ad2 efbe4786384f25e3
  0fc19dc68b8cd5b5 240ca1cc77ac9c65 2de92c6f592b0275 4a7484aa6ea6e483 5cb0a9dcbd41fbd4 76f988da831153b5
  983e5152ee66dfab a831c66d2db43210 b00327c898fb213f bf597fc7beef0ee4 c6e00bf33da88fc2 d5a79147930aa725
  06ca6351e003826f 142929670a0e6e70 27b70a8546d22ffc 2e1b21385c26c926 4d2c6dfc5ac42aed 53380d139d95b3df
  650a73548baf63de 766a0abb3c77b2a8 81c2c92e47edaee6 92722c851482353b a2bfe8a14cf10364 a81a664bbc423001
  c24b8b70d0f89791 c76c51a30654be30 d192e819d6ef5218 d69906245565a910 f40e35855771202a 106aa07032bbd1b8
  19a4c116b8d2d0c8 1e376c085141ab53 2748774cdf8eeb99 34b0bcb5e19b48a8 391c0cb3c5c95a63 4ed8aa4ae3418acb
  5b9cca4f7763e373 682e6ff3d6b2b8a3 748f82ee5defb2fc 78a5636f43172f60 84c87814a1f0ab72 8cc702081a6439ec
  90befffa23631e28 a4506cebde82bde9 bef9a3f7b2c67915 c67178f2e372532b ca273eceea26619c d186b8c721c0c207
  eada7dd6cde0eb1e f57d4f7fee6ed178 06f067aa72176fba 0a637dc5a2c898a6 113f9804bef90dae 1b710b35131c471b
  28db77f523047d84 32caab7b40c72493 3c9ebe0a15c9bebc 431d67c49c100d4c 4cc5d4becb3e42b6 597f299cfc657e2a
  5fcb6fab3ad6faec 6c44198c4a475817);
die unless @K512 == 80;

sub h32 { sprintf('0x%08x', $_[0]) }

# mov a 32-bit constant into a w register (movz + movk)
sub movc32 {
  my ($r, $v) = @_;
  return (sprintf("    movz  %s, #0x%04x", $r, $v & 0xffff),
          sprintf("    movk  %s, #0x%04x, lsl #16", $r, ($v >> 16) & 0xffff));
}

sub func {
  my ($name, $comment) = @_;
  return ("", "// $comment", "    .p2align 4", "    .globl SYM($name)", "SYM($name):");
}

# save / restore x19..x30
my @save = ("    stp   x19, x20, [sp, #-96]!", "    stp   x21, x22, [sp, #16]", "    stp   x23, x24, [sp, #32]",
            "    stp   x25, x26, [sp, #48]", "    stp   x27, x28, [sp, #64]", "    stp   x29, x30, [sp, #80]");
my @restore = ("    ldp   x29, x30, [sp, #80]", "    ldp   x27, x28, [sp, #64]", "    ldp   x25, x26, [sp, #48]",
               "    ldp   x23, x24, [sp, #32]", "    ldp   x21, x22, [sp, #16]", "    ldp   x19, x20, [sp], #96");

push @o,
  "// GENERATED by Tools\\gen_arm64.pl - do not edit by hand.",
  "//",
  "// Hand-written AArch64 twins of the C kernels in fasthash_arm64.c.",
  "",
  "#ifdef __APPLE__",
  "#define SYM(x) _##x",
  "#else",
  "#define SYM(x) x",
  "#endif",
  "",
  "    .arch armv8.2-a+crypto+sha3",
  "    .text";

# ======================================================================
# MD5
# ======================================================================
{
  my @S = ([7, 12, 17, 22], [5, 9, 14, 20], [4, 11, 16, 23], [6, 10, 15, 21]);
  push @o, func('fh_md5_asm', 'MD5: x0 = state (4 x u32), x1 = data, x2 = blocks');
  push @o,
    "    cbz   x2, 9f",
    "    ldp   w4, w5, [x0]",
    "    ldp   w6, w7, [x0, #8]",
    "    adr   x3, Lmd5_t",
    "1:",
    "    mov   w12, w4", "    mov   w13, w5", "    mov   w14, w6", "    mov   w15, w7";
  my @v = qw(w4 w5 w6 w7);
  for my $i (0 .. 63) {
    my $r = int($i / 16);
    my $j = $i % 16;
    my $k = $r == 0 ? $j : $r == 1 ? (1 + 5 * $j) % 16 : $r == 2 ? (5 + 3 * $j) % 16 : (7 * $j) % 16;
    my ($a, $b, $c, $d) = @v[(-$i) % 4, (1 - $i) % 4, (2 - $i) % 4, (3 - $i) % 4];
    push @o, "    // step $i",
      "    ldr   w8, [x1, #" . (4 * $k) . "]",
      "    ldr   w9, [x3, #" . (4 * $i) . "]",
      "    add   w8, w8, w9",
      "    add   $a, $a, w8";
    if ($r == 0) {      # F = ((c ^ d) & b) ^ d
      push @o, "    eor   w10, $c, $d", "    and   w10, w10, $b", "    eor   w10, w10, $d", "    add   $a, $a, w10";
    } elsif ($r == 1) { # G = (c & ~d) + (b & d)
      push @o, "    bic   w10, $c, $d", "    and   w11, $b, $d", "    add   $a, $a, w10", "    add   $a, $a, w11";
    } elsif ($r == 2) { # H = b ^ c ^ d
      push @o, "    eor   w10, $c, $d", "    eor   w10, w10, $b", "    add   $a, $a, w10";
    } else {            # I = c ^ (b | ~d)
      push @o, "    orn   w10, $b, $d", "    eor   w10, w10, $c", "    add   $a, $a, w10";
    }
    push @o, "    ror   $a, $a, #" . (32 - $S[$r][$i % 4]), "    add   $a, $a, $b";
  }
  push @o,
    "    add   w4, w4, w12", "    add   w5, w5, w13", "    add   w6, w6, w14", "    add   w7, w7, w15",
    "    add   x1, x1, #64",
    "    subs  x2, x2, #1",
    "    b.ne  1b",
    "    stp   w4, w5, [x0]",
    "    stp   w6, w7, [x0, #8]",
    "9:",
    "    ret";
}

# ======================================================================
# SHA-1 scalar
# a..e = w4..w8, W[0..15] in w9..w17,w19..w25, temps w26, w27, K in w28
# ======================================================================
{
  my @W = qw(w9 w10 w11 w12 w13 w14 w15 w16 w17 w19 w20 w21 w22 w23 w24 w25);
  my @K = (0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6);
  push @o, func('fh_sha1_asm', 'SHA-1 scalar: x0 = state (5 x u32), x1 = data, x2 = blocks');
  push @o, "    cbz   x2, 9f", @save,
    "    ldp   w4, w5, [x0]", "    ldp   w6, w7, [x0, #8]", "    ldr   w8, [x0, #16]",
    "1:";
  for my $k (0 .. 7) {
    push @o, "    ldp   $W[2*$k], $W[2*$k+1], [x1, #" . (8 * $k) . "]";
  }
  push @o, map { "    rev   $_, $_" } @W;
  push @o, "    stp   w4, w5, [sp, #-32]!", "    stp   w6, w7, [sp, #8]", "    str   w8, [sp, #16]";
  my @v = qw(w4 w5 w6 w7 w8);
  for my $i (0 .. 79) {
    my ($a, $b, $c, $d, $e) = @v;
    push @o, "    // round $i";
    push @o, movc32('w28', $K[int($i / 20)]) if $i % 20 == 0;
    my $wi = $W[$i & 15];
    if ($i >= 16) {
      push @o, "    eor   w26, " . $W[($i + 13) & 15] . ", " . $W[($i + 8) & 15],
               "    eor   w26, w26, " . $W[($i + 2) & 15],
               "    eor   $wi, $wi, w26",
               "    ror   $wi, $wi, #31";
    }
    push @o, "    add   $e, $e, w28", "    add   $e, $e, $wi";
    if ($i < 20) {          # Ch = (b & c) + (d & ~b)
      push @o, "    and   w26, $b, $c", "    bic   w27, $d, $b", "    add   $e, $e, w26", "    add   $e, $e, w27";
    } elsif ($i >= 40 && $i < 60) {   # Maj = (b & c) + (d & (b ^ c))
      push @o, "    and   w26, $b, $c", "    eor   w27, $b, $c", "    and   w27, w27, $d",
               "    add   $e, $e, w26", "    add   $e, $e, w27";
    } else {
      push @o, "    eor   w26, $b, $c", "    eor   w26, w26, $d", "    add   $e, $e, w26";
    }
    push @o, "    ror   w26, $a, #27", "    add   $e, $e, w26", "    ror   $b, $b, #2";
    @v = ($e, $a, $b, $c, $d);
  }
  push @o,
    "    ldp   w26, w27, [sp]", "    add   w4, w4, w26", "    add   w5, w5, w27",
    "    ldp   w26, w27, [sp, #8]", "    add   w6, w6, w26", "    add   w7, w7, w27",
    "    ldr   w26, [sp, #16]", "    add   w8, w8, w26",
    "    add   sp, sp, #32",
    "    add   x1, x1, #64",
    "    subs  x2, x2, #1",
    "    b.ne  1b",
    "    stp   w4, w5, [x0]", "    stp   w6, w7, [x0, #8]", "    str   w8, [x0, #16]",
    @restore,
    "9:",
    "    ret";
}

# ======================================================================
# SHA-256 / SHA-512 scalar (shared generator)
# a..h = r4..r11, W[0..15] in r12..r17,r19..r28, temps r29, r30,
# x3 = K table, x0 = state (saved on the stack while running)
# ======================================================================
sub sha2_scalar {
  my ($wide) = @_;
  my $p = $wide ? 'x' : 'w';
  my $ws = $wide ? 8 : 4;
  my $rounds = $wide ? 80 : 64;
  my @W = map { "$p$_" } (12 .. 17, 19 .. 28);
  my ($t0, $t1) = ("${p}29", "${p}30");
  my @S1 = $wide ? (14, 18, 41) : (6, 11, 25);
  my @S0 = $wide ? (28, 34, 39) : (2, 13, 22);
  my @s0 = $wide ? (1, 8, 7) : (7, 18, 3);
  my @s1 = $wide ? (19, 61, 6) : (17, 19, 10);
  my $name = $wide ? 'fh_sha512_asm' : 'fh_sha256_asm';
  my @r;
  push @r, func($name, ($wide ? 'SHA-512' : 'SHA-256') . " scalar: x0 = state, x1 = data, x2 = blocks");
  push @r, "    cbz   x2, 9f", @save,
    "    adr   x3, " . ($wide ? 'Lk512' : 'Lk256'),
    "    sub   sp, sp, #16",
    "    str   x0, [sp]";
  for my $k (0 .. 3) {
    push @r, "    ldp   $p" . (4 + 2 * $k) . ", $p" . (5 + 2 * $k) . ", [x0, #" . (2 * $ws * $k) . "]";
  }
  push @r, "1:";
  for my $k (0 .. 7) {
    push @r, "    ldp   $W[2*$k], $W[2*$k+1], [x1, #" . (2 * $ws * $k) . "]";
  }
  push @r, map { "    rev   $_, $_" } @W;
  my @v = map { "$p$_" } (4 .. 11);
  for my $i (0 .. $rounds - 1) {
    my ($a, $b, $c, $d, $e, $f, $g, $h) = @v;
    my $wi = $W[$i & 15];
    push @r, "    // round $i";
    if ($i >= 16) {
      my $w15 = $W[($i + 1) & 15];
      my $w2 = $W[($i + 14) & 15];
      push @r,
        "    ror   $t0, $w15, #$s0[0]", "    eor   $t0, $t0, $w15, ror #$s0[1]", "    eor   $t0, $t0, $w15, lsr #$s0[2]",
        "    ror   $t1, $w2, #$s1[0]", "    eor   $t1, $t1, $w2, ror #$s1[1]", "    eor   $t1, $t1, $w2, lsr #$s1[2]",
        "    add   $wi, $wi, $t0", "    add   $wi, $wi, $t1", "    add   $wi, $wi, " . $W[($i + 9) & 15];
    }
    push @r,
      "    ldr   $t0, [x3, #" . ($ws * $i) . "]",
      "    add   $h, $h, $wi",
      "    add   $h, $h, $t0",
      # Ch = (e & f) + (g & ~e), added before Sigma1 to keep the e chain short
      "    and   $t0, $e, $f", "    bic   $t1, $g, $e", "    add   $h, $h, $t0", "    add   $h, $h, $t1",
      "    ror   $t0, $e, #$S1[0]", "    eor   $t0, $t0, $e, ror #$S1[1]", "    eor   $t0, $t0, $e, ror #$S1[2]",
      "    add   $h, $h, $t0",
      "    add   $d, $d, $h",
      "    ror   $t0, $a, #$S0[0]", "    eor   $t0, $t0, $a, ror #$S0[1]", "    eor   $t0, $t0, $a, ror #$S0[2]",
      "    add   $h, $h, $t0",
      # Maj = (a & b) | (c & (a | b))
      "    orr   $t0, $a, $b", "    and   $t0, $t0, $c", "    and   $t1, $a, $b", "    orr   $t0, $t0, $t1",
      "    add   $h, $h, $t0";
    @v = ($h, $a, $b, $c, $d, $e, $f, $g);
  }
  push @r, "    ldr   x0, [sp]";
  for my $k (0 .. 3) {
    my ($r1, $r2) = ("$p" . (4 + 2 * $k), "$p" . (5 + 2 * $k));
    push @r, "    ldp   $t0, $t1, [x0, #" . (2 * $ws * $k) . "]", "    add   $r1, $r1, $t0", "    add   $r2, $r2, $t1",
             "    stp   $r1, $r2, [x0, #" . (2 * $ws * $k) . "]";
  }
  push @r,
    "    add   x1, x1, #" . (16 * $ws),
    "    subs  x2, x2, #1",
    "    b.ne  1b",
    "    add   sp, sp, #16",
    @restore,
    "9:",
    "    ret";
  return @r;
}
push @o, sha2_scalar(0);
push @o, sha2_scalar(1);

# ======================================================================
# SHA-1 with the crypto extension
# v0 = ABCD, s1 / s20 = E (alternating), v2/v3 = saved state, v4..v7 = W,
# v16..v19 = K, v21 = W+K
# ======================================================================
{
  my @K = (0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6);
  my @M = qw(v4 v5 v6 v7);
  push @o, func('fh_sha1_ce_asm', 'SHA-1, ARMv8 crypto: x0 = state, x1 = data, x2 = blocks');
  push @o, "    cbz   x2, 9f",
    "    ld1   {v0.4s}, [x0]",
    "    ldr   s1, [x0, #16]";
  for my $k (0 .. 3) {
    push @o, movc32('w9', $K[$k]), "    dup   v" . (16 + $k) . ".4s, w9";
  }
  push @o, "1:",
    "    ld1   {v4.16b, v5.16b, v6.16b, v7.16b}, [x1], #64",
    (map { "    rev32 $_.16b, $_.16b" } @M),
    "    mov   v2.16b, v0.16b",
    "    mov   v3.16b, v1.16b";
  my ($ecur, $enext) = ('1', '20');
  for my $g (0 .. 19) {
    my $op = $g < 5 ? 'sha1c' : $g < 10 ? 'sha1p' : $g < 15 ? 'sha1m' : 'sha1p';
    push @o, "    // rounds " . (4 * $g) . ".." . (4 * $g + 3),
      "    add   v21.4s, $M[$g % 4].4s, v" . (16 + int($g / 5)) . ".4s",
      "    sha1h s$enext, s0",
      "    $op q0, s$ecur, v21.4s";
    if ($g < 16) {
      push @o, "    sha1su0 $M[$g % 4].4s, $M[($g + 1) % 4].4s, $M[($g + 2) % 4].4s",
               "    sha1su1 $M[$g % 4].4s, $M[($g + 3) % 4].4s";
    }
    ($ecur, $enext) = ($enext, $ecur);
  }
  die "e parity" unless $ecur eq '1';
  push @o,
    "    add   v0.4s, v0.4s, v2.4s",
    "    add   v1.4s, v1.4s, v3.4s",
    "    subs  x2, x2, #1",
    "    b.ne  1b",
    "    st1   {v0.4s}, [x0]",
    "    str   s1, [x0, #16]",
    "9:",
    "    ret";
}

# ======================================================================
# SHA-256 with the crypto extension
# v0 = ABCD, v1 = EFGH, v2/v3 = saved, v4..v7 = W, v8 = W+K, v9 = ABCD copy,
# v16..v31 = K (all 64 constants stay in registers)
# ======================================================================
{
  my @M = qw(v4 v5 v6 v7);
  push @o, func('fh_sha256_ce_asm', 'SHA-256, ARMv8 crypto: x0 = state, x1 = data, x2 = blocks');
  push @o, "    cbz   x2, 9f",
    "    stp   d8, d9, [sp, #-16]!",
    "    ld1   {v0.4s, v1.4s}, [x0]",
    "    adr   x9, Lk256",
    "    ld1   {v16.4s, v17.4s, v18.4s, v19.4s}, [x9], #64",
    "    ld1   {v20.4s, v21.4s, v22.4s, v23.4s}, [x9], #64",
    "    ld1   {v24.4s, v25.4s, v26.4s, v27.4s}, [x9], #64",
    "    ld1   {v28.4s, v29.4s, v30.4s, v31.4s}, [x9]",
    "1:",
    "    ld1   {v4.16b, v5.16b, v6.16b, v7.16b}, [x1], #64",
    (map { "    rev32 $_.16b, $_.16b" } @M),
    "    mov   v2.16b, v0.16b",
    "    mov   v3.16b, v1.16b";
  for my $g (0 .. 15) {
    push @o, "    // rounds " . (4 * $g) . ".." . (4 * $g + 3),
      "    add   v8.4s, $M[$g % 4].4s, v" . (16 + $g) . ".4s",
      "    mov   v9.16b, v0.16b",
      "    sha256h  q0, q1, v8.4s",
      "    sha256h2 q1, q9, v8.4s";
    if ($g < 12) {
      push @o, "    sha256su0 $M[$g % 4].4s, $M[($g + 1) % 4].4s",
               "    sha256su1 $M[$g % 4].4s, $M[($g + 2) % 4].4s, $M[($g + 3) % 4].4s";
    }
  }
  push @o,
    "    add   v0.4s, v0.4s, v2.4s",
    "    add   v1.4s, v1.4s, v3.4s",
    "    subs  x2, x2, #1",
    "    b.ne  1b",
    "    st1   {v0.4s, v1.4s}, [x0]",
    "    ldp   d8, d9, [sp], #16",
    "9:",
    "    ret";
}

# ======================================================================
# SHA-512 with the ARMv8.2 crypto extension (same scheme as the C version)
# v0..v3 = state (ab cd ef gh), S[0..4] = v4..v7,v16 (rotating roles),
# M[0..7] = v17..v24, temps v25 (kw) v26 (fg) v27 (de) v28 (w7),
# K ring v29..v31 (loaded two steps ahead), x9 = K pointer
# ======================================================================
{
  my @S = qw(v4 v5 v6 v7 v16);
  my @M = map { "v$_" } (17 .. 24);
  my @R = qw(v29 v30 v31);
  push @o, func('fh_sha512_ce_asm', 'SHA-512, ARMv8.2 crypto: x0 = state, x1 = data, x2 = blocks');
  push @o, "    cbz   x2, 9f",
    "    ld1   {v0.2d, v1.2d, v2.2d, v3.2d}, [x0]",
    "1:",
    "    ld1   {v17.16b, v18.16b, v19.16b, v20.16b}, [x1], #64",
    "    ld1   {v21.16b, v22.16b, v23.16b, v24.16b}, [x1], #64",
    (map { "    rev64 $_.16b, $_.16b" } @M),
    "    adr   x9, Lk512",
    "    ld1   {v29.2d}, [x9], #16",
    "    ld1   {v30.2d}, [x9], #16",
    "    mov   v4.16b, v0.16b", "    mov   v5.16b, v1.16b", "    mov   v6.16b, v2.16b", "    mov   v7.16b, v3.16b";
  my @r = (0, 1, 2, 3, 4);
  for my $j (0 .. 39) {
    my ($r0, $r1, $r2, $r3, $r4) = map { $S[$_] } @r;
    (my $q3 = $r3) =~ s/^v/q/;
    (my $q1 = $r1) =~ s/^v/q/;
    push @o, "    // rounds " . (2 * $j) . ".." . (2 * $j + 1);
    push @o, "    ld1   {" . $R[($j + 2) % 3] . ".2d}, [x9], #16" if $j + 2 < 40;
    # W+K for this step first, then this step's schedule update (it only
    # depends on M, so it overlaps the round chain), then the rounds
    push @o, "    add   v25.2d, " . $R[$j % 3] . ".2d, " . $M[$j & 7] . ".2d";
    if ($j < 32) {
      push @o,
        "    ext   v28.16b, " . $M[($j + 4) & 7] . ".16b, " . $M[($j + 5) & 7] . ".16b, #8",
        "    sha512su0 " . $M[$j & 7] . ".2d, " . $M[($j + 1) & 7] . ".2d",
        "    sha512su1 " . $M[$j & 7] . ".2d, " . $M[($j + 7) & 7] . ".2d, v28.2d";
    }
    push @o,
      "    ext   v25.16b, v25.16b, v25.16b, #8",
      "    ext   v26.16b, $r2.16b, $r3.16b, #8",
      "    ext   v27.16b, $r1.16b, $r2.16b, #8",
      "    add   $r3.2d, $r3.2d, v25.2d",
      "    sha512h  $q3, q26, v27.2d";
    push @o,
      "    add   $r4.2d, $r1.2d, $r3.2d",
      "    sha512h2 $q3, $q1, $r0.2d";
    @r = ($r[3], $r[0], $r[4], $r[2], $r[1]);
  }
  die "role parity" unless "@r" eq "0 1 2 3 4";
  push @o,
    "    add   v0.2d, v0.2d, v4.2d", "    add   v1.2d, v1.2d, v5.2d",
    "    add   v2.2d, v2.2d, v6.2d", "    add   v3.2d, v3.2d, v7.2d",
    "    subs  x2, x2, #1",
    "    b.ne  1b",
    "    st1   {v0.2d, v1.2d, v2.2d, v3.2d}, [x0]",
    "9:",
    "    ret";
}

# ======================================================================
# Bob Jenkins lookup3 hashlittle: w0 <- (x0 = data, w1 = len, w2 = initval)
# a = w9, b = w10, c = w11
# ======================================================================
push @o, func('fh_bobjenkins_asm', 'BobJenkins lookup3: x0 = data, w1 = len, w2 = initval -> w0'),
  movc32('w9', 0xDEADBEEF),
  "    add   w9, w9, w1",
  "    add   w9, w9, w2",
  "    mov   w10, w9",
  "    mov   w11, w9",
  "    cbz   w1, 8f",
  "    tbnz  w1, #31, 7f              // negative length: final mix only",
  "    cmp   w1, #12",
  "    b.le  3f",
  "2:",
  "    ldp   w12, w13, [x0]",
  "    ldr   w14, [x0, #8]",
  "    add   w9, w9, w12",
  "    add   w10, w10, w13",
  "    add   w11, w11, w14",
  # mix: x -= y; x ^= rol(y, k)  ==  sub, eor with ROR #(32-k)
  "    sub   w9, w9, w11",  "    eor   w9, w9, w11, ror #28",  "    add   w11, w11, w10",
  "    sub   w10, w10, w9", "    eor   w10, w10, w9, ror #26", "    add   w9, w9, w11",
  "    sub   w11, w11, w10", "    eor   w11, w11, w10, ror #24", "    add   w10, w10, w9",
  "    sub   w9, w9, w11",  "    eor   w9, w9, w11, ror #16",  "    add   w11, w11, w10",
  "    sub   w10, w10, w9", "    eor   w10, w10, w9, ror #13", "    add   w9, w9, w11",
  "    sub   w11, w11, w10", "    eor   w11, w11, w10, ror #28", "    add   w10, w10, w9",
  "    add   x0, x0, #12",
  "    sub   w1, w1, #12",
  "    cmp   w1, #12",
  "    b.gt  2b",
  "3:                                // 1..12 bytes left",
  "    cmp   w1, #12",
  "    b.ne  4f",
  "    ldp   w12, w13, [x0]",
  "    ldr   w14, [x0, #8]",
  "    b     6f",
  "4:                                // copy the tail into a zeroed 16-byte buffer",
  "    sub   sp, sp, #16",
  "    stp   xzr, xzr, [sp]",
  "    mov   x15, sp",
  "5:",
  "    ldrb  w12, [x0], #1",
  "    strb  w12, [x15], #1",
  "    subs  w1, w1, #1",
  "    b.ne  5b",
  "    ldp   w12, w13, [sp]",
  "    ldr   w14, [sp, #8]",
  "    add   sp, sp, #16",
  "6:",
  "    add   w9, w9, w12",
  "    add   w10, w10, w13",
  "    add   w11, w11, w14",
  "7:                                // final: x ^= y; x -= rol(y, k)",
  "    eor   w11, w11, w10", "    ror   w12, w10, #18", "    sub   w11, w11, w12",
  "    eor   w9, w9, w11",   "    ror   w12, w11, #21", "    sub   w9, w9, w12",
  "    eor   w10, w10, w9",  "    ror   w12, w9, #7",   "    sub   w10, w10, w12",
  "    eor   w11, w11, w10", "    ror   w12, w10, #16", "    sub   w11, w11, w12",
  "    eor   w9, w9, w11",   "    ror   w12, w11, #28", "    sub   w9, w9, w12",
  "    eor   w10, w10, w9",  "    ror   w12, w9, #18",  "    sub   w10, w10, w12",
  "    eor   w11, w11, w10", "    ror   w12, w10, #8",  "    sub   w11, w11, w12",
  "8:",
  "    mov   w0, w11",
  "    ret";

# ======================================================================
# FNV-1a: (x0 = data, w1 = len, w2/x2 = seed) -> w0/x0. Four bytes per
# iteration; the byte loads are off the xor-multiply dependency chain.
# ======================================================================
for my $wide (0, 1) {
  my $p = $wide ? 'x' : 'w';
  my $h = "${p}2";
  my @b = map { "${p}$_" } (11 .. 14);
  my @bl = map { "w$_" } (11 .. 14);
  push @o, func($wide ? 'fh_fnv1a64_asm' : 'fh_fnv1a32_asm',
                'FNV-1a ' . ($wide ? 64 : 32) . ": x0 = data, w1 = len, ${p}2 = seed -> ${p}0");
  if ($wide) {
    push @o, "    movz  x9, #0x01b3", "    movk  x9, #0x0100, lsl #32";
  } else {
    push @o, movc32('w9', 0x01000193);
  }
  push @o,
    "    lsr   w10, w1, #2",
    "    and   w1, w1, #3",
    "    cbz   w10, 3f",
    "2:",
    "    ldrb  $bl[0], [x0]", "    ldrb  $bl[1], [x0, #1]", "    ldrb  $bl[2], [x0, #2]", "    ldrb  $bl[3], [x0, #3]",
    "    add   x0, x0, #4",
    (map { ("    eor   $h, $h, $b[$_]", "    mul   $h, $h, ${p}9") } (0 .. 3)),
    "    subs  w10, w10, #1",
    "    b.ne  2b",
    "3:",
    "    cbz   w1, 5f",
    "4:",
    "    ldrb  $bl[0], [x0], #1",
    "    eor   $h, $h, $b[0]",
    "    mul   $h, $h, ${p}9",
    "    subs  w1, w1, #1",
    "    b.ne  4b",
    "5:",
    "    mov   ${p}0, $h",
    "    ret";
}

# ======================================================================
# Constant tables (in .text, reached with adr)
# ======================================================================
push @o, "", "    .p2align 4", "Lmd5_t:";
push @o, "    .word " . join(", ", map { h32($_) } @MD5T[$_ * 8 .. $_ * 8 + 7]) for 0 .. 7;
push @o, "    .p2align 4", "Lk256:";
push @o, "    .word " . join(", ", map { h32($_) } @K256[$_ * 8 .. $_ * 8 + 7]) for 0 .. 7;
push @o, "    .p2align 4", "Lk512:";
push @o, "    .quad " . join(", ", map { "0x$_" } @K512[$_ * 4 .. $_ * 4 + 3]) for 0 .. 19;
push @o, "";

open(my $fh, '>', $out) or die "$out: $!";
print $fh join("\n", @o);
close $fh;
print "wrote $out\n";

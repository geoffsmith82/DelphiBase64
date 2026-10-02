#!/usr/bin/perl
# Generates Asm\SHA512.x86.inc and Asm\SHA512.x64.inc (SHA-384, SHA-512,
# SHA-512/224, SHA-512/256):
#
#   SHA512CompressScalar  SSE2 message schedule (two words per xmm) into a
#                         W+K table, then the 80 rounds:
#                           Win64: 64-bit integer registers
#                           Win32: 64-bit lanes of SSE2 xmm registers (32-bit
#                                  integer code would need add/adc pairs)
#   SHA512CompressAVX2    two blocks' schedule computed together in ymm
#                         registers (block A low lane, block B high lane), then
#                           Win64: BMI1/BMI2 (andn/rorx) rounds
#                           Win32: VEX-encoded xmm rounds (no register copies)
#
#   procedure X(State: Pointer; Data: PByte; Blocks: NativeUInt);
#
# State is 8 UInt64 (A..H). Win32 keeps A, E, T1 and Maj's carried (a xor b)
# in xmm registers and the other variables in a 16-byte-slot ring on the
# stack whose slot names rotate with the round number.
#
# Constant pool SHA512Consts (64-byte aligned, used by the SSE2 schedule):
#   +0     K, plain 80 words (640 bytes)
#
# Run from the Hash folder:  perl Tools\gen_sha512.pl
use strict;
use warnings;
use FindBin;

my $out_dir = "$FindBin::Bin/../Asm";

# ---------------------------------------------------------------------------
# Win64 integer rounds. $r: v => [a..h], t0, t1, x, bmi (bool),
#   wk => sub(i) memory operand of W[i]+K[i].
# ---------------------------------------------------------------------------
sub rounds64 {
  my ($r) = @_;
  my @v = @{ $r->{v} };
  my ($t0, $t1, $x) = @{$r}{qw(t0 t1 x)};
  my @o;
  for my $i (0 .. 79) {
    my ($a, $b, $c, $d, $e, $f, $g, $h) = @v;
    push @o, "    // round $i", "    add   $h, " . $r->{wk}->($i);
    # Ch is added before Sigma1 to keep the e -> new e chain short
    if ($r->{bmi}) {
      push @o, "    andn  $t0, $e, $g", "    mov   $t1, $e", "    and   $t1, $f",
               "    add   $h, $t0", "    add   $h, $t1",
               "    rorx  $t0, $e, 14", "    rorx  $t1, $e, 18", "    xor   $t0, $t1",
               "    rorx  $t1, $e, 41", "    xor   $t0, $t1", "    add   $h, $t0",
               "    add   $d, $h";
      push @o, $r->{extra}->($i) if $r->{extra};
      push @o, "    rorx  $t0, $a, 28", "    rorx  $t1, $a, 34", "    xor   $t0, $t1",
               "    rorx  $t1, $a, 39", "    xor   $t0, $t1", "    add   $h, $t0";
    } else {
      push @o, "    mov   $t1, $f", "    xor   $t1, $g", "    and   $t1, $e", "    xor   $t1, $g",
               "    add   $h, $t1",
               "    mov   $t0, $e", "    ror   $t0, 23", "    xor   $t0, $e", "    ror   $t0, 4",
               "    xor   $t0, $e", "    ror   $t0, 14", "    add   $h, $t0",
               "    add   $d, $h",
               "    mov   $t0, $a", "    ror   $t0, 5", "    xor   $t0, $a", "    ror   $t0, 6",
               "    xor   $t0, $a", "    ror   $t0, 28", "    add   $h, $t0";
    }
    push @o, "    mov   $t1, $a", "    xor   $t1, $b", "    and   $x, $t1", "    xor   $x, $b",
             "    add   $h, $x";
    ($x, $t1) = ($t1, $x);
    @v = ($h, $a, $b, $c, $d, $e, $f, $g);
  }
  die "x/t1 parity" unless $x eq $r->{x};
  return @o;
}

# ---------------------------------------------------------------------------
# Win32 xmm rounds. Registers: A, E, T (=T1), X (carried a xor b), t4..t6.
# A and T swap names every round. $r: ring (frame offset of the 16-byte-slot
# ring), wk => sub(i) memory operand of the 8-byte W[i]+K[i], vex (bool).
# ---------------------------------------------------------------------------
sub rounds32 {
  my ($r) = @_;
  my $ring = $r->{ring};
  my $vex = $r->{vex};
  my ($A, $E, $T, $X, $t4, $t5, $t6) = map { "xmm$_" } (0 .. 6);
  # helpers for two-operand vs three-operand forms
  my $sh = sub {   # $dst = $src shifted by $n ($op = 'psrlq' / 'psllq')
    my ($op, $dst, $src, $n) = @_;
    return $vex ? ("    v$op      $dst, $src, $n")
                : ($dst eq $src ? () : ("    movdqa      $dst, $src"), "    $op       $dst, $n");
  };
  my $op2 = sub {  # $dst = $dst op $src
    my ($op, $dst, $src) = @_;
    return $vex ? ("    v$op       $dst, $dst, $src") : ("    $op        $dst, $src");
  };
  my $mov = sub {
    my ($dst, $src) = @_;
    return $vex ? ("    vmovdqa     $dst, $src") : ("    movdqa      $dst, $src");
  };
  my $movq = $vex ? 'vmovq' : 'movq ';
  my @o;
  for my $i (0 .. 79) {
    my $S = sub { "dqword ptr [esp + " . ($ring + 16 * (($_[0] - $i) % 8)) . "]" };
    my ($sa, $sb, $sd, $se, $sf, $sg, $sh_) = map { $S->($_) } (0, 1, 3, 4, 5, 6, 7);
    push @o, "    // round $i";
    push @o, "    $movq       $T, " . $r->{wk}->($i);
    push @o, $op2->('paddq', $T, $sh_);
    # Ch first, then Sigma1, to keep the e -> new e chain short
    # Ch = ((f xor g) and e) xor g
    push @o, $mov->($t4, $sf), $op2->('pxor', $t4, $sg), $op2->('pand', $t4, $E),
             $op2->('pxor', $t4, $sg), $op2->('paddq', $T, $t4);
    # Sigma1(E) = ror14 ^ ror18 ^ ror41
    push @o, $sh->('psrlq', $t4, $E, 14), $sh->('psllq', $t5, $E, 23);
    push @o, $vex ? ("    vpxor       $t6, $t4, $t5") : ($mov->($t6, $t4), $op2->('pxor', $t6, $t5));
    push @o, $sh->('psrlq', $t4, $t4, 4), $op2->('pxor', $t6, $t4),
             $sh->('psllq', $t5, $t5, 23), $op2->('pxor', $t6, $t5),
             $sh->('psrlq', $t4, $t4, 23), $op2->('pxor', $t6, $t4),
             $sh->('psllq', $t5, $t5, 4), $op2->('pxor', $t6, $t5),
             $op2->('paddq', $T, $t6);
    # f <- e ; E <- d + T1
    push @o, $mov->($se, $E), $mov->($E, $sd), $op2->('paddq', $E, $T);
    # Sigma0(A) = ror28 ^ ror34 ^ ror39
    push @o, $sh->('psrlq', $t4, $A, 28), $sh->('psllq', $t5, $A, 25);
    push @o, $vex ? ("    vpxor       $t6, $t4, $t5") : ($mov->($t6, $t4), $op2->('pxor', $t6, $t5));
    push @o, $sh->('psrlq', $t4, $t4, 6), $op2->('pxor', $t6, $t4),
             $sh->('psllq', $t5, $t5, 5), $op2->('pxor', $t6, $t5),
             $sh->('psrlq', $t4, $t4, 5), $op2->('pxor', $t6, $t4),
             $sh->('psllq', $t5, $t5, 6), $op2->('pxor', $t6, $t5),
             $op2->('paddq', $T, $t6);
    # Maj = b xor ((a xor b) and (b xor c)); X holds b xor c
    push @o, $mov->($t4, $A), $op2->('pxor', $t4, $sb), $op2->('pand', $X, $t4),
             $op2->('pxor', $X, $sb), $op2->('paddq', $T, $X);
    # b <- a ; A <- T1  (by renaming)
    push @o, $mov->($sa, $A);
    ($X, $t4) = ($t4, $X);
    ($A, $T) = ($T, $A);
  }
  die "rename parity" unless $A eq 'xmm0' && $X eq 'xmm3';
  return @o;
}

sub load32 {   # state -> A (xmm0), E (xmm1), ring, X (xmm3)
  my ($ring, $stslot, $vex) = @_;
  my ($movq, $movdqa, $pxor) = $vex ? ('vmovq', 'vmovdqa', 'vpxor  xmm3, xmm3,') : ('movq ', 'movdqa ', 'pxor   xmm3,');
  my @o = ("    mov   esi, [esp + $stslot]",
           "    $movq       xmm0, [esi]",
           "    $movq       xmm1, [esi + 32]",
           "    $movq       xmm3, [esi + 8]",
           "    $movq       xmm4, [esi + 16]",
           "    $pxor xmm4");
  for my $v (1, 2, 3, 5, 6, 7) {
    push @o, "    $movq       xmm4, [esi + " . (8 * $v) . "]",
             "    $movdqa     [esp + " . ($ring + 16 * $v) . "], xmm4";
  }
  return @o;
}
sub store32 {   # A, E -> ring; state += ring
  my ($ring, $stslot, $vex) = @_;
  my ($movq, $movdqa, $paddq) = $vex ? ('vmovq', 'vmovdqa', 'vpaddq xmm4, xmm4,') : ('movq ', 'movdqa ', 'paddq  xmm4,');
  my @o = ("    $movdqa     [esp + $ring], xmm0",
           "    $movdqa     [esp + " . ($ring + 64) . "], xmm1",
           "    mov   esi, [esp + $stslot]");
  for my $v (0 .. 7) {
    push @o, "    $movq       xmm4, [esi + " . (8 * $v) . "]",
             "    $paddq [esp + " . ($ring + 16 * $v) . "]",
             "    $movq       [esi + " . (8 * $v) . "], xmm4";
  }
  return @o;
}

# ---------------------------------------------------------------------------
# SSE2 single-block schedule. $B = base register, W at +$w (640 bytes, 16-byte
# aligned, words 0..15 already byte-swapped), WK at +$wk, $CP = const pool.
# Uses xmm0..xmm4.
# ---------------------------------------------------------------------------
sub sse2_schedule {
  my ($B, $w, $wk, $CP) = @_;
  my $W = sub { "dqword ptr [$B + " . ($w + 16 * $_[0]) . "]" };
  my $WK = sub { "dqword ptr [$B + " . ($wk + 16 * $_[0]) . "]" };
  my $KP = sub { "dqword ptr [$CP + " . (16 * $_[0]) . "]" };
  my @o = ("    // SSE2 message schedule");
  for my $g (0 .. 7) {
    push @o, "    movdqa      xmm0, " . $W->($g), "    paddq       xmm0, " . $KP->($g),
             "    movdqa      " . $WK->($g) . ", xmm0";
  }
  for my $g (8 .. 39) {
    push @o,
      "    movdqa      xmm0, " . $W->($g - 8),
      "    shufpd      xmm0, " . $W->($g - 7) . ", 1",          # W[i-15], W[i-14]
      "    movdqa      xmm1, xmm0", "    psrlq       xmm1, 1",
      "    movdqa      xmm2, xmm0", "    psllq       xmm2, 56",
      "    movdqa      xmm3, xmm1", "    pxor        xmm3, xmm2",
      "    psrlq       xmm1, 6", "    pxor        xmm3, xmm1",
      "    psrlq       xmm1, 1", "    pxor        xmm3, xmm1",
      "    psllq       xmm2, 7", "    pxor        xmm3, xmm2",       # sigma0
      "    movdqa      xmm0, " . $W->($g - 1),                       # W[i-2], W[i-1]
      "    movdqa      xmm1, xmm0", "    psrlq       xmm1, 6",
      "    movdqa      xmm2, xmm0", "    psllq       xmm2, 3",
      "    movdqa      xmm4, xmm1", "    pxor        xmm4, xmm2",
      "    psrlq       xmm1, 13", "    pxor        xmm4, xmm1",
      "    psllq       xmm2, 42", "    pxor        xmm4, xmm2",
      "    psrlq       xmm1, 42", "    pxor        xmm4, xmm1",       # sigma1
      "    paddq       xmm3, xmm4",
      "    movdqa      xmm0, " . $W->($g - 4),
      "    shufpd      xmm0, " . $W->($g - 3) . ", 1",          # W[i-7], W[i-6]
      "    paddq       xmm3, xmm0",
      "    paddq       xmm3, " . $W->($g - 8);
    push @o, "    movdqa      " . $W->($g) . ", xmm3" if $g <= 38;
    push @o, "    paddq       xmm3, " . $KP->($g), "    movdqa      " . $WK->($g) . ", xmm3";
  }
  return @o;
}

# ---------------------------------------------------------------------------
# AVX2 two-block schedule. Frame: WK at +0 (1280 bytes), raw W at +1280.
# Constants are the named 32-byte rows SHA512_BSWAP and SHA512_KD0..39
# (emitted by consts()), so no register is needed for them.
# Returns (\@prelude, \@groups): the prelude loads groups 0..7 from the data;
# $groups[g] (g = 8..39) computes words 2g, 2g+1 of both blocks.
# ---------------------------------------------------------------------------
sub avx2_schedule {
  my ($r) = @_;
  my ($B, $DA, $DB) = @{$r}{qw(base da db)};
  my $WK = sub { "[$B + " . (32 * $_[0]) . "]" };
  my $WR = sub { "[$B + " . (1280 + 32 * $_[0]) . "]" };
  my $KK = sub { "[SHA512_KD$_[0]]" };
  my @pre = ("    // message schedule, groups 0..7 of both blocks");
  for my $g (0 .. 7) {
    push @pre, "    vmovdqu     xmm0, [$DA + " . (16 * $g) . "]",
               "    vinserti128 ymm0, ymm0, [$DB + " . (16 * $g) . "], 1",
               "    vpshufb     ymm0, ymm0, [SHA512_BSWAP]",
               "    vmovdqu     " . $WR->($g) . ", ymm0",
               "    vpaddq      ymm1, ymm0, " . $KK->($g),
               "    vmovdqu     " . $WK->($g) . ", ymm1";
  }
  my @groups;
  for my $g (8 .. 39) {
    my @o = ("    // schedule group $g");
    push @o,
      "    vmovdqu     ymm0, " . $WR->($g - 7),
      "    vpalignr    ymm0, ymm0, " . $WR->($g - 8) . ", 8",       # W[i-15], W[i-14]
      "    vpsrlq      ymm1, ymm0, 1",
      "    vpsllq      ymm2, ymm0, 56",
      "    vpxor       ymm3, ymm1, ymm2",
      "    vpsrlq      ymm1, ymm1, 6", "    vpxor       ymm3, ymm3, ymm1",
      "    vpsrlq      ymm1, ymm1, 1", "    vpxor       ymm3, ymm3, ymm1",
      "    vpsllq      ymm2, ymm2, 7", "    vpxor       ymm3, ymm3, ymm2",   # sigma0
      "    vmovdqu     ymm0, " . $WR->($g - 1),
      "    vpsrlq      ymm1, ymm0, 6",
      "    vpsllq      ymm2, ymm0, 3",
      "    vpxor       ymm4, ymm1, ymm2",
      "    vpsrlq      ymm1, ymm1, 13", "    vpxor       ymm4, ymm4, ymm1",
      "    vpsllq      ymm2, ymm2, 42", "    vpxor       ymm4, ymm4, ymm2",
      "    vpsrlq      ymm1, ymm1, 42", "    vpxor       ymm4, ymm4, ymm1",   # sigma1
      "    vpaddq      ymm3, ymm3, ymm4",
      "    vmovdqu     ymm0, " . $WR->($g - 3),
      "    vpalignr    ymm0, ymm0, " . $WR->($g - 4) . ", 8",       # W[i-7], W[i-6]
      "    vpaddq      ymm3, ymm3, ymm0",
      "    vpaddq      ymm3, ymm3, " . $WR->($g - 8);
    push @o, "    vmovdqu     " . $WR->($g) . ", ymm3" if $g <= 38;
    push @o, "    vpaddq      ymm1, ymm3, " . $KK->($g),
             "    vmovdqu     " . $WK->($g) . ", ymm1";
    $groups[$g] = \@o;
  }
  return (\@pre, \@groups);
}

# Spreads schedule group g over the $per rounds starting at
# $per * (g - $first) of block A: returns a callback giving the lines for round i.
sub interleave {
  my ($groups, $first, $per) = @_;
  return sub {
    my $i = shift;
    my $g = $first + int($i / $per);
    return () unless defined $groups->[$g];
    my @lines = @{ $groups->[$g] };
    my $n = scalar @lines;
    my $k = $i % $per;
    return @lines[int($n * $k / $per) .. int($n * ($k + 1) / $per) - 1];
  };
}

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
die "K512 count" unless @K512 == 80;

# The 32-byte constant rows used by the AVX2 code (VEX operands need no alignment).
sub consts {
  my @o = ("const");
  my @bs = map { (($_ & ~7) + 7 - ($_ & 7)) } (0 .. 31);
  push @o, "  SHA512_BSWAP: array[0..31] of Byte = (" . join(", ", @bs) . ");";
  for my $g (0 .. 39) {
    my @k = map { '$' . uc($K512[2 * $g + $_]) } (0 .. 1);
    push @o, "  SHA512_KD$g: array[0..3] of UInt64 = (" . join(", ", @k, @k) . ");";
  }
  return (@o, "");
}

sub wk2 {   # two-block WK operand
  my ($base, $lane) = @_;
  return sub { my $i = shift; "qword ptr [$base + " . (32 * ($i >> 1) + 16 * $lane + 8 * ($i & 1)) . "]" };
}
sub wk1 {   # single-block WK operand
  my ($base, $off) = @_;
  return sub { my $i = shift; "qword ptr [$base + " . ($off + 8 * $i) . "]" };
}

my (@x64, @x86);

# ============================ Scalar, Win64 ============================
# rdi = frame (W +0, WK +640, State +1280, End +1288), rsi = data.
# a..h = rax rbx rcx rdx r8 r9 r10 r11; t0 = r12, t1 = r13, x = r15.
{
  push @x64,
    "procedure SHA512CompressScalar(State: Pointer; Data: PByte; Blocks: NativeUInt);",
    "var",
    "  Frame: array[0..1311] of Byte;",
    "asm",
    "    // rcx = State, rdx = Data, r8 = Blocks",
    "    .PUSHNV rbx", "    .PUSHNV rsi", "    .PUSHNV rdi", "    .PUSHNV r12", "    .PUSHNV r13",
    "    .PUSHNV r15",
    "    test  r8, r8",
    "    jz    \@done",
    "    lea   rdi, Frame",
    "    add   rdi, 15",
    "    and   rdi, -16",
    "    mov   [rdi + 1280], rcx",
    "    mov   rsi, rdx",
    "    shl   r8, 7",
    "    add   r8, rsi",
    "    mov   [rdi + 1288], r8",
    "\@block:";
  for my $k (0 .. 15) {
    push @x64, "    mov   r12, [rsi + " . (8 * $k) . "]", "    bswap r12", "    mov   [rdi + " . (8 * $k) . "], r12";
  }
  push @x64, "    mov   r12, [SHA512Consts]";
  push @x64, sse2_schedule('rdi', 0, 640, 'r12');
  push @x64,
    "    mov   r15, [rdi + 1280]",
    "    mov   rax, [r15]", "    mov   rbx, [r15 + 8]", "    mov   rcx, [r15 + 16]", "    mov   rdx, [r15 + 24]",
    "    mov   r8, [r15 + 32]", "    mov   r9, [r15 + 40]", "    mov   r10, [r15 + 48]", "    mov   r11, [r15 + 56]",
    "    mov   r15, rbx",
    "    xor   r15, rcx";
  push @x64, rounds64({ v => [qw(rax rbx rcx rdx r8 r9 r10 r11)], t0 => 'r12', t1 => 'r13', x => 'r15',
                        bmi => 0, wk => wk1('rdi', 640) });
  push @x64,
    "    mov   r15, [rdi + 1280]",
    "    add   [r15], rax", "    add   [r15 + 8], rbx", "    add   [r15 + 16], rcx", "    add   [r15 + 24], rdx",
    "    add   [r15 + 32], r8", "    add   [r15 + 40], r9", "    add   [r15 + 48], r10", "    add   [r15 + 56], r11",
    "    add   rsi, 128",
    "    cmp   rsi, [rdi + 1288]",
    "    jb    \@block",
    "\@done:",
    "end;", "";
}

# ============================ Scalar, Win32 ============================
# Frame (16-byte aligned): W +0 (640), WK +640 (640), ring +1280 (128),
# State +1408, Data +1412, End +1416, saved esp +1420.
{
  push @x86,
    "procedure SHA512CompressScalar(State: Pointer; Data: PByte; Blocks: NativeUInt);",
    "asm",
    "    // eax = State, edx = Data, ecx = Blocks",
    "    test  ecx, ecx",
    "    jz    \@exit",
    "    push  ebx", "    push  esi", "    push  edi", "    push  ebp",
    "    mov   ebp, esp",
    "    sub   esp, 1440",
    "    and   esp, -16",
    "    mov   [esp + 1420], ebp",
    "    mov   [esp + 1408], eax",
    "    mov   [esp + 1412], edx",
    "    shl   ecx, 7",
    "    add   ecx, edx",
    "    mov   [esp + 1416], ecx",
    "\@block:",
    "    mov   esi, [esp + 1412]";
  for my $k (0 .. 15) {
    push @x86, "    mov   ecx, [esi + " . (8 * $k) . "]", "    mov   edx, [esi + " . (8 * $k + 4) . "]",
               "    bswap ecx", "    bswap edx",
               "    mov   [esp + " . (8 * $k) . "], edx", "    mov   [esp + " . (8 * $k + 4) . "], ecx";
  }
  push @x86, "    mov   eax, [SHA512Consts]";
  push @x86, sse2_schedule('esp', 0, 640, 'eax');
  push @x86, load32(1280, 1408, 0);
  push @x86, rounds32({ ring => 1280, wk => wk1('esp', 640), vex => 0 });
  push @x86, store32(1280, 1408, 0);
  push @x86,
    "    add   dword ptr [esp + 1412], 128",
    "    mov   ecx, [esp + 1412]",
    "    cmp   ecx, [esp + 1416]",
    "    jb    \@block",
    "    mov   esp, [esp + 1420]",
    "    pop   ebp", "    pop   edi", "    pop   esi", "    pop   ebx",
    "\@exit:",
    "end;", "";
}

# ============================ AVX2, Win64 ============================
# rbx = frame (WK +0, W +1280, DataA +2560, End +2568, DataB +2576), rdi = State.
# a..h = rax rcx rdx rsi r8 r9 r10 r11; t0 = r12, t1 = r13, x = r15.
{
  my @v = qw(rax rcx rdx rsi r8 r9 r10 r11);
  my @load = ("    mov   rax, [rdi]", "    mov   rcx, [rdi + 8]", "    mov   rdx, [rdi + 16]", "    mov   rsi, [rdi + 24]",
              "    mov   r8, [rdi + 32]", "    mov   r9, [rdi + 40]", "    mov   r10, [rdi + 48]", "    mov   r11, [rdi + 56]");
  my @addstore = ("    add   rax, [rdi]", "    add   rcx, [rdi + 8]", "    add   rdx, [rdi + 16]", "    add   rsi, [rdi + 24]",
                  "    add   r8, [rdi + 32]", "    add   r9, [rdi + 40]", "    add   r10, [rdi + 48]", "    add   r11, [rdi + 56]",
                  "    mov   [rdi], rax", "    mov   [rdi + 8], rcx", "    mov   [rdi + 16], rdx", "    mov   [rdi + 24], rsi",
                  "    mov   [rdi + 32], r8", "    mov   [rdi + 40], r9", "    mov   [rdi + 48], r10", "    mov   [rdi + 56], r11");
  push @x64,
    "procedure SHA512CompressAVX2(State: Pointer; Data: PByte; Blocks: NativeUInt);",
    "var",
    "  Frame: array[0..2623] of Byte;",
    "asm",
    "    // rcx = State, rdx = Data, r8 = Blocks",
    "    .PUSHNV rbx", "    .PUSHNV rsi", "    .PUSHNV rdi", "    .PUSHNV r12", "    .PUSHNV r13",
    "    .PUSHNV r15",
    "    test  r8, r8",
    "    jz    \@done",
    "    lea   rbx, Frame",
    "    add   rbx, 31",
    "    and   rbx, -32",
    "    mov   rdi, rcx",
    "    mov   [rbx + 2560], rdx",
    "    shl   r8, 7",
    "    add   r8, rdx",
    "    mov   [rbx + 2568], r8",
    "\@loop:",
    "    mov   rsi, [rbx + 2560]",
    "    mov   rdx, [rbx + 2568]",
    "    sub   rdx, rsi",
    "    cmp   rdx, 256",
    "    mov   rdx, rsi",
    "    jb    \@one",
    "    add   rdx, 128",
    "\@one:",
    "    mov   [rbx + 2576], rdx",
    "    // (schedule groups 8..39 are interleaved with block A's rounds)";
  my ($pre, $groups) = avx2_schedule({ base => 'rbx', da => 'rsi', db => 'rdx' });
  push @x64, @$pre;
  push @x64, @load, "    mov   r15, rcx", "    xor   r15, rdx";
  push @x64, rounds64({ v => \@v, t0 => 'r12', t1 => 'r13', x => 'r15', bmi => 1, wk => wk2('rbx', 0),
                        extra => interleave($groups, 8, 2) });
  push @x64, @addstore,
    "    mov   r12, [rbx + 2576]",
    "    cmp   r12, [rbx + 2560]",
    "    je    \@single",
    "    mov   r15, rcx",
    "    xor   r15, rdx";
  push @x64, rounds64({ v => \@v, t0 => 'r12', t1 => 'r13', x => 'r15', bmi => 1, wk => wk2('rbx', 1) });
  push @x64, @addstore,
    "    add   qword ptr [rbx + 2560], 256",
    "    jmp   \@next",
    "\@single:",
    "    add   qword ptr [rbx + 2560], 128",
    "\@next:",
    "    mov   r12, [rbx + 2560]",
    "    cmp   r12, [rbx + 2568]",
    "    jb    \@loop",
    "    vzeroupper",
    "\@done:",
    "end;", "";
}

# ============================ AVX2, Win32 ============================
# Frame (32-byte aligned): WK +0 (1280), W +1280 (1280), ring +2560 (128),
# State +2688, DataA +2692, End +2696, DataB +2700, saved esp +2704.
{
  push @x86,
    "procedure SHA512CompressAVX2(State: Pointer; Data: PByte; Blocks: NativeUInt);",
    "asm",
    "    // eax = State, edx = Data, ecx = Blocks",
    "    test  ecx, ecx",
    "    jz    \@exit",
    "    push  ebx", "    push  esi", "    push  edi", "    push  ebp",
    "    mov   ebp, esp",
    "    sub   esp, 2752",
    "    and   esp, -32",
    "    mov   [esp + 2704], ebp",
    "    mov   [esp + 2688], eax",
    "    mov   [esp + 2692], edx",
    "    shl   ecx, 7",
    "    add   ecx, edx",
    "    mov   [esp + 2696], ecx",
    "\@loop:",
    "    mov   edi, [esp + 2692]",
    "    mov   ebp, [esp + 2696]",
    "    sub   ebp, edi",
    "    cmp   ebp, 256",
    "    mov   ebp, edi",
    "    jb    \@one",
    "    add   ebp, 128",
    "\@one:",
    "    mov   [esp + 2700], ebp",
    "    // (the rounds use xmm0..6, so the whole schedule runs first here)";
  my ($pre, $groups) = avx2_schedule({ base => 'esp', da => 'edi', db => 'ebp' });
  push @x86, @$pre, map { @{ $groups->[$_] } } (8 .. 39);
  push @x86, load32(2560, 2688, 1);
  push @x86, rounds32({ ring => 2560, wk => wk2('esp', 0), vex => 1 });
  push @x86, store32(2560, 2688, 1);
  push @x86,
    "    mov   ecx, [esp + 2700]",
    "    cmp   ecx, [esp + 2692]",
    "    je    \@single";
  push @x86, load32(2560, 2688, 1);
  push @x86, rounds32({ ring => 2560, wk => wk2('esp', 1), vex => 1 });
  push @x86, store32(2560, 2688, 1);
  push @x86,
    "    add   dword ptr [esp + 2692], 256",
    "    jmp   \@next",
    "\@single:",
    "    add   dword ptr [esp + 2692], 128",
    "\@next:",
    "    mov   ecx, [esp + 2692]",
    "    cmp   ecx, [esp + 2696]",
    "    jb    \@loop",
    "    vzeroupper",
    "    mov   esp, [esp + 2704]",
    "    pop   ebp", "    pop   edi", "    pop   esi", "    pop   ebx",
    "\@exit:",
    "end;", "";
}

write_file("$out_dir/SHA512.x64.inc", "// GENERATED by Tools\\gen_sha512.pl - do not edit by hand.", "", consts(), @x64);
write_file("$out_dir/SHA512.x86.inc", "// GENERATED by Tools\\gen_sha512.pl - do not edit by hand.", "", consts(), @x86);

sub write_file {
  my ($name, @lines) = @_;
  open(my $fh, '>:crlf', $name) or die "$name: $!";
  print $fh join("\n", @lines);
  close $fh;
  print "wrote $name\n";
}

#!/usr/bin/perl
# Generates Asm\SHA256.x86.inc and Asm\SHA256.x64.inc (SHA-224 and SHA-256):
#
#   SHA256CompressScalar  unrolled integer rounds, 16-word circular schedule
#   SHA256CompressAVX2    two blocks' W+K schedule computed together in ymm
#                         registers (block A low lane, block B high lane),
#                         then BMI1/BMI2 (andn/rorx) rounds
#   SHA256CompressSHANI   Intel SHA extensions (sha256rnds2/msg1/msg2)
#
#   procedure X(State: Pointer; Data: PByte; Blocks: NativeUInt);
#
# State is 8 Cardinals (A..H). Win64 keeps all eight in registers; Win32 has
# only seven, so it keeps A and E in registers and the other six in an
# 8-slot ring on the stack whose slot names rotate with the round number
# (no data moves between rounds).
#
# Constant pool SHA256Consts (64-byte aligned, used by the SHA-NI code):
#   +0    per-dword byte swap mask (16 bytes)
#   +16   K, plain 64 words (256 bytes)
#
# Run from the Hash folder:  perl Tools\gen_sha256.pl
use strict;
use warnings;
use FindBin;

my $out_dir = "$FindBin::Bin/../Asm";

my @K = (
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
);
sub hex32 { sprintf('$%08X', $_[0]) }

# ---------------------------------------------------------------------------
# Win64 rounds, all state in registers. $r: v => [a..h], t0, t1, t2, x,
#   w => sub(i) code leaving W[i] (scalar) in t0   (undef for the BMI variant)
#   wk => sub(i) memory operand of W[i]+K[i]        (BMI variant)
# x holds the previous round's (a xor b) == this round's (b xor c), so
#   Maj(a,b,c) = b xor ((a xor b) and (b xor c)).
# ---------------------------------------------------------------------------
sub rounds64 {
  my ($r) = @_;
  my @v = @{ $r->{v} };
  my ($t0, $t1, $t2, $x) = @{$r}{qw(t0 t1 t2 x)};
  my $bmi = defined $r->{wk};
  my @o;
  for my $i (0 .. 63) {
    my ($a, $b, $c, $d, $e, $f, $g, $h) = @v;
    push @o, "    // round $i";
    # T1 = h + W+K + Ch(e,f,g) + Sigma1(e). Ch is added before Sigma1 so the
    # e -> new e dependency chain is as short as possible.
    if ($bmi) {
      push @o, "    add   $h, " . $r->{wk}->($i),
               "    andn  $t0, $e, $g", "    mov   $t1, $e", "    and   $t1, $f",
               "    add   $h, $t0", "    add   $h, $t1",
               "    rorx  $t0, $e, 6", "    rorx  $t1, $e, 11", "    xor   $t0, $t1",
               "    rorx  $t1, $e, 25", "    xor   $t0, $t1", "    add   $h, $t0",
               "    add   $d, $h";
      push @o, $r->{extra}->($i) if $r->{extra};
      push @o, "    rorx  $t0, $a, 2", "    rorx  $t1, $a, 13", "    xor   $t0, $t1",
               "    rorx  $t1, $a, 22", "    xor   $t0, $t1", "    add   $h, $t0";
    } else {
      push @o, $r->{w}->($i, $t0, $t1, $t2);
      push @o, "    add   $h, $t0", "    add   $h, " . hex32($K[$i]),
               "    mov   $t1, $f", "    xor   $t1, $g", "    and   $t1, $e", "    xor   $t1, $g",
               "    add   $h, $t1",
               "    mov   $t0, $e", "    ror   $t0, 14", "    xor   $t0, $e", "    ror   $t0, 5",
               "    xor   $t0, $e", "    ror   $t0, 6", "    add   $h, $t0",
               "    add   $d, $h",
               "    mov   $t0, $a", "    ror   $t0, 9", "    xor   $t0, $a", "    ror   $t0, 11",
               "    xor   $t0, $a", "    ror   $t0, 2", "    add   $h, $t0";
    }
    push @o, "    mov   $t1, $a", "    xor   $t1, $b", "    and   $x, $t1", "    xor   $x, $b",
             "    add   $h, $x";
    ($x, $t1) = ($t1, $x);
    @v = ($h, $a, $b, $c, $d, $e, $f, $g);
  }
  die "x/t1 parity" unless $x eq $r->{x};
  return @o;
}

# Scalar schedule step for Win64: leaves W[i] in t0 and stores it.
sub sched64 {
  my ($i, $W, $data, $t0, $t1, $t2) = @_;
  if ($i < 16) {
    return ("    mov   $t0, [$data + " . (4 * $i) . "]", "    bswap $t0", "    mov   " . $W->($i) . ", $t0");
  }
  my @o = ("    mov   $t1, " . $W->(($i - 15) & 15), "    mov   $t2, $t1", "    ror   $t1, 7",
           "    shr   $t2, 3", "    xor   $t2, $t1", "    ror   $t1, 11", "    xor   $t2, $t1",
           "    mov   $t1, " . $W->(($i - 2) & 15), "    mov   $t0, $t1", "    ror   $t1, 17",
           "    shr   $t0, 10", "    xor   $t0, $t1", "    ror   $t1, 2", "    xor   $t0, $t1",
           "    add   $t0, $t2", "    add   $t0, " . $W->(($i - 7) & 15),
           "    add   $t0, " . $W->($i & 15));
  push @o, "    mov   " . $W->($i & 15) . ", $t0" if $i + 2 <= 63;
  return @o;
}

# ---------------------------------------------------------------------------
# Win32 rounds: eax = A, ebx = E, ebp = T1, edi = x, ecx/edx/esi temps.
# Ring slot of variable v (0=a..7=h) at round i: $ring + 4*((v - i) mod 8).
# $r: ring (offset), w => sub(i) code leaving W[i] (scalar) in ebp, or
#     wk => sub(i) memory operand of W[i]+K[i].
# ---------------------------------------------------------------------------
sub rounds32 {
  my ($r) = @_;
  my $ring = $r->{ring};
  my $bmi = defined $r->{wk};
  my @o;
  for my $i (0 .. 63) {
    my $S = sub { "dword ptr [esp + " . ($ring + 4 * (($_[0] - $i) % 8)) . "]" };
    my ($sa, $sb, $sd, $se, $sf, $sg, $sh) = map { $S->($_) } (0, 1, 3, 4, 5, 6, 7);
    push @o, "    // round $i";
    if ($bmi) {
      push @o, "    mov   ebp, " . $r->{wk}->($i), "    add   ebp, $sh",
               "    andn  ecx, ebx, $sg", "    mov   edx, $sf", "    and   edx, ebx",
               "    add   ebp, ecx", "    add   ebp, edx",
               "    rorx  ecx, ebx, 6", "    rorx  edx, ebx, 11", "    xor   ecx, edx",
               "    rorx  edx, ebx, 25", "    xor   ecx, edx", "    add   ebp, ecx",
               "    mov   $se, ebx", "    mov   ebx, $sd", "    add   ebx, ebp";
      push @o, $r->{extra}->($i) if $r->{extra};
      push @o, "    rorx  ecx, eax, 2", "    rorx  edx, eax, 13", "    xor   ecx, edx",
               "    rorx  edx, eax, 22", "    xor   ecx, edx", "    add   ebp, ecx";
    } else {
      push @o, $r->{w}->($i);
      push @o, "    add   ebp, " . hex32($K[$i]), "    add   ebp, $sh",
               "    mov   ecx, $sf", "    xor   ecx, $sg", "    and   ecx, ebx", "    xor   ecx, $sg",
               "    add   ebp, ecx",
               "    mov   ecx, ebx", "    ror   ecx, 14", "    xor   ecx, ebx", "    ror   ecx, 5",
               "    xor   ecx, ebx", "    ror   ecx, 6", "    add   ebp, ecx",
               "    mov   $se, ebx", "    mov   ebx, $sd", "    add   ebx, ebp",
               "    mov   ecx, eax", "    ror   ecx, 9", "    xor   ecx, eax", "    ror   ecx, 11",
               "    xor   ecx, eax", "    ror   ecx, 2", "    add   ebp, ecx";
    }
    push @o, "    mov   edx, eax", "    xor   edx, $sb", "    and   edi, edx", "    xor   edi, $sb",
             "    add   ebp, edi", "    mov   edi, edx",
             "    mov   $sa, eax", "    mov   eax, ebp";
  }
  return @o;
}

# Win32 scalar schedule: leaves W[i] in ebp (W pre-swapped at [esp+0..63]).
sub sched32 {
  my ($i) = @_;
  my $W = sub { "dword ptr [esp + " . (4 * $_[0]) . "]" };
  return ("    mov   ebp, " . $W->($i)) if $i < 16;
  my @o = ("    mov   ecx, " . $W->(($i - 15) & 15), "    mov   edx, ecx", "    ror   ecx, 7",
           "    shr   edx, 3", "    xor   edx, ecx", "    ror   ecx, 11", "    xor   edx, ecx",
           "    mov   ecx, " . $W->(($i - 2) & 15), "    mov   esi, ecx", "    ror   ecx, 17",
           "    shr   esi, 10", "    xor   esi, ecx", "    ror   ecx, 2", "    xor   esi, ecx",
           "    mov   ebp, " . $W->($i & 15), "    add   ebp, edx", "    add   ebp, esi",
           "    add   ebp, " . $W->(($i - 7) & 15));
  push @o, "    mov   " . $W->($i & 15) . ", ebp" if $i + 2 <= 63;
  return @o;
}

# Win32: load state into A/E/ring/x at block start; finish by adding into state.
sub load32 {
  my ($ring, $stateslot) = @_;
  my @o = ("    mov   esi, [esp + $stateslot]",
           "    mov   eax, [esi]", "    mov   ebx, [esi + 16]",
           "    mov   edi, [esi + 4]", "    xor   edi, [esi + 8]");
  for my $v (1, 2, 3, 5, 6, 7) {
    push @o, "    mov   ecx, [esi + " . (4 * $v) . "]", "    mov   [esp + " . ($ring + 4 * $v) . "], ecx";
  }
  return @o;
}
sub store32 {
  my ($ring, $stateslot) = @_;
  my @o = ("    mov   [esp + $ring], eax", "    mov   [esp + " . ($ring + 16) . "], ebx",
           "    mov   esi, [esp + $stateslot]");
  for my $v (0 .. 7) {
    push @o, "    mov   ecx, [esp + " . ($ring + 4 * $v) . "]", "    add   [esi + " . (4 * $v) . "], ecx";
  }
  return @o;
}

# ---------------------------------------------------------------------------
# AVX2 two-block schedule. Frame: WK at +0 (512 bytes), raw W at +512.
# Constants are the 32-byte rows SHA256_BSWAP, SHA256_SHUF00BA,
# SHA256_SHUFDC00 and SHA256_KD0..15 (emitted by consts()), referenced by
# name so no register is needed for them while rounds are running.
# Returns (\@prelude, \@groups): the prelude loads groups 0..3 from the data
# (needs the data pointers); $groups[g] (g = 4..15) computes group g and is
# meant to be interleaved with block A's rounds.
# ---------------------------------------------------------------------------
sub avx2_schedule {
  my ($r) = @_;
  my ($B, $DA, $DB) = @{$r}{qw(base da db)};
  my $WK = sub { "[$B + " . (32 * $_[0]) . "]" };
  my $WR = sub { "[$B + " . (512 + 32 * $_[0]) . "]" };
  my @pre = ("    // message schedule, groups 0..3 of both blocks");
  for my $g (0 .. 3) {
    push @pre, "    vmovdqu     xmm0, [$DA + " . (16 * $g) . "]",
                "    vinserti128 ymm0, ymm0, [$DB + " . (16 * $g) . "], 1",
                "    vpshufb     ymm0, ymm0, [SHA256_BSWAP]",
                "    vmovdqu     " . $WR->($g) . ", ymm0",
                "    vpaddd      ymm1, ymm0, [SHA256_KD$g]",
                "    vmovdqu     " . $WK->($g) . ", ymm1";
  }
  my @groups;
  for my $g (4 .. 15) {
    my @o = ("    // schedule group $g",
             "    vmovdqu     ymm0, " . $WR->($g - 1),                   # X3 = W[-4..-1]
             "    vpalignr    ymm1, ymm0, " . $WR->($g - 2) . ", 4",    # W[-7..-4]
             "    vpaddd      ymm1, ymm1, " . $WR->($g - 4),             # + W[-16..-13]
             "    vmovdqu     ymm2, " . $WR->($g - 3),
             "    vpalignr    ymm2, ymm2, " . $WR->($g - 4) . ", 4",    # W[-15..-12]
             "    vpsrld      ymm3, ymm2, 7",
             "    vpslld      ymm4, ymm2, 25",
             "    vpxor       ymm3, ymm3, ymm4",
             "    vpsrld      ymm4, ymm2, 18",
             "    vpxor       ymm3, ymm3, ymm4",
             "    vpslld      ymm4, ymm2, 14",
             "    vpxor       ymm3, ymm3, ymm4",
             "    vpsrld      ymm2, ymm2, 3",
             "    vpxor       ymm3, ymm3, ymm2",                         # sigma0
             "    vpaddd      ymm1, ymm1, ymm3",
             "    vpshufd     ymm2, ymm0, \$FA",                         # {W-2,W-2,W-1,W-1}
             "    vpsrld      ymm3, ymm2, 10",
             "    vpsrlq      ymm4, ymm2, 19",
             "    vpsrlq      ymm2, ymm2, 17",
             "    vpxor       ymm2, ymm2, ymm4",
             "    vpxor       ymm3, ymm3, ymm2",
             "    vpshufb     ymm3, ymm3, [SHA256_SHUF00BA]",            # {s1, s1, 0, 0}
             "    vpaddd      ymm1, ymm1, ymm3",                         # W[0], W[1] done
             "    vpshufd     ymm2, ymm1, \$50",                         # {W0,W0,W1,W1}
             "    vpsrld      ymm3, ymm2, 10",
             "    vpsrlq      ymm4, ymm2, 19",
             "    vpsrlq      ymm2, ymm2, 17",
             "    vpxor       ymm2, ymm2, ymm4",
             "    vpxor       ymm3, ymm3, ymm2",
             "    vpshufb     ymm3, ymm3, [SHA256_SHUFDC00]",            # {0, 0, s1, s1}
             "    vpaddd      ymm1, ymm1, ymm3");
    push @o, "    vmovdqu     " . $WR->($g) . ", ymm1" if $g <= 14;
    push @o, "    vpaddd      ymm2, ymm1, [SHA256_KD$g]",
             "    vmovdqu     " . $WK->($g) . ", ymm2";
    $groups[$g] = \@o;
  }
  return (\@pre, \@groups);
}

# Spreads schedule group g (first = first group to interleave) over the
# four rounds 4*(g - first) .. 4*(g - first) + 3 of block A: returns a
# callback giving the lines to insert into round i.
sub interleave {
  my ($groups, $first, $per) = @_;     # $per = rounds per group
  return sub {
    my $i = shift;
    my $g = $first + int($i / $per);
    return () unless defined $groups->[$g];
    my @lines = @{ $groups->[$g] };
    my $n = scalar @lines;
    my $k = $i % $per;
    my ($lo, $hi) = (int($n * $k / $per), int($n * ($k + 1) / $per) - 1);
    return @lines[$lo .. $hi];
  };
}

# The 32-byte constant rows used by the AVX2 code (VEX operands need no alignment).
sub consts {
  my @o = ("const");
  my @bs = map { (($_ & ~3) + 3 - ($_ & 3)) } (0 .. 31);
  push @o, "  SHA256_BSWAP: array[0..31] of Byte = (" . join(", ", @bs) . ");";
  push @o, "  SHA256_SHUF00BA: array[0..31] of Byte = (" . join(", ", (0, 1, 2, 3, 8, 9, 10, 11, (255) x 8) x 2) . ");";
  push @o, "  SHA256_SHUFDC00: array[0..31] of Byte = (" . join(", ", ((255) x 8, 0, 1, 2, 3, 8, 9, 10, 11) x 2) . ");";
  for my $g (0 .. 15) {
    my @k = map { hex32($K[4 * $g + $_]) } (0 .. 3);
    push @o, "  SHA256_KD$g: array[0..7] of Cardinal = (" . join(", ", @k, @k) . ");";
  }
  return (@o, "");
}

sub wk_operand {
  my ($base, $lane) = @_;
  return sub { my $i = shift; "dword ptr [$base + " . (32 * ($i >> 2) + 16 * $lane + 4 * ($i & 3)) . "]" };
}

# ---------------------------------------------------------------------------
# SHA-NI. xmm0 = MSG, xmm1 = STATE0 (ABEF), xmm2 = STATE1 (CDGH),
# xmm3..6 = MSG0..3, xmm7 = temp. $cp = const pool register, $dp = data.
# Group h >= 4 needs sha256msg1(h-4, h-3) at g = h-3 and the palignr/msg2
# step with group h-1 at g = h-1.
# ---------------------------------------------------------------------------
sub shani_groups {
  my ($cp, $dp) = @_;
  my @M = ('xmm3', 'xmm4', 'xmm5', 'xmm6');
  my @o;
  for my $g (0 .. 15) {
    push @o, "    // rounds " . (4 * $g) . ".." . (4 * $g + 3);
    if ($g < 4) {
      push @o, "    movdqu      xmm0, [$dp + " . (16 * $g) . "]",
               "    pshufb      xmm0, [$cp]",
               "    movdqa      $M[$g], xmm0";
    } else {
      push @o, "    movdqa      xmm0, $M[$g % 4]";
    }
    push @o, "    paddd       xmm0, [$cp + " . (16 + 16 * $g) . "]",
             "    sha256rnds2 xmm2, xmm1, xmm0";
    if ($g >= 3 && $g <= 14) {
      push @o, "    movdqa      xmm7, $M[$g % 4]",
               "    palignr     xmm7, $M[($g - 1) % 4], 4",
               "    paddd       $M[($g + 1) % 4], xmm7",
               "    sha256msg2  $M[($g + 1) % 4], $M[$g % 4]";
    }
    push @o, "    pshufd      xmm0, xmm0, \$0E",
             "    sha256rnds2 xmm1, xmm2, xmm0";
    push @o, "    sha256msg1  $M[($g - 1) % 4], $M[$g % 4]" if $g >= 1 && $g <= 12;
  }
  return @o;
}

sub shani_entry {
  my ($st) = @_;
  return ("    movdqu      xmm1, [$st]",
          "    movdqu      xmm2, [$st + 16]",
          "    pshufd      xmm1, xmm1, \$B1",       # CDAB
          "    pshufd      xmm2, xmm2, \$1B",       # EFGH
          "    movdqa      xmm7, xmm1",
          "    palignr     xmm1, xmm2, 8",          # ABEF
          "    pblendw     xmm2, xmm7, \$F0");      # CDGH
}
sub shani_exit {
  my ($st) = @_;
  return ("    pshufd      xmm1, xmm1, \$1B",       # FEBA
          "    pshufd      xmm2, xmm2, \$B1",       # DCHG
          "    movdqa      xmm7, xmm1",
          "    pblendw     xmm1, xmm2, \$F0",       # DCBA
          "    palignr     xmm2, xmm7, 8",          # HGFE
          "    movdqu      [$st], xmm1",
          "    movdqu      [$st + 16], xmm2");
}

my (@x64, @x86);

# ============================ Scalar, Win64 ============================
# a..h = eax ebx ecx edx r8d r9d r10d r11d; t0..t2 = r12d..r14d; x = r15d;
# rsi = data; rdi = frame (W at +0, State at +64, End at +72).
{
  my $W = sub { "dword ptr [rdi + " . (4 * $_[0]) . "]" };
  push @x64,
    "procedure SHA256CompressScalar(State: Pointer; Data: PByte; Blocks: NativeUInt);",
    "var",
    "  Frame: array[0..79] of Byte;",
    "asm",
    "    // rcx = State, rdx = Data, r8 = Blocks",
    "    .PUSHNV rbx", "    .PUSHNV rsi", "    .PUSHNV rdi", "    .PUSHNV r12", "    .PUSHNV r13",
    "    .PUSHNV r14", "    .PUSHNV r15",
    "    test  r8, r8",
    "    jz    \@done",
    "    lea   rdi, Frame",
    "    mov   [rdi + 64], rcx",
    "    mov   rsi, rdx",
    "    shl   r8, 6",
    "    add   r8, rsi",
    "    mov   [rdi + 72], r8",
    "\@block:",
    "    mov   r15, [rdi + 64]",
    "    mov   eax, [r15]", "    mov   ebx, [r15 + 4]", "    mov   ecx, [r15 + 8]", "    mov   edx, [r15 + 12]",
    "    mov   r8d, [r15 + 16]", "    mov   r9d, [r15 + 20]", "    mov   r10d, [r15 + 24]", "    mov   r11d, [r15 + 28]",
    "    mov   r15d, ebx",
    "    xor   r15d, ecx";
  push @x64, rounds64({
    v => [qw(eax ebx ecx edx r8d r9d r10d r11d)], t0 => 'r12d', t1 => 'r13d', t2 => 'r14d', x => 'r15d',
    w => sub { sched64($_[0], $W, 'rsi', $_[1], $_[2], $_[3]) },
  });
  push @x64,
    "    mov   r15, [rdi + 64]",
    "    add   [r15], eax", "    add   [r15 + 4], ebx", "    add   [r15 + 8], ecx", "    add   [r15 + 12], edx",
    "    add   [r15 + 16], r8d", "    add   [r15 + 20], r9d", "    add   [r15 + 24], r10d", "    add   [r15 + 28], r11d",
    "    add   rsi, 64",
    "    cmp   rsi, [rdi + 72]",
    "    jb    \@block",
    "\@done:",
    "end;", "";
}

# ============================ Scalar, Win32 ============================
# Frame: W +0 (64), ring +64 (32), State +96, Data +100, End +104.
{
  push @x86,
    "procedure SHA256CompressScalar(State: Pointer; Data: PByte; Blocks: NativeUInt);",
    "asm",
    "    // eax = State, edx = Data, ecx = Blocks",
    "    test  ecx, ecx",
    "    jz    \@exit",
    "    push  ebx", "    push  esi", "    push  edi", "    push  ebp",
    "    sub   esp, 112",
    "    mov   [esp + 96], eax",
    "    mov   [esp + 100], edx",
    "    shl   ecx, 6",
    "    add   ecx, edx",
    "    mov   [esp + 104], ecx",
    "\@block:",
    "    mov   esi, [esp + 100]";
  for my $k (0 .. 15) {
    push @x86, "    mov   ecx, [esi + " . (4 * $k) . "]", "    bswap ecx", "    mov   [esp + " . (4 * $k) . "], ecx";
  }
  push @x86, load32(64, 96);
  push @x86, rounds32({ ring => 64, w => \&sched32 });
  push @x86, store32(64, 96);
  push @x86,
    "    add   dword ptr [esp + 100], 64",
    "    mov   ecx, [esp + 100]",
    "    cmp   ecx, [esp + 104]",
    "    jb    \@block",
    "    add   esp, 112",
    "    pop   ebp", "    pop   edi", "    pop   esi", "    pop   ebx",
    "\@exit:",
    "end;", "";
}

# ============================ AVX2, Win64 ============================
# rbx = frame (WK +0, W +512, DataA +1024, End +1032, DataB +1040)
# a..h = eax ecx edx esi r8d r9d r10d r11d; t0..t2 = r12d..r14d; x = r15d; rdi = State.
{
  my @v = qw(eax ecx edx esi r8d r9d r10d r11d);
  my @load = ("    mov   eax, [rdi]", "    mov   ecx, [rdi + 4]", "    mov   edx, [rdi + 8]", "    mov   esi, [rdi + 12]",
              "    mov   r8d, [rdi + 16]", "    mov   r9d, [rdi + 20]", "    mov   r10d, [rdi + 24]", "    mov   r11d, [rdi + 28]");
  my @addstore = ("    add   eax, [rdi]", "    add   ecx, [rdi + 4]", "    add   edx, [rdi + 8]", "    add   esi, [rdi + 12]",
                  "    add   r8d, [rdi + 16]", "    add   r9d, [rdi + 20]", "    add   r10d, [rdi + 24]", "    add   r11d, [rdi + 28]",
                  "    mov   [rdi], eax", "    mov   [rdi + 4], ecx", "    mov   [rdi + 8], edx", "    mov   [rdi + 12], esi",
                  "    mov   [rdi + 16], r8d", "    mov   [rdi + 20], r9d", "    mov   [rdi + 24], r10d", "    mov   [rdi + 28], r11d");
  push @x64,
    "procedure SHA256CompressAVX2(State: Pointer; Data: PByte; Blocks: NativeUInt);",
    "var",
    "  Frame: array[0..1087] of Byte;",
    "asm",
    "    // rcx = State, rdx = Data, r8 = Blocks",
    "    .PUSHNV rbx", "    .PUSHNV rsi", "    .PUSHNV rdi", "    .PUSHNV r12", "    .PUSHNV r13",
    "    .PUSHNV r14", "    .PUSHNV r15",
    "    test  r8, r8",
    "    jz    \@done",
    "    lea   rbx, Frame",
    "    add   rbx, 31",
    "    and   rbx, -32",
    "    mov   rdi, rcx",
    "    mov   [rbx + 1024], rdx",
    "    shl   r8, 6",
    "    add   r8, rdx",
    "    mov   [rbx + 1032], r8",
    "\@loop:",
    "    mov   rsi, [rbx + 1024]",
    "    mov   rdx, [rbx + 1032]",
    "    sub   rdx, rsi",
    "    cmp   rdx, 128",
    "    mov   rdx, rsi",
    "    jb    \@one",
    "    add   rdx, 64",
    "\@one:",
    "    mov   [rbx + 1040], rdx",
    "    // (schedule groups 4..15 are interleaved with block A's rounds)";
  my ($pre, $groups) = avx2_schedule({ base => 'rbx', da => 'rsi', db => 'rdx' });
  push @x64, @$pre;
  push @x64, @load, "    mov   r15d, ecx", "    xor   r15d, edx";
  push @x64, rounds64({ v => \@v, t0 => 'r12d', t1 => 'r13d', t2 => 'r14d', x => 'r15d', wk => wk_operand('rbx', 0),
                        extra => interleave($groups, 4, 4) });
  push @x64, @addstore,
    "    mov   r12, [rbx + 1040]",
    "    cmp   r12, [rbx + 1024]",
    "    je    \@single",
    "    mov   r15d, ecx",
    "    xor   r15d, edx";
  push @x64, rounds64({ v => \@v, t0 => 'r12d', t1 => 'r13d', t2 => 'r14d', x => 'r15d', wk => wk_operand('rbx', 1) });
  push @x64, @addstore,
    "    add   qword ptr [rbx + 1024], 128",
    "    jmp   \@next",
    "\@single:",
    "    add   qword ptr [rbx + 1024], 64",
    "\@next:",
    "    mov   r12, [rbx + 1024]",
    "    cmp   r12, [rbx + 1032]",
    "    jb    \@loop",
    "    vzeroupper",
    "\@done:",
    "end;", "";
}

# ============================ AVX2, Win32 ============================
# Frame: WK +0, W +512, ring +1024, State +1056, DataA +1060, End +1064,
# DataB +1068, saved esp +1072.
{
  push @x86,
    "procedure SHA256CompressAVX2(State: Pointer; Data: PByte; Blocks: NativeUInt);",
    "asm",
    "    // eax = State, edx = Data, ecx = Blocks",
    "    test  ecx, ecx",
    "    jz    \@exit",
    "    push  ebx", "    push  esi", "    push  edi", "    push  ebp",
    "    mov   ebp, esp",
    "    sub   esp, 1120",
    "    and   esp, -32",
    "    mov   [esp + 1072], ebp",
    "    mov   [esp + 1056], eax",
    "    mov   [esp + 1060], edx",
    "    shl   ecx, 6",
    "    add   ecx, edx",
    "    mov   [esp + 1064], ecx",
    "\@loop:",
    "    mov   edi, [esp + 1060]",
    "    mov   ebp, [esp + 1064]",
    "    sub   ebp, edi",
    "    cmp   ebp, 128",
    "    mov   ebp, edi",
    "    jb    \@one",
    "    add   ebp, 64",
    "\@one:",
    "    mov   [esp + 1068], ebp",
    "    // (schedule groups 4..15 are interleaved with block A's rounds)";
  my ($pre, $groups) = avx2_schedule({ base => 'esp', da => 'edi', db => 'ebp' });
  push @x86, @$pre;
  push @x86, load32(1024, 1056);
  push @x86, rounds32({ ring => 1024, wk => wk_operand('esp', 0), extra => interleave($groups, 4, 4) });
  push @x86, store32(1024, 1056);
  push @x86,
    "    mov   ecx, [esp + 1068]",
    "    cmp   ecx, [esp + 1060]",
    "    je    \@single";
  push @x86, load32(1024, 1056);
  push @x86, rounds32({ ring => 1024, wk => wk_operand('esp', 1) });
  push @x86, store32(1024, 1056);
  push @x86,
    "    add   dword ptr [esp + 1060], 128",
    "    jmp   \@next",
    "\@single:",
    "    add   dword ptr [esp + 1060], 64",
    "\@next:",
    "    mov   ecx, [esp + 1060]",
    "    cmp   ecx, [esp + 1064]",
    "    jb    \@loop",
    "    vzeroupper",
    "    mov   esp, [esp + 1072]",
    "    pop   ebp", "    pop   edi", "    pop   esi", "    pop   ebx",
    "\@exit:",
    "end;", "";
}

# ============================ SHA-NI ============================
push @x64,
  "procedure SHA256CompressSHANI(State: Pointer; Data: PByte; Blocks: NativeUInt);",
  "var",
  "  Save: array[0..31] of Byte;",
  "asm",
  "    // rcx = State, rdx = Data, r8 = Blocks",
  "    .SAVENV xmm6", "    .SAVENV xmm7",
  "    test  r8, r8",
  "    jz    \@done",
  "    shl   r8, 6",
  "    add   r8, rdx",
  "    mov   r9, [SHA256Consts]",
  "    lea   rax, Save";
push @x64, shani_entry('rcx');
push @x64, "\@loop:", "    movdqu      [rax], xmm1", "    movdqu      [rax + 16], xmm2";
push @x64, shani_groups('r9', 'rdx');
push @x64,
  "    movdqu      xmm3, [rax]",
  "    paddd       xmm1, xmm3",
  "    movdqu      xmm3, [rax + 16]",
  "    paddd       xmm2, xmm3",
  "    add   rdx, 64",
  "    cmp   rdx, r8",
  "    jb    \@loop";
push @x64, shani_exit('rcx');
push @x64, "\@done:", "end;", "";

push @x86,
  "procedure SHA256CompressSHANI(State: Pointer; Data: PByte; Blocks: NativeUInt);",
  "asm",
  "    // eax = State, edx = Data, ecx = Blocks",
  "    test  ecx, ecx",
  "    jz    \@exit",
  "    push  esi",
  "    sub   esp, 32",
  "    shl   ecx, 6",
  "    add   ecx, edx",
  "    mov   esi, [SHA256Consts]";
push @x86, shani_entry('eax');
push @x86, "\@loop:", "    movdqu      [esp], xmm1", "    movdqu      [esp + 16], xmm2";
push @x86, shani_groups('esi', 'edx');
push @x86,
  "    movdqu      xmm3, [esp]",
  "    paddd       xmm1, xmm3",
  "    movdqu      xmm3, [esp + 16]",
  "    paddd       xmm2, xmm3",
  "    add   edx, 64",
  "    cmp   edx, ecx",
  "    jb    \@loop";
push @x86, shani_exit('eax');
push @x86, "    add   esp, 32", "    pop   esi", "\@exit:", "end;", "";

write_file("$out_dir/SHA256.x64.inc", "// GENERATED by Tools\\gen_sha256.pl - do not edit by hand.", "", consts(), @x64);
write_file("$out_dir/SHA256.x86.inc", "// GENERATED by Tools\\gen_sha256.pl - do not edit by hand.", "", consts(), @x86);

sub write_file {
  my ($name, @lines) = @_;
  open(my $fh, '>:crlf', $name) or die "$name: $!";
  print $fh join("\n", @lines);
  close $fh;
  print "wrote $name\n";
}

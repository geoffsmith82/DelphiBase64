#!/usr/bin/perl
# Generates Asm\SHA1.x86.inc and Asm\SHA1.x64.inc:
#
#   SHA1CompressScalar  unrolled integer rounds, 16-word circular schedule
#   SHA1CompressAVX2    two blocks' message schedule (W+K) computed together in
#                       ymm registers (block A in the low lane, block B in the
#                       high lane), then BMI1/BMI2 (andn/rorx) rounds
#   SHA1CompressSHANI   Intel SHA extensions (sha1rnds4/sha1nexte/sha1msg1/2)
#
#   procedure X(State: Pointer; Data: PByte; Blocks: NativeUInt);
#
# State is 5 Cardinals (A..E). The SHA-NI code reads the 16-byte-aligned
# constant pool SHA1Consts (see FastHash.SHA1.pas):
#   +0   SHA-NI full 16-byte reversal mask
#   +16  SHA-NI upper-dword mask
#
# Run from the Hash folder:  perl Tools\gen_sha1.pl
use strict;
use warnings;
use FindBin;

my $out_dir = "$FindBin::Bin/../Asm";
my @K = (0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6);
sub hex32 { sprintf('$%08X', $_[0]) }

# ---------------------------------------------------------------------------
# Scalar rounds. $r: v => [a,b,c,d,e regs], t1, t2,
#   w => sub($k) returning the memory operand of circular W slot k,
#   load => sub($i) returning code that leaves big-endian W[i] (i<16) in t2
# ---------------------------------------------------------------------------
sub scalar_rounds {
  my ($r) = @_;
  my @v = @{ $r->{v} };
  my ($t1, $t2, $W) = ($r->{t1}, $r->{t2}, $r->{w});
  my @o;
  for my $i (0 .. 79) {
    my ($a, $b, $c, $d, $e) = @v;
    push @o, "    // round $i";
    if ($i < 16) {
      push @o, $r->{load}->($i);
    } else {
      push @o, "    mov   $t2, " . $W->(($i + 13) & 15),
               "    xor   $t2, " . $W->(($i + 8) & 15),
               "    xor   $t2, " . $W->(($i + 2) & 15),
               "    xor   $t2, " . $W->($i & 15),
               "    rol   $t2, 1";
      push @o, "    mov   " . $W->($i & 15) . ", $t2" if $i + 3 <= 79;
    }
    push @o, "    add   $e, $t2", "    add   $e, " . hex32($K[int($i / 20)]);
    if ($i < 20) {          # Ch = ((c xor d) and b) xor d
      push @o, "    mov   $t1, $c", "    xor   $t1, $d", "    and   $t1, $b", "    xor   $t1, $d";
    } elsif ($i >= 40 && $i < 60) {   # Maj = ((b or c) and d) or (b and c)
      push @o, "    mov   $t1, $b", "    or    $t1, $c", "    and   $t1, $d",
               "    mov   $t2, $b", "    and   $t2, $c", "    or    $t1, $t2";
    } else {                # Parity
      push @o, "    mov   $t1, $c", "    xor   $t1, $d", "    xor   $t1, $b";
    }
    push @o, "    add   $e, $t1", "    mov   $t1, $a", "    rol   $t1, 5", "    add   $e, $t1",
             "    ror   $b, 2";
    @v = ($e, $a, $b, $c, $d);
  }
  return @o;
}

# ---------------------------------------------------------------------------
# BMI rounds reading W+K from the precomputed area. $r: v, t1, t2,
#   wk => sub($i) memory operand of W[i]+K for this block
# ---------------------------------------------------------------------------
sub bmi_rounds {
  my ($r) = @_;
  my @v = @{ $r->{v} };
  my ($t1, $t2) = ($r->{t1}, $r->{t2});
  my @o;
  for my $i (0 .. 79) {
    my ($a, $b, $c, $d, $e) = @v;
    push @o, "    // round $i", "    add   $e, " . $r->{wk}->($i);
    if ($i < 20) {          # Ch = (b and c) + (not b and d)
      push @o, "    andn  $t1, $b, $d", "    mov   $t2, $c", "    and   $t2, $b",
               "    add   $e, $t1", "    add   $e, $t2";
    } elsif ($i >= 40 && $i < 60) {   # Maj = (b and c) + (d and (b xor c))
      push @o, "    mov   $t1, $c", "    xor   $t1, $b", "    and   $t1, $d",
               "    mov   $t2, $c", "    and   $t2, $b", "    add   $e, $t1", "    add   $e, $t2";
    } else {
      push @o, "    mov   $t1, $c", "    xor   $t1, $d", "    xor   $t1, $b", "    add   $e, $t1";
    }
    push @o, "    rorx  $t1, $a, 27", "    add   $e, $t1", "    rorx  $b, $b, 2";
    push @o, $r->{extra}->($i) if $r->{extra};
    @v = ($e, $a, $b, $c, $d);
  }
  return @o;
}

# ---------------------------------------------------------------------------
# AVX2 two-block message schedule. $r: base (frame register), da, db (block
# A/B data pointers). Frame: WK at +0 (640 bytes), raw W at +640 (640 bytes).
# Group g = words 4g..4g+3, 32 bytes: low 16 = block A, high 16 = block B.
# Constants are the named 32-byte rows SHA1_BSWAP and SHA1_K0..3 (emitted by
# consts()), so no register is needed for them while rounds are running.
# Returns (\@prelude, \@groups): the prelude loads groups 0..3 from the data;
# $groups[g] (g = 4..19) computes group g.
# ---------------------------------------------------------------------------
sub avx2_schedule {
  my ($r) = @_;
  my ($B, $DA, $DB) = @{$r}{qw(base da db)};
  my $WK = sub { "[$B + " . (32 * $_[0]) . "]" };
  my $WR = sub { "[$B + " . (640 + 32 * $_[0]) . "]" };
  my $KK = sub { "[SHA1_K" . int($_[0] / 5) . "]" };
  my @pre = ("    // message schedule, groups 0..3 of both blocks");
  for my $g (0 .. 3) {
    push @pre, "    vmovdqu     xmm0, [$DA + " . (16 * $g) . "]",
               "    vinserti128 ymm0, ymm0, [$DB + " . (16 * $g) . "], 1",
               "    vpshufb     ymm0, ymm0, [SHA1_BSWAP]",
               "    vmovdqu     " . $WR->($g) . ", ymm0",
               "    vpaddd      ymm1, ymm0, " . $KK->($g),
               "    vmovdqu     " . $WK->($g) . ", ymm1";
  }
  my @groups;
  for my $g (4 .. 7) {
    # W[i..i+3] = rol1(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16]); lane 3 needs W[i],
    # so it is patched with rol2 of the lane-0 pre-rotation value.
    $groups[$g] = [
             "    // schedule group $g",
             "    vmovdqu     ymm0, " . $WR->($g - 4),
             "    vmovdqu     ymm1, " . $WR->($g - 3),
             "    vpalignr    ymm2, ymm1, ymm0, 8",
             "    vpxor       ymm2, ymm2, ymm0",
             "    vmovdqu     ymm3, " . $WR->($g - 1),
             "    vpsrldq     ymm3, ymm3, 4",
             "    vpxor       ymm3, ymm3, " . $WR->($g - 2),
             "    vpxor       ymm2, ymm2, ymm3",
             "    vpslldq     ymm4, ymm2, 12",
             "    vpsrld      ymm3, ymm2, 31",
             "    vpslld      ymm2, ymm2, 1",
             "    vpor        ymm2, ymm2, ymm3",
             "    vpsrld      ymm3, ymm4, 30",
             "    vpslld      ymm4, ymm4, 2",
             "    vpor        ymm4, ymm4, ymm3",
             "    vpxor       ymm2, ymm2, ymm4",
             "    vmovdqu     " . $WR->($g) . ", ymm2",
             "    vpaddd      ymm3, ymm2, " . $KK->($g),
             "    vmovdqu     " . $WK->($g) . ", ymm3" ];
  }
  for my $g (8 .. 19) {
    # W[i..i+3] = rol2(W[i-6] ^ W[i-16] ^ W[i-28] ^ W[i-32])
    my @o = ("    // schedule group $g",
             "    vmovdqu     ymm1, " . $WR->($g - 1),
             "    vpalignr    ymm2, ymm1, " . $WR->($g - 2) . ", 8",
             "    vpxor       ymm2, ymm2, " . $WR->($g - 4),
             "    vpxor       ymm2, ymm2, " . $WR->($g - 7),
             "    vpxor       ymm2, ymm2, " . $WR->($g - 8),
             "    vpsrld      ymm3, ymm2, 30",
             "    vpslld      ymm2, ymm2, 2",
             "    vpor        ymm2, ymm2, ymm3");
    push @o, "    vmovdqu     " . $WR->($g) . ", ymm2" if $g <= 18;
    push @o, "    vpaddd      ymm3, ymm2, " . $KK->($g),
             "    vmovdqu     " . $WK->($g) . ", ymm3";
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

# The 32-byte constant rows used by the AVX2 code (VEX operands need no alignment).
sub consts {
  my @o = ("const");
  my @bs = map { (($_ & ~3) + 3 - ($_ & 3)) } (0 .. 31);
  push @o, "  SHA1_BSWAP: array[0..31] of Byte = (" . join(", ", @bs) . ");";
  for my $j (0 .. 3) {
    push @o, "  SHA1_K$j: array[0..7] of Cardinal = (" . join(", ", (hex32($K[$j])) x 8) . ");";
  }
  return (@o, "");
}

sub wk_operand {
  my ($base, $lane) = @_;
  return sub { my $i = shift; "dword ptr [$base + " . (32 * ($i >> 2) + 16 * $lane + 4 * ($i & 3)) . "]" };
}

# ---------------------------------------------------------------------------
# SHA-NI groups (Intel reference ordering). xmm0 = ABCD, xmm1 = E0, xmm2 = E1,
# xmm3..xmm6 = MSG0..3, xmm7 = byte-reversal mask.
# ---------------------------------------------------------------------------
sub shani_groups {
  my ($dp) = @_;
  my @M = ('xmm3', 'xmm4', 'xmm5', 'xmm6');
  my @o;
  for my $g (0 .. 19) {
    my ($cur, $nxt) = $g % 2 == 0 ? ('xmm1', 'xmm2') : ('xmm2', 'xmm1');
    push @o, "    // rounds " . (4 * $g) . ".." . (4 * $g + 3);
    if ($g < 4) {
      push @o, "    movdqu    $M[$g], [$dp + " . (16 * $g) . "]", "    pshufb    $M[$g], xmm7";
    }
    push @o, $g == 0 ? "    paddd     xmm1, xmm3" : "    sha1nexte $cur, $M[$g % 4]";
    push @o, "    movdqa    $nxt, xmm0";
    push @o, "    sha1msg2  $M[($g + 1) % 4], $M[$g % 4]" if $g >= 3 && $g <= 18;
    push @o, "    sha1rnds4 xmm0, $cur, " . int($g / 5);
    push @o, "    sha1msg1  $M[($g - 1) % 4], $M[$g % 4]" if $g >= 1 && $g <= 16;
    push @o, "    pxor      $M[($g - 2) % 4], $M[$g % 4]" if $g >= 2 && $g <= 17;
  }
  return @o;
}

my @x64;
my @x86;

# ============================ Scalar ============================
push @x64,
  "procedure SHA1CompressScalar(State: Pointer; Data: PByte; Blocks: NativeUInt);",
  "var",
  "  W: array[0..15] of Cardinal;",
  "asm",
  "    // rcx = State, rdx = Data, r8 = Blocks",
  "    .PUSHNV rbx", "    .PUSHNV rsi", "    .PUSHNV rdi", "    .PUSHNV r12", "    .PUSHNV r13",
  "    test  r8, r8",
  "    jz    \@done",
  "    lea   rbx, W",
  "    mov   rdi, rcx",
  "    mov   rsi, rdx",
  "    mov   r13, r8",
  "    shl   r13, 6",
  "    add   r13, rsi",
  "    mov   r8d, [rdi]",
  "    mov   r9d, [rdi + 4]",
  "    mov   r10d, [rdi + 8]",
  "    mov   r11d, [rdi + 12]",
  "    mov   r12d, [rdi + 16]",
  "\@block:";
push @x64, scalar_rounds({
  v => ['r8d', 'r9d', 'r10d', 'r11d', 'r12d'], t1 => 'eax', t2 => 'ecx',
  w => sub { "dword ptr [rbx + " . (4 * $_[0]) . "]" },
  load => sub { my $i = shift; ("    mov   ecx, [rsi + " . (4 * $i) . "]", "    bswap ecx",
                                "    mov   dword ptr [rbx + " . (4 * $i) . "], ecx") },
});
push @x64,
  "    add   r8d, [rdi]", "    add   r9d, [rdi + 4]", "    add   r10d, [rdi + 8]",
  "    add   r11d, [rdi + 12]", "    add   r12d, [rdi + 16]",
  "    mov   [rdi], r8d", "    mov   [rdi + 4], r9d", "    mov   [rdi + 8], r10d",
  "    mov   [rdi + 12], r11d", "    mov   [rdi + 16], r12d",
  "    add   rsi, 64",
  "    cmp   rsi, r13",
  "    jb    \@block",
  "\@done:",
  "end;", "";

# Win32 frame: W at [esp+0..63], State [esp+64], Data [esp+68], End [esp+72]
push @x86,
  "procedure SHA1CompressScalar(State: Pointer; Data: PByte; Blocks: NativeUInt);",
  "asm",
  "    // eax = State, edx = Data, ecx = Blocks",
  "    test  ecx, ecx",
  "    jz    \@exit",
  "    push  ebx", "    push  esi", "    push  edi", "    push  ebp",
  "    sub   esp, 80",
  "    mov   [esp + 64], eax",
  "    mov   [esp + 68], edx",
  "    shl   ecx, 6",
  "    add   ecx, edx",
  "    mov   [esp + 72], ecx",
  "\@block:",
  "    mov   edi, [esp + 68]";
for my $k (0 .. 15) {
  push @x86, "    mov   ebp, [edi + " . (4 * $k) . "]", "    bswap ebp", "    mov   [esp + " . (4 * $k) . "], ebp";
}
push @x86,
  "    mov   edi, [esp + 64]",
  "    mov   eax, [edi]", "    mov   ebx, [edi + 4]", "    mov   ecx, [edi + 8]",
  "    mov   edx, [edi + 12]", "    mov   esi, [edi + 16]";
push @x86, scalar_rounds({
  v => ['eax', 'ebx', 'ecx', 'edx', 'esi'], t1 => 'edi', t2 => 'ebp',
  w => sub { "dword ptr [esp + " . (4 * $_[0]) . "]" },
  load => sub { my $i = shift; ("    mov   ebp, [esp + " . (4 * $i) . "]") },
});
push @x86,
  "    mov   edi, [esp + 64]",
  "    add   [edi], eax", "    add   [edi + 4], ebx", "    add   [edi + 8], ecx",
  "    add   [edi + 12], edx", "    add   [edi + 16], esi",
  "    add   dword ptr [esp + 68], 64",
  "    mov   edi, [esp + 68]",
  "    cmp   edi, [esp + 72]",
  "    jb    \@block",
  "    add   esp, 80",
  "    pop   ebp", "    pop   edi", "    pop   esi", "    pop   ebx",
  "\@exit:",
  "end;", "";

# ============================ AVX2 ============================
# Frame (32-byte aligned): WK +0, W +640.
push @x64,
  "procedure SHA1CompressAVX2(State: Pointer; Data: PByte; Blocks: NativeUInt);",
  "var",
  "  Frame: array[0..1311] of Byte;",
  "asm",
  "    // rcx = State, rdx = Data, r8 = Blocks",
  "    .PUSHNV rbx", "    .PUSHNV rsi", "    .PUSHNV rdi", "    .PUSHNV r12", "    .PUSHNV r13",
  "    .PUSHNV r14", "    .PUSHNV r15", "    .SAVENV xmm6", "    .SAVENV xmm7",
  "    test  r8, r8",
  "    jz    \@done",
  "    lea   rbx, Frame",
  "    add   rbx, 31",
  "    and   rbx, -32",
  "    mov   rdi, rcx                // State",
  "    mov   rsi, rdx                // Data (block A)",
  "    mov   r13, r8",
  "    shl   r13, 6",
  "    add   r13, rsi                // End",
  "    // (schedule groups 4..19 are interleaved with block A's rounds)",
  "\@loop:",
  "    mov   r15, r13",
  "    sub   r15, rsi",
  "    cmp   r15, 128",
  "    mov   r15, rsi                // block B = block A when only one is left",
  "    jb    \@one",
  "    add   r15, 64",
  "\@one:";
my ($pre64, $groups64) = avx2_schedule({ base => 'rbx', da => 'rsi', db => 'r15' });
push @x64, @$pre64;
push @x64,
  "    mov   r8d, [rdi]", "    mov   r9d, [rdi + 4]", "    mov   r10d, [rdi + 8]",
  "    mov   r11d, [rdi + 12]", "    mov   r12d, [rdi + 16]";
push @x64, bmi_rounds({ v => ['r8d', 'r9d', 'r10d', 'r11d', 'r12d'], t1 => 'eax', t2 => 'ecx', wk => wk_operand('rbx', 0),
                       extra => interleave($groups64, 4, 4) });
push @x64,
  "    add   r8d, [rdi]", "    add   r9d, [rdi + 4]", "    add   r10d, [rdi + 8]",
  "    add   r11d, [rdi + 12]", "    add   r12d, [rdi + 16]",
  "    mov   [rdi], r8d", "    mov   [rdi + 4], r9d", "    mov   [rdi + 8], r10d",
  "    mov   [rdi + 12], r11d", "    mov   [rdi + 16], r12d",
  "    cmp   r15, rsi",
  "    je    \@single";
push @x64, bmi_rounds({ v => ['r8d', 'r9d', 'r10d', 'r11d', 'r12d'], t1 => 'eax', t2 => 'ecx', wk => wk_operand('rbx', 1) });
push @x64,
  "    add   [rdi], r8d", "    add   [rdi + 4], r9d", "    add   [rdi + 8], r10d",
  "    add   [rdi + 12], r11d", "    add   [rdi + 16], r12d",
  "    add   rsi, 128",
  "    jmp   \@next",
  "\@single:",
  "    add   rsi, 64",
  "\@next:",
  "    cmp   rsi, r13",
  "    jb    \@loop",
  "    vzeroupper",
  "\@done:",
  "end;", "";

# Win32 frame (32-byte aligned): WK +0, W +640, State +1280, Data A +1284,
# End +1288, Data B +1292, saved esp +1296.
push @x86,
  "procedure SHA1CompressAVX2(State: Pointer; Data: PByte; Blocks: NativeUInt);",
  "asm",
  "    // eax = State, edx = Data, ecx = Blocks",
  "    test  ecx, ecx",
  "    jz    \@exit",
  "    push  ebx", "    push  esi", "    push  edi", "    push  ebp",
  "    mov   ebp, esp",
  "    sub   esp, 1344",
  "    and   esp, -32",
  "    mov   [esp + 1296], ebp",
  "    mov   [esp + 1280], eax",
  "    mov   [esp + 1284], edx",
  "    shl   ecx, 6",
  "    add   ecx, edx",
  "    mov   [esp + 1288], ecx",
  "\@loop:",
  "    mov   edi, [esp + 1284]",
  "    mov   ebp, [esp + 1288]",
  "    sub   ebp, edi",
  "    cmp   ebp, 128",
  "    mov   ebp, edi",
  "    jb    \@one",
  "    add   ebp, 64",
  "\@one:",
  "    mov   [esp + 1292], ebp",
  "    // (schedule groups 4..19 are interleaved with block A's rounds)";
my ($pre32, $groups32) = avx2_schedule({ base => 'esp', da => 'edi', db => 'ebp' });
push @x86, @$pre32;
push @x86,
  "    mov   edi, [esp + 1280]",
  "    mov   eax, [edi]", "    mov   ebx, [edi + 4]", "    mov   ecx, [edi + 8]",
  "    mov   edx, [edi + 12]", "    mov   esi, [edi + 16]";
push @x86, bmi_rounds({ v => ['eax', 'ebx', 'ecx', 'edx', 'esi'], t1 => 'edi', t2 => 'ebp', wk => wk_operand('esp', 0),
                       extra => interleave($groups32, 4, 4) });
push @x86,
  "    mov   edi, [esp + 1280]",
  "    add   eax, [edi]", "    add   ebx, [edi + 4]", "    add   ecx, [edi + 8]",
  "    add   edx, [edi + 12]", "    add   esi, [edi + 16]",
  "    mov   [edi], eax", "    mov   [edi + 4], ebx", "    mov   [edi + 8], ecx",
  "    mov   [edi + 12], edx", "    mov   [edi + 16], esi",
  "    mov   edi, [esp + 1292]",
  "    cmp   edi, [esp + 1284]",
  "    je    \@single";
push @x86, bmi_rounds({ v => ['eax', 'ebx', 'ecx', 'edx', 'esi'], t1 => 'edi', t2 => 'ebp', wk => wk_operand('esp', 1) });
push @x86,
  "    mov   edi, [esp + 1280]",
  "    add   [edi], eax", "    add   [edi + 4], ebx", "    add   [edi + 8], ecx",
  "    add   [edi + 12], edx", "    add   [edi + 16], esi",
  "    add   dword ptr [esp + 1284], 128",
  "    jmp   \@next",
  "\@single:",
  "    add   dword ptr [esp + 1284], 64",
  "\@next:",
  "    mov   edi, [esp + 1284]",
  "    cmp   edi, [esp + 1288]",
  "    jb    \@loop",
  "    vzeroupper",
  "    mov   esp, [esp + 1296]",
  "    pop   ebp", "    pop   edi", "    pop   esi", "    pop   ebx",
  "\@exit:",
  "end;", "";

# ============================ SHA-NI ============================
push @x64,
  "procedure SHA1CompressSHANI(State: Pointer; Data: PByte; Blocks: NativeUInt);",
  "var",
  "  Save: array[0..31] of Byte;",
  "asm",
  "    // rcx = State, rdx = Data, r8 = Blocks",
  "    .SAVENV xmm6", "    .SAVENV xmm7",
  "    test  r8, r8",
  "    jz    \@done",
  "    shl   r8, 6",
  "    add   r8, rdx",
  "    mov   r9, [SHA1Consts]",
  "    lea   rax, Save",
  "    pxor      xmm1, xmm1",
  "    pinsrd    xmm1, dword ptr [rcx + 16], 3",
  "    movdqu    xmm0, [rcx]",
  "    pand      xmm1, [r9 + 16]",
  "    pshufd    xmm0, xmm0, \$1B",
  "    movdqa    xmm7, [r9]",
  "\@loop:",
  "    movdqu    [rax], xmm1",
  "    movdqu    [rax + 16], xmm0";
push @x64, shani_groups('rdx');
push @x64,
  "    movdqu    xmm3, [rax]",
  "    sha1nexte xmm1, xmm3",
  "    movdqu    xmm3, [rax + 16]",
  "    paddd     xmm0, xmm3",
  "    add   rdx, 64",
  "    cmp   rdx, r8",
  "    jb    \@loop",
  "    pshufd    xmm0, xmm0, \$1B",
  "    movdqu    [rcx], xmm0",
  "    pextrd    dword ptr [rcx + 16], xmm1, 3",
  "\@done:",
  "end;", "";

push @x86,
  "procedure SHA1CompressSHANI(State: Pointer; Data: PByte; Blocks: NativeUInt);",
  "asm",
  "    // eax = State, edx = Data, ecx = Blocks",
  "    test  ecx, ecx",
  "    jz    \@exit",
  "    push  esi",
  "    sub   esp, 32",
  "    shl   ecx, 6",
  "    add   ecx, edx",
  "    mov   esi, [SHA1Consts]",
  "    pxor      xmm1, xmm1",
  "    pinsrd    xmm1, dword ptr [eax + 16], 3",
  "    movdqu    xmm0, [eax]",
  "    pand      xmm1, [esi + 16]",
  "    pshufd    xmm0, xmm0, \$1B",
  "    movdqa    xmm7, [esi]",
  "\@loop:",
  "    movdqu    [esp], xmm1",
  "    movdqu    [esp + 16], xmm0";
push @x86, shani_groups('edx');
push @x86,
  "    movdqu    xmm3, [esp]",
  "    sha1nexte xmm1, xmm3",
  "    movdqu    xmm3, [esp + 16]",
  "    paddd     xmm0, xmm3",
  "    add   edx, 64",
  "    cmp   edx, ecx",
  "    jb    \@loop",
  "    pshufd    xmm0, xmm0, \$1B",
  "    movdqu    [eax], xmm0",
  "    pextrd    dword ptr [eax + 16], xmm1, 3",
  "    add   esp, 32",
  "    pop   esi",
  "\@exit:",
  "end;", "";

write_file("$out_dir/SHA1.x64.inc", "// GENERATED by Tools\\gen_sha1.pl - do not edit by hand.", "", consts(), @x64);
write_file("$out_dir/SHA1.x86.inc", "// GENERATED by Tools\\gen_sha1.pl - do not edit by hand.", "", consts(), @x86);

sub write_file {
  my ($name, @lines) = @_;
  open(my $fh, '>:crlf', $name) or die "$name: $!";
  print $fh join("\n", @lines);
  close $fh;
  print "wrote $name\n";
}

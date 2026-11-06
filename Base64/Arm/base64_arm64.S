// Hand-written AArch64 twins of the C kernels in base64_arm64.c (same names
// with _asm instead of _c); the contracts are described there.
//
// Unlike Hash\Arm\fasthash_arm64.S this file is not generated: nothing here is
// unrolled, so there is no generator script.
//
// The file is preprocessed (.S), so one source serves Mach-O (macOS/iOS, '_'
// symbol prefix) and ELF (Android). x18 is never touched (platform register on
// Apple). Only caller-saved registers are used: x0-x15, v0-v7 and v16-v31.

#ifdef __APPLE__
#define SYM(x) _##x
#else
#define SYM(x) x
#endif

    .arch armv8-a
    .text

    .p2align 4
Lenc_table:
    .ascii "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
Ldec_lo:
    .byte 0x15,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x13,0x1A,0x1B,0x1B,0x1B,0x1A
Ldec_hi:
    .byte 0x10,0x10,0x01,0x02,0x04,0x08,0x04,0x08,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10
Ldec_roll:
    .byte 0,16,19,4,0xBF,0xBF,0xB9,0xB9,0,0,0,0,0,0,0,0
Ldec_pack:
    .byte 2,1,0,6,5,4,10,9,8,14,13,12,0xFF,0xFF,0xFF,0xFF

// ---------------------------------------------------------------------------
// Shared pieces
// ---------------------------------------------------------------------------

// Encode whole groups, x7 bytes of them (a multiple of 3). Bytes are loaded one
// at a time so the last group never reads past the input.
// In: x1 src, x2 dst, x5 table. Uses x7-x11.
.macro ENCODE_GROUPS
    cbz   x7, 8f
7:
    ldrb  w8, [x1]
    ldrb  w9, [x1, #1]
    ldrb  w10, [x1, #2]
    add   x1, x1, #3
    orr   w9, w9, w8, lsl #8
    orr   w10, w10, w9, lsl #8      // w10 = the 24-bit group
    ubfx  w8, w10, #18, #6
    ubfx  w9, w10, #12, #6
    ubfx  w11, w10, #6, #6
    and   w10, w10, #63
    ldrb  w8, [x5, w8, uxtw]
    ldrb  w9, [x5, w9, uxtw]
    ldrb  w11, [x5, w11, uxtw]
    ldrb  w10, [x5, w10, uxtw]
    strb  w8, [x2]
    strb  w9, [x2, #1]
    strb  w11, [x2, #2]
    strb  w10, [x2, #3]
    add   x2, x2, #4
    subs  x7, x7, #3
    b.ne  7b
8:
.endm

// Encode the last x4 (0, 1 or 2) bytes with padding.
// In: x1 src, x2 dst, x5 table. Uses x8-x10.
.macro ENCODE_FINAL
    cbz   x4, 3f
    ldrb  w8, [x1]
    lsr   w9, w8, #2
    ldrb  w9, [x5, w9, uxtw]
    strb  w9, [x2]
    and   w8, w8, #3
    lsl   w8, w8, #4
    mov   w10, #'='
    cmp   x4, #1
    b.ne  1f
    ldrb  w8, [x5, w8, uxtw]
    strb  w8, [x2, #1]
    strb  w10, [x2, #2]
    b     2f
1:
    ldrb  w9, [x1, #1]
    orr   w8, w8, w9, lsr #4
    and   w9, w9, #15
    lsl   w9, w9, #2
    ldrb  w8, [x5, w8, uxtw]
    ldrb  w9, [x5, w9, uxtw]
    strb  w8, [x2, #1]
    strb  w9, [x2, #2]
2:
    strb  w10, [x2, #3]
    add   x2, x2, #4
3:
.endm

// Copy the separator (x3, x6 bytes) to x2. Uses x8, x9.
.macro WRITE_SEP
    cbz   x6, 8f
    mov   x8, #0
7:
    ldrb  w9, [x3, x8]
    strb  w9, [x2], #1
    add   x8, x8, #1
    cmp   x8, x6
    b.lo  7b
8:
.endm

// Load the encode table into v16-v19 and the 6-bit mask into v20.
// In: x5 table.
.macro NEON_ENCODE_SETUP
    ld1   {v16.16b, v17.16b, v18.16b, v19.16b}, [x5]
    movi  v20.16b, #63
.endm

// 48 input bytes to 64 chars while x7 >= 48; x7 keeps the remainder.
// In: x1 src, x2 dst, v16-v20 from NEON_ENCODE_SETUP.
.macro NEON_ENCODE_BLOCKS
    cmp   x7, #48
    b.lo  6f
5:
    ld3   {v0.16b, v1.16b, v2.16b}, [x1], #48
    sub   x7, x7, #48
    ushr  v4.16b, v1.16b, #4
    ushr  v5.16b, v2.16b, #6
    ushr  v3.16b, v0.16b, #2
    sli   v4.16b, v0.16b, #4
    sli   v5.16b, v1.16b, #2
    and   v6.16b, v2.16b, v20.16b
    and   v4.16b, v4.16b, v20.16b
    and   v5.16b, v5.16b, v20.16b
    tbl   v3.16b, {v16.16b, v17.16b, v18.16b, v19.16b}, v3.16b
    tbl   v4.16b, {v16.16b, v17.16b, v18.16b, v19.16b}, v4.16b
    tbl   v5.16b, {v16.16b, v17.16b, v18.16b, v19.16b}, v5.16b
    tbl   v6.16b, {v16.16b, v17.16b, v18.16b, v19.16b}, v6.16b
    st4   {v3.16b, v4.16b, v5.16b, v6.16b}, [x2], #64
    cmp   x7, #48
    b.hs  5b
6:
.endm

// Split x4 bytes into whole groups (x7, in bytes) and the 0-2 final bytes (x4).
// Uses x8, x9.
.macro SPLIT_FINAL
    mov   x8, #3
    udiv  x9, x4, x8
    mul   x7, x9, x8
    sub   x4, x4, x7
.endm

// Load x1 src, x2 dst, x3 sep, x4 len, x6 sep length and x13 line bytes from
// the TFusedInfo at x0, and the table into x5.
.macro FUSED_SETUP
    ldp   x1, x2, [x0]
    ldp   x3, x4, [x0, #16]
    ldr   x6, [x0, #40]
    ldr   x13, [x0, #48]
    adr   x5, Lenc_table
.endm

// ---------------------------------------------------------------------------
// Scalar
// ---------------------------------------------------------------------------

// x0 = src, x1 = len, x2 = dst; returns chars written
    .p2align 4
    .globl SYM(b64_encode_scalar_asm)
SYM(b64_encode_scalar_asm):
    mov   x13, x2
    mov   x4, x1
    mov   x1, x0
    adr   x5, Lenc_table
    SPLIT_FINAL
    ENCODE_GROUPS
    ENCODE_FINAL
    sub   x0, x2, x13
    ret

// x0 = TFusedInfo
    .p2align 4
    .globl SYM(b64_fused_scalar_asm)
SYM(b64_fused_scalar_asm):
    FUSED_SETUP
    cmp   x4, x13
    b.lo  20f
10:
    sub   x4, x4, x13
    mov   x7, x13
    ENCODE_GROUPS
    WRITE_SEP
    cmp   x4, x13
    b.hs  10b
20:
    SPLIT_FINAL
    ENCODE_GROUPS
    ENCODE_FINAL
    ret

// ---------------------------------------------------------------------------
// NEON
// ---------------------------------------------------------------------------

// x0 = src, x1 = len, x2 = dst; returns chars written
    .p2align 4
    .globl SYM(b64_encode_neon_asm)
SYM(b64_encode_neon_asm):
    mov   x13, x2
    mov   x7, x1
    mov   x1, x0
    adr   x5, Lenc_table
    NEON_ENCODE_SETUP
    NEON_ENCODE_BLOCKS
    mov   x4, x7
    SPLIT_FINAL
    ENCODE_GROUPS
    ENCODE_FINAL
    sub   x0, x2, x13
    ret

// x0 = TFusedInfo
    .p2align 4
    .globl SYM(b64_fused_neon_asm)
SYM(b64_fused_neon_asm):
    FUSED_SETUP
    NEON_ENCODE_SETUP
    cmp   x4, x13
    b.lo  20f
10:
    sub   x4, x4, x13
    mov   x7, x13
    NEON_ENCODE_BLOCKS
    ENCODE_GROUPS
    WRITE_SEP
    cmp   x4, x13
    b.hs  10b
20:
    mov   x7, x4
    NEON_ENCODE_BLOCKS
    mov   x4, x7
    SPLIT_FINAL
    ENCODE_GROUPS
    ENCODE_FINAL
    ret

// Validity of one lane of ASCII in \c: errors are ORed into v7, and \h keeps the
// high nibbles for ROLL_LANE. v16, v17 = lo, hi; v19 = 0x0F. Uses v21, v22.
//
// Checking comes first and ROLL_LANE runs only for clean data, because every
// wrapped line ends in a dirty block and the translation would be wasted on it.
.macro CHECK_LANE c, h
    ushr  \h\().16b, \c\().16b, #4
    and   v22.16b, \c\().16b, v19.16b
    tbl   v22.16b, {v16.16b}, v22.16b
    tbl   v21.16b, {v17.16b}, \h\().16b
    and   v22.16b, v22.16b, v21.16b
    orr   v7.16b, v7.16b, v22.16b
.endm

// ASCII in \c to 6-bit values. \h from CHECK_LANE; v18 = roll; v20 = '/'.
// Uses v23.
.macro ROLL_LANE c, h
    cmeq  v23.16b, \c\().16b, v20.16b
    add   v23.16b, v23.16b, \h\().16b
    tbl   v23.16b, {v18.16b}, v23.16b
    add   \c\().16b, \c\().16b, v23.16b
.endm

// x0 = src, x1 = numchars, x2 = dst, x3 = written (out); returns chars consumed.
// Skips CR and LF between quanta. The 16-char loop can write up to 16 bytes past
// the decoded output.
    .p2align 4
    .globl SYM(b64_decode_neon_asm)
SYM(b64_decode_neon_asm):
    mov   x6, x3
    mov   x3, x0
    mov   x5, x2
    cmp   x1, #16
    b.lo  9f
    adr   x4, Ldec_lo
    ld1   {v16.16b, v17.16b, v18.16b}, [x4]
    ldr   q24, [x4, #48]
    movi  v19.16b, #0x0F
    movi  v20.16b, #0x2F
    movi  v25.8h, #0xFF
    movi  v26.2d, #0x0000FFFF0000FFFF
    .p2align 4
0:
    cmp   x1, #64
    b.lo  2f
    .p2align 4
1:
    ld4   {v0.16b, v1.16b, v2.16b, v3.16b}, [x0]
    movi  v7.16b, #0
    CHECK_LANE v0, v28
    CHECK_LANE v1, v29
    CHECK_LANE v2, v30
    CHECK_LANE v3, v31
    umaxv b6, v7.16b
    fmov  w4, s6
    cbnz  w4, 2f
    ROLL_LANE v0, v28
    ROLL_LANE v1, v29
    ROLL_LANE v2, v30
    ROLL_LANE v3, v31
    shl   v4.16b, v0.16b, #2
    shl   v5.16b, v1.16b, #4
    shl   v6.16b, v2.16b, #6
    usra  v4.16b, v1.16b, #4
    usra  v5.16b, v2.16b, #2
    orr   v6.16b, v6.16b, v3.16b
    st3   {v4.16b, v5.16b, v6.16b}, [x2], #48
    add   x0, x0, #64
    sub   x1, x1, #64
    cmp   x1, #64
    b.hs  1b
    // What is left, or the block that was dirty: 16 chars at a time. On a dirty
    // load the quanta before the first bad byte are still good.
    .p2align 4
2:
    cmp   x1, #16
    b.lo  9f
    ld1   {v0.16b}, [x0]
    movi  v7.16b, #0
    CHECK_LANE v0, v28
    ROLL_LANE v0, v28
    ushr  v1.8h, v0.8h, #8
    and   v0.16b, v0.16b, v25.16b
    shl   v0.8h, v0.8h, #6
    orr   v0.16b, v0.16b, v1.16b
    ushr  v1.4s, v0.4s, #16
    and   v0.16b, v0.16b, v26.16b
    shl   v0.4s, v0.4s, #12
    orr   v0.16b, v0.16b, v1.16b
    tbl   v0.16b, {v0.16b}, v24.16b
    cmtst v7.16b, v7.16b, v7.16b
    shrn  v7.8b, v7.8h, #4
    fmov  x4, d7
    cbnz  x4, 3f
    str   q0, [x2], #12
    add   x0, x0, #16
    sub   x1, x1, #16
    b     2b
3:
    rbit  x4, x4
    clz   x4, x4                    // 4 * index of the first bad byte
    lsr   x7, x4, #4                // clean quanta before it
    cbz   x7, 4f
    str   q0, [x2]
    sub   x1, x1, x7, lsl #2
    add   x0, x0, x7, lsl #2
    add   x7, x7, x7, lsl #1
    add   x2, x2, x7
4:
    tst   x4, #12                   // inside a quantum: not a line break
    b.ne  9f
    mov   x8, x0
5:
    cbz   x1, 6f
    ldrb  w7, [x0]
    cmp   w7, #13
    ccmp  w7, #10, #4, ne
    b.ne  6f
    add   x0, x0, #1
    sub   x1, x1, #1
    b     5b
6:
    cmp   x0, x8
    b.ne  0b                        // skipped a line break: carry on
9:
    sub   x2, x2, x5
    sub   x0, x0, x3
    str   x2, [x6]
    ret

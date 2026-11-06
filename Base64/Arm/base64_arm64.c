/*
  Base64 ARM64 kernels written in C (clang, arm_neon.h intrinsics).

  Built for macOS, iOS, the iOS simulator and Android by build_arm64.sh and
  linked into the Delphi ARM64 targets. Every function has a hand-written
  assembly twin in base64_arm64.S (suffix _asm); the Delphi side registers
  both, the tests check both against the Pascal reference, and the benchmark
  decides which one is used (see the README).

    b64_encode_scalar_c   plain C
    b64_fused_scalar_c    plain C
    b64_encode_neon_c     NEON, 48 input bytes at a time
    b64_fused_neon_c      NEON for the bulk of each line
    b64_decode_neon_c     NEON, 64 chars at a time, then 16

  NEON is part of the ARMv8-A baseline, so there is no feature probe. No libc
  dependency.

  Encode: (src, len, dst) returns the chars written, '=' padded, no line breaks.
  Reads exactly len bytes.

  Fused: (info) writes base64 with the separator inserted after every full line.
  b64_fused_t matches TFusedInfo in Base64EncodingPolyFill.pas.

  Decode: (src, numchars, dst, written) decodes clean chars, returns the chars
  consumed and sets *written to the bytes decoded. Clean 64-char blocks go
  through ld4/st3 and the rest of a line goes 16 chars at a time. CR and LF
  between quanta are skipped here rather than in the driver, because Delphi's
  ARM64 code for that once-per-line loop costs more than decoding the line.
  It stops before the first quantum holding anything else outside the alphabet
  (space, tab, '=', invalid, or CR/LF inside a quantum), which the Pascal driver
  then deals with, or when fewer than 16 chars remain. It always stops on a
  quantum boundary of the output. It may write up to 16 bytes past *written and
  never reads past src + numchars.
*/

#include <stdint.h>
#include <stddef.h>
#include <arm_neon.h>

typedef struct {
  const uint8_t *src;
  uint8_t *dst;
  const uint8_t *sep;
  intptr_t len, line_quanta, sep_len, line_bytes, qcount;
} b64_fused_t;

static const uint8_t ENC[65] __attribute__((aligned(16))) =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Validity (Lemire/Aqrit): a byte is in the alphabet iff
   LUT_LO[low nibble] & LUT_HI[high nibble] == 0. */
static const uint8_t LUT_LO[16] __attribute__((aligned(16))) = {
  0x15,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x13,0x1A,0x1B,0x1B,0x1B,0x1A };
static const uint8_t LUT_HI[16] __attribute__((aligned(16))) = {
  0x10,0x10,0x01,0x02,0x04,0x08,0x04,0x08,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10 };
/* Offset from ASCII to the 6-bit value, by high nibble ('/' uses index 1). */
static const int8_t LUT_ROLL[16] __attribute__((aligned(16))) = {
  0,16,19,4,-65,-65,-71,-71,0,0,0,0,0,0,0,0 };

/* Byte order of a decoded 32-bit word's three bytes; the rest read as 0. */
static const uint8_t LUT_PACK[16] __attribute__((aligned(16))) = {
  2,1,0,6,5,4,10,9,8,14,13,12,255,255,255,255 };

/* ------------------------------------------------------------------------
   Scalar
   ------------------------------------------------------------------------ */

static inline uint8_t *encode_groups(const uint8_t **ps, ptrdiff_t groups, uint8_t *d) {
  const uint8_t *s = *ps;
  for (; groups > 0; groups--) {
    uint32_t v = ((uint32_t)s[0] << 16) | ((uint32_t)s[1] << 8) | s[2];
    d[0] = ENC[v >> 18];
    d[1] = ENC[(v >> 12) & 63];
    d[2] = ENC[(v >> 6) & 63];
    d[3] = ENC[v & 63];
    s += 3;
    d += 4;
  }
  *ps = s;
  return d;
}

/* The last 1 or 2 bytes of the input, with padding. */
static inline uint8_t *encode_final(const uint8_t *s, ptrdiff_t n, uint8_t *d) {
  if (n == 1) {
    d[0] = ENC[s[0] >> 2];
    d[1] = ENC[(s[0] & 3) << 4];
    d[2] = '=';
    d[3] = '=';
    return d + 4;
  }
  if (n == 2) {
    d[0] = ENC[s[0] >> 2];
    d[1] = ENC[((s[0] & 3) << 4) | (s[1] >> 4)];
    d[2] = ENC[(s[1] & 15) << 2];
    d[3] = '=';
    return d + 4;
  }
  return d;
}

intptr_t b64_encode_scalar_c(const uint8_t *src, intptr_t len, uint8_t *dst) {
  uint8_t *d = encode_groups(&src, len / 3, dst);
  d = encode_final(src, len % 3, d);
  return d - dst;
}

static inline uint8_t *put_sep(uint8_t *d, const b64_fused_t *f) {
  for (intptr_t i = 0; i < f->sep_len; i++)
    *d++ = f->sep[i];
  return d;
}

void b64_fused_scalar_c(b64_fused_t *f) {
  const uint8_t *s = f->src;
  uint8_t *d = f->dst;
  intptr_t n = f->len;
  for (; n >= f->line_bytes; n -= f->line_bytes) {
    d = encode_groups(&s, f->line_quanta, d);
    d = put_sep(d, f);
  }
  d = encode_groups(&s, n / 3, d);
  encode_final(s, n % 3, d);
}

/* ------------------------------------------------------------------------
   NEON
   ------------------------------------------------------------------------ */

/* 48 bytes to 64 chars per block. Advances *ps; returns the new dst. */
static inline uint8_t *encode_blocks(const uint8_t **ps, ptrdiff_t blocks, uint8_t *d) {
  const uint8_t *s = *ps;
  const uint8x16x4_t tbl = vld1q_u8_x4(ENC);
  const uint8x16_t m63 = vdupq_n_u8(63);
  for (; blocks > 0; blocks--) {
    uint8x16x3_t in = vld3q_u8(s);
    uint8x16x4_t o;
    o.val[0] = vshrq_n_u8(in.val[0], 2);
    o.val[1] = vandq_u8(vsliq_n_u8(vshrq_n_u8(in.val[1], 4), in.val[0], 4), m63);
    o.val[2] = vandq_u8(vsliq_n_u8(vshrq_n_u8(in.val[2], 6), in.val[1], 2), m63);
    o.val[3] = vandq_u8(in.val[2], m63);
    o.val[0] = vqtbl4q_u8(tbl, o.val[0]);
    o.val[1] = vqtbl4q_u8(tbl, o.val[1]);
    o.val[2] = vqtbl4q_u8(tbl, o.val[2]);
    o.val[3] = vqtbl4q_u8(tbl, o.val[3]);
    vst4q_u8(d, o);
    s += 48;
    d += 64;
  }
  *ps = s;
  return d;
}

intptr_t b64_encode_neon_c(const uint8_t *src, intptr_t len, uint8_t *dst) {
  uint8_t *d = encode_blocks(&src, len / 48, dst);
  len %= 48;
  d = encode_groups(&src, len / 3, d);
  d = encode_final(src, len % 3, d);
  return d - dst;
}

void b64_fused_neon_c(b64_fused_t *f) {
  const uint8_t *s = f->src;
  uint8_t *d = f->dst;
  intptr_t n = f->len;
  const ptrdiff_t blocks = f->line_bytes / 48;
  const ptrdiff_t groups = (f->line_bytes % 48) / 3;
  for (; n >= f->line_bytes; n -= f->line_bytes) {
    d = encode_blocks(&s, blocks, d);
    d = encode_groups(&s, groups, d);
    d = put_sep(d, f);
  }
  d = encode_blocks(&s, n / 48, d);
  n %= 48;
  d = encode_groups(&s, n / 3, d);
  encode_final(s, n % 3, d);
}

static inline uint8x16_t decode_lane(uint8x16_t c, uint8x16_t *err, uint8x16_t lo,
                                     uint8x16_t hi, uint8x16_t roll) {
  const uint8x16_t h = vshrq_n_u8(c, 4);
  const uint8x16_t l = vandq_u8(c, vdupq_n_u8(0x0F));
  *err = vorrq_u8(*err, vandq_u8(vqtbl1q_u8(lo, l), vqtbl1q_u8(hi, h)));
  const uint8x16_t slash = vceqq_u8(c, vdupq_n_u8(0x2F));
  return vaddq_u8(c, vqtbl1q_u8(roll, vaddq_u8(h, slash)));
}

/* 16 6-bit values to 12 bytes, in the low 12 bytes of the result. */
static inline uint8x16_t decode_pack(uint8x16_t v) {
  const uint16x8_t t = vreinterpretq_u16_u8(v);
  const uint16x8_t x = vorrq_u16(vshlq_n_u16(vandq_u16(t, vdupq_n_u16(0x00FF)), 6),
                                 vshrq_n_u16(t, 8));
  const uint32x4_t w = vreinterpretq_u32_u16(x);
  const uint32x4_t y = vorrq_u32(vshlq_n_u32(vandq_u32(w, vdupq_n_u32(0xFFFF)), 12),
                                 vshrq_n_u32(w, 16));
  return vqtbl1q_u8(vreinterpretq_u8_u32(y), vld1q_u8(LUT_PACK));
}

intptr_t b64_decode_neon_c(const uint8_t *src, intptr_t numchars, uint8_t *dst,
                           intptr_t *written) {
  const uint8x16_t lo = vld1q_u8(LUT_LO), hi = vld1q_u8(LUT_HI);
  const uint8x16_t roll = vreinterpretq_u8_s8(vld1q_s8(LUT_ROLL));
  const uint8_t *s = src;
  uint8_t *const dst0 = dst;
again:
  for (; numchars >= 64; numchars -= 64) {
    uint8x16x4_t in = vld4q_u8(s);
    uint8x16_t err = vdupq_n_u8(0);
    uint8x16_t a = decode_lane(in.val[0], &err, lo, hi, roll);
    uint8x16_t b = decode_lane(in.val[1], &err, lo, hi, roll);
    uint8x16_t c = decode_lane(in.val[2], &err, lo, hi, roll);
    uint8x16_t e = decode_lane(in.val[3], &err, lo, hi, roll);
    if (vmaxvq_u8(err))
      break;
    uint8x16x3_t o;
    o.val[0] = vorrq_u8(vshlq_n_u8(a, 2), vshrq_n_u8(b, 4));
    o.val[1] = vorrq_u8(vshlq_n_u8(b, 4), vshrq_n_u8(c, 2));
    o.val[2] = vorrq_u8(vshlq_n_u8(c, 6), e);
    vst3q_u8(dst, o);
    s += 64;
    dst += 48;
  }
  for (; numchars >= 16; numchars -= 16) {
    uint8x16_t err = vdupq_n_u8(0);
    const uint8x16_t o = decode_pack(decode_lane(vld1q_u8(s), &err, lo, hi, roll));
    /* 4 bits per byte: non-zero where the byte is outside the alphabet */
    const uint64_t bad = vget_lane_u64(vreinterpret_u64_u8(
      vshrn_n_u16(vreinterpretq_u16_u8(vtstq_u8(err, err)), 4)), 0);
    if (bad) {
      const int index = __builtin_ctzll(bad) >> 2;
      const int quanta = index >> 2;
      if (quanta) {
        vst1q_u8(dst, o);
        s += quanta * 4;
        numchars -= quanta * 4;
        dst += quanta * 3;
      }
      if (index & 3)
        break;                   /* inside a quantum */
      const uint8_t *const start = s;
      while (numchars > 0 && (*s == 13 || *s == 10)) {
        s++;
        numchars--;
      }
      if (s == start)
        break;
      goto again;
    }
    vst1q_u8(dst, o);
    s += 16;
    dst += 12;
  }
  *written = dst - dst0;
  return s - src;
}

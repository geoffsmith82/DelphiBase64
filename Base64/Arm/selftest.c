/*
  Developer self-test for the ARM64 kernels, run directly on an ARM64 Mac:
    build_arm64.sh selftest
  Checks every variant against a plain reference for many lengths, line widths
  and bad-byte positions, then prints throughput. The Delphi harness
  (Tests\PolyFillTestRunner.pas) is the authoritative check; this exists to
  iterate quickly on the kernels.
*/
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

typedef struct {
  const uint8_t *src; uint8_t *dst; const uint8_t *sep;
  intptr_t len, line_quanta, sep_len, line_bytes, qcount;
} b64_fused_t;

typedef intptr_t (*encfn)(const uint8_t *, intptr_t, uint8_t *);
typedef void (*fusedfn)(b64_fused_t *);
typedef intptr_t (*decfn)(const uint8_t *, intptr_t, uint8_t *, intptr_t *);

#define E(n) intptr_t n(const uint8_t *, intptr_t, uint8_t *);
#define F(n) void n(b64_fused_t *);
E(b64_encode_scalar_c) E(b64_encode_scalar_asm) E(b64_encode_neon_c) E(b64_encode_neon_asm)
F(b64_fused_scalar_c) F(b64_fused_scalar_asm) F(b64_fused_neon_c) F(b64_fused_neon_asm)
intptr_t b64_decode_neon_c(const uint8_t *, intptr_t, uint8_t *, intptr_t *);
intptr_t b64_decode_neon_asm(const uint8_t *, intptr_t, uint8_t *, intptr_t *);

static const char AB[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static int fails = 0;

static size_t ref_encode(const uint8_t *s, size_t n, uint8_t *d) {
  uint8_t *o = d;
  for (; n >= 3; n -= 3, s += 3) {
    uint32_t v = s[0] << 16 | s[1] << 8 | s[2];
    *o++ = AB[v >> 18]; *o++ = AB[(v >> 12) & 63]; *o++ = AB[(v >> 6) & 63]; *o++ = AB[v & 63];
  }
  if (n) {
    uint32_t v = s[0] << 16 | (n == 2 ? s[1] << 8 : 0);
    *o++ = AB[v >> 18]; *o++ = AB[(v >> 12) & 63];
    *o++ = n == 2 ? AB[(v >> 6) & 63] : '='; *o++ = '=';
  }
  return o - d;
}

/* Wrap reference: a separator after every full line of groups. */
static size_t ref_fused(const uint8_t *s, size_t n, size_t q, const uint8_t *sep, size_t sl, uint8_t *d) {
  uint8_t *o = d;
  for (; n >= q * 3; n -= q * 3, s += q * 3) {
    o += ref_encode(s, q * 3, o);
    memcpy(o, sep, sl); o += sl;
  }
  o += ref_encode(s, n, o);
  return o - d;
}

static int in_alphabet(uint8_t c) { return c && strchr(AB, c) != NULL; }

#define MAXN 8192
#define GUARD 64
static uint8_t in[MAXN], out1[MAXN * 3], out2[MAXN * 3];

static void check_encode(const char *name, encfn fn) {
  for (size_t n = 0; n < 2000; n = n < 300 ? n + 1 : n * 3 / 2) {
    size_t rl = ref_encode(in, n, out1);
    memset(out2, 0xCC, rl + GUARD);
    intptr_t r = fn(in, n, out2);
    if ((size_t)r != rl || memcmp(out1, out2, rl)) { printf("FAIL %s n=%zu\n", name, n); fails++; }
    for (size_t i = rl; i < rl + GUARD; i++)
      if (out2[i] != 0xCC) { printf("FAIL %s overrun n=%zu\n", name, n); fails++; break; }
  }
}

static void check_fused(const char *name, fusedfn fn) {
  static const uint8_t seps[] = { 13, 10, 0x7C, 0x21, 0x22 };
  for (size_t n = 0; n < 1500; n = n < 260 ? n + 1 : n * 3 / 2)
    for (size_t q = 1; q < 70; q = q < 20 ? q + 1 : q * 2)
      for (size_t sl = 0; sl <= 5; sl++) {
        size_t rl = ref_fused(in, n, q, seps, sl, out1);
        memset(out2, 0xCC, rl + GUARD);
        b64_fused_t f = { in, out2, seps, (intptr_t)n, (intptr_t)q, (intptr_t)sl, (intptr_t)(q * 3), 0 };
        fn(&f);
        if (memcmp(out1, out2, rl)) { printf("FAIL %s n=%zu q=%zu sl=%zu\n", name, n, q, sl); fails++; }
        for (size_t i = rl; i < rl + GUARD; i++)
          if (out2[i] != 0xCC) { printf("FAIL %s overrun n=%zu q=%zu\n", name, n, q); fails++; break; }
      }
}

static void check_decode(const char *name, decfn fn) {
  intptr_t wr;
  /* clean input of every block count, with a dirty-free remainder < 64 */
  for (size_t blocks = 0; blocks <= 6; blocks++) {
    size_t n = blocks * 48;
    size_t chars = ref_encode(in, n, out1);
    for (size_t extra = 0; extra < 64; extra += 7) {
      memset(out1 + chars, 'A', extra);
      memset(out2, 0xCC, n + 48 + GUARD);
      intptr_t c = fn(out1, chars + extra, out2, &wr);
      size_t want = chars + (extra & ~(size_t)15);   /* whole 16-char loads */
      if ((size_t)c != want || (size_t)wr != want / 4 * 3 || memcmp(out2, in, n)) { printf("FAIL %s clean blocks=%zu extra=%zu\n", name, blocks, extra); fails++; }
      if (out2[want / 4 * 3 + 16] != 0xCC) { printf("FAIL %s overrun blocks=%zu\n", name, blocks); fails++; }
    }
  }
  /* every byte value at every position of the second block */
  ref_encode(in, 48 * 3, out1);
  for (int v = 0; v < 256; v++)
    for (int pos = 64; pos < 128; pos++) {
      uint8_t save = out1[pos];
      out1[pos] = (uint8_t)v;
      intptr_t c = fn(out1, 64 * 3, out2, &wr);
      intptr_t want = in_alphabet((uint8_t)v) ? 64 * 3 : pos & ~3;
      if ((v == 13 || v == 10) && (pos & 3) == 0) {
        /* a line break between quanta: skipped, then the rest in 16-char loads */
        intptr_t rest = 64 * 3 - pos - 1;
        want = pos + 1 + (rest & ~(intptr_t)15);
      }
      if (c != want) { printf("FAIL %s byte=%d pos=%d consumed %ld want %ld\n", name, v, pos, (long)c, (long)want); fails++; }
      else if (!in_alphabet((uint8_t)v) && memcmp(out2, in, (pos & ~3) / 4 * 3)) { printf("FAIL %s bytes before byte=%d pos=%d\n", name, v, pos); fails++; }
      out1[pos] = save;
    }
  /* each alphabet char must decode to its own value, in every lane, on both
     the 64-char and the 16-char paths */
  for (int len = 16; len <= 64; len += 48)
    for (int lane = 0; lane < 4; lane++) {
      uint8_t chars[64], o[64];
      for (int i = 0; i < 64; i++) chars[i] = 'A';
      for (int v = 0; v < 64; v++) {
        for (int i = 0; i < len / 4; i++) chars[i * 4 + lane] = (uint8_t)AB[(v + i) & 63];
        fn(chars, len, o, &wr);
        for (int i = 0; i < len / 4; i++) {
          uint32_t w = o[i * 3] << 16 | o[i * 3 + 1] << 8 | o[i * 3 + 2];
          if (((w >> (18 - lane * 6)) & 63) != (uint32_t)((v + i) & 63)) { printf("FAIL %s value len=%d lane=%d v=%d\n", name, len, lane, v); fails++; }
        }
      }
    }
  /* input ending in line breaks, with more of them just past the end: skipping
     must stop at numchars */
  for (int clean = 16; clean <= 64 + 16; clean += 16) {
    memset(out1, 'A', clean);
    memset(out1 + clean, 10, 32);
    intptr_t c = fn(out1, clean + 16, out2, &wr);
    if (c != clean + 16) { printf("FAIL %s trailing breaks clean=%d consumed %ld\n", name, clean, (long)c); fails++; }
  }
  /* wrapped text: every line width, CRLF and LF. Everything but the last few
     chars must go through the kernel in one call, with the right bytes. */
  for (size_t line = 4; line <= 300; line += 4)
    for (int crlf = 0; crlf <= 1; crlf++) {
      size_t chars = ref_encode(in, 3000, out2), n = 0;
      for (size_t i = 0; i < chars; i++) {
        if (i && i % line == 0) { if (crlf) out1[n++] = 13; out1[n++] = 10; }
        out1[n++] = out2[i];
      }
      memset(out2, 0xCC, 3000 + 64);
      intptr_t c = fn(out1, n, out2, &wr);
      if ((size_t)c + 16 + 2 < n || wr < 3000 - 12 - 3 || memcmp(out2, in, wr)) {
        printf("FAIL %s wrapped line=%zu crlf=%d consumed %ld of %zu wrote %ld\n", name, line, crlf, (long)c, n, (long)wr);
        fails++;
      }
    }
}

static double now(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return t.tv_sec + t.tv_nsec * 1e-9;
}

#define BENCHN (1 << 20)
#define BEST(EXPR, BYTES) do { double best = 1e9; \
    for (int r = 0; r < 15; r++) { double t0 = now(); EXPR; double t = now() - t0; if (t < best) best = t; } \
    printf(" %8.0f MB/s", (BYTES) / best / (1024.0 * 1024.0)); } while (0)

static uint8_t *bin, *txt, *o;
static const uint8_t CRLF[2] = { 13, 10 };

static void bench_enc(const char *name, encfn fn) {
  printf("%-22s", name); BEST(fn(bin, BENCHN, o), BENCHN); printf("\n");
}
static void bench_fused(const char *name, fusedfn fn) {
  printf("%-22s", name);
  b64_fused_t f = { bin, o, CRLF, BENCHN, 19, 2, 57, 0 };
  BEST(fn(&f), BENCHN); printf("\n");
}
static void bench_dec(const char *name, decfn fn, size_t chars) {
  intptr_t wr;
  printf("%-22s", name); BEST(fn(txt, chars, o, &wr), chars); printf("\n");
}

int main(void) {
  srand(12345);
  for (size_t i = 0; i < MAXN; i++) in[i] = (uint8_t)(rand() >> 7);
  check_encode("encode scalar c", b64_encode_scalar_c);
  check_encode("encode scalar asm", b64_encode_scalar_asm);
  check_encode("encode neon c", b64_encode_neon_c);
  check_encode("encode neon asm", b64_encode_neon_asm);
  check_fused("fused scalar c", b64_fused_scalar_c);
  check_fused("fused scalar asm", b64_fused_scalar_asm);
  check_fused("fused neon c", b64_fused_neon_c);
  check_fused("fused neon asm", b64_fused_neon_asm);
  check_decode("decode neon c", b64_decode_neon_c);
  check_decode("decode neon asm", b64_decode_neon_asm);
  printf(fails ? "SELFTEST FAILED: %d\n" : "selftest ok\n", fails);

  bin = malloc(BENCHN + 64); txt = malloc(BENCHN * 2); o = malloc(BENCHN * 2);
  for (size_t i = 0; i < BENCHN; i++) bin[i] = (uint8_t)(rand() >> 7);
  size_t chars = ref_encode(bin, BENCHN, txt) & ~(size_t)63;
  bench_enc("encode scalar c", b64_encode_scalar_c);
  bench_enc("encode scalar asm", b64_encode_scalar_asm);
  bench_enc("encode neon c", b64_encode_neon_c);
  bench_enc("encode neon asm", b64_encode_neon_asm);
  bench_fused("fused scalar c", b64_fused_scalar_c);
  bench_fused("fused scalar asm", b64_fused_scalar_asm);
  bench_fused("fused neon c", b64_fused_neon_c);
  bench_fused("fused neon asm", b64_fused_neon_asm);
  bench_dec("decode neon c", b64_decode_neon_c, chars);
  bench_dec("decode neon asm", b64_decode_neon_asm, chars);
  /* 76-char lines, CRLF */
  b64_fused_t f = { bin, txt, CRLF, BENCHN, 19, 2, 57, 0 };
  b64_fused_neon_asm(&f);
  chars = BENCHN / 57 * 78;
  bench_dec("decode 76 neon c", b64_decode_neon_c, chars);
  bench_dec("decode 76 neon asm", b64_decode_neon_asm, chars);
  return fails != 0;
}

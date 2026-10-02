/*
  Developer self-test for the ARM64 kernels, run directly on an ARM64 Mac:
    build_arm64.sh selftest
  Checks every variant (C, C+crypto, asm, asm+crypto) against known digests
  and against each other for 0..40 blocks of random data, then prints raw
  block-function throughput. The Delphi tests (Tests\FastHashTests) are the
  authoritative check; this exists to iterate quickly on the kernels.
*/
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

typedef void (*blockfn)(void *st, const uint8_t *p, size_t blocks);

#define DECL(n) void n(void *st, const uint8_t *p, size_t blocks);
DECL(fh_md5_c) DECL(fh_md5_asm)
DECL(fh_sha1_c) DECL(fh_sha1_asm) DECL(fh_sha1_ce_c) DECL(fh_sha1_ce_asm)
DECL(fh_sha256_c) DECL(fh_sha256_asm) DECL(fh_sha256_ce_c) DECL(fh_sha256_ce_asm)
DECL(fh_sha512_c) DECL(fh_sha512_asm) DECL(fh_sha512_ce_c) DECL(fh_sha512_ce_asm)
int32_t fh_bobjenkins_c(const uint8_t *p, int32_t len, int32_t initval);
int32_t fh_bobjenkins_asm(const uint8_t *p, int32_t len, int32_t initval);
uint32_t fh_fnv1a32_c(const uint8_t *p, uint32_t len, uint32_t h);
uint32_t fh_fnv1a32_asm(const uint8_t *p, uint32_t len, uint32_t h);
uint64_t fh_fnv1a64_c(const uint8_t *p, uint32_t len, uint64_t h);
uint64_t fh_fnv1a64_asm(const uint8_t *p, uint32_t len, uint64_t h);
uint32_t fh_arm64_features(void);

typedef struct { const char *name; blockfn fn; int need; } impl_t;
typedef struct {
  const char *alg; int bs; int statesz; int bigend; int lenbytes;
  uint8_t iv[64]; impl_t impls[4]; const char *abc;
} alg_t;

static int fails = 0;

static void hash_msg(const alg_t *a, blockfn fn, const uint8_t *msg, size_t len, uint8_t *out) {
  uint8_t st[64], buf[256];
  memcpy(st, a->iv, a->statesz);
  size_t full = len / a->bs;
  if (full) fn(st, msg, full);
  size_t rem = len - full * a->bs;
  memset(buf, 0, sizeof(buf));
  memcpy(buf, msg + full * a->bs, rem);
  buf[rem] = 0x80;
  size_t tot = (rem + 1 + a->lenbytes <= (size_t)a->bs) ? a->bs : 2 * a->bs;
  uint64_t bits = (uint64_t)len * 8;
  for (int i = 0; i < 8; i++) {
    if (a->bigend) buf[tot - 1 - i] = (uint8_t)(bits >> (8 * i));
    else buf[tot - 8 + i] = (uint8_t)(bits >> (8 * i));
  }
  fn(st, buf, tot / a->bs);
  /* digest: words in big-endian for SHA, little-endian for MD5 */
  int wsz = (a->statesz == 64) ? 8 : 4;
  for (int i = 0; i < a->statesz; i += wsz)
    for (int j = 0; j < wsz; j++)
      out[i + j] = a->bigend ? st[i + wsz - 1 - j] : st[i + j];
}

static void hex(const uint8_t *b, int n, char *s) {
  for (int i = 0; i < n; i++) sprintf(s + 2 * i, "%02x", b[i]);
}

static double now(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec + ts.tv_nsec * 1e-9;
}

int main(void) {
  uint32_t feat = fh_arm64_features();
  printf("features: sha1=%d sha256=%d sha512=%d\n", !!(feat & 1), !!(feat & 2), !!(feat & 4));

  static alg_t algs[4];
  memset(algs, 0, sizeof(algs));
  uint32_t md5iv[4] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};
  uint32_t sha1iv[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
  uint32_t sha256iv[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
  uint64_t sha512iv[8] = {0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
                          0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};
  algs[0] = (alg_t){"MD5", 64, 16, 0, 8, {0}, {{"c", (blockfn)fh_md5_c, 0}, {"asm", (blockfn)fh_md5_asm, 0}},
                    "900150983cd24fb0d6963f7d28e17f72"};
  memcpy(algs[0].iv, md5iv, 16);
  algs[1] = (alg_t){"SHA-1", 64, 20, 1, 8, {0},
                    {{"c", (blockfn)fh_sha1_c, 0}, {"asm", (blockfn)fh_sha1_asm, 0},
                     {"ce_c", (blockfn)fh_sha1_ce_c, 1}, {"ce_asm", (blockfn)fh_sha1_ce_asm, 1}},
                    "a9993e364706816aba3e25717850c26c9cd0d89d"};
  memcpy(algs[1].iv, sha1iv, 20);
  algs[2] = (alg_t){"SHA-256", 64, 32, 1, 8, {0},
                    {{"c", (blockfn)fh_sha256_c, 0}, {"asm", (blockfn)fh_sha256_asm, 0},
                     {"ce_c", (blockfn)fh_sha256_ce_c, 2}, {"ce_asm", (blockfn)fh_sha256_ce_asm, 2}},
                    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"};
  memcpy(algs[2].iv, sha256iv, 32);
  algs[3] = (alg_t){"SHA-512", 128, 64, 1, 16, {0},
                    {{"c", (blockfn)fh_sha512_c, 0}, {"asm", (blockfn)fh_sha512_asm, 0},
                     {"ce_c", (blockfn)fh_sha512_ce_c, 4}, {"ce_asm", (blockfn)fh_sha512_ce_asm, 4}},
                    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                    "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"};
  memcpy(algs[3].iv, sha512iv, 64);

  size_t big = 1 << 20;
  uint8_t *data = malloc(big);
  uint32_t seed = 12345;
  for (size_t i = 0; i < big; i++) { seed = seed * 1103515245 + 12345; data[i] = (uint8_t)(seed >> 16); }

  for (int ai = 0; ai < 4; ai++) {
    alg_t *a = &algs[ai];
    for (int k = 0; k < 4 && a->impls[k].fn; k++) {
      impl_t *im = &a->impls[k];
      if (im->need && !(feat & im->need)) { printf("%-8s %-7s skipped (no CPU support)\n", a->alg, im->name); continue; }
      uint8_t out[64], ref[64];
      char s[160];
      hash_msg(a, im->fn, (const uint8_t *)"abc", 3, out);
      hex(out, a->statesz, s);
      int ok = strcmp(s, a->abc) == 0;
      /* cross-check against the plain C variant over many lengths */
      int bad = 0;
      for (size_t len = 0; len < 3000; len += 1 + len / 3) {
        hash_msg(a, a->impls[0].fn, data, len, ref);
        hash_msg(a, im->fn, data, len, out);
        if (memcmp(ref, out, a->statesz) != 0) bad++;
      }
      /* throughput of the raw block function on 1 MB */
      uint8_t st[64];
      memcpy(st, a->iv, a->statesz);
      double best = 1e9;
      for (int r = 0; r < 20; r++) {
        double t0 = now();
        im->fn(st, data, big / a->bs);
        double t = now() - t0;
        if (t < best) best = t;
      }
      printf("%-8s %-7s abc %s  cross %s  %8.1f MB/s\n", a->alg, im->name, ok ? "ok  " : "FAIL",
             bad ? "FAIL" : "ok  ", big / 1048576.0 / best);
      if (!ok || bad) fails++;
    }
  }

  /* non-crypto: asm vs C over lengths, alignments and seeds */
  {
    int bad = 0;
    for (int off = 0; off < 4; off++)
      for (int len = 0; len < 400; len++) {
        int32_t s = len * 7919 - 12345;
        if (fh_bobjenkins_c(data + off, len, s) != fh_bobjenkins_asm(data + off, len, s)) bad++;
        if (fh_fnv1a32_c(data + off, len, (uint32_t)s) != fh_fnv1a32_asm(data + off, len, (uint32_t)s)) bad++;
        if (fh_fnv1a64_c(data + off, len, (uint64_t)s * 31) != fh_fnv1a64_asm(data + off, len, (uint64_t)s * 31)) bad++;
      }
    /* lookup3.c driver vectors and FNV-1a reference values */
    const char *fs = "Four score and seven years ago";
    if ((uint32_t)fh_bobjenkins_asm((const uint8_t *)fs, 30, 0) != 0x17770551u) bad++;
    if ((uint32_t)fh_bobjenkins_c((const uint8_t *)fs, 30, 1) != 0xcd628161u) bad++;
    if (fh_fnv1a32_asm((const uint8_t *)"foobar", 6, 0x811C9DC5u) != 0xbf9cf968u) bad++;
    if (fh_fnv1a64_asm((const uint8_t *)"foobar", 6, 0xCBF29CE484222325ULL) != 0x85944171f73967e8ULL) bad++;
    printf("noncrypto asm vs c + vectors: %s\n", bad ? "FAIL" : "ok");
    if (bad) fails++;

    struct { const char *n; int which; } nc[] = {{"bobjenkins", 0}, {"fnv1a32", 1}, {"fnv1a64", 2}};
    for (int i = 0; i < 3; i++) {
      double bc = 1e9, ba = 1e9;
      volatile uint64_t sink = 0;
      for (int r = 0; r < 10; r++) {
        double t0 = now();
        if (nc[i].which == 0) sink += fh_bobjenkins_c(data, (int32_t)big, 0);
        else if (nc[i].which == 1) sink += fh_fnv1a32_c(data, (uint32_t)big, 1);
        else sink += fh_fnv1a64_c(data, (uint32_t)big, 1);
        double t = now() - t0; if (t < bc) bc = t;
        t0 = now();
        if (nc[i].which == 0) sink += fh_bobjenkins_asm(data, (int32_t)big, 0);
        else if (nc[i].which == 1) sink += fh_fnv1a32_asm(data, (uint32_t)big, 1);
        else sink += fh_fnv1a64_asm(data, (uint32_t)big, 1);
        t = now() - t0; if (t < ba) ba = t;
      }
      printf("%-10s c %8.1f MB/s   asm %8.1f MB/s\n", nc[i].n, big / 1048576.0 / bc, big / 1048576.0 / ba);
    }
  }
  printf(fails ? "SELFTEST FAILED (%d)\n" : "SELFTEST OK\n", fails);
  return fails != 0;
}

/*
  FastHash ARM64 kernels written in C (clang, arm_neon.h intrinsics).

  Built for macOS, iOS, the iOS simulator and Android by build_arm64.sh and
  linked into the Delphi ARM64 targets. Every function has a hand-written
  assembly twin in fasthash_arm64.S (suffix _asm); the Delphi side registers
  both, the tests check both against the Pascal reference, and the benchmark
  decides which one each algorithm uses (see the README).

    fh_<alg>_c        plain C, any ARMv8-A CPU
    fh_<alg>_ce_c     ARMv8 Cryptographic Extension instructions via
                      intrinsics: SHA-1/SHA-256 need FEAT_SHA1/FEAT_SHA256,
                      SHA-512 needs FEAT_SHA512 (ARMv8.2)

  Block functions: fh_X(state, data, blocks) - state layout is the same as
  the Delphi units (MD5/SHA-1/SHA-256: Cardinals, SHA-512: UInt64), all
  native (little-endian) words. No libc dependency except the feature probe.
*/

#include <stdint.h>
#include <stddef.h>
#include <arm_neon.h>

#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define ROR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

static inline uint32_t load_be32(const uint8_t *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
static inline uint64_t load_be64(const uint8_t *p) {
  return ((uint64_t)load_be32(p) << 32) | load_be32(p + 4);
}
static inline uint32_t load_le32(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* ------------------------------------------------------------------------
   CPU features
   ------------------------------------------------------------------------ */

#define FH_FEAT_SHA1   1
#define FH_FEAT_SHA256 2
#define FH_FEAT_SHA512 4

#if defined(__APPLE__)
extern int sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
static int apple_has(const char *name, int dflt) {
  int v = 0;
  size_t sz = sizeof(v);
  if (sysctlbyname(name, &v, &sz, NULL, 0) != 0)
    return dflt;
  return v != 0;
}
#elif defined(__ANDROID__) || defined(__linux__)
extern unsigned long getauxval(unsigned long type);
#define FH_AT_HWCAP      16
#define FH_HWCAP_SHA1    (1UL << 5)
#define FH_HWCAP_SHA2    (1UL << 6)
#define FH_HWCAP_SHA512  (1UL << 21)
#endif

uint32_t fh_arm64_features(void) {
  uint32_t f = 0;
#if defined(__APPLE__)
  /* every Apple ARM64 CPU has SHA-1/SHA-256; the FEAT_ names need macOS 12 / iOS 15 */
  if (apple_has("hw.optional.arm.FEAT_SHA1", 1)) f |= FH_FEAT_SHA1;
  if (apple_has("hw.optional.arm.FEAT_SHA256", 1)) f |= FH_FEAT_SHA256;
  if (apple_has("hw.optional.arm.FEAT_SHA512", 0) || apple_has("hw.optional.armv8_2_sha512", 0))
    f |= FH_FEAT_SHA512;
#elif defined(__ANDROID__) || defined(__linux__)
  unsigned long hw = getauxval(FH_AT_HWCAP);
  if (hw & FH_HWCAP_SHA1) f |= FH_FEAT_SHA1;
  if (hw & FH_HWCAP_SHA2) f |= FH_FEAT_SHA256;
  if (hw & FH_HWCAP_SHA512) f |= FH_FEAT_SHA512;
#endif
  return f;
}

/* ------------------------------------------------------------------------
   MD5
   ------------------------------------------------------------------------ */

static const uint32_t MD5_T[64] = {
  0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
  0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
  0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
  0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
  0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
  0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
  0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
  0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
};
static const uint8_t MD5_S[4][4] = { {7, 12, 17, 22}, {5, 9, 14, 20}, {4, 11, 16, 23}, {6, 10, 15, 21} };

void fh_md5_c(uint32_t *st, const uint8_t *p, size_t blocks) {
  uint32_t a = st[0], b = st[1], c = st[2], d = st[3];
  while (blocks--) {
    uint32_t x[16];
    for (int i = 0; i < 16; i++) x[i] = load_le32(p + 4 * i);
    uint32_t aa = a, bb = b, cc = c, dd = d;
#pragma clang loop unroll(full)
    for (int i = 0; i < 64; i++) {
      uint32_t f;
      int k;
      if (i < 16)      { f = d ^ (b & (c ^ d));  k = i; }
      else if (i < 32) { f = (b & d) + (c & ~d); k = (1 + 5 * i) & 15; }
      else if (i < 48) { f = b ^ c ^ d;          k = (5 + 3 * i) & 15; }
      else             { f = c ^ (b | ~d);       k = (7 * i) & 15; }
      uint32_t t = a + f + x[k] + MD5_T[i];
      a = d; d = c; c = b;
      b = b + ROL32(t, MD5_S[i >> 4][i & 3]);
    }
    a += aa; b += bb; c += cc; d += dd;
    p += 64;
  }
  st[0] = a; st[1] = b; st[2] = c; st[3] = d;
}

/* ------------------------------------------------------------------------
   SHA-1
   ------------------------------------------------------------------------ */

void fh_sha1_c(uint32_t *st, const uint8_t *p, size_t blocks) {
  uint32_t h0 = st[0], h1 = st[1], h2 = st[2], h3 = st[3], h4 = st[4];
  while (blocks--) {
    uint32_t w[16];
    for (int i = 0; i < 16; i++) w[i] = load_be32(p + 4 * i);
    uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;
#pragma clang loop unroll(full)
    for (int i = 0; i < 80; i++) {
      uint32_t wi;
      if (i < 16) wi = w[i];
      else {
        uint32_t t = w[(i + 13) & 15] ^ w[(i + 8) & 15] ^ w[(i + 2) & 15] ^ w[i & 15];
        wi = w[i & 15] = ROL32(t, 1);
      }
      uint32_t f, k;
      if (i < 20)      { f = d ^ (b & (c ^ d));          k = 0x5A827999; }
      else if (i < 40) { f = b ^ c ^ d;                  k = 0x6ED9EBA1; }
      else if (i < 60) { f = (b & c) | (d & (b | c));    k = 0x8F1BBCDC; }
      else             { f = b ^ c ^ d;                  k = 0xCA62C1D6; }
      uint32_t t = ROL32(a, 5) + f + e + k + wi;
      e = d; d = c; c = ROL32(b, 30); b = a; a = t;
    }
    h0 += a; h1 += b; h2 += c; h3 += d; h4 += e;
    p += 64;
  }
  st[0] = h0; st[1] = h1; st[2] = h2; st[3] = h3; st[4] = h4;
}

__attribute__((target("sha2")))
void fh_sha1_ce_c(uint32_t *st, const uint8_t *p, size_t blocks) {
  uint32x4_t abcd = vld1q_u32(st);
  uint32_t e = st[4];
  const uint32x4_t K0 = vdupq_n_u32(0x5A827999), K1 = vdupq_n_u32(0x6ED9EBA1),
                   K2 = vdupq_n_u32(0x8F1BBCDC), K3 = vdupq_n_u32(0xCA62C1D6);
  while (blocks--) {
    uint32x4_t abcd0 = abcd;
    uint32_t e0 = e;
    uint32x4_t m[4];
    for (int i = 0; i < 4; i++)
      m[i] = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p + 16 * i)));
#pragma clang loop unroll(full)
    for (int g = 0; g < 20; g++) {
      uint32x4_t k = g < 5 ? K0 : g < 10 ? K1 : g < 15 ? K2 : K3;
      uint32x4_t t = vaddq_u32(m[g & 3], k);
      uint32_t en = vsha1h_u32(vgetq_lane_u32(abcd, 0));
      if (g < 5)       abcd = vsha1cq_u32(abcd, e, t);
      else if (g < 10) abcd = vsha1pq_u32(abcd, e, t);
      else if (g < 15) abcd = vsha1mq_u32(abcd, e, t);
      else             abcd = vsha1pq_u32(abcd, e, t);
      e = en;
      if (g < 16)
        m[g & 3] = vsha1su1q_u32(vsha1su0q_u32(m[g & 3], m[(g + 1) & 3], m[(g + 2) & 3]), m[(g + 3) & 3]);
    }
    abcd = vaddq_u32(abcd, abcd0);
    e += e0;
    p += 64;
  }
  vst1q_u32(st, abcd);
  st[4] = e;
}

/* ------------------------------------------------------------------------
   SHA-256
   ------------------------------------------------------------------------ */

static const uint32_t K256[64] __attribute__((aligned(16))) = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

void fh_sha256_c(uint32_t *st, const uint8_t *p, size_t blocks) {
  while (blocks--) {
    uint32_t w[16];
    for (int i = 0; i < 16; i++) w[i] = load_be32(p + 4 * i);
    uint32_t a = st[0], b = st[1], c = st[2], d = st[3], e = st[4], f = st[5], g = st[6], h = st[7];
#pragma clang loop unroll(full)
    for (int i = 0; i < 64; i++) {
      uint32_t wi;
      if (i < 16) wi = w[i];
      else {
        uint32_t w15 = w[(i + 1) & 15], w2 = w[(i + 14) & 15];
        uint32_t s0 = ROR32(w15, 7) ^ ROR32(w15, 18) ^ (w15 >> 3);
        uint32_t s1 = ROR32(w2, 17) ^ ROR32(w2, 19) ^ (w2 >> 10);
        wi = w[i & 15] = w[i & 15] + s0 + w[(i + 9) & 15] + s1;
      }
      uint32_t t1 = h + (ROR32(e, 6) ^ ROR32(e, 11) ^ ROR32(e, 25)) + (g ^ (e & (f ^ g))) + K256[i] + wi;
      uint32_t t2 = (ROR32(a, 2) ^ ROR32(a, 13) ^ ROR32(a, 22)) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    st[0] += a; st[1] += b; st[2] += c; st[3] += d; st[4] += e; st[5] += f; st[6] += g; st[7] += h;
    p += 64;
  }
}

__attribute__((target("sha2")))
void fh_sha256_ce_c(uint32_t *st, const uint8_t *p, size_t blocks) {
  uint32x4_t s0 = vld1q_u32(st), s1 = vld1q_u32(st + 4);
  while (blocks--) {
    uint32x4_t save0 = s0, save1 = s1;
    uint32x4_t m[4];
    for (int i = 0; i < 4; i++)
      m[i] = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p + 16 * i)));
#pragma clang loop unroll(full)
    for (int g = 0; g < 16; g++) {
      uint32x4_t t = vaddq_u32(m[g & 3], vld1q_u32(K256 + 4 * g));
      uint32x4_t tmp = s0;
      s0 = vsha256hq_u32(s0, s1, t);
      s1 = vsha256h2q_u32(s1, tmp, t);
      if (g < 12)
        m[g & 3] = vsha256su1q_u32(vsha256su0q_u32(m[g & 3], m[(g + 1) & 3]), m[(g + 2) & 3], m[(g + 3) & 3]);
    }
    s0 = vaddq_u32(s0, save0);
    s1 = vaddq_u32(s1, save1);
    p += 64;
  }
  vst1q_u32(st, s0);
  vst1q_u32(st + 4, s1);
}

/* ------------------------------------------------------------------------
   SHA-512
   ------------------------------------------------------------------------ */

static const uint64_t K512[80] __attribute__((aligned(16))) = {
  0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
  0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
  0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
  0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
  0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
  0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
  0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
  0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
  0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
  0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
  0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
  0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
  0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
  0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
  0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
  0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
  0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
  0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
  0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
  0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
};

void fh_sha512_c(uint64_t *st, const uint8_t *p, size_t blocks) {
  while (blocks--) {
    uint64_t w[16];
    for (int i = 0; i < 16; i++) w[i] = load_be64(p + 8 * i);
    uint64_t a = st[0], b = st[1], c = st[2], d = st[3], e = st[4], f = st[5], g = st[6], h = st[7];
#pragma clang loop unroll(full)
    for (int i = 0; i < 80; i++) {
      uint64_t wi;
      if (i < 16) wi = w[i];
      else {
        uint64_t w15 = w[(i + 1) & 15], w2 = w[(i + 14) & 15];
        uint64_t s0 = ROR64(w15, 1) ^ ROR64(w15, 8) ^ (w15 >> 7);
        uint64_t s1 = ROR64(w2, 19) ^ ROR64(w2, 61) ^ (w2 >> 6);
        wi = w[i & 15] = w[i & 15] + s0 + w[(i + 9) & 15] + s1;
      }
      uint64_t t1 = h + (ROR64(e, 14) ^ ROR64(e, 18) ^ ROR64(e, 41)) + (g ^ (e & (f ^ g))) + K512[i] + wi;
      uint64_t t2 = (ROR64(a, 28) ^ ROR64(a, 34) ^ ROR64(a, 39)) + ((a & b) | (c & (a | b)));
      h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    st[0] += a; st[1] += b; st[2] += c; st[3] += d; st[4] += e; st[5] += f; st[6] += g; st[7] += h;
    p += 128;
  }
}

/*
  SHA-512 with the ARMv8.2 SHA512H/SHA512H2/SHA512SU0/SHA512SU1 instructions.
  Each step does two rounds. The state lives in five 2x64-bit registers
  S[0..4] whose roles rotate every step: in step j the roles are
  (i0,i1,i2,i3,i4) = (ab, cd, ef, gh, spare), and afterwards
  (ab, cd, ef, gh, spare) := (i3, i0, i4, i2, i1). W lives in eight
  registers M[0..7] holding words 2j..2j+1 in M[j & 7]; steps 0..31 also
  compute words 2j+16..2j+17 into that register.
*/
__attribute__((target("sha3")))
void fh_sha512_ce_c(uint64_t *st, const uint8_t *p, size_t blocks) {
  uint64x2_t ab = vld1q_u64(st), cd = vld1q_u64(st + 2), ef = vld1q_u64(st + 4), gh = vld1q_u64(st + 6);
  while (blocks--) {
    uint64x2_t M[8];
    for (int i = 0; i < 8; i++)
      M[i] = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(p + 16 * i)));
    uint64x2_t S[5] = { ab, cd, ef, gh, ab };
    int r0 = 0, r1 = 1, r2 = 2, r3 = 3, r4 = 4;
#pragma clang loop unroll(full)
    for (int j = 0; j < 40; j++) {
      uint64x2_t kw = vaddq_u64(vld1q_u64(K512 + 2 * j), M[j & 7]);
      uint64x2_t fg = vextq_u64(S[r2], S[r3], 1);
      kw = vextq_u64(kw, kw, 1);
      uint64x2_t de = vextq_u64(S[r1], S[r2], 1);
      S[r3] = vaddq_u64(S[r3], kw);
      if (j < 32) {
        uint64x2_t w7 = vextq_u64(M[(j + 4) & 7], M[(j + 5) & 7], 1);
        M[j & 7] = vsha512su0q_u64(M[j & 7], M[(j + 1) & 7]);
        S[r3] = vsha512hq_u64(S[r3], fg, de);
        M[j & 7] = vsha512su1q_u64(M[j & 7], M[(j + 7) & 7], w7);
      } else {
        S[r3] = vsha512hq_u64(S[r3], fg, de);
      }
      S[r4] = vaddq_u64(S[r1], S[r3]);
      S[r3] = vsha512h2q_u64(S[r3], S[r1], S[r0]);
      int n0 = r3, n1 = r0, n2 = r4, n3 = r2, n4 = r1;
      r0 = n0; r1 = n1; r2 = n2; r3 = n3; r4 = n4;
    }
    ab = vaddq_u64(ab, S[r0]);
    cd = vaddq_u64(cd, S[r1]);
    ef = vaddq_u64(ef, S[r2]);
    gh = vaddq_u64(gh, S[r3]);
    p += 128;
  }
  vst1q_u64(st, ab);
  vst1q_u64(st + 2, cd);
  vst1q_u64(st + 4, ef);
  vst1q_u64(st + 6, gh);
}

/* ------------------------------------------------------------------------
   Non-cryptographic hashes (identical results to System.Hash)
   ------------------------------------------------------------------------ */

int32_t fh_bobjenkins_c(const uint8_t *p, int32_t len, int32_t initval) {
  uint32_t a, b, c;
  a = b = c = 0xDEADBEEFu + (uint32_t)len + (uint32_t)initval;
  if (len == 0)
    return (int32_t)c;
  if (len > 0) {
    while (len > 12) {
      a += load_le32(p); b += load_le32(p + 4); c += load_le32(p + 8);
      a -= c; a ^= ROL32(c, 4);  c += b;
      b -= a; b ^= ROL32(a, 6);  a += c;
      c -= b; c ^= ROL32(b, 8);  b += a;
      a -= c; a ^= ROL32(c, 16); c += b;
      b -= a; b ^= ROL32(a, 19); a += c;
      c -= b; c ^= ROL32(b, 4);  b += a;
      len -= 12;
      p += 12;
    }
    uint8_t tail[12] = {0};
    for (int i = 0; i < len; i++) tail[i] = p[i];
    a += load_le32(tail); b += load_le32(tail + 4); c += load_le32(tail + 8);
  }
  c ^= b; c -= ROL32(b, 14);
  a ^= c; a -= ROL32(c, 11);
  b ^= a; b -= ROL32(a, 25);
  c ^= b; c -= ROL32(b, 16);
  a ^= c; a -= ROL32(c, 4);
  b ^= a; b -= ROL32(a, 14);
  c ^= b; c -= ROL32(b, 24);
  return (int32_t)c;
}

uint32_t fh_fnv1a32_c(const uint8_t *p, uint32_t len, uint32_t h) {
  for (uint32_t i = 0; i < len; i++)
    h = (h ^ p[i]) * 0x01000193u;
  return h;
}

uint64_t fh_fnv1a64_c(const uint8_t *p, uint32_t len, uint64_t h) {
  for (uint32_t i = 0; i < len; i++)
    h = (h ^ p[i]) * 0x00000100000001B3ULL;
  return h;
}

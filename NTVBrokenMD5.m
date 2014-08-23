
#import "NTVBrokenMD5.h"
#include <string.h>	/* for memcpy() */

/* The four core functions - F1 is optimized somewhat */
typedef CC_LONG(*MD5_FN)(CC_LONG, CC_LONG, CC_LONG);

NTV_ALWAYS_INLINE CC_LONG F1(CC_LONG x, CC_LONG y, CC_LONG z) {
	return (z ^ (x & (y ^ z)));
}

NTV_ALWAYS_INLINE CC_LONG F2(CC_LONG x, CC_LONG y, CC_LONG z) {
	return F1(z, x, y);
}

NTV_ALWAYS_INLINE CC_LONG F3(CC_LONG x, CC_LONG y, CC_LONG z) {
	return (x ^ y ^ z);
}

NTV_ALWAYS_INLINE CC_LONG F4(CC_LONG x, CC_LONG y, CC_LONG z) {
	return y ^ (x | ~z);
}

typedef NS_ENUM(CC_LONG, S) {
	S11 =  7,
	S12 = 12,
	S13 = 17,
	S14 = 22,
	S21 =  5,
	S22 =  9,
	S23 = 14,
	S24 = 20,
	S31 =  4,
	S32 = 11,
	S33 = 16,
	S34 = 23,
	S41 =  6,
	S42 = 10,
	S43 = 15,
	S44 = 21,
};

NTV_ALWAYS_INLINE CC_LONG rotate_left(CC_LONG x, S n) {
	return (x << n) | (x >> (32-n));
}

/* This is the central step in the MD5 algorithm. */
NTV_ALWAYS_INLINE void step(MD5_FN fn, CC_LONG *w, CC_LONG x, CC_LONG y, CC_LONG z, CC_LONG data, CC_LONG ac, S s) {
	*w = rotate_left(*w + fn(x, y, z) + data + ac, s) + x;
}

/*
 * The core of the MD5 algorithm, this alters an existing MD5 hash to
 * reflect the addition of 16 longwords of new data.  MD5Update blocks
 * the data and converts bytes into longwords for this routine.
 */
static void transform(CC_LONG buf[4], CC_LONG const in[NTV_BROKEN_MD5_BLOCK_LONG])
{
	CC_LONG a, b, c, d;

	a = buf[0];
	b = buf[1];
	c = buf[2];
	d = buf[3];

	step(F1, &a, b, c, d, in[ 0], 0xd76aa478, S11);
	step(F1, &d, a, b, c, in[ 1], 0xe8c7b756, S12);
	step(F1, &c, d, a, b, in[ 2], 0x242070db, S13);
	step(F1, &b, c, d, a, in[ 3], 0xc1bdceee, S14);
	step(F1, &a, b, c, d, in[ 4], 0xf57c0faf, S11);
	step(F1, &d, a, b, c, in[ 5], 0x4787c62a, S12);
	step(F1, &c, d, a, b, in[ 6], 0xa8304613, S13);
	step(F1, &b, c, d, a, in[ 7], 0xfd469501, S14);
	step(F1, &a, b, c, d, in[ 8], 0x698098d8, S11);
	step(F1, &d, a, b, c, in[ 9], 0x8b44f7af, S12);
	step(F1, &c, d, a, b, in[10], 0xffff5bb1, S13);
	step(F1, &b, c, d, a, in[11], 0x895cd7be, S14);
	step(F1, &a, b, c, d, in[12], 0x6b901122, S11);
	step(F1, &d, a, b, c, in[13], 0xfd987193, S12);
	step(F1, &c, d, a, b, in[14], 0xa679438e, S13);
	step(F1, &b, c, d, a, in[15], 0x49b40821, S14);

	step(F2, &a, b, c, d, in[ 1], 0xf61e2562, S21);
	step(F2, &d, a, b, c, in[ 6], 0xc040b340, S22);
	step(F2, &c, d, a, b, in[11], 0x265e5a51, S23);
	step(F2, &b, c, d, a, in[ 0], 0xe9b6c7aa, S24);
	step(F2, &a, b, c, d, in[ 5], 0xd62f105d, S21);
	step(F2, &d, a, b, c, in[10], 0x02441453, S22);
	step(F2, &c, d, a, b, in[15], 0xd8a1e681, S23);
	step(F2, &b, c, d, a, in[ 4], 0xe7d3fbc8, S24);
	step(F2, &a, b, c, d, in[ 9], 0x21e1cde6, S21);
	step(F2, &d, a, b, c, in[14], 0xc33707d6, S22);
	step(F2, &c, d, a, b, in[ 3], 0xf4d50d87, S23);
	step(F2, &b, c, d, a, in[ 8], 0x455a14ed, S24);
	step(F2, &a, b, c, d, in[13], 0xa9e3e905, S21);
	step(F2, &d, a, b, c, in[ 2], 0xfcefa3f8, S22);
	step(F2, &c, d, a, b, in[ 7], 0x676f02d9, S23);
	step(F2, &b, c, d, a, in[12], 0x8d2a4c8a, S24);

	step(F3, &a, b, c, d, in[ 5], 0xfffa3942, S31);
	step(F3, &d, a, b, c, in[ 8], 0x8771f681, S32);
	step(F3, &c, d, a, b, in[11], 0x6d9d6122, S33);
	step(F3, &b, c, d, a, in[14], 0xfde5380c, S34);
	step(F3, &a, b, c, d, in[ 1], 0xa4beea44, S31);
	step(F3, &d, a, b, c, in[ 4], 0x4bdecfa9, S32);
	step(F3, &c, d, a, b, in[ 7], 0xf6bb4b60, S33);
	step(F3, &b, c, d, a, in[10], 0xbebfbc70, S34);
	step(F3, &a, b, c, d, in[13], 0x289b7ec6, S31);
	step(F3, &d, a, b, c, in[ 0], 0xeaa127fa, S32);
	step(F3, &c, d, a, b, in[ 3], 0xd4ef3085, S33);
	step(F3, &b, c, d, a, in[ 6], 0x04881d05, S34);
	step(F3, &a, b, c, d, in[ 9], 0xd9d4d039, S31);
	step(F3, &d, a, b, c, in[12], 0xe6db99e5, S32);
	step(F3, &c, d, a, b, in[15], 0x1fa27cf8, S33);
	step(F3, &b, c, d, a, in[ 2], 0xc4ac5665, S34);

	step(F4, &a, b, c, d, in[ 0], 0xf4292244, S41);
	step(F4, &d, a, b, c, in[ 7], 0x432aff97, S42);
	step(F4, &c, d, a, b, in[14], 0xab9423a7, S43);
	step(F4, &b, c, d, a, in[ 5], 0xfc93a039, S44);
	step(F4, &a, b, c, d, in[12], 0x655b59c3, S41);
	step(F4, &d, a, b, c, in[ 3], 0x8f0ccc92, S42);
	step(F4, &c, d, a, b, in[10], 0xffeff47d, S43);
	step(F4, &b, c, d, a, in[ 1], 0x85845dd1, S44);
	step(F4, &a, b, c, d, in[ 8], 0x6fa87e4f, S41);
	step(F4, &d, a, b, c, in[15], 0xfe2ce6e0, S42);
	step(F4, &c, d, a, b, in[ 6], 0xa3014314, S43);
	step(F4, &b, c, d, a, in[13], 0x4e0811a1, S44);
	step(F4, &a, b, c, d, in[ 4], 0xf7537e82, S41);
	step(F4, &d, a, b, c, in[11], 0xbd3af235, S42);
	step(F4, &c, d, a, b, in[ 2], 0x2ad7d2bb, S43);
	step(F4, &b, c, d, a, in[ 9], 0xeb86d391, S44);

	buf[0] += a;
	buf[1] += b;
	buf[2] += c;
	buf[3] += d;
}

/*
 * Note: this code is harmless on little-endian machines.
 */
NTV_ALWAYS_INLINE void byteReverse(CC_LONG *buf, CC_LONG longs) {
	for (CC_LONG i = 0; i < longs; i++) {
		buf[i] = ntohl(buf[i]);
	}
}

/*
 * Start MD5 accumulation.  Set bit count to 0 and buffer to mysterious
 * initialization constants.
 */
void NTV_BrokenMD5_Init(NTV_BrokenMD5_CTX *ctx)
{
    ctx->A = 0x67452301;
    ctx->B = 0xefcdab89;
    ctx->C = 0x98badcfe;
	ctx->D = 0x10325476;
	
	ctx->Nl = 0;
	ctx->Nh = 0;
}

/*
 * Update context to reflect the concatenation of another buffer full
 * of bytes.
 */
void NTV_BrokenMD5_Update(NTV_BrokenMD5_CTX *ctx, const void *buf, CC_LONG len)
{
    CC_LONG t;

    /* Update bitcount */

    t = ctx->Nl;
	if ((ctx->Nl = t + (len << 3)) < t) {
		// Carry from low to high
		ctx->Nh++;
	}
	ctx->Nh += len >> 29;

    t = (t >> 3) & 0x3f;	/* Bytes already in shsInfo->data */

    /* Handle any leading odd-sized chunks */

    if (t) {
		void *p = (void *)ctx->data + t;

		t = 64 - t;
		if (len < t) {
			memcpy(p, buf, len);
			return;
		}
		memcpy(p, buf, t);

		byteReverse(ctx->data, NTV_BROKEN_MD5_BLOCK_LONG);
		transform(&ctx->A, ctx->data);
		buf += t;
		len -= t;
    }
    /* Process data in 64-byte chunks */

    while (len >= 64) {
		memcpy(ctx->data, buf, 64);
		byteReverse(ctx->data, NTV_BROKEN_MD5_BLOCK_LONG);
		transform(&ctx->A, ctx->data);
		buf += 64;
		len -= 64;
    }

    /* Handle any remaining bytes of data. */
    memcpy(ctx->data, buf, len);
}

/*
 * Final wrapup - pad to 64-byte boundary with the bit pattern 
 * 1 0* (64-bit count of bits processed, MSB-first)
 */
void NTV_BrokenMD5_Final(unsigned char *md, NTV_BrokenMD5_CTX *ctx)
{
    CC_LONG count;
    uint8_t *p;

    /* Compute number of bytes mod 64 */
    count = (ctx->Nl >> 3) & 0x3F;

    /* Set the first char of padding to 0x80.  This is safe since there is
       always at least one byte free */
    p = (uint8_t *)ctx->data + count;
    *p++ = 0x80;

    /* Bytes of padding needed to make 64 bytes */
    count = 64 - 1 - count;

    /* Pad out to 56 mod 64 */
    if (count < 8) {
		/* Two lots of padding:  Pad the first block to 64 bytes */
		memset(p, 0, count);
		byteReverse(ctx->data, NTV_BROKEN_MD5_BLOCK_LONG);
		transform(&ctx->A, ctx->data);

		/* Now fill the next block with 56 bytes */
		memset(ctx->data, 0, 56);
    } else {
		/* Pad block to 56 bytes */
		memset(p, 0, count - 8);
    }
    byteReverse(ctx->data, NTV_BROKEN_MD5_BLOCK_LONG - (2 * sizeof(CC_LONG)));

    /* Append length in bits and transform */
    ctx->data[14] = ctx->Nl;
    ctx->data[15] = ctx->Nh;

    transform(&ctx->A, ctx->data);
    byteReverse(&ctx->A, NTV_BROKEN_MD5_BLOCK_LONG);
    memcpy(md, &ctx->A, NTV_BROKEN_MD5_DIGEST_LENGTH);
	bzero(ctx, sizeof(NTV_BrokenMD5_CTX));	/* In case it's sensitive */
}

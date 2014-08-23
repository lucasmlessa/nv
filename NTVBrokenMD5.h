//
//  NTVBrokenMD5.h
//  Notation
//
// This code implements the MD5 message-digest algorithm.
// The algorithm is due to Ron Rivest.  This code was
// written by Colin Plumb in 1993, no copyright is claimed.
// This code is in the public domain; do with it what you wish.
//
// Equivalent code is available from RSA Data Security, Inc.
// This code has been tested against that, and is equivalent,
// except that you don't need to include two pages of legalese
// with every copy.
//
// To compute the message digest of a chunk of bytes, declare an
// MD5Context structure, pass it to MD5Init, call MD5Update as
// needed on buffers full of bytes, and then call MD5Final, which
// will fill a supplied 16-byte array with the digest.
//
// Code modified in July 2000 by David Rigel <davidrigel@yahoo.com>
//

#import <CommonCrypto/CommonDigest.h>

#define NTV_BROKEN_MD5_DIGEST_LENGTH    16          /* digest length in bytes */
#define NTV_BROKEN_MD5_BLOCK_BYTES      64          /* block size in bytes */
#define NTV_BROKEN_MD5_BLOCK_LONG       (NTV_BROKEN_MD5_BLOCK_BYTES / sizeof(CC_LONG))

typedef struct {
	CC_LONG A,B,C,D;
	CC_LONG Nl,Nh;
	CC_LONG data[NTV_BROKEN_MD5_BLOCK_LONG];
} NTV_BrokenMD5_CTX;

void NTV_BrokenMD5_Init(NTV_BrokenMD5_CTX *context);
void NTV_BrokenMD5_Update(NTV_BrokenMD5_CTX *context, const void *buf, CC_LONG len);
void NTV_BrokenMD5_Final(unsigned char *md, NTV_BrokenMD5_CTX *context);

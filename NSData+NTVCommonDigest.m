//
//  NSData+NTVCommonDigest.m
//  Notation
//
//  Created by Zachary Waldowski on 8/23/14.
//  Copyright (c) 2014 ElasticThreads. All rights reserved.
//

#import "NSData+NTVCommonDigest.h"
#import <CommonCrypto/CommonDigest.h>
#import "NTVBrokenMD5.h"
@import Darwin.malloc;

// Function pointer types for functions used in the computation
// of a cryptographic hash.
typedef int (*NTVDigestFunctionInit)   (void *contextPtr);
typedef int (*NTVDigestFunctionUpdate) (void *contextPtr, const void *data, CC_LONG len);
typedef int (*NTVDigestFunctionFinal)  (unsigned char *buf, void *contextPtr);

struct __NTVDigest {
	NTVDigestFunctionInit init;
	NTVDigestFunctionUpdate update;
	NTVDigestFunctionFinal final;
	size_t digestLength;
	size_t contextSize;
};

static const struct __NTVDigest _NTVDigestMD5 = {
	(NTVDigestFunctionInit)CC_MD5_Init,
	(NTVDigestFunctionUpdate)CC_MD5_Update,
	(NTVDigestFunctionFinal)CC_MD5_Final,
	CC_MD5_DIGEST_LENGTH, sizeof(CC_MD5_CTX)
};
const NTVDigestRef NTVDigestMD5 = &_NTVDigestMD5;

static const struct __NTVDigest _NTVDigestSHA1 = {
	(NTVDigestFunctionInit)CC_SHA1_Init,
	(NTVDigestFunctionUpdate)CC_SHA1_Update,
	(NTVDigestFunctionFinal)CC_SHA1_Final,
	CC_SHA1_DIGEST_LENGTH, sizeof(CC_SHA1_CTX)
};
const NTVDigestRef NTVDigestSHA1 = &_NTVDigestSHA1;

static const struct __NTVDigest _NTVDigestSHA256 = {
	(NTVDigestFunctionInit)CC_SHA256_Init,
	(NTVDigestFunctionUpdate)CC_SHA256_Update,
	(NTVDigestFunctionFinal)CC_SHA256_Final,
	CC_SHA256_DIGEST_LENGTH, sizeof(CC_SHA256_CTX)
};
const NTVDigestRef NTVDigestSHA256 = &_NTVDigestSHA256;

static const struct __NTVDigest _NTVDigestBrokenMD5 = {
	(NTVDigestFunctionInit)NTV_BrokenMD5_Init,
	(NTVDigestFunctionUpdate)NTV_BrokenMD5_Update,
	(NTVDigestFunctionFinal)NTV_BrokenMD5_Final,
	NTV_BROKEN_MD5_DIGEST_LENGTH, sizeof(NTV_BrokenMD5_CTX)
};
const NTVDigestRef NTVDigestBrokenMD5 = &_NTVDigestBrokenMD5;

@implementation NSData (NTVCommonDigest)

+ (NSData *)ntv_dataWithDigest:(NTVDigestRef)digest stream:(NSInputStream *)stream
{
	CFReadStreamRef readStream = (CFReadStreamRef)stream;
	if (!readStream || !CFReadStreamOpen(readStream)) { return nil; }

	// Use default value for the chunk size for reading data.
	static const size_t chunkSizeForReadingData = NBPG;

	// Initialize the hash object
	uint8_t context[digest->contextSize];
	digest->init(context);

	// Feed the data to the hash object
	BOOL hasMoreData = YES;
	while (hasMoreData) {
		UInt8 buffer[chunkSizeForReadingData];
		CFIndex readBytesCount = CFReadStreamRead(readStream, buffer, chunkSizeForReadingData);
		if (readBytesCount < 0) {
			break;
		} else if (readBytesCount == 0) {
			hasMoreData = NO;
		} else {
			digest->update(context, buffer, (CC_LONG)readBytesCount);
		}
	}

	// Compute the hash digest
	NSMutableData *data = [NSMutableData dataWithLength:digest->digestLength];
	digest->final(data.mutableBytes, context);
	return data;
}

- (NSData *)ntv_dataWithDigest:(NTVDigestRef)digest
{
	NSInputStream *stream = [NSInputStream inputStreamWithData:self];
	return [[self class] ntv_dataWithDigest:digest stream:stream];
}

- (NSData *)ntv_SHA1Digest {
	return [self ntv_dataWithDigest:NTVDigestSHA1];
}

- (NSData *)ntv_brokenMD5Digest {
	return [self ntv_dataWithDigest:NTVDigestBrokenMD5];
}

- (NSData *)ntv_MD5Digest {
	return [self ntv_dataWithDigest:NTVDigestMD5];
}

@end

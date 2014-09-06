//
//  NSData+NTVCommonDigest.h
//  Notation
//
//  Created by Zachary Waldowski on 8/23/14.
//  Copyright (c) 2014 ElasticThreads. All rights reserved.
//

@import Foundation;

typedef const struct __NTVDigest *NTVDigestRef;

extern const NTVDigestRef NTVDigestMD5;
extern const NTVDigestRef NTVDigestSHA1;
extern const NTVDigestRef NTVDigestSHA256;
extern const NTVDigestRef NTVDigestBrokenMD5;

@interface NSData (NTVCommonDigest)

+ (NSData *)ntv_dataWithDigest:(NTVDigestRef)digest stream:(NSInputStream *)stream;

- (NSData *)ntv_dataWithDigest:(NTVDigestRef)digest;

- (NSData *)ntv_SHA1Digest;
- (NSData *)ntv_brokenMD5Digest;
- (NSData *)ntv_MD5Digest;

@end

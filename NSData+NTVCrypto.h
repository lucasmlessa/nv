//
//  NSData+NTVCrypto.h
//  Notation
//
//  Created by Zachary Waldowski on 8/24/14.
//  Copyright (c) 2014 ElasticThreads. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSData (NTVCrypto)

+ (instancetype)ntv_randomDataOfLength:(NSUInteger)len;

- (NSData *)ntv_derivedKeyOfLength:(NSUInteger)len salt:(NSData *)salt;
- (NSData *)ntv_derivedKeyOfLength:(NSUInteger)len salt:(NSData *)salt iterations:(NSUInteger)count;

@end

@interface  NSMutableData (NTVCrypto)

- (BOOL)ntv_encryptDataWithKey:(NSData *)key iv:(NSData *)iv;
- (BOOL)ntv_decryptDataWithKey:(NSData *)key iv:(NSData *)iv;

@end

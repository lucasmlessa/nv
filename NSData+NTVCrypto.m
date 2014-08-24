//
//  NSData+NTVCrypto.m
//  Notation
//
//  Created by Zachary Waldowski on 8/24/14.
//  Copyright (c) 2014 ElasticThreads. All rights reserved.
//

#import "NSData+NTVCrypto.h"
#import <Security/Security.h>
#import <CommonCrypto/CommonCrypto.h>

static BOOL NTVCryptAESDataInPlace(NSMutableData *data, CCOperation op, NSData *key, NSData *iv) {
	size_t originalLength = data.length;

	// check IV and key lengths
	if (key.length != kCCKeySizeAES256) {
		NSLog(@"key length was wrong: %lu", key.length);
		return NO;
	}

	if (iv.length != kCCBlockSizeAES128) {
		NSLog(@"initialization vector length was wrong: %lu", iv.length);
		return NO;
	}

	__block size_t outputLength = 0;

	CCCryptorStatus(^perform)(void) = ^{
		return CCCrypt(op, kCCAlgorithmAES, kCCOptionPKCS7Padding,
					   key.bytes, key.length, iv.bytes,
					   data.bytes, originalLength,
					   data.mutableBytes, data.length, &outputLength);
	};

	CCCryptorStatus status = perform();

	if (status == kCCBufferTooSmall) {
		data.length = outputLength;
		status = perform();
	}

	if (status != kCCSuccess) {
		NSLog(@"unable to encrypt/decrypt");
		return NO;
	}

	data.length = outputLength;
	return YES;
}

@implementation NSData (NTVCrypto)

+ (instancetype)ntv_randomDataOfLength:(NSUInteger)len {
	NSMutableData *data = [NSMutableData dataWithLength:len];
	if (SecRandomCopyBytes(kSecRandomDefault, len, data.mutableBytes) != noErr) {
		return nil;
	}
	return [self dataWithData:data];
}

- (NSData *)ntv_derivedKeyOfLength:(NSUInteger)len salt:(NSData *)salt {
	return [self ntv_derivedKeyOfLength:len salt:salt iterations:1];
}

- (NSData *)ntv_derivedKeyOfLength:(NSUInteger)len salt:(NSData *)salt iterations:(NSUInteger)count {
	NSMutableData *derivedKey = [NSMutableData dataWithLength:len];

	if (CCKeyDerivationPBKDF(kCCPBKDF2, self.bytes, self.length, salt.bytes, salt.length, kCCPRFHmacAlgSHA1, (unsigned int)count, derivedKey.mutableBytes, derivedKey.length) != kCCSuccess) {
		return nil;
	}

	return [[derivedKey copy] autorelease];
}

@end

@implementation NSMutableData (NTVCrypto)

- (BOOL)ntv_encryptDataWithKey:(NSData*)key iv:(NSData*)iv {
	return NTVCryptAESDataInPlace(self, kCCEncrypt, key, iv);
}

- (BOOL)ntv_decryptDataWithKey:(NSData*)key iv:(NSData*)iv {
	return NTVCryptAESDataInPlace(self, kCCDecrypt, key, iv);
}

@end

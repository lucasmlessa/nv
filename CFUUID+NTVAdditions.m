//
//  CFUUID+NTVAdditions.m
//  Notation
//
//  Created by Zachary Waldowski on 9/6/14.
//  Copyright (c) 2014 ElasticThreads. All rights reserved.
//

#import "CFUUID+NTVAdditions.h"

CFComparisonResult NTVUUIDBytesCompare(const CFUUIDBytes *a, const CFUUIDBytes *b) {
    int cmp = memcmp(a, b, sizeof(CFUUIDBytes));
    if (cmp > 0) {
        return kCFCompareGreaterThan;
    } else if (cmp < 0) {
        return kCFCompareLessThan;
    }
    return kCFCompareEqualTo;
}

static Boolean NTVUUIDEqualToUUID(const CFUUIDBytes *a, const CFUUIDBytes *b) {
    return !NTVUUIDBytesCompare(a, b);
}

CFHashCode NTVUUIDBytesGetHash(const CFUUIDBytes *bytesPtr) {
    /* The ELF hash algorithm, adapted from CFUtilities.c */
    const uint8_t *bytes = (const uint8_t *)bytesPtr;
    CFHashCode H = 0, T1, T2;
#define ELF_STEP(B) T1 = (H << 4) + B; T2 = T1 & 0xF0000000; if (T2) T1 ^= (T2 >> 24); T1 &= (~T2); H = T1;
    for (size_t i = 0; i < 16; i += 4) {
        ELF_STEP(bytes[i]);
        ELF_STEP(bytes[i + 1]);
        ELF_STEP(bytes[i + 2]);
        ELF_STEP(bytes[i + 3]);
    }
    return H;
#undef ELF_STEP
}

static CFStringRef NTVCopyUUIDStringForBytes(const CFUUIDBytes *bytesPtr) {
    if (!bytesPtr) { return NULL; }
    
    CFUUIDRef uuidRef = CFUUIDCreateFromUUIDBytes(NULL, *bytesPtr);
    if (!uuidRef) { return NULL; }
    
    CFStringRef uuidString = CFUUIDCreateString(NULL, uuidRef);
    CFRelease(uuidRef);
    
    return uuidString;
}

CFDictionaryEqualCallBack const NTVUUIDIsEqualBytes = (CFDictionaryEqualCallBack)NTVUUIDEqualToUUID;
CFDictionaryHashCallBack const NTVUUIDGetHashForBytes = (CFDictionaryHashCallBack)NTVUUIDBytesGetHash;
CFDictionaryCopyDescriptionCallBack const NTVUUIDCopyDescriptionForBytes = (CFDictionaryCopyDescriptionCallBack)NTVCopyUUIDStringForBytes;

@implementation NSString (NTVUUIDAdditions)

+ (instancetype)ntv_UUIDStringForBytes:(const CFUUIDBytes *)bytesPtr {
    return CFBridgingRelease(NTVCopyUUIDStringForBytes(bytesPtr));
}

- (BOOL)ntv_getUUIDBytes:(out CFUUIDBytes *)bytesPtr {
    CFUUIDRef uuidRef = CFUUIDCreateFromString(NULL, (CFStringRef)self);
    if (!uuidRef) { return NO; }
    
    CFUUIDBytes bytes = CFUUIDGetUUIDBytes(uuidRef);
    CFRelease(uuidRef);
    
    if (bytesPtr) { *bytesPtr = bytes; }
    return YES;
}

@end

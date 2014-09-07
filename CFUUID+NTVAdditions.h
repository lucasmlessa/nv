//
//  CFUUID+NTVAdditions.h
//  Notation
//
//  Created by Zachary Waldowski on 9/6/14.
//  Copyright (c) 2014 ElasticThreads. All rights reserved.
//

@import CoreFoundation;

extern CFComparisonResult NTVUUIDBytesCompare(const CFUUIDBytes *a, const CFUUIDBytes *b);
extern CFHashCode NTVUUIDBytesGetHash(const CFUUIDBytes *bytes);

extern CFDictionaryEqualCallBack const NTVUUIDIsEqualBytes;
extern CFDictionaryHashCallBack const NTVUUIDGetHashForBytes;
extern CFDictionaryCopyDescriptionCallBack const NTVUUIDCopyDescriptionForBytes;

@interface NSString (NTVUUIDAdditions)

+ (instancetype)ntv_UUIDStringForBytes:(in const CFUUIDBytes *)bytesPtr;

- (BOOL)ntv_getUUIDBytes:(out CFUUIDBytes *)bytesPtr;

@end

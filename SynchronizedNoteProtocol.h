/*
 *  SynchronizedNoteProtocol.h
 *  Notation
 *
 *  Created by Zachary Schneirov on 4/22/06.
 */

/*Copyright (c) 2010, Zachary Schneirov. All rights reserved.
  Redistribution and use in source and binary forms, with or without modification, are permitted 
  provided that the following conditions are met:
   - Redistributions of source code must retain the above copyright notice, this list of conditions 
     and the following disclaimer.
   - Redistributions in binary form must reproduce the above copyright notice, this list of 
	 conditions and the following disclaimer in the documentation and/or other materials provided with
     the distribution.
   - Neither the name of Notational Velocity nor the names of its contributors may be used to endorse 
     or promote products derived from this software without specific prior written permission. */

@import Foundation;
#import "CFUUID+NTVAdditions.h"

@protocol SynchronizedNote <NSCoding, NSObject>

@property (nonatomic, readonly) const CFUUIDBytes *uniqueNoteIDBytes;

@property (nonatomic, readonly) NSDictionary *syncServicesMD;
- (void)setSyncObjectAndKeyMD:(NSDictionary*)aDict forService:(NSString*)serviceName;
- (void)removeAllSyncMDForService:(NSString*)serviceName;

@property (nonatomic, readonly) unsigned int logSequenceNumber;
- (void)incrementLSN;

@end

NTV_ALWAYS_INLINE BOOL NTVSynchronizedNoteIsEqual(id<SynchronizedNote> a, id<SynchronizedNote> b) {
    if (![b conformsToProtocol:@protocol(SynchronizedNote)]) { return NO; }
    return NTVUUIDIsEqualBytes(a.uniqueNoteIDBytes, b.uniqueNoteIDBytes);
}

NTV_ALWAYS_INLINE BOOL NTVSynchronizedNoteIsYounger(id<SynchronizedNote> a, id<SynchronizedNote> b) {
	return [a logSequenceNumber] < [b logSequenceNumber];
}

NTV_ALWAYS_INLINE BOOL NTVSynchronizedNoteGetUUIDBytes(id<SynchronizedNote> a, CFUUIDBytes *b) {
    const CFUUIDBytes *aPtr = a.uniqueNoteIDBytes;
    if (!aPtr || !b) { return NO; }
    *b = *aPtr;
    return YES;
}

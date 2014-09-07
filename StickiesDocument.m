//
//  StickiesDocument.m
//  Notation
//
//  Created by Zachary Schneirov on 11/15/06.

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


#import "StickiesDocument.h"

#if __LP64__
// Needed for compatability with data created by 32bit app
typedef struct {
    struct {
        float x;
        float y;
    };
    struct {
        float width;
        float height;
    };
} NTVRect32;
#else
typedef CGRect NTVRect32;
#endif

@implementation StickiesDocument {
    int mWindowColor;
    int mWindowFlags;
    NTVRect32 mWindowFrame;
}

- (void)dealloc {
	
	[_RTFDData release];
	[_creationDate release];
	[_modificationDate release];
	
	[super dealloc];
}

- (id)initWithCoder:(id)decoder {
	self = [super init];
	if (!self) { return nil; }

	_RTFDData = [[decoder decodeObject] retain];
	[decoder decodeValueOfObjCType:@encode(int) at:&mWindowFlags];
	[decoder decodeValueOfObjCType:@encode(NTVRect32) at:&mWindowFrame];
	[decoder decodeValueOfObjCType:@encode(int) at:&mWindowColor];
	_creationDate = [[decoder decodeObject] retain];
	_modificationDate = [[decoder decodeObject] retain];
        
	return self;
}

- (void)encodeWithCoder:(id)coder {
	NSAssert(NO, @"Notational Velocity is not supposed to make stickies!");
}

@end

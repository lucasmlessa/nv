//
//  NTVPasswordGenerator.h
//  Notation
//
//  Created by Brian Bergstrand on 9/27/2009.
//  Copyright 2009 Brian Bergstrand. All rights reserved.
//

@import Foundation;

typedef NS_ENUM(NSUInteger, NTVPasswordSet) {
	NTVPasswordSetNumeric,
	NTVPasswordSetAlpha,
	NTVPasswordSetMixedCase,
	NTVPasswordSetSymbol
};
static const NSUInteger NTVPasswordSetCount = NTVPasswordSetMixedCase + 1;

typedef NS_OPTIONS(NSUInteger, NTVPasswordOptions) {
	NTVPasswordNumeric = (1 << NTVPasswordSetNumeric),
	NTVPasswordAlpha = (1 << NTVPasswordSetAlpha),
	NTVPasswordMixedCase = (1 << NTVPasswordSetMixedCase),
	NTVPasswordSymbol = (1 << NTVPasswordSetSymbol),
	NTVPasswordAllowDuplicates = (1 << (NTVPasswordSetCount + 1)),
};

@interface NTVPasswordGenerator : NSObject

+ (NSString *)passwordWithLength:(NSUInteger)length options:(NTVPasswordOptions)options;
+ (NSString *)numericPasswordWithLength:(NSUInteger)len;
+ (NSString *)alphaNumericPasswordWithLength:(NSUInteger)len;

+ (NSString *)strong;
+ (NSString *)medium;
+ (NSString *)light;
+ (NSString *)lightNumeric;

// ordered from strong to light
+ (NSArray*)suggestions;

@end

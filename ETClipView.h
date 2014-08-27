//
//  ETClipView.m
//  nvALT
//
//  Created by elasticthreads on 8/15/11.
//

#import "GlobalPrefs.h"

#define kTextMargins 50.0

@interface ETClipView : NSClipView <GlobalPrefsObserver> {
    BOOL managesTextWidth;
}

- (BOOL)clipWidthSettingChanged:(NSRect)frameRect;
- (BOOL)clipRect:(NSRect *)clipRect forFrameRect:(NSRect)frameRect;

@end

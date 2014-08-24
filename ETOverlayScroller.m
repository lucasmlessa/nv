//
//  ETOverlayScroller.m
//  Notation
//
//  Created by elasticthreads on 9/15/11.
//  Copyright 2011 elasticthreads. All rights reserved.
//

#import "ETOverlayScroller.h"

NTV_ALWAYS_INLINE CGFloat ETOverlayScrollerMinXPadding(NSScrollerStyle scrollerStyle) {
	if (scrollerStyle == NSScrollerStyleOverlay) {
		return 4.5;
	}
	return 4.0;
}

@implementation ETOverlayScroller

+ (BOOL)isCompatibleWithOverlayScrollers {
    return self == [ETOverlayScroller class];
}

- (void)setScrollerStyle:(NSScrollerStyle)newScrollerStyle{
	verticalPaddingLeft = ETOverlayScrollerMinXPadding(newScrollerStyle);
    [super setScrollerStyle:newScrollerStyle];
}

+ (NSScrollerStyle)preferredScrollerStyle{
   
    return [[NSScroller class]preferredScrollerStyle];
}

- (id)initWithFrame:(NSRect)frameRect{
	self = [super initWithFrame:frameRect];
	if (!self) { return nil; }

	verticalPaddingRight = 3.0f;
	verticalPaddingLeft = ETOverlayScrollerMinXPadding(self.scrollerStyle);
	knobAlpha=0.6f;
	slotAlpha=0.55f;
	fillBackground=NO;

	return self;
}


@end

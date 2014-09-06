//
//  ETTransparentScroller.h
//
//  Created by Brandon Walkin (www.brandonwalkin.com)
//  All code is provided under the New BSD license.
//
//	Modified by elasticthreads 10/19/2010
//

@import Cocoa;


@interface ETTransparentScroller : NSScroller {
    NSImage *knobTop, *knobVerticalFill, *knobBottom, *slotTop, *slotVerticalFill, *slotBottom;
    CGFloat verticalPaddingLeft;
    CGFloat verticalPaddingRight;
    CGFloat verticalPaddingTop;
    CGFloat verticalPaddingBottom;
    CGFloat minKnobHeight;
    CGFloat slotAlpha;
    CGFloat knobAlpha;
//    BOOL isOverlay;
    BOOL fillBackground;
}

- (void)setFillBackground:(BOOL)fillIt;


@end


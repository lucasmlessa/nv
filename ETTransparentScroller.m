//
//  ETTransparentScroller.h
//
//  Created by Brandon Walkin (www.brandonwalkin.com)
//  All code is provided under the New BSD license.
//
//	Modified by elasticthreads 10/19/2010
//

#import "ETTransparentScroller.h"

//@interface NSScroller (NVTSPrivate)
//- (NSRect)_drawingRectForPart:(NSScrollerPart)aPart;
//@end

@implementation ETTransparentScroller

//+ (void)initialize
//{
//}

+ (BOOL)isCompatibleWithResponsiveScrolling{
    return NO;
}

- (id)initWithFrame:(NSRect)frameRect{
	self = [super initWithFrame:frameRect];
	if (!self) { return nil; }

	fillBackground=NO;
	NSBundle *bundle = [NSBundle mainBundle];
	
	knobTop				= [[bundle imageForResource:@"TransparentScrollerKnobTop"] retain];
	knobVerticalFill		= [[bundle imageForResource:@"TransparentScrollerKnobVerticalFill"] retain];
	knobBottom			= [[bundle imageForResource:@"TransparentScrollerKnobBottom"] retain];
	slotTop				= [[bundle imageForResource:@"TransparentScrollerSlotTop"] retain];
	slotVerticalFill		= [[bundle imageForResource:@"TransparentScrollerSlotVerticalFill"] retain];
	slotBottom			= [[bundle imageForResource:@"TransparentScrollerSlotBottom"] retain];
	verticalPaddingLeft = 4.0f;
	verticalPaddingRight = 3.0f;
	verticalPaddingTop =3.75f;
	verticalPaddingBottom = 4.25f;
	minKnobHeight = knobTop.size.height + knobVerticalFill.size.height + knobBottom.size.height + 20.0;
	slotAlpha=0.45f;
	knobAlpha=0.45f;
	[self setArrowsPosition:NSScrollerArrowsNone];

	return self;
}

+ (BOOL)isCompatibleWithOverlayScrollers {
    return NO;
}

+ (NSScrollerStyle)preferredScrollerStyle{
    return NSScrollerStyleLegacy;
}

- (void)dealloc{
    [knobTop release];
    [knobVerticalFill release];
    [knobBottom release];
    [slotTop release];
    [slotBottom release];
    [slotVerticalFill release];
    [super dealloc];
}

+ (CGFloat)scrollerWidthForControlSize:(NSControlSize)controlSize scrollerStyle:(NSScrollerStyle)scrollerStyle{
    return 15.0;
}

- (void)setFillBackground:(BOOL)fillIt{
    fillBackground=fillIt;
}

- (void)drawKnobSlotInRect:(NSRect)slotRect highlight:(BOOL)flag{  
   
    NSDrawThreePartImage(slotRect, slotTop, slotVerticalFill, slotBottom, YES, NSCompositeSourceOver, slotAlpha, NO);
   
}

- (void)drawKnob
{
	NSRect knobRect = [self rectForPart:NSScrollerKnob];

	NSDrawThreePartImage(knobRect, knobTop, knobVerticalFill, knobBottom, YES, NSCompositeSourceOver, knobAlpha, NO);
   
}
//
//- (NSRect)_drawingRectForPart:(NSScrollerPart)aPart;
//{
//	// Call super even though we're not using its value (has some side effects we need)
//	[super _drawingRectForPart:aPart];
//	
//	// Return our own rects rather than use the default behavior
//	return [self rectForPart:aPart];
//}



//- (void)trackKnob:(NSEvent *)theEvent{
//    NSPoint aPoint=[theEvent locationInWindow];
//    NSScrollerPart aPart=[super testPart:aPoint];
//    [super trackKnob:theEvent];
//}

- (NSRect)rectForPart:(NSScrollerPart)aPart{    
	switch (aPart)
	{
        case NSScrollerKnob:
		{
			NSRect knobRect=[super rectForPart:NSScrollerKnob];
//			NSRect slotRect = [self rectForPart:NSScrollerKnobSlot];
//			float knobHeight = roundf(slotRect.size.height * [self knobProportion]);
//			if (knobHeight < minKnobHeight){
//                if (minKnobHeight>slotRect.size.height) {
//                    knobHeight=knobRect.size.height;
//                }else{
//                    knobHeight = minKnobHeight;
//                }
//            }
            CGFloat slotY=round(verticalPaddingTop);
            CGFloat knobY=knobRect.origin.y;
            CGFloat slotHt=round([self bounds].size.height-(verticalPaddingTop+verticalPaddingBottom));
            if (knobY<slotY) {
                knobY=slotY;
            }
            else if ((knobY+knobRect.size.height)>(slotHt+slotY)){
                knobY=slotHt+slotY-knobRect.size.height;

            }
//			knobRect = NSMakeRect(verticalPaddingLeft, knobY, slotRect.size.width, knobHeight);
            knobRect.origin.x=round(verticalPaddingLeft);
            knobRect.origin.y=round(knobY);
            knobRect.size.width=round([self bounds].size.width - verticalPaddingLeft - verticalPaddingRight);
			
			return knobRect;
		}
		case NSScrollerKnobSlot:
		{
			NSRect slotRect=[self bounds];
			slotRect.origin.x=round(verticalPaddingLeft);
            slotRect.size.width=round(slotRect.size.width - verticalPaddingLeft - verticalPaddingRight);
            slotRect.origin.y=round(verticalPaddingTop);
            slotRect.size.height=round(slotRect.size.height-(verticalPaddingTop+verticalPaddingBottom));
			return slotRect;
		}
		case NSScrollerIncrementLine:
			return NSZeroRect;
		case NSScrollerDecrementLine:
			return NSZeroRect;
		case NSScrollerIncrementPage:
		{
			NSRect incrementPageRect;
			NSRect knobRect = [self rectForPart:NSScrollerKnob];
//			NSRect slotRect = [self rectForPart:NSScrollerKnobSlot];
//			NSRect decPageRect = [self rectForPart:NSScrollerDecrementPage];
            CGFloat slotHt=round([self bounds].size.height-(verticalPaddingTop+verticalPaddingBottom));
			CGFloat knobY = round(knobRect.origin.y + knobRect.size.height);
            CGFloat knobHt=round(slotHt - knobRect.size.height - knobRect.origin.y - verticalPaddingTop);
			incrementPageRect = NSMakeRect(round(verticalPaddingLeft), knobY, knobRect.size.width, knobHt);
            
			return incrementPageRect;
		}
		case NSScrollerDecrementPage:
		{
			NSRect decrementPageRect;
			NSRect knobRect = [self rectForPart:NSScrollerKnob];
			
            
			decrementPageRect = NSMakeRect(round(verticalPaddingLeft), round(verticalPaddingTop), knobRect.size.width, round(knobRect.origin.y - verticalPaddingTop));
            
			return decrementPageRect;
		}
		default:
        {
			return [self bounds];
		}
	}
}

@end

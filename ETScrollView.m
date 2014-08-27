//
//  ETScrollView.m
//  Notation
//
//  Created by elasticthreads on 3/14/11.
//

#import "ETScrollView.h"
#import "ETOverlayScroller.h"
#import "GlobalPrefs.h"
#import "LinkingEditor.h"

@implementation ETScrollView


+ (BOOL)isCompatibleWithResponsiveScrolling{
    return NO;
}

- (NSView *)hitTest:(NSPoint)aPoint{
    if([[[self documentView]className] isEqualToString:@"LinkingEditor"]){
        NSRect vsRect=[[self verticalScroller] frame];
        vsRect.origin.x-=4.0;
        vsRect.size.width+=4.0;
        
        if (NSPointInRect (aPoint,vsRect)) {
            return [self verticalScroller];
		} else if([[self subviews]containsObject:[self findBarView]]) {
			NSView *tView=[super hitTest:aPoint];
			if ((tView==[self findBarView])||([tView superview]==[self findBarView])||([[tView className]isEqualToString:@"NSFindPatternFieldEditor"])) {
				[[self window]invalidateCursorRectsForView:tView];
				[[self documentView]setMouseInside:NO];
				return tView;
			}
		}
        [[self documentView]setMouseInside:YES];
        return [self documentView];
    }
    return [super hitTest:aPoint];
}


- (void)awakeFromNib{ 
    needsOverlayTiling=NO;
    if([[[self documentView] className] isEqualToString:@"NotesTableView"]){
		scrollerClass = ETOverlayScroller.class;
    }else{
		scrollerClass = ETTransparentScroller.class;
    }

	[[GlobalPrefs defaultPrefs] registerTarget:self forChangesInSettings:@selector(setUseETScrollbarsOnLion:sender:), NULL];
	[self setHorizontalScrollElasticity:NSScrollElasticityNone];
	[self setVerticalScrollElasticity:NSScrollElasticityAllowed];
	[self changeUseETScrollbarsOnLion];
}


- (void)settingChangedForSelector:(SEL)selector {
	if (sel_isEqual(selector, @selector(setUseETScrollbarsOnLion:sender:))) {
		[self changeUseETScrollbarsOnLion];
	}
}

- (void)changeUseETScrollbarsOnLion{
    id theScroller;
    if ([[GlobalPrefs defaultPrefs] useETScrollbarsOnLion]) {
        theScroller = [[scrollerClass alloc]init];
        [theScroller setFillBackground:NO];
    } else{
        theScroller = [[NSScroller alloc]init];
    }

    NSScrollerStyle style=[[theScroller class] preferredScrollerStyle];
    [self setVerticalScroller:theScroller];
    [theScroller release];
    
	[theScroller setScrollerStyle:style];
	[self setScrollerStyle:style];
    [self tile];
    [self reflectScrolledClipView:[self contentView]];
}

- (void)tile {
	[super tile];
    if (needsOverlayTiling) {
        if (![[self verticalScroller] isHidden]) {
            //            NSRect vsRect=[[self verticalScroller] frame];
            NSRect conRect = [[self contentView] frame];
            //            NSView *wdContent = [[self contentView] retain];
            conRect.size.width = conRect.size.width + [[self verticalScroller] frame].size.width;
            [[self contentView] setFrameSize:conRect.size];
            //            [wdContent setFrame:conRect];
            //            [wdContent release];
            //            [[self verticalScroller] setFrame:vsRect];            
        }
    }
}


@end

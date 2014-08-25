//
//  BTTransparentScroller.m
//
//  Created by Brandon Walkin (www.brandonwalkin.com)
//  All code is provided under the New BSD license.
//
//  Modified by Brett Terpstra on 12/8/10.
//  Copyright 2010 Circle Six Design. All rights reserved.
//
// Modified again by ElasticThreads on 03/10/11


#import "BTTransparentScroller.h"



@implementation BTTransparentScroller

+ (BOOL)isCompatibleWithOverlayScrollers {
    return self == [BTTransparentScroller class];
}

- (id)initWithFrame:(NSRect)frameRect{
	self = [super initWithFrame:frameRect];
	if (!self) { return nil; }

	NSBundle *bundle = [NSBundle mainBundle];        
	knobTop				= [[bundle imageForResource:@"greyscrollerverttop3"] retain];
	knobVerticalFill		= [[bundle imageForResource:@"greyscrollervertfill3"] retain];
	knobBottom			= [[bundle imageForResource:@"greyscrollervertbottom3"] retain];
	slotTop				= [NSImage imageNamed:nil];
	slotVerticalFill	= [NSImage imageNamed:nil];
	slotBottom			= [NSImage imageNamed:nil];
	verticalPaddingLeft = 5.0f;
	verticalPaddingRight = 4.0f;
	verticalPaddingTop = 3.5f;
	verticalPaddingBottom = 3.5f;
	knobAlpha=0.95f;        

	return self;
}

- (void)drawKnobSlotInRect:(NSRect)slotRect highlight:(BOOL)flag{ }

@end

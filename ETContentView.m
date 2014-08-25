//
//  ETContentView.m
//  Notation
//
//  Created by elasticthreads on 3/15/11.
//

#import "ETContentView.h"
#import "AppController.h"

@implementation ETContentView

- (void)dealloc
{
    [backColor release];
    [super dealloc];
}

- (void)drawRect:(NSRect)dirtyRect
{
//    [super drawRect:dirtyRect];
    if (!backColor) {
        backColor = [[NTVAppDelegate() backgrndColor] retain];
    }
    [backColor set];
    NSRectFill([self bounds]);
    
}

- (void)setBackgroundColor:(NSColor *)inCol{
    if (backColor) {
        [backColor release];
    }
    backColor = inCol;
    [backColor retain];
}

- (NSColor *)backgroundColor{    
    if (!backColor) {
        backColor = [[NTVAppDelegate() backgrndColor] retain];
    }
    return backColor;
}

@end

//
//  MAAttachedWindow.h
//
//  Created by Matt Gemmell on 27/09/2007.
//  Copyright 2007 Magic Aubergine.
//

#import <Cocoa/Cocoa.h>

/*
 Below are the positions the attached window can be displayed at.
 
 Note that these positions are relative to the point passed to the constructor, 
 e.g. MAPositionBottomRight will put the window below the point and towards the right, 
      MAPositionTop will horizontally center the window above the point, 
      MAPositionRightTop will put the window to the right and above the point, 
 and so on.
 
 You can also pass MAPositionAutomatic (or use an initializer which omits the 'onSide:' 
 argument) and the attached window will try to position itself sensibly, based on 
 available screen-space.
 
 Notes regarding automatically-positioned attached windows:
 
 (a) The window prefers to position itself horizontally centered below the specified point.
     This gives a certain enhanced visual sense of an attachment/relationship.
 
 (b) The window will try to align itself with its parent window (if any); i.e. it will 
     attempt to stay within its parent window's frame if it can.
 
 (c) The algorithm isn't perfect. :) If in doubt, do your own calculations and then 
     explicitly request that the window attach itself to a particular side.
 */

typedef enum _MAWindowPosition {
    // The four primary sides are compatible with the preferredEdge of NSDrawer.
    MAPositionLeft          = CGRectMinXEdge, // 0
    MAPositionRight         = CGRectMaxXEdge, // 2
    MAPositionTop           = CGRectMaxYEdge, // 3
    MAPositionBottom        = CGRectMinYEdge, // 1
    MAPositionLeftTop       = 4,
    MAPositionLeftBottom    = 5,
    MAPositionRightTop      = 6,
    MAPositionRightBottom   = 7,
    MAPositionTopLeft       = 8,
    MAPositionTopRight      = 9,
    MAPositionBottomLeft    = 10,
    MAPositionBottomRight   = 11,
    MAPositionAutomatic     = 12
} MAWindowPosition;

@interface MAAttachedWindow : NSWindow {
    NSColor *borderColor;
    CGFloat viewMargin;
    CGFloat arrowBaseWidth;
    CGFloat arrowHeight;
    BOOL hasArrow;
    CGFloat cornerRadius;
    BOOL drawsRoundCornerBesideArrow;
    
    @private
    NSColor *_MABackgroundColor;
    __weak NSView *_view;
    __weak NSWindow *_window;
    CGPoint _point;
    MAWindowPosition _side;
    CGFloat _distance;
    CGRect _viewFrame;
    BOOL _resizing;
}

/*
 Initialization methods
 
 Parameters:
 
 view       The view to display in the attached window. Must not be nil.
 
 point      The point to which the attached window should be attached. If you 
            are also specifying a parent window, the point should be in the 
            coordinate system of that parent window. If you are not specifying 
            a window, the point should be in the screen's coordinate space.
            This value is required.
 
 window     The parent window to attach this one to. Note that no actual 
            relationship is created (particularly, this window is not made 
            a childWindow of the parent window).
            Default: nil.
 
 side       The side of the specified point on which to attach this window.
            Default: MAPositionAutomatic.
 
 distance   How far from the specified point this window should be.
            Default: 0.
 */

- (MAAttachedWindow *)initWithView:(NSView *)view           // designated initializer
                   attachedToPoint:(CGPoint)point
                          inWindow:(NSWindow *)window
                            onSide:(MAWindowPosition)side
                        atDistance:(CGFloat)distance;
- (MAAttachedWindow *)initWithView:(NSView *)view
                   attachedToPoint:(CGPoint)point
                          inWindow:(NSWindow *)window
                        atDistance:(CGFloat)distance;
- (MAAttachedWindow *)initWithView:(NSView *)view
                   attachedToPoint:(CGPoint)point
                            onSide:(MAWindowPosition)side
                        atDistance:(CGFloat)distance;
- (MAAttachedWindow *)initWithView:(NSView *)view
                   attachedToPoint:(CGPoint)point
                        atDistance:(CGFloat)distance;
- (MAAttachedWindow *)initWithView:(NSView *)view
                   attachedToPoint:(CGPoint)point
                          inWindow:(NSWindow *)window;
- (MAAttachedWindow *)initWithView:(NSView *)view
                   attachedToPoint:(CGPoint)point
                            onSide:(MAWindowPosition)side;
- (MAAttachedWindow *)initWithView:(NSView *)view
                   attachedToPoint:(CGPoint)point;

// Accessor methods
@property (nonatomic, readonly) CGPoint point;
- (void)setPoint:(CGPoint)point side:(MAWindowPosition)side;
@property (nonatomic, retain) NSColor *borderColor;
@property (nonatomic) CGFloat borderWidth;              // See note 1 below.
@property (nonatomic) CGFloat viewMargin;               // See note 2 below.
@property (nonatomic) CGFloat arrowBaseWidth;           // See note 2 below.
@property (nonatomic) CGFloat arrowHeight;              // See note 2 below.
@property (nonatomic) BOOL hasArrow;
@property (nonatomic) CGFloat cornerRadius;             // See note 2 below.
@property (nonatomic) BOOL drawsRoundCornerBesideArrow; // See note 3 below.

- (void)setBackgroundImage:(NSImage *)value;

/*
 Notes regarding accessor methods:
 
 1. The border is drawn inside the viewMargin area, expanding inwards; it does not 
    increase the width/height of the window. You can use the -setBorderWidth: and
    -setViewMargin: methods together to achieve the exact look/geometry you want.
    (viewMargin is the distance between the edge of the view and the window edge.)
 
 2. The specified setter methods are primarily intended to be used _before_ the window 
    is first shown. If you use them while the window is already visible, be aware 
    that they may cause the window to move and/or resize, in order to stay anchored 
    to the point specified in the initializer. They may also cause the view to move 
    within the window, in order to remain centered there.
 
    Note that the -setHasArrow: method can safely be used at any time, and will not 
    cause moving/resizing of the window. This is for convenience, in case you want 
    to add or remove the arrow in response to user interaction. For example, you 
    could make the attached window movable by its background, and if the user dragged 
    it away from its initial point, the arrow could be removed. This would duplicate 
    how Aperture's attached windows behave.
 
 3. drawsRoundCornerBesideArrow takes effect when the arrow is being drawn at a corner,
    i.e. when it's not at one of the four primary compass directions. In this situation, 
    if drawsRoundCornerBesideArrow is YES (the default), then that corner of the window 
    will be rounded just like the other three corners, thus the arrow will be inset 
    slightly from the edge of the window to allow room for the rounded corner. If this 
    value is NO, the corner beside the arrow will be a square corner, and the other 
    three corners will be rounded.
 
    This is useful when you want to attach a window very near the edge of another window, 
    and don't want the attached window's edge to be visually outside the frame of the 
    parent window.
 
 4. Note that to retrieve the background color of the window, you should use the 
    -windowBackgroundColor method, instead of -backgroundColor. This is because we draw 
    the entire background of the window (rounded path, arrow, etc) in an NSColor pattern 
    image, and set it as the backgroundColor of the window.
 */

@end

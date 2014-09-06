//
//  PTKeyBroadcaster.m
//  Protein
//
//  Created by Quentin Carnicelli on Sun Aug 03 2003.
//  Copyright (c) 2003 Quentin D. Carnicelli. All rights reserved.
//

#import "PTKeyBroadcaster.h"
#import "PTKeyCombo.h"
@import Carbon;

NSString *const PTKeyBroadcasterKeyEvent = @"PTKeyBroadcasterKeyEvent";

@implementation PTKeyBroadcaster

- (void)_bcastKeyCode: (short)keyCode modifiers: (int)modifiers
{
	PTKeyCombo* keyCombo = [PTKeyCombo keyComboWithKeyCode: keyCode modifiers: modifiers];
	NSDictionary* userInfo = @{
		@"keyCombo": keyCombo
	};

	[[NSNotificationCenter defaultCenter]
		postNotificationName: PTKeyBroadcasterKeyEvent
		object: self
		userInfo: userInfo];
}

- (void)_bcastEvent: (NSEvent*)event
{
	short keyCode;
	int modifiers;
	
	keyCode = [event keyCode];
	modifiers = [event modifierFlags];
	modifiers = [[self class] cocoaModifiersAsCarbonModifiers: modifiers];

	[self _bcastKeyCode: keyCode modifiers: modifiers];
}

- (BOOL)resignFirstResponder {
	return NO;
}

- (void)keyDown: (NSEvent*)event
{
	[self _bcastEvent: event];
}

- (BOOL)performKeyEquivalent: (NSEvent*)event
{
	[self _bcastEvent: event];
	return YES;
}

+ (int)cocoaModifiersAsCarbonModifiers: (NSEventModifierFlags)cocoaModifiers
{
	static long cocoaToCarbon[6][2] =
	{
		{ NSCommandKeyMask, cmdKey},
		{ NSAlternateKeyMask, optionKey},
		{ NSControlKeyMask, controlKey},
		{ NSShiftKeyMask, shiftKey},
		{ NSFunctionKeyMask, rightControlKey},
		//{ NSAlphaShiftKeyMask, alphaLock }, //Ignore this?
	};

	int carbonModifiers = 0;

	for(int i = 0 ; i < 6; i++ )
		if( cocoaModifiers & cocoaToCarbon[i][0] )
			carbonModifiers += cocoaToCarbon[i][1];
	
	return carbonModifiers;
}


@end

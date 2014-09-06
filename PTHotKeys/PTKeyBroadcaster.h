//
//  PTKeyBroadcaster.h
//  Protein
//
//  Created by Quentin Carnicelli on Sun Aug 03 2003.
//  Copyright (c) 2003 Quentin D. Carnicelli. All rights reserved.
//

@import Cocoa;


@interface PTKeyBroadcaster : NSButton
{
}

+ (int)cocoaModifiersAsCarbonModifiers: (NSEventModifierFlags)cocoaModifiers;

@end

extern NSString *const PTKeyBroadcasterKeyEvent; //keys: keyCombo as PTKeyCombo

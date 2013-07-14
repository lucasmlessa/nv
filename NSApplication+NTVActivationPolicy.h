//
//  NSApplication+NTVActivationPolicy.h
//  Notation
//
//  Created by Zach Waldowski on 7/14/13.
//  Copyright (c) 2013 elasticthreads. All rights reserved.
//

#import <Cocoa/Cocoa.h>

@interface NSApplication (NTVActivationPolicy)

- (BOOL)ntv_setActivationPolicy:(NSApplicationActivationPolicy)activationPolicy NS_DEPRECATED_MAC(10_6, 10_9);

@end

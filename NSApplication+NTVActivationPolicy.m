//
//  NSApplication+NTVActivationPolicy.m
//  Notation
//
//  Created by Zach Waldowski on 7/14/13.
//  Copyright (c) 2013 elasticthreads. All rights reserved.
//

#import "NSApplication+NTVActivationPolicy.h"

static ProcessApplicationTransformState NTVApplicationTransformStateForActivationPolicy(NSApplicationActivationPolicy policy)
{
	switch (policy) {
		case NSApplicationActivationPolicyRegular:		return kProcessTransformToForegroundApplication;
		case NSApplicationActivationPolicyAccessory:	return kProcessTransformToUIElementApplication;
		case NSApplicationActivationPolicyProhibited:	return kProcessTransformToBackgroundApplication;
	}
	return 0;
}

@implementation NSApplication (NTVActivationPolicy)

- (BOOL)ntv_setActivationPolicy:(NSApplicationActivationPolicy)activationPolicy
{
	if (IsMavericksOrLater) {
		return [self setActivationPolicy:activationPolicy];
	}

	if (self.activationPolicy == activationPolicy) {
		return NO;
	}

	[self willChangeValueForKey:@"activationPolicy"];
	ProcessSerialNumber psn = { 0, kCurrentProcess };
	ProcessApplicationTransformState state = NTVApplicationTransformStateForActivationPolicy(activationPolicy);
	OSStatus returnCode = TransformProcessType(&psn, state);

	[self didChangeValueForKey:@"activationPolicy"];

	return (returnCode == noErr);
}

@end

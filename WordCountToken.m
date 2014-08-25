//
//  WordCountToken.m
//  Notation
//
//  Created by ElasticThreads on 3/1/11.
//

#import "WordCountToken.h"
#import "AppController.h"

@implementation WordCountToken

- (void)awakeFromNib{
	[self refusesFirstResponder];
}

- (void)mouseDown:(NSEvent *)theEvent{
	[NTVAppDelegate() toggleWordCount:self];
}

@end

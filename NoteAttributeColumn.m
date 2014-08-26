/*Copyright (c) 2010, Zachary Schneirov. All rights reserved.
  Redistribution and use in source and binary forms, with or without modification, are permitted 
  provided that the following conditions are met:
   - Redistributions of source code must retain the above copyright notice, this list of conditions 
     and the following disclaimer.
   - Redistributions in binary form must reproduce the above copyright notice, this list of 
	 conditions and the following disclaimer in the documentation and/or other materials provided with
     the distribution.
   - Neither the name of Notational Velocity nor the names of its contributors may be used to endorse 
     or promote products derived from this software without specific prior written permission. */


#import "NoteAttributeColumn.h"

@interface NoteAttributeColumn ()

@property (nonatomic, readonly) CGFloat absoluteMinimumWidth;

@end

@implementation NoteAttributeColumn

@synthesize attributeGetter = _attributeGetter;
@synthesize attributeSetter = _attributeSetter;
@synthesize comparator = _comparator;
@synthesize secondaryComparator = _secondaryComparator;

- (id)initWithIdentifier:(id)anObject {
	self = [super initWithIdentifier:anObject];
	if (!self) { return nil; }

	_absoluteMinimumWidth = [anObject sizeWithAttributes:[NoteAttributeColumn standardDictionary]].width + 5;
	[self setMinWidth:_absoluteMinimumWidth];

	return self;
}

+ (NSDictionary *)standardDictionary {
	return @{
		NSFontAttributeName: [NSFont systemFontOfSize:NSFont.smallSystemFontSize]
	};
}

- (void)updateWidthForHighlight {
	[self setMinWidth:_absoluteMinimumWidth + ([[self tableView] highlightedTableColumn] == self ? 10 : 0)];
}

@end

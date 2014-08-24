/* NoteAttributeColumn */

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


#import <Cocoa/Cocoa.h>

@class NotesTableView;


/// return type is @c NSString or @c NSAttributedString, satisifying @c NSTableDataSource otherwise
typedef id(^NTVNoteAttributeGetter)(NotesTableView *tv, id object, NSInteger row);

@interface NoteAttributeColumn : NSTableColumn {
	SEL mutateObjectSelector;
	CGFloat absoluteMinimumWidth;
}

+ (NSDictionary*)standardDictionary;
SEL columnAttributeMutator(NoteAttributeColumn *col);
- (void)setMutatingSelector:(SEL)selector;
id columnAttributeForObject(NotesTableView *tv, NoteAttributeColumn *col, id object, NSInteger row);
- (void)updateWidthForHighlight;

@property (nonatomic, copy) NSComparator comparator;
@property (nonatomic, copy) NSComparator secondaryComparator;
@property (nonatomic, copy) NTVNoteAttributeGetter attributeGetter;

- (void)setResizingMaskNumber:(NSNumber*)resizingMaskNumber;

@end

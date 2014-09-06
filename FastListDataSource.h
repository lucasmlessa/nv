//
//  FastListDataSource.h
//  Notation
//
//  Created by Zachary Schneirov on 1/8/06.

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


@import Cocoa;

@class NoteAttributeColumn;

/// return type is @c NSString or @c NSAttributedString, satisifying @c NSTableDataSource otherwise
typedef id(^NTVColumnAttributeGetter)(NSTableView *tv, id object, NSInteger row);
typedef void(^NTVColumnAttributeSetter)(NSTableView *tv, id attribute, id object, NSInteger row);

@protocol NTVAttributeColumn <NSObject>

@property (nonatomic, copy) NTVColumnAttributeGetter attributeGetter;
@property (nonatomic, copy) NTVColumnAttributeSetter attributeSetter;
@property (nonatomic, copy) NSComparator comparator;
@property (nonatomic, copy) NSComparator secondaryComparator;

@end

@interface FastListDataSource : NSObject <NSTableViewDataSource> {
	id *objects;
    NSUInteger count;
}

- (const id *)immutableObjects;
- (NSUInteger)count;

- (NSUInteger)indexOfObjectIdenticalTo:(id)address;
- (NSArray*)objectsAtFilteredIndexes:(NSIndexSet*)indexSet;

- (void)fillArrayFromArray:(NSArray*)array;
- (BOOL)filterArrayUsingFunction:(BOOL (*)(id, void*))present context:(void*)context;

- (void)sortStableUsingComparator:(NSComparator)compare;
- (void)sortStableUsingFunction:(NSInteger (*)(id *, id *))compare;

@end

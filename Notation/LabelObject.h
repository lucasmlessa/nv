//
//  LabelObject.h
//  Notation
//
//  Created by Zachary Schneirov on 12/30/05.

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

@class NoteObject;

@interface LabelObject : NSObject

- (id)initWithTitle:(NSString *)name;

@property (nonatomic, copy) NSString *title;
@property (nonatomic, readonly, copy) NSSet *noteSet;

- (void)addNote:(NoteObject *)note;

- (void)addNoteSet:(NSSet *)noteSet;

- (void)removeNote:(NoteObject *)note;

- (void)removeNoteSet:(NSSet *)noteSet;

@end
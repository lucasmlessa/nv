//
//  NotationFileManager.h
//  Notation
//
//  Created by Zachary Schneirov on 4/9/06.

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


#import "NotationController.h"
#import "BufferUtils.h"
#import "NTNFileManager.h"

extern NSString *NotesDatabaseFileName;

typedef union VolumeUUID {
	u_int32_t value[2];
	struct {
		u_int32_t high;
		u_int32_t low;
	} v;
} VolumeUUID;

@interface NotationController (NotationFileManager) <NTNFileManager>

CFUUIDRef CopyHFSVolumeUUIDForMount(const char *mntonname);

NSUInteger diskUUIDIndexForNotation(NotationController *controller);

- (void)initializeDiskUUIDIfNecessary;

- (BOOL)notesDirectoryIsTrashed;

- (OSStatus)refreshFileRefIfNecessary:(FSRef *)childRef withName:(NSString *)filename charsBuffer:(UniChar *)charsBuffer;

- (OSStatus)renameAndForgetNoteDatabaseFile:(NSString *)newfilename;

- (BOOL)removeSpuriousDatabaseFileNotes;

- (void)relocateNotesDirectory;

+ (NSURL *)defaultNotesDirectoryURLReturningError:(out NSError **)outErr;

- (OSStatus)noteFileRenamed:(FSRef *)childRef fromName:(NSString *)oldName toName:(NSString *)newName;

- (NSString *)uniqueFilenameForTitle:(NSString *)title fromNote:(NoteObject *)note;

- (OSStatus)deleteFileInNotesDirectory:(FSRef *)childRef forFilename:(NSString *)filename;

+ (OSStatus)trashFolderRef:(FSRef *)trashRef forChild:(FSRef *)childRef;

- (void)notifyOfChangedTrash;

@end

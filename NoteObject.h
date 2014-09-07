//
//  NoteObject.h
//  Notation
//
//  Created by Zachary Schneirov on 12/19/05.

/*Copyright (c) 2010, Zachary Schneirov. All rights reserved.
    This file is part of Notational Velocity.

    Notational Velocity is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Notational Velocity is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Notational Velocity.  If not, see <http://www.gnu.org/licenses/>. */


@import Cocoa;
#import "NTVTypes.h"
#import "NoteCatalogEntry.h"
#import "BufferUtils.h"
#import "SynchronizedNoteProtocol.h"
#import "NoteAttributeColumn.h"

@class LabelObject;
@class WALStorageController;
@class NotesTableView;
@class ExternalEditor;

typedef struct _NoteFilterContext {
	char* needle;
	BOOL useCachedPositions;
} NoteFilterContext;

extern NSComparator const NTVNoteCompareDateModified;
extern NSComparator const NTVNoteCompareDateCreated;
extern NSComparator const NTVNoteCompareLabelString;
extern NSComparator const NTVNoteCompareTitle;

extern NSComparator const NTVNoteCompareFilename;
extern NSComparator const NTVNoteCompareNodeID;
extern NSComparator const NTVNoteCompareFileSize;

extern NTVColumnAttributeGetter const NTVNoteUnifiedCellGetter;
extern NTVColumnAttributeGetter const NTVNoteUnifiedCellSingleLineGetter;
extern NTVColumnAttributeGetter const NTVNoteTableTitleGetter;
extern NTVColumnAttributeGetter const NTVNoteHighlightedTableTitleGetter;
extern NTVColumnAttributeGetter const NTVNoteTitleGetter;

extern NTVColumnAttributeGetter const NTVNoteLabelCellGetter;
extern NTVColumnAttributeGetter const NTVNoteDateModifiedStringGetter;
extern NTVColumnAttributeGetter const NTVNoteDateCreatedStringGetter;

extern NTVColumnAttributeSetter const NTVNoteTitleSetter;
extern NTVColumnAttributeSetter const NTVNoteLabelCellSetter;

extern NSString *const NTVNoteFileUpdatedNotification;
extern NSString *const NTVNoteContentsUpdatedNotification;
extern NSString *const NTVNoteNeedsWriteNotification;

@class NoteObject;

@protocol NoteObjectDelegate <NSObject>

@property (nonatomic, readonly) NTVStorageFormat currentNoteStorageFormat;

- (void)note:(NoteObject *)note didAddLabelSet:(NSSet *)labelSet;
- (void)note:(NoteObject *)note didRemoveLabelSet:(NSSet *)labelSet;
- (void)note:(NoteObject *)note attributeChanged:(NSString *)attribute;
- (void)noteDidNotWrite:(NoteObject*)note errorCode:(OSStatus)error;

- (void)updateLinksToNote:(NoteObject*)aNoteObject fromOldName:(NSString*)oldname;

@property (nonatomic, readonly) CGFloat titleColumnWidth;


@end

@protocol NoteObjectFileManager <NSObject>

@property (nonatomic, readonly) UInt32 diskUUIDIndex;
@property (nonatomic, readonly) long blockSize;

- (NSString*)uniqueFilenameForTitle:(NSString*)title fromNote:(NoteObject*)note;

- (BOOL)notesDirectoryContainsFile:(NSString*)filename returningFSRef:(FSRef*)childRef;
- (OSStatus)refreshFileRefIfNecessary:(FSRef *)childRef withName:(NSString *)filename charsBuffer:(UniChar*)charsBuffer;

- (NSMutableData*)dataFromFileInNotesDirectory:(FSRef*)childRef forFilename:(NSString*)filename;
- (NSMutableData*)dataFromFileInNotesDirectory:(FSRef*)childRef forCatalogEntry:(NoteCatalogEntry*)catEntry;

- (OSStatus)noteFileRenamed:(FSRef*)childRef fromName:(NSString*)oldName toName:(NSString*)newName;
- (OSStatus)fileInNotesDirectory:(FSRef*)childRef isOwnedByUs:(BOOL*)owned hasCatalogInfo:(FSCatalogInfo *)info;
- (OSStatus)createFileIfNotPresentInNotesDirectory:(FSRef*)childRef forFilename:(NSString*)filename fileWasCreated:(BOOL*)created;
- (OSStatus)storeDataAtomicallyInNotesDirectory:(NSData*)data withName:(NSString*)filename destinationRef:(FSRef*)destRef;
- (OSStatus)moveFileToTrash:(FSRef *)childRef forFilename:(NSString*)filename;

@end

@interface NoteObject : NSObject <SynchronizedNote>

//syncing w/ files in directory
@property (nonatomic, readonly) NSInteger storageFormat;
@property (nonatomic, copy, readonly) NSString *filename;
@property (nonatomic, readonly) UInt32 fileNodeID;
@property (nonatomic, readonly) UInt32 fileSize;
@property (nonatomic, readonly) const UTCDateTime *fileModifiedDate;
@property (nonatomic, readonly) const UTCDateTime *attributesModifiedDate;
@property (nonatomic) CFAbsoluteTime modifiedDate;
@property (nonatomic) CFAbsoluteTime createdDate;
@property (nonatomic) NSStringEncoding fileEncoding;

@property (nonatomic, copy) NSString *title;
@property (nonatomic, copy) NSString *labels;
@property (nonatomic, copy, readonly) NSArray *prefixParents;

- (void)resetFoundPtrs;
BOOL noteContainsUTF8String(NoteObject *note, NoteFilterContext *context);
BOOL noteTitleHasPrefixOfUTF8String(NoteObject *note, const char* fullString, size_t stringLen);
BOOL noteTitleIsAPrefixOfOtherNoteTitle(NoteObject *longerNote, NoteObject *shorterNote);

@property (nonatomic, assign) id<NoteObjectDelegate> delegate;
@property (nonatomic, assign) id<NoteObjectFileManager> fileManager;

- (instancetype)initWithNoteBody:(NSAttributedString*)bodyText title:(NSString*)aNoteTitle delegate:(id <NoteObjectDelegate>)aDelegate fileManager:(id <NoteObjectFileManager>)fileManager format:(NTVStorageFormat)formatID labels:(NSString*)aLabelString NS_DESIGNATED_INITIALIZER;
- (instancetype)initWithCatalogEntry:(NoteCatalogEntry*)entry delegate:(id <NoteObjectDelegate>)aDelegate fileManager:(id <NoteObjectFileManager>)fileManager NS_DESIGNATED_INITIALIZER;

@property (nonatomic, readonly) NSSet *labelSet;
- (void)replaceMatchingLabelSet:(NSSet*)aLabelSet;
- (void)replaceMatchingLabel:(LabelObject*)label;
- (void)updateLabelConnectionsAfterDecoding;
- (void)updateLabelConnections;
- (void)disconnectLabels;
- (NSMutableSet*)labelSetFromCurrentString;
- (NSArray*)orderedLabelTitles;

- (void)updateWithSyncBody:(NSString*)newBody andTitle:(NSString*)newTitle;
- (void)registerModificationWithOwnedServices;

- (OSStatus)writeCurrentFileEncodingToFSRef:(FSRef*)fsRef;
- (BOOL)upgradeToUTF8IfUsingSystemEncoding;
- (BOOL)upgradeEncodingToUTF8;
- (BOOL)updateFromFile;
- (BOOL)updateFromCatalogEntry:(NoteCatalogEntry*)catEntry;
- (BOOL)updateFromData:(NSMutableData*)data inFormat:(NSInteger)fmt;

- (OSStatus)writeFileDatesAndUpdateTrackingInfo;

- (void)mirrorTags;

- (NSURL*)uniqueNoteLink;
- (NSString*)noteFilePath;
- (void)invalidateFSRef;

- (BOOL)writeUsingJournal:(WALStorageController*)wal;

- (BOOL)writeUsingCurrentFileFormatIfNecessary;
- (BOOL)writeUsingCurrentFileFormatIfNonExistingOrChanged;
- (BOOL)writeUsingCurrentFileFormat;
- (void)makeNoteDirtyUpdateTime:(BOOL)updateTime updateFile:(BOOL)updateFile;

- (void)moveFileToTrash;
- (void)removeFileFromDirectory;
- (BOOL)removeUsingJournal:(WALStorageController*)wal;

- (OSStatus)exportToDirectoryRef:(FSRef*)directoryRef withFilename:(NSString*)userFilename usingFormat:(NSInteger)storageFormat overwrite:(BOOL)overwrite;
- (NSRange)nextRangeForWords:(NSArray*)words options:(unsigned)opts range:(NSRange)inRange;
- (void)editExternallyUsingEditor:(ExternalEditor*)ed;
- (void)abortEditingInExternalEditor;

- (void)setFilenameFromTitle;
- (void)setFilename:(NSString*)aString withExternalTrigger:(BOOL)externalTrigger;
- (void)updateTablePreviewString;
- (void)initContentCacheCString;
- (void)updateContentCacheCStringIfNecessary;
@property (nonatomic, copy) NSAttributedString *contentString;
- (NSAttributedString*)printableStringRelativeToBodyFont:(NSFont*)bodyFont;
- (NSString*)combinedContentWithContextSeparator:(NSString*)sepWContext;
- (void)setForegroundTextColorOnly:(NSColor*)aColor;
- (void)_resanitizeContent;
- (void)updateUnstyledTextWithBaseFont:(NSFont*)baseFont;
- (void)updateDateStrings;
@property (nonatomic) NSRange selectedRange;
- (BOOL)contentsWere7Bit;
- (void)addPrefixParentNote:(NoteObject*)aNote;
- (void)removeAllPrefixParentNotes;
- (void)previewUsingMarked;

@property (nonatomic, readonly) NSUndoManager *undoManager;

@end

@interface NoteObject (NTVLabelDrawing)

- (NSSize)sizeOfLabelBlocks;
- (void)drawLabelBlocksInRect:(NSRect)aRect rightAlign:(BOOL)onRight highlighted:(BOOL)isHighlighted;

@end

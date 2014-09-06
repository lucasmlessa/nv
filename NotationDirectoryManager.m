//
//  NotationDirectoryManager.m
//  Notation
//
//  Created by Zachary Schneirov on 12/10/09.

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

#import "NotationDirectoryManager.h"
#import "NSFileManager_NV.h"
#import "NotationPrefs.h"
#import "BufferUtils.h"
#import "GlobalPrefs.h"
#import "NotationSyncServiceManager.h"
#import "NoteObject.h"
#import "DeletionManager.h"
#import "NSCollection_utils.h"

#define kMaxFileIteratorCount 100

@implementation NotationController (NotationDirectoryManager)


NSInteger compareCatalogEntryName(const void *one, const void *two) {
    return (int)CFStringCompare((CFStringRef)((*(NoteCatalogEntry **)one)->filename), 
								(CFStringRef)((*(NoteCatalogEntry **)two)->filename), kCFCompareCaseInsensitive);
}

static NSComparisonResult(^const NTVCatalogValueCompareNodeID)(NSValue *, NSValue *) = ^(NSValue *a, NSValue *b){
	NoteCatalogEntry* aEntry = (NoteCatalogEntry*)[a pointerValue];
	NoteCatalogEntry* bEntry = (NoteCatalogEntry*)[b pointerValue];
	return NTVCompare(aEntry->nodeID, bEntry->nodeID);
};

NSInteger compareCatalogValueFileSize(id *a, id *b) {
	NoteCatalogEntry* aEntry = (NoteCatalogEntry*)[*(id*)a pointerValue];
	NoteCatalogEntry* bEntry = (NoteCatalogEntry*)[*(id*)b pointerValue];
	
    return aEntry->logicalSize - bEntry->logicalSize;
}


//used to find notes corresponding to a group of existing files in the notes dir, with the understanding 
//that the files' contents are up-to-date and the filename property of the note objs is also up-to-date
//e.g. caller should know that if notes are stored as a single DB, then the file could still be out-of-date
- (NSSet*)notesWithFilenames:(NSArray*)filenames unknownFiles:(NSArray**)unknownFiles {
	//intersects a list of filenames with the current set of available notes

	NSMutableDictionary *lcNamesDict = [NSMutableDictionary dictionaryWithCapacity:[filenames count]];
	for (NSString *path in filenames) {
		//assume that paths are of NSFileManager origin, not Carbon File Manager
		//(note filenames are derived with the expectation of matching against Carbon File Manager)
		NSString *key = [[[[path lastPathComponent] precomposedStringWithCanonicalMapping] lowercaseString] stringByReplacingOccurrencesOfString:@":" withString:@"/"];
		lcNamesDict[key] = path;
	}
	
	NSMutableSet *foundNotes = [NSMutableSet setWithCapacity:[filenames	count]];

	for (NoteObject *aNote in allNotes) {
		NSString *existingRequestedFilename = [filenameOfNote(aNote) lowercaseString];
		if (existingRequestedFilename && lcNamesDict[existingRequestedFilename]) {
			[foundNotes addObject:aNote];
			//remove paths from the dict as they are matched to existing notes; those left over will be new ("unknown") files
			[lcNamesDict removeObjectForKey:existingRequestedFilename];
		}
	}
	if (unknownFiles) *unknownFiles = [lcNamesDict allValues];
	return foundNotes;
}


void FSEventsCallback(ConstFSEventStreamRef stream, void* info, size_t num_events, void* event_paths, 
					  const FSEventStreamEventFlags flags[],
                      const FSEventStreamEventId event_ids[]) {
	NotationController* self = (NotationController*)info;
	
	BOOL rootChanged = NO;
	size_t i = 0;
	for (i = 0; i < num_events; i++) {
		// We could also check whether all the events are bookended by eventIDs
		// that were contemporaneous with a change by NotationFileManager
		// as it lacks kFSEventStreamCreateFlagIgnoreSelf
		if ((flags[i] & kFSEventStreamEventFlagRootChanged) && !event_ids[i]) {
			rootChanged = YES;
			break;
		}
	}
	
	//the directory was moved; re-initialize the event stream for the new path
	//but do so after this callback ends to avoid confusing FSEvents
	if (rootChanged) {
		NSLog(@"FSEventsCallback detected directory dislocation; reconfiguring stream");
		[self performSelector:@selector(_configureDirEventStream) withObject:nil afterDelay:0];
	}
	
	//NSLog(@"FSEventsCallback got a path change");
	[NSObject cancelPreviousPerformRequestsWithTarget:self selector:@selector(synchronizeNotesFromDirectory) object:nil];
	[self performSelector:@selector(synchronizeNotesFromDirectory) withObject:nil afterDelay:0.0];
}


- (void)_configureDirEventStream {
	//"updates" the event stream to point to the current notation directory path
	//or if the stream doesn't exist, creates it
	
	if (!eventStreamStarted) return;
	
	if (noteDirEventStreamRef) {
		//remove the event stream if it already exists, so that a new one can be created
		[self _destroyDirEventStream];
	}
	
	NSString *path = [[NSFileManager defaultManager] pathWithFSRef:&noteDirectoryRef];
	
	FSEventStreamContext context = { 0, self, CFRetain, CFRelease, CFCopyDescription };
	
	noteDirEventStreamRef = FSEventStreamCreate(NULL, &FSEventsCallback, &context, (CFArrayRef)@[path], kFSEventStreamEventIdSinceNow, 
												1.0, kFSEventStreamCreateFlagWatchRoot | 0x00000008 /*kFSEventStreamCreateFlagIgnoreSelf*/);
	
	FSEventStreamScheduleWithRunLoop(noteDirEventStreamRef, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
	if (!FSEventStreamStart(noteDirEventStreamRef)) {
		NSLog(@"could not start the FSEvents stream!");
	}
	
}

- (void)_destroyDirEventStream {
	if (eventStreamStarted) {
		NSAssert(noteDirEventStreamRef != NULL, @"can't destroy a NULL event stream");
		
		FSEventStreamStop(noteDirEventStreamRef);
		FSEventStreamInvalidate(noteDirEventStreamRef);
		FSEventStreamRelease(noteDirEventStreamRef);
		noteDirEventStreamRef = NULL;
	}
}

- (void)startFileNotifications {
	eventStreamStarted = YES;
	
	[self _configureDirEventStream];
}

- (void)stopFileNotifications {
	
	if (!eventStreamStarted) return;
	
	[self _destroyDirEventStream];

	eventStreamStarted = NO;
}

- (BOOL)synchronizeNotesFromDirectory {
    if ([self currentNoteStorageFormat] == SingleDatabaseFormat) {
		//NSLog(@"%s: called when storage format is singledatabase", _cmd);
		return NO;
	}
	
    //NSDate *date = [NSDate date];
    if ([self _readFilesInDirectory]) {
		//NSLog(@"read files in directory");
		
		directoryChangesFound = NO;
		if (catEntriesCount && [allNotes count]) {
			[self makeNotesMatchCatalogEntries:sortedCatalogEntries ofSize:catEntriesCount];
		} else {
			unsigned int i;
			
			if (![allNotes count]) {
				//no notes exist, so every file must be new
				for (i=0; i<catEntriesCount; i++) {
					if ([notationPrefs catalogEntryAllowed:sortedCatalogEntries[i]])
						[self addNoteFromCatalogEntry:sortedCatalogEntries[i]];
				}
			}
			
			if (!catEntriesCount) {
				//there is nothing at all in the directory, so remove all the notes
				[deletionManager addDeletedNotes:allNotes];
			}
		}
		
		if (directoryChangesFound) {
			[self resortAllNotes];
		    [self refilterNotes];
			
			[self updateTitlePrefixConnections];
		}
		
		//NSLog(@"file sync time: %g, ",[[NSDate date] timeIntervalSinceDate:date]);
		return YES;
    }
    
    return NO;
}

//scour the notes directory for fresh meat
- (BOOL)_readFilesInDirectory {
    
    OSStatus status = noErr;
    FSIterator dirIterator;
    ItemCount totalObjects = 0, dirObjectCount = 0;
    size_t i = 0, catIndex = 0;
    
    //something like 16 VM pages used here?
    if (!fsCatInfoArray) fsCatInfoArray = (FSCatalogInfo *)calloc(kMaxFileIteratorCount, sizeof(FSCatalogInfo));
    if (!HFSUniNameArray) HFSUniNameArray = (HFSUniStr255 *)calloc(kMaxFileIteratorCount, sizeof(HFSUniStr255));
	
    if ((status = FSOpenIterator(&noteDirectoryRef, kFSIterateFlat, &dirIterator)) == noErr) {
		//catEntriesCount = 0;
		
        do {
            // Grab a batch of source files to process from the source directory
            status = FSGetCatalogInfoBulk(dirIterator, kMaxFileIteratorCount, &dirObjectCount, NULL,
										  kFSCatInfoNodeFlags | kFSCatInfoFinderInfo | kFSCatInfoContentMod | 
										  kFSCatInfoAttrMod | kFSCatInfoDataSizes | kFSCatInfoNodeID,
										  fsCatInfoArray, NULL, NULL, HFSUniNameArray);
			
            if ((status == errFSNoMoreItems || status == noErr) && dirObjectCount) {
                status = noErr;
				
				totalObjects += dirObjectCount;
				if (totalObjects > totalCatEntriesCount) {
					size_t oldCatEntriesCount = totalCatEntriesCount;
					
					totalCatEntriesCount = totalObjects;
					catalogEntries = (NoteCatalogEntry *)realloc(catalogEntries, totalObjects * sizeof(NoteCatalogEntry));
					sortedCatalogEntries = (NoteCatalogEntry **)realloc(sortedCatalogEntries, totalObjects * sizeof(NoteCatalogEntry*));
					
					//clear unused memory to make filename and filenameChars null
					
					size_t newSpace = (totalCatEntriesCount - oldCatEntriesCount) * sizeof(NoteCatalogEntry);
					bzero(catalogEntries + oldCatEntriesCount, newSpace);
				}
				
				for (i = 0; i < dirObjectCount; i++) {
					// Only read files, not directories
					if (!(fsCatInfoArray[i].nodeFlags & kFSNodeIsDirectoryMask)) { 
						//filter these only for files that will be added
						//that way we can catch changes in files whose format is still being lazily updated
						
						NoteCatalogEntry *entry = &catalogEntries[catIndex];
						HFSUniStr255 *filename = &HFSUniNameArray[i];
						
						entry->fileType = ((FileInfo *)fsCatInfoArray[i].finderInfo)->fileType;
						entry->logicalSize = (UInt32)(fsCatInfoArray[i].dataLogicalSize & 0xFFFFFFFF);
						entry->nodeID = (UInt32)fsCatInfoArray[i].nodeID;
						entry->lastModified = fsCatInfoArray[i].contentModDate;
						entry->lastAttrModified = fsCatInfoArray[i].attributeModDate;

						
						if (filename->length > entry->filenameCharCount) {
							entry->filenameCharCount = filename->length;
							entry->filenameChars = (UniChar*)realloc(entry->filenameChars, entry->filenameCharCount * sizeof(UniChar));
						}
						
						memcpy(entry->filenameChars, filename->unicode, filename->length * sizeof(UniChar));
						
						if (!entry->filename)
							entry->filename = CFStringCreateMutableWithExternalCharactersNoCopy(NULL, entry->filenameChars, filename->length, entry->filenameCharCount, kCFAllocatorNull);
						else
							CFStringSetExternalCharactersNoCopy(entry->filename, entry->filenameChars, filename->length, entry->filenameCharCount);
						
						// mipe: Normalize the filename to make sure that it will be found regardless of international characters
						CFStringNormalize(entry->filename, kCFStringNormalizationFormC);

						catIndex++;
                    }
                }
				
				catEntriesCount = catIndex;
            }
            
        } while (status == noErr);
		
		FSCloseIterator(dirIterator);
		
		for (i=0; i<catEntriesCount; i++) {
			sortedCatalogEntries[i] = &catalogEntries[i];
		}
		
		return YES;
    }
    
    NSLog(@"Error opening FSIterator: %d", status);
    
    return NO;
}

- (BOOL)modifyNoteIfNecessary:(NoteObject*)aNoteObject usingCatalogEntry:(NoteCatalogEntry*)catEntry {
	//check dates
	UTCDateTime lastReadDate = fileModifiedDateOfNote(aNoteObject);
	UTCDateTime *lastAttrModDate = attrsModifiedDateOfNote(aNoteObject);
	
	//should we always update the note's stored inode here regardless?
//	NSLog(@"content mod: %d,%d,%d, attr mod: %d,%d,%d", catEntry->lastModified.highSeconds,catEntry->lastModified.lowSeconds,catEntry->lastModified.fraction,
//		  catEntry->lastAttrModified.highSeconds,catEntry->lastAttrModified.lowSeconds,catEntry->lastAttrModified.fraction);
	
	updateForVerifiedExistingNote(deletionManager, aNoteObject);
	
	if (fileSizeOfNote(aNoteObject) != catEntry->logicalSize ||
		*(int64_t*)&lastReadDate != *(int64_t*)&(catEntry->lastModified) ||
		*(int64_t*)lastAttrModDate != *(int64_t*)&(catEntry->lastAttrModified)) {

		//assume the file on disk was modified by someone other than us
				
		//check if this note has changes in memory that still need to be committed -- that we _know_ the other writer never had a chance to see
		if (![unwrittenNotes containsObject:aNoteObject]) {
			
			if (![aNoteObject updateFromCatalogEntry:catEntry]) {
				NSLog(@"file %@ was modified but could not be updated", catEntry->filename);
				//return NO;
			}
			//do not call makeNoteDirty because use of the WAL in this instance would cause redundant disk activity
			//in the event of a crash this change could still be recovered; 
			
			[aNoteObject registerModificationWithOwnedServices];
			[self schedulePushToAllSyncServicesForNote:aNoteObject];
			
			[self note:aNoteObject attributeChanged:NotePreviewString]; //reverse delegate?
			
			[delegate contentsUpdatedForNote:aNoteObject];
			
			[self performSelector:@selector(scheduleUpdateListForAttribute:) withObject:NoteDateModifiedColumnString afterDelay:0.0];
			
			notesChanged = YES;
			NSLog(@"FILE WAS MODIFIED: %@", catEntry->filename);
			
			return YES;
		} else {
			//it's a conflict! we win.
			NSLog(@"%@ was modified with unsaved changes in NV! Deciding the conflict in favor of NV.", catEntry->filename); 
		}
		
	}
	
	return NO;
}

- (void)makeNotesMatchCatalogEntries:(NoteCatalogEntry **)catEntriesPtrs ofSize:(size_t)bSize {
	NSArray *currentNotes = [allNotes sortedArrayWithOptions:NSSortConcurrent|NSSortStable usingComparator:NTVNoteCompareFilename];
	mergesort((void *)catEntriesPtrs, (size_t)bSize, sizeof(NoteCatalogEntry*), (int (*)(const void *, const void *))compareCatalogEntryName);
	
    NSMutableArray *addedEntries = [NSMutableArray array];
    NSMutableArray *removedEntries = [NSMutableArray array];
	
    //oldItems(a,i) = currentNotes
    //newItems(b,j) = catEntries;
    
    NSUInteger lastInserted = 0;

	for (NoteObject *currentNote in currentNotes) {
		BOOL exitedEarly = NO;
		for (NSUInteger j=lastInserted; j<bSize; j++) {

			CFComparisonResult order = CFStringCompare((CFStringRef)(catEntriesPtrs[j]->filename),
													   (CFStringRef)filenameOfNote(currentNote),
													   kCFCompareCaseInsensitive);
			if (order == kCFCompareGreaterThan) {    //if (A[i] < B[j])
				lastInserted = j;
				exitedEarly = YES;

				//NSLog(@"FILE DELETED (during): %@", filenameOfNote(currentNotes[i]));
				[removedEntries addObject:currentNote];
				break;
			} else if (order == kCFCompareEqualTo) {			//if (A[i] == B[j])
				//the name matches, so add this to changed iff its contents also changed
				lastInserted = j + 1;
				exitedEarly = YES;

				[self modifyNoteIfNecessary:currentNote usingCatalogEntry:catEntriesPtrs[j]];

				break;
			}

			//NSLog(@"FILE ADDED (during): %@", catEntriesPtrs[j]->filename);
			if ([notationPrefs catalogEntryAllowed:catEntriesPtrs[j]])
				[addedEntries addObject:[NSValue valueWithPointer:catEntriesPtrs[j]]];
		}

		if (!exitedEarly) {

			//element A[i] "appended" to the end of list B
			if (CFStringCompare((CFStringRef)filenameOfNote(currentNote),
								(CFStringRef)(catEntriesPtrs[MIN(lastInserted, bSize-1)]->filename),
								kCFCompareCaseInsensitive) == kCFCompareGreaterThan) {
				lastInserted = bSize;

				//NSLog(@"FILE DELETED (after): %@", filenameOfNote(currentNotes[i]));
				[removedEntries addObject:currentNote];
			}
		}

	}
    
    for (NSUInteger j=lastInserted; j<bSize; j++) {
		
		//NSLog(@"FILE ADDED (after): %@", catEntriesPtrs[j]->filename);
		if ([notationPrefs catalogEntryAllowed:catEntriesPtrs[j]])
			[addedEntries addObject:[NSValue valueWithPointer:catEntriesPtrs[j]]];
    }
    
	if ([addedEntries count] && [removedEntries count]) {
		[self processNotesAddedByCNID:addedEntries removed:removedEntries];
	} else {
		
		if (![removedEntries count]) {
			for (NSValue *addedEntryPtr in addedEntries) {
				[self addNoteFromCatalogEntry:(NoteCatalogEntry*)[addedEntryPtr pointerValue]];
			}
		}
		
		if (![addedEntries count]) {
			[deletionManager addDeletedNotes:removedEntries];
		}
	}
	
}

//find renamed notes through unique file IDs
- (void)processNotesAddedByCNID:(NSMutableArray*)addedEntries removed:(NSMutableArray*)removedEntries {
	NSUInteger aSize = [removedEntries count], bSize = [addedEntries count];
    
    //sort on nodeID here
	[addedEntries sortWithOptions:NSSortConcurrent usingComparator:NTVCatalogValueCompareNodeID];
	[removedEntries sortWithOptions:NSSortConcurrent usingComparator:NTVNoteCompareNodeID];
	
	NSMutableArray *hfsAddedEntries = [NSMutableArray array];
	NSMutableArray *hfsRemovedEntries = [NSMutableArray array];
	
    //oldItems(a,i) = currentNotes
    //newItems(b,j) = catEntries;
    
    NSUInteger i, j, lastInserted = 0;
    
    for (i=0; i<aSize; i++) {
		NoteObject *currentNote = removedEntries[i];
		
		BOOL exitedEarly = NO;
		for (j=lastInserted; j<bSize; j++) {
			
			NoteCatalogEntry *catEntry = (NoteCatalogEntry *)[addedEntries[j] pointerValue];
			int order = catEntry->nodeID - fileNodeIDOfNote(currentNote);
			
			if (order > 0) {    //if (A[i] < B[j])
				lastInserted = j;
				exitedEarly = YES;
				
				NSLog(@"File deleted as per CNID: %@", filenameOfNote(currentNote));
				[hfsRemovedEntries addObject:currentNote];
				
				break;
			} else if (order == 0) {			//if (A[i] == B[j])
				lastInserted = j + 1;
				exitedEarly = YES;
				
				
				//note was renamed!
				NSLog(@"File %@ renamed as per CNID to %@", filenameOfNote(currentNote), catEntry->filename);
				if (![self modifyNoteIfNecessary:currentNote usingCatalogEntry:catEntry]) {
					//at least update the file name, because we _know_ that changed
					
					directoryChangesFound = YES;
					
					[currentNote setFilename:(NSString*)catEntry->filename withExternalTrigger:YES];
				}
				
				notesChanged = YES;
				
				break;
			}
			
			//a new file was found on the disk! read it into memory!
			
			NSLog(@"File added as per CNID: %@", catEntry->filename);
			[hfsAddedEntries addObject:[NSValue valueWithPointer:catEntry]];
		}
		
		if (!exitedEarly) {
			
			NoteCatalogEntry *appendedCatEntry = (NoteCatalogEntry *)[addedEntries[MIN(lastInserted, bSize-1)] pointerValue];
			if (fileNodeIDOfNote(currentNote) - appendedCatEntry->nodeID > 0) {
				lastInserted = bSize;
				
				//file deleted from disk; 
				NSLog(@"File deleted as per CNID: %@", filenameOfNote(currentNote));
				[hfsRemovedEntries addObject:currentNote];
			}
		}
    }
    
    for (j=lastInserted; j<bSize; j++) {
		NoteCatalogEntry *appendedCatEntry = (NoteCatalogEntry *)[addedEntries[j] pointerValue];
		NSLog(@"File added as per CNID: %@", appendedCatEntry->filename);
		[hfsAddedEntries addObject:[NSValue valueWithPointer:appendedCatEntry]];
    }
	
	if ([hfsAddedEntries count] && [hfsRemovedEntries count]) {
		[self processNotesAddedByContent:hfsAddedEntries removed:hfsRemovedEntries];
	} else {
		//NSLog(@"hfsAddedEntries: %@, hfsRemovedEntries: %@", hfsAddedEntries, hfsRemovedEntries);
		if (![hfsRemovedEntries count]) {
			for (NSValue *entryValue in hfsAddedEntries) {
				NoteCatalogEntry *entry = entryValue.pointerValue;
				NSLog(@"File _actually_ added: %@ (%@)", entry->filename, NSStringFromSelector(_cmd));
				[self addNoteFromCatalogEntry:entry];
			}
		}
		
		if (![hfsAddedEntries count]) {
			[deletionManager addDeletedNotes:hfsRemovedEntries];
		}
	}
	
}

//reconcile the "actually" added/deleted files into renames for files with identical content, looking at logical size first
- (void)processNotesAddedByContent:(NSMutableArray*)addedEntries removed:(NSMutableArray*)removedEntries {
	//more than 1 entry in the same list could have the same file size, so sort-algo assumptions above don't apply here
	//instead of sorting, build a dict keyed by file size, with duplicate sizes (on the same side) chained into arrays
	//make temporary notes out of the new NoteCatalogEntries to allow their contents to be compared directly where sizes match
	NSMutableDictionary *addedDict = [NSMutableDictionary dictionaryWithCapacity:[addedEntries count]];

	for (NSValue *entryPointer in addedEntries) {
		NoteCatalogEntry *entry = entryPointer.pointerValue;

		NSNumber *sizeKey = @(entry->logicalSize);
		id sameSizeObj = addedDict[sizeKey];
		
		if ([sameSizeObj isKindOfClass:[NSArray class]]) {
			//just insert it directly; an array already exists
			NSAssert([sameSizeObj isKindOfClass:[NSMutableArray class]], @"who's inserting immutable collections into my dictionary?");
			[sameSizeObj addObject:entryPointer];
		} else if (sameSizeObj) {
			//two objects need to be inserted into the new array
			addedDict[sizeKey] = [NSMutableArray arrayWithObjects:sameSizeObj, entryPointer, nil];
		} else {
			//nothing with this key, just insert it directly
			addedDict[sizeKey] = entryPointer;
		}
	}
//	NSLog(@"removedEntries: %@", removedEntries);
//	NSLog(@"addedDict: %@", addedDict);

	for (NoteObject *removedObj in removedEntries) {
		NSNumber *sizeKey = @(fileSizeOfNote(removedObj));
		BOOL foundMatchingContent = NO;
		
		//does any added item have the same size as removedObj?
		//if sizes match, see if that added item's actual content fully matches removedObj's
		//if content matches, then both items cancel each other out, with a rename operation resulting on the item in the removedEntries list
		//if content doesn't match, then check the next item in the array (if there is more than one matching size), and so on
		//any item in removedEntries that has no match in the addedEntries list is marked deleted
		//everything left over in the addedEntries list is marked as new
		
		id sameSizeObj = addedDict[sizeKey];
		NSUInteger addedObjCount = [sameSizeObj isKindOfClass:[NSArray class]] ? [sameSizeObj count]: 1;
		while (sameSizeObj && !foundMatchingContent && addedObjCount-- > 0) {
			NSValue *val = [sameSizeObj isKindOfClass:[NSArray class]] ? sameSizeObj[addedObjCount] : sameSizeObj;
			NoteObject *addedObjToCompare = [[NoteObject alloc] initWithCatalogEntry:[val pointerValue] delegate:self];
			
			if ([[[addedObjToCompare contentString] string] isEqualToString:[[removedObj contentString] string]]) {
				//process this pair as a modification
				
				NSLog(@"File %@ renamed as per content to %@", filenameOfNote(removedObj), filenameOfNote(addedObjToCompare));
				if (![self modifyNoteIfNecessary:removedObj usingCatalogEntry:[val pointerValue]]) {
					//at least update the file name, because we _know_ that changed
					directoryChangesFound = YES;
					notesChanged = YES;
					[removedObj setFilename:filenameOfNote(addedObjToCompare) withExternalTrigger:YES];
				}
				
				if ([sameSizeObj isKindOfClass:[NSArray class]]) {
					[sameSizeObj removeObjectIdenticalTo:val];
				} else {
					[addedDict removeObjectForKey:sizeKey];
				}
				//also remove it from original array, which is easier to process for the leftovers that will actually be added
				[addedEntries removeObjectIdenticalTo:val];
				foundMatchingContent = YES;
			}
			[addedObjToCompare release];
		}
		
		if (!foundMatchingContent) {
			NSLog(@"File %@ _actually_ removed (size: %u)", filenameOfNote(removedObj), fileSizeOfNote(removedObj));
			[deletionManager addDeletedNote:removedObj];
		}
	}

	for (NSValue *entryPointer in addedEntries) {
		NoteCatalogEntry *appendedCatEntry = entryPointer.pointerValue;
		NSLog(@"File _actually_ added: %@ (%@)", appendedCatEntry->filename, NSStringFromSelector(_cmd));
		[self addNoteFromCatalogEntry:appendedCatEntry];
    }	
}

@end



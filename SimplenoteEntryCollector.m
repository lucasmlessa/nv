//
//  SimplenoteEntryCollector.m
//  Notation
//
//  Created by Zachary Schneirov on 12/4/09.

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


#import "GlobalPrefs.h"
#import "SimplenoteEntryCollector.h"
#import "SyncResponseFetcher.h"
#import "SimplenoteSession.h"
#import "NSString_NV.h"
#import "SynchronizedNoteProtocol.h"
#import "NoteObject.h"
#import "DeletedNoteObject.h"
#import "NotationController.h"

@implementation SimplenoteEntryCollector

//instances this short-lived class are intended to be started only once, and then deallocated

- (id)initWithEntriesToCollect:(NSArray*)wantedEntries simperiumToken:(NSString*)aSimperiumToken {
	self = [super init];
	if (!self) { return nil; }

	simperiumToken = [aSimperiumToken retain];
	entriesToCollect = [wantedEntries retain];
	entriesCollected = [[NSMutableArray alloc] init];
	entriesInError = [[NSMutableArray alloc] init];

	if (![simperiumToken length] || ![entriesToCollect count]) {
		NSLog(@"%@: missing parameters", NSStringFromSelector(_cmd));
		[self release];
		return (self = nil);
	}

	return self;
}

- (NSArray*)entriesToCollect {
	return entriesToCollect;
}

- (NSArray*)entriesCollected {
	return entriesCollected;
}
- (NSArray*)entriesInError {
	return entriesInError;
}

- (BOOL)collectionStarted {
	return entryFinishedCount != 0;
}

- (BOOL)collectionStoppedPrematurely {
	return stopped;
}

- (void)setRepresentedObject:(id)anObject {
	[representedObject autorelease];
	representedObject = [anObject retain];
}

- (id)representedObject {
	return representedObject;
}

- (void)dealloc {
	[entriesCollected release];
	[entriesToCollect release];
	[entriesInError release];
	[representedObject release];
	[simperiumToken release];
	[super dealloc];
}

- (NSString*)statusText {
	return [NSString stringWithFormat:NSLocalizedString(@"Downloading %lu of %lu notes", @"status text when downloading a note from the remote sync server"),
			(unsigned long)entryFinishedCount, (unsigned long)[entriesToCollect count]];
}

- (SyncResponseFetcher*)currentFetcher {
	return currentFetcher;
}

- (NSString*)localizedActionDescription {
	return NSLocalizedString(@"Downloading", nil);
}

- (void)stop {
	stopped = YES;
	
	//cancel the current fetcher, which will cause it to send its finished callback
	//and the stopped condition will send this class' finished callback
	[currentFetcher cancel];
}

- (SyncResponseFetcher*)fetcherForEntry:(id)entry {
	
	id<SynchronizedNote>originalNote = nil;
	if ([entry conformsToProtocol:@protocol(SynchronizedNote)]) {
		originalNote = entry;
		entry = [entry syncServicesMD][SimplenoteServiceName];
	}
	NSDictionary *headers = @{
		@"X-Simperium-Token": simperiumToken
	};
	NSURL *noteURL = [SimplenoteSession simperiumURLWithPath:[NSString stringWithFormat:@"/Note/i/%@", entry[@"key"]] parameters:nil];
	SyncResponseFetcher *fetcher = [[SyncResponseFetcher alloc] initWithURL:noteURL POSTData:nil headers:headers delegate:self];
	//remember the note for later? why not.
	if (originalNote) [fetcher setRepresentedObject:originalNote];
	return [fetcher autorelease];
}

- (void)startCollectingWithCallback:(SEL)aSEL collectionDelegate:(id)aDelegate {
	NSAssert([aDelegate respondsToSelector:aSEL], @"delegate doesn't respond!");
	NSAssert(![self collectionStarted], @"collection already started!");
	entriesFinishedCallback = aSEL;
	collectionDelegate = [aDelegate retain];
	
	[self retain];
	
	[(currentFetcher = [self fetcherForEntry:entriesToCollect[entryFinishedCount++]]) start];
}

- (NSDictionary*)preparedDictionaryWithFetcher:(SyncResponseFetcher*)fetcher receivedData:(NSData*)data {
	//logic abstracted for subclassing
	
	NSInteger version = 0;
	if ([fetcher headers][@"X-Simperium-Version"]) {
		version = [[fetcher headers][@"X-Simperium-Version"] integerValue];
	}

	NSError *error = nil;
	NSDictionary *rawObject = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
	if (!rawObject) {
		NSLog(@"Error while parsing Simplenote JSON note object: %@", error);
		return nil;
	}

	NSURL *url = [fetcher requestURL];
	NSUInteger index = [[url pathComponents] indexOfObject:@"i"];
	NSString *key = nil;
	if (index > 0 && index+1 < [[url pathComponents] count]) {
		key = [url pathComponents][(index+1)];
	}

	NSMutableDictionary *entry = [NSMutableDictionary dictionaryWithCapacity:12];
	NSNumber *deleted = @([rawObject[@"deleted"] integerValue]);
	NSArray *systemTags = rawObject[@"systemTags"];
    if (!systemTags)
        systemTags = @[];
    NSArray *tags = rawObject[@"tags"];
    if (!tags)
        tags = @[];
    NSString *content = rawObject[@"content"];
    if (!content)
        content = @"";
    
	if (key) { entry[@"key"] = key; }
	entry[@"version"] = @(version);
	entry[@"deleted"] = deleted;
	// Normalize dates from unix epoch timestamps to mac os x epoch timestamps
	entry[@"create"] = @([[NSDate dateWithTimeIntervalSince1970:[rawObject[@"creationDate"] doubleValue]] timeIntervalSinceReferenceDate]);
	entry[@"modify"] = @([[NSDate dateWithTimeIntervalSince1970:[rawObject[@"modificationDate"] doubleValue]] timeIntervalSinceReferenceDate]);
	if (rawObject[@"sharekey"]) {
		entry[@"sharekey"] = rawObject[@"shareURL"];
	}
	if (rawObject[@"publishkey"]) {
		entry[@"publishkey"] = rawObject[@"publishURL"];
	}
	entry[@"systemtags"] = systemTags;
	entry[@"tags"] = tags;
	if ([[fetcher representedObject] conformsToProtocol:@protocol(SynchronizedNote)]) entry[@"NoteObject"] = [fetcher representedObject];
	entry[@"content"] = content;

	//NSLog(@"fetched entry %@" , entry);

	return entry;
}

- (void)syncResponseFetcher:(SyncResponseFetcher*)fetcher receivedData:(NSData*)data returningError:(NSString*)errString {
	
	if (errString) {
		NSLog(@"%@: collector-%@ returned %@", NSStringFromSelector(_cmd), fetcher, errString);
		id obj = [fetcher representedObject];
		if (obj) {
			[entriesInError addObject:@{
				@"NoteObject": obj,
				@"StatusCode": @([fetcher statusCode])
			}];
		}
	} else {
		NSDictionary *preparedDictionary = [self preparedDictionaryWithFetcher:fetcher receivedData:data];
		if (!preparedDictionary) {
			// Parsing JSON failed.  Is this the right way to handle the error?
			id obj = [fetcher representedObject];
			if (obj) {
				[entriesInError addObject: @{
					@"NoteObject": obj,
					@"StatusCode": @([fetcher statusCode])
				}];
			}
		} else {
			if ([preparedDictionary count]) {
				[entriesCollected addObject: preparedDictionary];
			}
		}
	}
	
	if (entryFinishedCount >= [entriesToCollect count] || stopped) {
		//no more entries to collect!
		currentFetcher = nil;
		[collectionDelegate performSelector:entriesFinishedCallback withObject:self];
		[self autorelease];
		[collectionDelegate autorelease];
	} else {
		//queue next entry
		[(currentFetcher = [self fetcherForEntry:entriesToCollect[entryFinishedCount++]]) start];
	}
	
}

@end

@implementation SimplenoteEntryModifier

//TODO:
//if modification or creation date is 0, set it to the most recent time as parsed from the HTTP response headers
//when updating notes, sync times will be set to 0 when they are older than the time of the last HTTP header date
//which will be stored in notePrefs as part of the simplenote service dict

//all this to prevent syncing mishaps when notes are created and user's clock is set inappropriately

//modification times dates are set in case the app has been out of connectivity for a long time
//and to ensure we know what the time was for the next time we compare dates

- (id)initWithEntries:(NSArray*)wantedEntries operation:(SEL)opSEL simperiumToken:(NSString *)aSimperiumToken {
	self = [super initWithEntriesToCollect:wantedEntries simperiumToken:aSimperiumToken];
	if (!self) { return nil; }

	//set creation and modification date when creating
	//set modification date when updating
	//need to check for success when deleting
	if (![self respondsToSelector:opSEL]) {
		NSLog(@"%@ doesn't respond to %@", self, NSStringFromSelector(opSEL));
		[self release];
		return (self = nil);
	}
	fetcherOpSEL = opSEL;

	return self;
}

- (SyncResponseFetcher*)fetcherForEntry:(id)anEntry {
	return [self performSelector:fetcherOpSEL withObject:anEntry];
}

- (SyncResponseFetcher*)_fetcherForNote:(NoteObject*)aNote creator:(BOOL)doesCreate {
	NSAssert([aNote isKindOfClass:[NoteObject class]], @"need a real note to create");
	
	//if we're creating a note, grab the metadata directly from the note object itself, as it will not have a syncServiceMD dict
	NSDictionary *info = [aNote syncServicesMD][SimplenoteServiceName];
	//following assertion tests the efficacy our queued invocations system
	NSAssert(doesCreate == (nil == info), @"noteobject has MD for this service when it was attempting to be created or vise versa!");
	CFAbsoluteTime modNum = doesCreate ? aNote.modifiedDate : [info[@"modify"] doubleValue];
	
	//always set the mod date, set created date if we are creating, set the key if we are updating
	NSMutableString *noteBody = [[[aNote combinedContentWithContextSeparator: /* explicitly assume default separator if creating */
								   doesCreate ? nil : info[SimplenoteSeparatorKey]] mutableCopy] autorelease];
	//simpletext iPhone app loses any tab characters
	[noteBody replaceTabsWithSpacesOfWidth:[[GlobalPrefs defaultPrefs] numberOfSpacesInTab]];
	
	NSMutableDictionary *rawObject = [NSMutableDictionary dictionaryWithCapacity: 8];
	if (modNum > 0.0) rawObject[@"modificationDate"] = @([[NSDate dateWithTimeIntervalSinceReferenceDate:modNum] timeIntervalSince1970]);
	if (doesCreate) {
		rawObject[@"creationDate"] = @([[NSDate dateWithTimeIntervalSinceReferenceDate:aNote.createdDate] timeIntervalSince1970]);
		rawObject[@"systemTags"] = [NSMutableArray array];
		rawObject[@"shareURL"] = @"";
		rawObject[@"publishURL"] = @"";
		rawObject[@"deleted"] = @0;
	}
	
	NSArray *tags = [aNote orderedLabelTitles];
	rawObject[@"tags"] = tags;
	
	rawObject[@"content"] = noteBody;

	NSURL *noteURL = nil;
	NSDictionary *params = @{
		@"response": @"1"
	};
	if (doesCreate) {
		CFUUIDRef theUUID = CFUUIDCreate(NULL);
		CFStringRef string = CFUUIDCreateString(NULL, theUUID);
		CFRelease(theUUID);

		NSString *str = [(NSString *)string autorelease];
		str = [[str stringByReplacingOccurrencesOfString:@"-" withString:@""] lowercaseString];
		noteURL = [SimplenoteSession simperiumURLWithPath:[NSString stringWithFormat:@"/Note/i/%@", str] parameters:params];
	} else {
		NSUInteger v = [info[@"version"] integerValue];
		if (v > 0) {
			noteURL = [SimplenoteSession simperiumURLWithPath:[NSString stringWithFormat:@"/Note/i/%@/v/%lu", info[@"key"], (unsigned long)v] parameters:params];
		} else {
			noteURL = [SimplenoteSession simperiumURLWithPath:[NSString stringWithFormat:@"/Note/i/%@", info[@"key"]] parameters:params];
		}
	}
	NSData *POSTData = [NSJSONSerialization dataWithJSONObject:rawObject options:0 error:NULL];
	NSDictionary *headers = @{
		@"X-Simperium-Token": simperiumToken
	};
	SyncResponseFetcher *fetcher = [[SyncResponseFetcher alloc] initWithURL:noteURL POSTData:POSTData headers:headers contentType:@"application/json" delegate:self];
	[fetcher setRepresentedObject:aNote];
	return [fetcher autorelease];
}

- (SyncResponseFetcher*)fetcherForCreatingNote:(NoteObject*)aNote {
	return [self _fetcherForNote:aNote creator:YES];
}

- (SyncResponseFetcher*)fetcherForUpdatingNote:(NoteObject*)aNote {
	return [self _fetcherForNote:aNote creator:NO];
}

- (SyncResponseFetcher*)fetcherForDeletingNote:(DeletedNoteObject*)aDeletedNote {
	NSAssert([aDeletedNote isKindOfClass:[DeletedNoteObject class]], @"can't delete a note until you delete it yourself");
	
	NSDictionary *info = [aDeletedNote syncServicesMD][SimplenoteServiceName];
	
	if (!info[@"key"]) {
		//the deleted note lacks a key, so look up its created-equivalent and use _its_ metadata
		//handles the case of deleting a newly-created note after it had begun to sync, but before the remote operation gave it a key
		//because notes are queued against each other, by the time the create operation finishes on originalNote, it will have syncMD
		if ((info = [[aDeletedNote originalNote] syncServicesMD][SimplenoteServiceName]))
			[aDeletedNote setSyncObjectAndKeyMD:info forService:SimplenoteServiceName];
	}
	NSAssert(info[@"key"], @"fetcherForDeletingNote: got deleted note and couldn't find a key anywhere!");
	
	//in keeping with nv's behavior with sn api1, deleting only marks a note as deleted.
	//may want to implement actual purging (using HTTP DELETE) in the future
	NSURL *noteURL = [SimplenoteSession simperiumURLWithPath:[NSString stringWithFormat:@"/Note/i/%@", info[@"key"]] parameters:nil];
	NSData *postData = [NSJSONSerialization dataWithJSONObject:@{
		@"deleted": @1
	} options:0 error:NULL];
	NSDictionary *headers = @{
		@"X-Simperium-Token": simperiumToken
	};
	SyncResponseFetcher *fetcher = [[SyncResponseFetcher alloc] initWithURL:noteURL POSTData:postData headers:headers contentType:@"application/json" delegate:self];
	[fetcher setRepresentedObject:aDeletedNote];
	return [fetcher autorelease];
	
	return nil;
}

- (NSString*)localizedActionDescription {
	return (@selector(fetcherForCreatingNote:) == fetcherOpSEL ? NSLocalizedString(@"Creating", nil) :
			(@selector(fetcherForUpdatingNote:) == fetcherOpSEL ? NSLocalizedString(@"Updating",nil) : 
			 (@selector(fetcherForDeletingNote:) == fetcherOpSEL ? NSLocalizedString(@"Deleting", nil) : NSLocalizedString(@"Processing", nil)) ));
}

- (NSString*)statusText {
	NSString *opName = [self localizedActionDescription];
	if ([entriesToCollect count] == 1) {
		NoteObject *aNote = [currentFetcher representedObject];
		if ([aNote isKindOfClass:[NoteObject class]]) {
			return [NSString stringWithFormat:NSLocalizedString(@"%@ quot%@quot...",@"example: Updating 'joe shmoe note'"), opName, aNote.title];
		} else {
			return [NSString stringWithFormat:NSLocalizedString(@"%@ a note...", @"e.g., 'Deleting a note...'"), opName];
		}
	}
	return [NSString stringWithFormat:NSLocalizedString(@"%@ %lu of %lu notes", @"Downloading/Creating/Updating/Deleting 5 of 10 notes"),
			opName, (unsigned long)entryFinishedCount, (unsigned long)[entriesToCollect count]];
}

- (NSDictionary*)preparedDictionaryWithFetcher:(SyncResponseFetcher*)fetcher receivedData:(NSData*)data {
	NSError *error = nil;
	NSDictionary *rawObject = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
	if (!rawObject) {
		NSLog(@"Error while parsing Simplenote JSON note object: %@", error);
	}

	NSString *keyString = nil;
	NSURL *url = [fetcher requestURL];
	NSUInteger index = [[url pathComponents] indexOfObject:@"i"];
	if (index > 0 && index+1 < [[url pathComponents] count]) {
		keyString = [url pathComponents][(index+1)];
	}
	NSInteger version = 0;
	if ([fetcher headers][@"X-Simperium-Version"]) {
		version = [[fetcher headers][@"X-Simperium-Version"] integerValue];
	}
	
	NSMutableDictionary *result = [NSMutableDictionary dictionaryWithCapacity:5];
	NSMutableDictionary *syncMD = [NSMutableDictionary dictionaryWithCapacity:5];
	if (rawObject) {
		if (keyString) { syncMD[@"key"] = keyString; }
		syncMD[@"create"] = @([[NSDate dateWithTimeIntervalSince1970:[rawObject[@"creationDate"] doubleValue]] timeIntervalSinceReferenceDate]);
		syncMD[@"modify"] = @([[NSDate dateWithTimeIntervalSince1970:[rawObject[@"modificationDate"] doubleValue]] timeIntervalSinceReferenceDate]);
		syncMD[@"version"] = @(version);
		syncMD[@"dirty"] = @NO;
	} else {
		if ([fetcher statusCode] == 412) {
			syncMD[@"dirty"] = @NO;
		} else if ([fetcher statusCode] == 413) {
			// note was too large, don't clear dirty flag
			syncMD[@"error"] = @YES;
		}
		syncMD[@"version"] = @(version);
	}
	if ([fetcher representedObject]) {
		id <SynchronizedNote> aNote = [fetcher representedObject];
		result[@"NoteObject"] = aNote;
		
		if (@selector(fetcherForCreatingNote:) == fetcherOpSEL) {
			//these entries were created because no metadata had existed, thus we must give them metadata now,
			//which SHOULD be the same metadata we used when creating the note, but in theory the note could have changed in the meantime
			//in that case the newer modification date should later cause a resynchronization
			
			//we are giving this note metadata immediately instead of waiting for the SimplenoteSession delegate to do it during the final callback
			//to reduce the possibility of duplicates in the case of interruptions (where we might have forgotten that we had already created this)
			
			NSAssert([aNote isKindOfClass:[NoteObject class]], @"received a non-noteobject from a fetcherForCreatingNote: operation!");
			//don't need to store a separator for newly-created notes; when nil it is presumed the default separator
			if (rawObject) {
				[aNote setSyncObjectAndKeyMD:syncMD forService:SimplenoteServiceName];
			}

			[(NoteObject*)aNote makeNoteDirtyUpdateTime:NO updateFile:NO];
		} else if (@selector(fetcherForDeletingNote:) == fetcherOpSEL) {
			//this note has been successfully deleted, and can now have its Simplenote syncServiceMD entry removed 
			//so that _purgeAlreadyDistributedDeletedNotes can remove it permanently once the deletion has been synced with all other registered services
			NSAssert([aNote isKindOfClass:[DeletedNoteObject class]], @"received a non-deletednoteobject from a fetcherForDeletingNote: operation");
			[aNote removeAllSyncMDForService:SimplenoteServiceName];
		} else if (@selector(fetcherForUpdatingNote:) == fetcherOpSEL) {
			// SN api2 can return a content key in an update response containing
			// the merged changes from other clients....
			if (rawObject) {
				if (rawObject[@"content"]) {
					NSUInteger bodyLoc = 0;
					NSString *separator = nil;
					NSString *combinedContent = rawObject[@"content"];
                    NSAssert([aNote isKindOfClass:[NoteObject class]], @"received a non-noteobject from a fetcherForUpdatingNote: operation!");
					NSString *newTitle = [combinedContent syntheticTitleAndSeparatorWithContext:&separator bodyLoc:&bodyLoc oldTitle:((NoteObject *)aNote).title maxTitleLen:60];
				
					[(NoteObject *)aNote updateWithSyncBody:[combinedContent substringFromIndex:bodyLoc] andTitle:newTitle];
				}
			
				// Tags may have been changed by another client...
				NSSet *localTags = [NSSet setWithArray:[(NoteObject *)aNote orderedLabelTitles]];
				NSSet *remoteTags = [NSSet setWithArray:rawObject[@"tags"]];
				if (![localTags isEqualToSet:remoteTags]) {
					NSLog(@"Updating tags with remote values.");
					NSString *newLabelString = [remoteTags.allObjects componentsJoinedByString:@" "];
                    ((NoteObject *)aNote).labels = newLabelString;
				}
			}
			NSNumber *originalVersion = [aNote syncServicesMD][SimplenoteServiceName][@"version"];
			// There have been changes besides ours if the new version number is more than 1 from what we posted to
			BOOL merged = (version - [originalVersion integerValue]) > 1 ? YES : NO;
			[aNote setSyncObjectAndKeyMD:syncMD forService: SimplenoteServiceName];

			//NSLog(@"note update:\n %@", [aNote syncServicesMD]);
			if (merged) {
                [[NSNotificationCenter defaultCenter] postNotificationName:NTVNoteContentsUpdatedNotification object:aNote];
			}
		} else {
			NSLog(@"%@ called with unknown opSEL: %@", NSStringFromSelector(_cmd),NSStringFromSelector(fetcherOpSEL));
		}
		
	} else {
		NSLog(@"Hmmm. Fetcher %@ doesn't have a represented object. op = %@", fetcher, NSStringFromSelector(fetcherOpSEL));
	}

	if (keyString) { result[@"key"] = keyString; }
	
	
	return result;
}

@end

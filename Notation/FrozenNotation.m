//
//  FrozenNotation.m
//  Notation
//
//  Created by Zachary Schneirov on 4/4/06.

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


#import "FrozenNotation.h"
#import "PassphraseRetriever.h"
#import "NSData_transformations.h"
#import "NotationPrefs.h"

@implementation FrozenNotation

- (id)initWithCoder:(NSCoder *)decoder {
	if ([decoder containsValueForKey:VAR_STR(prefs)]) {
		prefs = [decoder decodeObjectForKey:VAR_STR(prefs)];
		notesData = [decoder decodeObjectForKey:VAR_STR(notesData)];
		deletedNoteSet = [decoder decodeObjectForKey:VAR_STR(deletedNoteSet)];
	} else {
		NSLog(@"FrozenNotation: decoding legacy %@", decoder);
		prefs = [decoder decodeObject];
		notesData = [decoder decodeObject];
		(void) [decoder decodeObject];
	}
	return self;
}

- (void)encodeWithCoder:(NSCoder *)coder {
	if ([coder allowsKeyedCoding]) {
		[coder encodeObject:prefs forKey:VAR_STR(prefs)];
		[coder encodeObject:notesData forKey:VAR_STR(notesData)];
		[coder encodeObject:deletedNoteSet forKey:VAR_STR(deletedNoteSet)];
	} else {
		[coder encodeObject:prefs];
		[coder encodeObject:notesData];
		[coder encodeObject:deletedNoteSet];
	}
}

- (id)initWithNotes:(NSMutableArray *)notes deletedNotes:(NSMutableSet *)antiNotes prefs:(NotationPrefs *)somePrefs {

	if ((self = [super init])) {

		notesData = [[NSMutableData alloc] init];
		NSKeyedArchiver *archiver = [[NSKeyedArchiver alloc] initForWritingWithMutableData:notesData];
		[archiver encodeObject:notes forKey:@"notes"];
		[archiver finishEncoding];

		prefs = somePrefs;
		deletedNoteSet = antiNotes;

		NSMutableData *oldNotesData = notesData;
		notesData = [oldNotesData compressedData];

		//ostensibly to create more entropy in the first blocks, relying on CBC dependency to crack
		//[notesData reverseBytes];

		if ([somePrefs doesEncryption]) {
			//compress?, reverse?, encrypt notesData based on notationprefs
			//we also want to have the salt reset here, but that requires knowing the original password

			if (![prefs encryptDataInNewSession:notesData]) {
				NSLog(@"Couldn't encrypt data!");
				return nil;
			}
		}

		if (![notesData length]) {
			NSLog(@"%@: empty notesData; returning nil", NSStringFromSelector(_cmd));
			return nil;
		}
	}

	return self;
}


+ (NSData *)frozenDataWithExistingNotes:(NSMutableArray *)notes
						   deletedNotes:(NSMutableSet *)antiNotes
								  prefs:(NotationPrefs *)prefs {
	FrozenNotation *frozenNotation = [[FrozenNotation alloc] initWithNotes:notes deletedNotes:antiNotes prefs:prefs];

	if (!frozenNotation)
		return nil;

	return [NSKeyedArchiver archivedDataWithRootObject:frozenNotation];
}

- (NSMutableArray *)unpackedNotesWithPrefs:(NotationPrefs *)somePrefs returningError:(OSStatus *)err {

	//decrypt notesData if necessary, then unarchive

	*err = noErr;

	@try {
		if ([somePrefs doesEncryption]) {
			if (![somePrefs decryptDataWithCurrentSettings:notesData]) {
				NSLog(@"Error decrypting data!");
				*err = kNoAuthErr;
				return nil;
			}
		}

		NSMutableData *oldNotesData = notesData;
		notesData = [oldNotesData uncompressedData];

		if (!notesData) {
			*err = kCompressionErr;
			NSLog(@"Error decompressing data");
			return nil;
		}
		NSKeyedUnarchiver *unarchiver = [[NSKeyedUnarchiver alloc] initForReadingWithData:notesData];
		allNotes = [unarchiver decodeObjectForKey:@"notes"];

	} @catch (NSException *e) {
		*err = kCoderErr;
		NSLog(@"(VERIFY) Error unarchiving notes from data (%@, %@)", [e name], [e reason]);
		return nil;
	}

	return allNotes;
}


- (NSMutableArray *)unpackedNotesReturningError:(OSStatus *)err {

	//decrypt notesData, grabbing password from from keychain or user as necessary, then unarchive

	*err = noErr;

	if (!allNotes) {

		@try {
			if ([prefs doesEncryption]) {
				BOOL keychainGood = YES;
				if (![prefs storesPasswordInKeychain] || !(keychainGood = [prefs canLoadPassphraseData:[prefs passwordDataFromKeychain]])) {

					if (!keychainGood) {
						//reset keychain identifier in case database file was duplicated and password was changed, and this is the old DB
						[prefs forgetKeychainIdentifier];
					}
					NSInteger result = [[PassphraseRetriever retrieverWithNotationPrefs:prefs] loadedUserPassphraseData];

					if (!result) {
						//must have clicked cancel or equivalent
						*err = kPassCanceledErr;
						return (nil);
					}
					//if result is 1, passphrase should already be loaded
				}
				if (![prefs decryptDataWithCurrentSettings:notesData]) {
					NSLog(@"Error decrypting data!");
					*err = kNoAuthErr;
					return (nil);
				}
			}

			NSMutableData *oldNotesData = notesData;
			notesData = [oldNotesData uncompressedData];

			if (!notesData) {
				*err = kCompressionErr;
				NSLog(@"Error decompressing data");
				return (nil);
			}
			BOOL keyedArchiveFailed = NO;
			@try {
				allNotes = [[[NSKeyedUnarchiver alloc] initForReadingWithData:notesData] decodeObjectForKey:@"notes"];
			} @catch (NSException *e) {
				keyedArchiveFailed = YES;
			}

			if (keyedArchiveFailed)
				allNotes = [NSUnarchiver unarchiveObjectWithData:notesData];
		} @catch (NSException *e) {
			*err = kCoderErr;
			NSLog(@"Error unarchiving notes from data (%@, %@)", [e name], [e reason]);
			return (nil);
		}
	}

	return allNotes;
}

- (NSMutableSet *)deletedNotes {
	return deletedNoteSet;
}

- (NotationPrefs *)notationPrefs {
	return prefs;
}


@end
//
//  TemporaryFileCachePreparer.m
//  Notation
//

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


#import "TemporaryFileCachePreparer.h"
#import "NotationPrefs.h"
#include <sys/mount.h>

//used to mount a RAM disk for temporary file editing
//instances of this class are probably not useful for more than one preparation
//(which probably wouldn't be necessary anyway as RAM disks can't be unmounted)

@implementation TemporaryFileCachePreparer

static BOOL MountPointExists(const char *expectedMountPath);

static NSString *RAMDiskMountPath();

static NSString *TempDirectoryPathForEditing();

- (id)init {
	if ((self = [super init])) {

		[[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(taskTerminated:)
													 name:NSTaskDidTerminateNotification object:nil];
	}

	return self;
}

- (void)dealloc {
	[[NSNotificationCenter defaultCenter] removeObserver:self];
}

static BOOL MountPointExists(const char *expectedMountPath) {
	struct statfs *buf;

	int i, numMounts = getmntinfo(&buf, MNT_NOWAIT);
	if (!numMounts) return NO;

	char absExpectedMountPath[PATH_MAX];
	if (!realpath(expectedMountPath, absExpectedMountPath)) {
		NSLog(@"error getting realpath from path '%s': %d", expectedMountPath, errno);
		return NO;
	}

	for (i = 0; i < numMounts; ++i) {
		if (!strcmp(absExpectedMountPath, buf[i].f_mntonname)) {
			return YES;
		}
	}

	return NO;
}

static NSString *RAMDiskMountPath() {
	return [NSTemporaryDirectory() stringByAppendingPathComponent:@"NVProtectedEditingSpace"];
}

static NSString *TempDirectoryPathForEditing() {
	return [NSTemporaryDirectory() stringByAppendingPathComponent:@"NVPlainTextEditingSpace"];
}

- (void)prepEditingSpaceIfNecessaryForNotationPrefs:(NotationPrefs *)prefs {

	NSAssert(prefs != nil, @"prefs are nil");

	if ([self isPreparing]) {
		NSLog(@"prepEditingSpaceIfNecessary: already preparing");
		return;
	}

	notationPrefs = prefs;

	/*
		single-DB with encryption: use a mounted RAM disk
		single-DB without encryption: use temp directory
		plain text files: just use files directly
		rich text files: use temp directory
		HTML files: use temp directory

		ODBEditor will decide based on each specific file whether to open it directly
		e.g., if it's a plain text file in plain-text-mode, or if the editor supports RTF/HTML
	*/

	if ([prefs notesStorageFormat] != SingleDatabaseFormat || ![prefs doesEncryption] ||
			[[NSUserDefaults standardUserDefaults] boolForKey:@"UseInsecureTempEditing"]) {
		if ([self _createFolderAtPath:TempDirectoryPathForEditing()]) {
			[self _finishPreparationWithPath:TempDirectoryPathForEditing()];
		} else {
			[self _stopPreparation];
		}
		return;
	}

	if (MountPointExists([RAMDiskMountPath() fileSystemRepresentation])) {
		//NSLog(@"mount point already exists; giving path directly");
		[self _finishPreparationWithPath:RAMDiskMountPath()];
		return;
	}

	NSAssert(preparedCachePath == nil, @"preparedCachePath was already set");

	startedPreparing = YES;

	//now do a callback-chained hdiutil attach, newfs_hfs, and mount -t at RAMDiskMountPath()

	[self _attachRAMDiskOfCapacity:2];
}

- (void)_attachRAMDiskOfCapacity:(NSUInteger)numberOfMegabytes {
	NSAssert(attachTask == nil, @"attachTask was already used!");
	NSAssert(numberOfMegabytes > 0 && numberOfMegabytes < 100, @"unreasonable capacity requested");

	[(attachTask = [NSTask new]) setLaunchPath:@"/usr/bin/hdiutil"];
	[attachTask setArguments:@[@"attach", @"-nomount", @"-nobrowse", [NSString stringWithFormat:@"ram://%lu", (2 * 1024 * numberOfMegabytes)]]];
	[attachTask setStandardOutput:[NSPipe pipe]];
	[attachTask launch];
}

- (void)_buildHFSFileSystemOnDevice:(NSString *)aDeviceName {
	NSAssert(newfsTask == nil, @"newfsTask was already used!");
	NSAssert(aDeviceName != nil, @"no device name passed");

	[(newfsTask = [NSTask new]) setLaunchPath:@"/sbin/newfs_hfs"];
	[newfsTask setArguments:@[@"-v", [RAMDiskMountPath() lastPathComponent], aDeviceName]];
	[newfsTask launch];
}

- (void)_mountHFSFileSystemOnDevice:(NSString *)aDeviceName {
	NSAssert(mountTask == nil, @"mountTask was already used!");
	NSAssert(aDeviceName != nil, @"no device name passed");

	[(mountTask = [NSTask new]) setLaunchPath:@"/sbin/mount"];
	[mountTask setArguments:@[@"-t", @"hfs", @"-o", @"nobrowse", aDeviceName, RAMDiskMountPath()]];
	[mountTask launch];
}

- (BOOL)isPreparing {
	return startedPreparing;
}

- (NSString *)preparedCachePath {
	return preparedCachePath;
}

- (void)_finishPreparationWithPath:(NSString *)aPath {
	//funnel for the success delegate method

	NSAssert(preparedCachePath == nil, @"preparedCachePath already set?");
	preparedCachePath = aPath;

	startedPreparing = NO;

	id <TemporaryFileCachePreparerDelegate> delegate = self.delegate;
	[delegate temporaryFileCachePreparerFinished:self];
}

- (void)_stopPreparation {

	startedPreparing = NO;

	id <TemporaryFileCachePreparerDelegate> delegate = self.delegate;
	[delegate temporaryFileCachePreparerDidNotFinish:self];
}

- (BOOL)_createFolderAtPath:(NSString *)path {
	NSError *err = nil;
	NSFileManager *fileMan = [NSFileManager defaultManager];
	BOOL isDirectory = NO, didCreate = ([fileMan fileExistsAtPath:path isDirectory:&isDirectory] && isDirectory) ? YES :
			[fileMan createDirectoryAtPath:path withIntermediateDirectories:NO attributes:@{NSFilePosixPermissions : @0700} error:&err];
	if (!didCreate) NSLog(@"couldn't create directory '%@': %@", path, (err ? [err localizedDescription] : @"(unknown error)"));
	return didCreate;
}

- (void)taskTerminated:(NSNotification *)aNotification {

	if (startedPreparing) {
		NSTask *task = [aNotification object];

		if (task == attachTask || task == newfsTask || task == mountTask) {
			//each launched task retains self, so as long as each task triggers this method, then each retain should be balanced with an autorelease

			if ([task terminationStatus]) {
				//assume an exit status of 0 means success
				[self _stopPreparation];
				return;
			}
		}

		if (task == attachTask) {
			//read deviceName and store in ivar
			//start newfs task

			NSData *outData = [[[attachTask standardOutput] fileHandleForReading] readDataToEndOfFile];
			if (outData) {
				NSString *outString = [[NSString alloc] initWithData:outData encoding:NSUTF8StringEncoding];

				NSString *newDeviceName = nil;
				[[NSScanner scannerWithString:outString]   scanUpToCharactersFromSet:
						[NSCharacterSet whitespaceAndNewlineCharacterSet] intoString:&newDeviceName];
				deviceName = newDeviceName;

				if (!deviceName) deviceName = outString;
			}
			if (![deviceName length]) {
				NSLog(@"couldn't get device name from hdiutil attach");
				[self _stopPreparation];
			} else {
//				NSLog(@"device name is '%@'", deviceName);
				[self _buildHFSFileSystemOnDevice:deviceName];
			}
		}

		if (task == newfsTask) {
			//make directory and set permissions
			if (![self _createFolderAtPath:RAMDiskMountPath()]) {
				[self _stopPreparation];
			} else {
				//start mount task
				[self _mountHFSFileSystemOnDevice:deviceName];
			}
		}

		if (task == mountTask) {
			//return newly initialized path to delegate, after verifying

			NSString *path = RAMDiskMountPath();
			if (MountPointExists([path fileSystemRepresentation])) {
				[self _finishPreparationWithPath:path];
			} else {
				NSLog(@"the RAM disk somehow does not exist!");
				[self _stopPreparation];
			}
		}

	} else {
		//don't bother doing anything unless we're actually expecting one of this instance's tasks to complete
	}
}


@end
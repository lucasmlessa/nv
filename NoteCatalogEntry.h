//
//  NoteCatalogEntry.h
//  Notation
//
//  Created by Zachary Waldowski on 9/6/14.
//  Copyright (c) 2014 ElasticThreads. All rights reserved.
//

@import CoreFoundation;

typedef struct _NoteCatalogEntry {
    UTCDateTime lastModified;
    UTCDateTime lastAttrModified;
    UInt32 logicalSize;
    OSType fileType;
    UInt32 nodeID;
    CFMutableStringRef filename;
    UniChar *filenameChars;
    UniCharCount filenameCharCount;
} NoteCatalogEntry;

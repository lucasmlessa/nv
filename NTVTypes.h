//
//  NTVTypes.h
//  Notation
//
//  Created by Zachary Waldowski on 9/6/14.
//  Copyright (c) 2014 ElasticThreads. All rights reserved.
//

@import Foundation;

typedef NS_ENUM(NSInteger, NTVStorageFormat) {
    NTVStorageFormatDatabase = 0,
    NTVStorageFormatPlainText,
    NTVStorageFormatRichText,
    NTVStorageFormatHTML,
    NTVStorageFormatWord,
    NTVStorageFormatOpenXML
};
